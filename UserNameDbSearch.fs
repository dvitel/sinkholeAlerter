module SinkholeAlerter.UserNameDbSearch

open System
open SinkholeAlerter.Types

let private createRadiusQueryAndParams ipMacPairs = 
    //TODO: here we have andother req id - use one req id during 1 session of searches
    let reqId = Guid.NewGuid().ToString().Replace("-", "_") |> sprintf "radius_%s"
    let _, reqValuesQueryParts, reqValuesParameters = 
        ipMacPairs
        |> List.fold(fun (i, reqValuesQueryParts, reqValuesParameters) (ip, mac) -> 
            let ipParamName = sprintf "@ip%d" i
            let macParamName = sprintf "@mac%d" i
            let reqValuesQueryParts = 
                (sprintf "(%s, %s)" ipParamName macParamName)::reqValuesQueryParts
            let reqValuesParameters = 
                reqValuesParameters
                |> Map.add ipParamName (ip :> obj)
                |> Map.add macParamName (mac :> obj)
            i+1, reqValuesQueryParts, reqValuesParameters
        ) (0, [], Map.empty)    
    let query = 
        sprintf "
CREATE TEMPORARY TABLE %s (
    ip varchar(15) NOT NULL,
    mac varchar(50) NOT NULL, 
    PRIMARY KEY pk_tmp (ip, mac));
        
INSERT INTO %s VALUES %s;

SELECT radacct.username, radacct.FramedIPAddress, radacct.CallingStationId FROM radacct 
    JOIN %s r ON radacct.FramedIPAddress = r.ip AND radacct.CallingStationId = r.mac;
            " reqId reqId (String.Join(",", reqValuesQueryParts)) reqId
    query, reqValuesParameters

let private radiusTableSearch (infringements: Infringement list) = async {
    let chunks = 
        infringements
        |> List.splitInto 10    
    let! infringements = 
        chunks 
        |> List.fold(fun acc chunk -> async {
            let! infringements = acc
            let query, parameters = 
                chunk
                |> List.map(fun infringement -> 
                    let ip = string infringement.preNatIp
                    ip, infringement.mac)
                |> createRadiusQueryAndParams
            let! ipMacToUserNameMapping = 
                Db.queryDbAsync query parameters 
                    (fun reader acc -> 
                        let userName = reader.[0] :?> string
                        let ip = reader.[1] :?> string
                        let mac = reader.[2] :?> string
                        Map.add (ip, mac) userName acc) Map.empty
            return
                chunk
                |> List.fold(fun acc infringement -> 
                    let ip = string infringement.preNatIp
                    match Map.tryFind (ip, infringement.mac) ipMacToUserNameMapping with
                    | Some username -> 
                        {infringement with userName = username}::acc
                    | _ -> infringement::acc) infringements
            }) (async.Return [])    
    return infringements        
}

let private createNonRadiusQueryAndParams macs = 
    //TODO: here we have andother req id - use one req id during 1 session of searches
    let reqId = Guid.NewGuid().ToString().Replace("-", "_") |> sprintf "nonradius_%s"
    let _, reqValuesQueryParts, reqValuesParameters = 
        macs
        |> List.fold(fun (i, reqValuesQueryParts, reqValuesParameters) mac -> 
            let macParamName = sprintf "@mac%d" i
            let reqValuesQueryParts = 
                (sprintf "(%s)" macParamName)::reqValuesQueryParts
            let reqValuesParameters = 
                reqValuesParameters
                |> Map.add macParamName (mac :> obj)
            i+1, reqValuesQueryParts, reqValuesParameters
        ) (0, [], Map.empty)    
    let query = 
        sprintf "
CREATE TEMPORARY TABLE %s (
    mac varchar(50) NOT NULL PRIMARY KEY UNIQUE);
        
INSERT INTO %s VALUES %s;

SELECT contactinfo.contact, contactinfo.mac_string FROM contactinfo 
    JOIN %s r ON contactinfo.mac_string = r.mac;
            " reqId reqId (String.Join(",", reqValuesQueryParts)) reqId
    query, reqValuesParameters

let private nonradiusTableSearch (infringements: Infringement list) = async {
    let chunks = 
        infringements
        |> List.splitInto 10    
    let! infringements = 
        chunks 
        |> List.fold(fun acc chunk -> async {
            let! infringements = acc
            let query, parameters = 
                chunk
                |> List.map(fun infringement -> infringement.mac)
                |> createNonRadiusQueryAndParams
            let! macToUserNameMapping = 
                Db.queryDbAsync query parameters 
                    (fun reader acc -> 
                        let userName = reader.[0] :?> string
                        let mac = reader.[1] :?> string
                        Map.add mac userName acc) Map.empty
            return
                chunk
                |> List.fold(fun acc infringement -> 
                    match Map.tryFind infringement.mac macToUserNameMapping with
                    | Some username -> 
                        {infringement with userName = username}::acc
                    | _ -> infringement::acc) infringements
            }) (async.Return [])    
    return infringements        
}

let searchAsync (infringements: Infringement list) = async {
    //first we filter all these infringements which does not have mac from prev step
    let radiusInfringements, nonradiusInfringements = 
        infringements |> List.fold(fun (radiusInfringements, nonradiusInfringements) infringement ->   
            match infringement.mac, infringement.preNatIp.GetAddressBytes() with
            | (null | ""), _ -> 
                eprintfn "No MAC was found for infringement during dhcp search: %s" (string infringement)
                radiusInfringements, nonradiusInfringements
            | _, [| 172uy; 19uy; _; _ |] -> 
                infringement::radiusInfringements, nonradiusInfringements
            | _ -> 
                radiusInfringements, infringement::nonradiusInfringements) ([], [])
    let! radiusInfringements = 
        match radiusInfringements with
        | [] -> async.Return []
        | _ -> radiusTableSearch radiusInfringements
    let! nonradiusInfringements = 
        match radiusInfringements with
        | [] -> async.Return []
        | _ -> nonradiusTableSearch nonradiusInfringements
    return radiusInfringements @ nonradiusInfringements
}        
