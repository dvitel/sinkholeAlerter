module SinkholeAlerter.UserNameDbSearch

open System
open SinkholeAlerter.Types

//as with DHCP MySQL query this module performs quering of radacct or contactinfo 
//methods here are very similar to those in DHCP quering - TODO: think about refactoring and another generalization
let private createRadiusQueryAndParams reqId ipMacPairs = 
    //TODO: here we have andother req id - use one req id during 1 session of searches
    let reqTable = reqId.ToString().Replace("-", "_") |> sprintf "radius_%s"
    let _, reqValuesQueryParts, reqValuesParameters = 
        ipMacPairs
        |> List.fold(fun (i, reqValuesQueryParts, reqValuesParameters) (ip, mac, tm) -> 
            let ipParamName = sprintf "@ip%d" i
            let macParamName = sprintf "@mac%d" i
            let tmParamName = sprintf "@tm%d" i
            let reqValuesQueryParts = 
                (sprintf "(%s, %s, %s)" ipParamName macParamName tmParamName)::reqValuesQueryParts
            let reqValuesParameters = 
                reqValuesParameters
                |> Map.add ipParamName (ip :> obj)
                |> Map.add macParamName (mac :> obj)
                |> Map.add tmParamName (tm :> obj)
            i+1, reqValuesQueryParts, reqValuesParameters
        ) (0, [], Map.empty)    
    let query = 
        sprintf "
CREATE TEMPORARY TABLE %s (
    ip varchar(15) NOT NULL,
    mac varchar(50) NOT NULL, 
    tm timestamp NOT NULL);
        
INSERT INTO %s VALUES %s;

SELECT radacct.username, radacct.FramedIPAddress, radacct.CallingStationId, res2.tm FROM radacct
    JOIN
    (SELECT res.FramedIPAddress, res.CallingStationId, res.tm, MAX(timestamp) as timestamp FROM
        (SELECT radacct.FramedIPAddress, radacct.CallingStationId, r.tm, radacct.timestamp FROM radacct 
            JOIN %s r ON radacct.FramedIPAddress = r.ip AND radacct.CallingStationId = r.mac AND radacct.timestamp <= r.tm) res
        GROUP BY res.FramedIPAddress, res.CallingStationId, res.tm) res2
    ON radacct.FramedIPAddress = res2.FramedIPAddress AND radacct.CallingStationId = res2.CallingStationId AND radacct.timestamp = res2.timestamp;
  
            " reqTable reqTable (String.Join(",", reqValuesQueryParts)) reqTable
    query, reqValuesParameters

//again:
// 1) we split infringements by chunks of 20
// 2) for each chunk we perform query
// 3) we filter errored data and fill necessary fields
let private radiusTableSearch reqId connectionString (infringements: Infringement list) = async {
    try
    let! infringements = 
        infringements
        |> List.chunkBySize 20  //again - do experiments here
        |> List.fold(fun acc chunk -> async {
            let! infringements = acc
            let query, parameters = 
                chunk
                |> List.map(fun infringement -> 
                    let ip = string infringement.preNatIp
                    ip, infringement.mac, infringement.localTimeStamp)
                |> List.distinct
                |> createRadiusQueryAndParams reqId
            let! ipMacToUserNameMapping = 
                Db.queryDbAsync connectionString query parameters 
                    (fun reader acc -> 
                        let userName = reader.[0] :?> string
                        let ip = reader.[1] :?> string
                        let mac = reader.[2] :?> string
                        let tm = reader.[3] :?> DateTime
                        Map.add (ip, mac, tm) userName acc) Map.empty
            return
                chunk
                |> List.fold(fun infringements infringement -> 
                    let ip = string infringement.preNatIp
                    match Map.tryFind (ip, infringement.mac, infringement.localTimeStamp) ipMacToUserNameMapping with
                    | Some username -> 
                        {infringement with userName = username}::infringements
                    | _ -> {infringement with error = "RADIUS user name not found"}::infringements) 
                        infringements
            }) (async.Return [])
    return infringements
    with e -> 
        let msg = 
            match e with
            | :? AggregateException as e -> e.InnerException.Message
            | e -> e.Message
        return 
            infringements
            |> List.map(fun i -> {i with error = msg})
}

//NON-RADIUS user: using contactinfo
let private createNonRadiusQueryAndParams reqId macs = 
    let reqTable = reqId.ToString().Replace("-", "_") |> sprintf "nonradius_%s"
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
            " reqTable reqTable (String.Join(",", reqValuesQueryParts)) reqTable
    query, reqValuesParameters

//again:
// 1) we split infringements by chunks of 20
// 2) for each chunk we perform query
// 3) we filter errored data and fill necessary fields
let private nonradiusTableSearch reqId connectionString (infringements: Infringement list) = async {
    try
    let chunks = 
        infringements
        |> List.chunkBySize 10    
    let! infringements = 
        chunks 
        |> List.fold(fun acc chunk -> async {
            let! infringements = acc
            let query, parameters = 
                chunk
                |> List.map(fun infringement -> infringement.mac)
                |> List.distinct
                |> createNonRadiusQueryAndParams reqId
            let! macToUserNameMapping = 
                Db.queryDbAsync connectionString query parameters 
                    (fun reader acc -> 
                        let userName = reader.[0] :?> string
                        let mac = reader.[1] :?> string
                        Map.add mac userName acc) Map.empty
            return
                chunk
                |> List.fold(fun infringements infringement -> 
                    match Map.tryFind infringement.mac macToUserNameMapping with
                    | Some username -> {infringement with userName = username}::infringements
                    | _ -> {infringement with error="NON-RADIUS user name not found"}::infringements) 
                        infringements
            }) (async.Return [])    
    return infringements
    with e -> 
        let msg = 
            match e with
            | :? AggregateException as e -> e.InnerException.Message
            | e -> e.Message
        return 
            infringements
            |> List.map(fun i -> {i with error = e.Message})
            
}

//here we first partition infringements into RADIUS, NON-RADIUS collections by analysing first 2 bytes 
let searchAsync reqId connectionString (infringements: Infringement list) = async {
    //first we filter all these infringements which does not have mac from prev step
    let radiusInfringements, nonradiusInfringements = 
        infringements |> List.fold(fun (radiusInfringements, nonradiusInfringements) infringement ->   
            match infringement.mac, infringement.preNatIp.GetAddressBytes() with
            | (null | ""), _ -> 
                eprintfn "No MAC was found for infringement during dhcp search: %s" (string infringement)
                radiusInfringements, nonradiusInfringements
            | _, [| 172uy; 19uy; _; _ |] -> //here is pattern matching of first 2 bytes, neat
                infringement::radiusInfringements, nonradiusInfringements
            | _ -> 
                radiusInfringements, infringement::nonradiusInfringements) ([], [])
    let! radiusInfringements' = 
        match radiusInfringements with
        | [] -> async.Return []
        | _ -> radiusTableSearch reqId connectionString radiusInfringements
    let! nonradiusInfringements' = 
        match nonradiusInfringements with
        | [] -> async.Return []
        | _ -> nonradiusTableSearch reqId connectionString nonradiusInfringements
    return radiusInfringements' @ nonradiusInfringements'
}        
