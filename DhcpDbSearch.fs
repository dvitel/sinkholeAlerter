module SinkholeAlerter.DhcpDbSearch

open System
open SinkholeAlerter.Types

let private createDhcpQueryAndParameters ipDecimalWithTimeStamp = 
    let reqId = Guid.NewGuid().ToString().Replace("-", "_") |> sprintf "dhcp_%s"
    let _, reqValuesQueryParts, reqValuesParameters = 
        ipDecimalWithTimeStamp
        |> List.fold(fun (i, reqValuesQueryParts, reqValuesParameters) (ipDecimal, timeStamp) -> 
            let ipDecimalParamName = sprintf "@ip%d" i
            let timeStampParamName = sprintf "@tm%d" i
            let reqValuesQueryParts = 
                (sprintf "(%s, %s)" ipDecimalParamName timeStampParamName)::reqValuesQueryParts
            let reqValuesParameters = 
                reqValuesParameters
                |> Map.add ipDecimalParamName (ipDecimal :> obj)
                |> Map.add timeStampParamName (timeStamp :> obj)
            i+1, reqValuesQueryParts, reqValuesParameters
        ) (0, [], Map.empty)    
    let query = 
        sprintf "
CREATE TEMPORARY TABLE %s (
    ip_decimal int(10) NOT NULL PRIMARY KEY UNIQUE,
    tm timestamp NOT NULL);
        
INSERT INTO %s VALUES %s;

SELECT * FROM 
    (SELECT dhcp.ip_decimal, dhcp.mac_string FROM dhcp 
        JOIN %s r ON dhcp.ip_decimal = r.ip_decimal 
                AND dhcp.timeStamp <= r.tm 
                AND dhcp.timeStamp > TIMESTAMPADD(minute, -10, r.tm)
        ORDER BY dhcp.ip_decimal ASC, dhcp.timestamp DESC) res
GROUP BY ip_decimal;    
            " reqId reqId (String.Join(",", reqValuesQueryParts)) reqId
    query, reqValuesParameters

let findMacInDhcpAsync (infringements: Infringement list) = async {
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
                    infringement.preNatIpDecimal, infringement.localTimeStamp)
                |> createDhcpQueryAndParameters
            let! ipToMacMapping = 
                Db.queryDbAsync query parameters 
                    (fun reader acc -> 
                        Map.add (reader.[0] :?> uint32)
                            (reader.[1] :?> string) acc) Map.empty
            return
                chunk
                |> List.fold(fun acc infringement -> 
                    match Map.tryFind infringement.preNatIpDecimal ipToMacMapping with
                    | Some mac -> 
                        {infringement with mac = mac}::acc
                    | _ -> infringement::acc) infringements
            }) (async.Return [])    
    return infringements        
}               
