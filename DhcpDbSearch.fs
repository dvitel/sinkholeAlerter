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
    ip_decimal int(10) UNSIGNED NOT NULL PRIMARY KEY UNIQUE,
    tm timestamp NOT NULL);
        
INSERT INTO %s VALUES %s;

SELECT * FROM 
    (SELECT dhcp.ip_decimal, dhcp.mac_string FROM dhcp 
        JOIN %s r ON dhcp.ip_decimal = r.ip_decimal 
                AND dhcp.timeStamp <= r.tm 
        ORDER BY dhcp.ip_decimal ASC, dhcp.timestamp DESC) res
GROUP BY ip_decimal;    
            " reqId reqId (String.Join(",", reqValuesQueryParts)) reqId
    query, reqValuesParameters

type DhcpSearchResult = 
    | Processed of Infringement list * Infringement list
    | Error of string
let findMacInDhcpAsync (infringements: Infringement list) = async {
    try
    let chunks = 
        infringements
        |> List.splitInto 10    
    let! infringementsWithMac, infringementsWithoutMac = 
        chunks 
        |> List.fold(fun acc chunk -> async {
            let! infringementsWithMac, infringementsWithoutMac = acc
            let query, parameters = 
                chunk
                |> List.map(fun infringement -> 
                    infringement.preNatIpDecimal, infringement.localTimeStamp)
                |> createDhcpQueryAndParameters
            let! ipToMacMapping = 
                Db.queryDbAsync query parameters 
                    (fun reader acc -> 
                        let ipDecimal = reader.[0] :?> uint32
                        let mac = reader.[1] :?> string
                        Map.add ipDecimal mac acc) Map.empty
            return
                chunk
                |> List.fold(fun (infringementsWithMac, infringementsWithoutMac) infringement -> 
                    match Map.tryFind infringement.preNatIpDecimal ipToMacMapping with
                    | Some mac -> 
                        {infringement with mac = mac}::infringementsWithMac, infringementsWithoutMac
                    | _ -> infringementsWithMac, infringement::infringementsWithoutMac) 
                    (infringementsWithMac, infringementsWithoutMac)
            }) (async.Return ([], []))    
    return Processed(infringementsWithMac, infringementsWithoutMac)            
    with e -> 
        let e = 
            match e with 
            | :? AggregateException as e -> e.InnerException
            | _ -> e 
        return Error e.Message                           
}               
