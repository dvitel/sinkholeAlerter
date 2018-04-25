module SinkholeAlerter.DhcpDbSearch
//this module is about quering Dhcp table from MySQL. It uses DB.fs

open System
open SinkholeAlerter.Types

///<summary>
///Creates query string along with parameter map from given list of tuples (ipDecimal, timeStamp)
///</summary>
///<param name='reqId'>
///Guid which represents current program launch. 
/// DB queries create temp tables of form dhcp_<reqId> in order to gather data in optimal fashion 
///</param>
///<param name='ipDecimalWithTimeStamp'>
///List of (ipDecimal, timeStamp) pairs
///</param>
let private createDhcpQueryAndParameters reqId ipDecimalWithTimeStamp = 
    let reqTable = reqId.ToString().Replace("-", "_") |> sprintf "dhcp_%s"
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

    //Query explanation:
    // 1. We create temporary table
    // 2. We load all requested records in it by constructed INSERT
    //    Do not wory, params are secure here from SQL injection  
    // 3. We perform JOIN of special form:
    //    We select all dhcp records for given ipDecimal and with timeStamp 
    //    which is less or equal to given timeStamp.
    //    Each ipDecimal could have its own given timeStamp.
    //    Then in selected data we select records with maximum timeStamp for each given ipDecimal
    //    Thus, we find all dhcp record which were assigned to ipDecimals just before infringements
    let query = 
        sprintf "
CREATE TEMPORARY TABLE %s (
    ip_decimal int(10) UNSIGNED NOT NULL PRIMARY KEY UNIQUE,
    tm timestamp NOT NULL);
        
INSERT INTO %s VALUES %s;

SELECT * FROM dhcp 
JOIN
((SELECT ip_decimal, MAX(timeStamp) as timeStamp FROM 
    (SELECT dhcp.ip_decimal, dhcp.timeStamp FROM dhcp 
        JOIN %s r ON dhcp.ip_decimal = r.ip_decimal 
                AND dhcp.timeStamp <= r.tm 
        ORDER BY dhcp.ip_decimal ASC, dhcp.timestamp DESC) res
GROUP BY ip_decimal) as dhcp2) ON dhcp.ip_decimal = dhcp2.ip_decimal AND dhcp.timeStamp = dhcp2.timeStamp;   
            " reqTable reqTable (String.Join(",", reqValuesQueryParts)) reqTable
    query, reqValuesParameters

//This function is actually perform quering 
//We split all given infringements by chunks of 20 - could be ajusted or put in config
let findMacInDhcpAsync reqId connectionString (infringements: Infringement list) = async {
    try
    let! infringements = 
        infringements 
        |> List.chunkBySize 20 //todo: some experimentation
        |> List.fold(fun acc chunk -> async {
            let! infringements = acc
            let query, parameters = 
                chunk
                |> List.map(fun infringement -> 
                    infringement.preNatIpDecimal, infringement.localTimeStamp)
                |> createDhcpQueryAndParameters reqId
            //printfn "Executing %s" query
            let! ipToMacMapping = 
                Db.queryDbAsync connectionString query parameters 
                    (fun reader acc -> 
                        let ipDecimal = reader.[0] :?> uint32
                        let mac = reader.[1] :?> string
                        Map.add ipDecimal mac acc) Map.empty
            return
                chunk
                |> List.fold(fun infringements infringement -> 
                    match Map.tryFind infringement.preNatIpDecimal ipToMacMapping with
                    | Some mac -> 
                        {infringement with mac = mac}::infringements
                    | _ -> {infringement with error = "DHCP record not found"}::infringements) 
                    infringements
            }) (async.Return [])
    return infringements
    with e -> 
        //TODO: in noraml prudction impl here should be retry logic!!!!
        //but we do not care much for local db
        let e = 
            match e with 
            | :? AggregateException as e -> e.InnerException
            | _ -> e 
        return 
            infringements
            |> List.map(fun infringement -> 
                {
                    infringement with
                        error = e.Message
                })                    
}               
