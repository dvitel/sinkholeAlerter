module SinkholeAlerter.App
open System.IO
open Microsoft.Extensions.Configuration
open System

///<summary>
///Build pipeline for reading and searching infringements
///argv[0] - optional json config file (see example config.json)
///</summary>
[<EntryPoint>]
let main argv =
    try    
    let configFileName =
        if argv.Length > 1 then argv.[0]
        else "config.json"        
    //parse json config
    let config = 
        ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile(configFileName)
            .Build()
    let natLogChunkSize = 
        match Int32.TryParse config.["natChunkSize"] with
        | true, v when v > 0 && v < 100 -> v 
        | _ -> 8
    let reqId = System.Guid.NewGuid() //this we use for temp tables
    let stopwatch = System.Diagnostics.Stopwatch()        
    async { //async is kind of deferred computation, usually used for IO, or parallel threading in F#
        stopwatch.Start()
        printfn "----------------------------------------"        
        printfn "Reading infringements from notices..."
        //parsing noticesFolder notices      
        let! infringements = NoticeXmlParsing.parseManyAsync config.["noticesFolder"]            
        let infringementsByNatLog, failedInfringementsOnParse, noticeCount, natLogs = 
            infringements |> Array.fold(fun (infringementsByNatLog, failedInfringements, noticeCount, natLogs) infringement -> 
                match infringement.error with
                | "" -> 
                    let natLogFile = Path.Combine(config.["natLogFolder"], infringement.natLogFileName)
                    let infringementsByNatLog = 
                        match Map.tryFind natLogFile infringementsByNatLog with
                        | None -> 
                            Map.add natLogFile [infringement] infringementsByNatLog
                        | Some infringements -> 
                            Map.add natLogFile (infringement::infringements) infringementsByNatLog
                    infringementsByNatLog, failedInfringements, noticeCount+1, infringement.natLogFileName::natLogs
                | _ ->
                    infringementsByNatLog, infringement::failedInfringements, noticeCount, natLogs) (Map.empty, [], 0, [])
        printfn "Parse done: %d to search, %d notices unparsable, elapsed %s" noticeCount failedInfringementsOnParse.Length
            (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------"
        printfn "Searching NAT logs in parallel (Chunk size: %dMB)..." natLogChunkSize
        natLogs |> List.iter(printfn "\t%s")
        let! infringements = 
            infringementsByNatLog
            |> Map.fold(fun acc natLogFileName infringements -> 
                (NatLogSearch.searchNatLogForManyAsync natLogChunkSize natLogFileName infringements)::acc) []
            |> Async.Parallel                        
        let infringements, failedInfringementsOnNat = 
            infringements
            |> Seq.collect id
            |> Seq.toList
            |> List.partition(function {error=""} -> true | _ -> false)
        printfn "Search done: %d found, %d has errors, %d filtered in total, elapsed %s"
            infringements.Length failedInfringementsOnNat.Length (failedInfringementsOnNat.Length + failedInfringementsOnParse.Length)
            (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------"    
        printfn "DHCP db search..."             
        let! infringements = DhcpDbSearch.findMacInDhcpAsync reqId config.["connectionString"] infringements
        let infringements, failedInfringementsOnDhcp =
            infringements
            |> List.partition(function {error=""} -> true | _ -> false)
        printfn "Search done: %d found, %d has errors, %d filtered in total, elapsed %s"
            infringements.Length failedInfringementsOnDhcp.Length (failedInfringementsOnDhcp.Length + failedInfringementsOnNat.Length + failedInfringementsOnParse.Length)  
            (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------"          
        let! infringements = async {
            match infringements with
            | [] -> return []
            | _ ->                  
                printfn "Fetching user info data..."
                let! infringements = UserNameDbSearch.searchAsync reqId config.["connectionString"] infringements
                let infringements, failedInfringementsOnUserFetch = 
                    infringements |> List.partition (function {error=""} -> true | _ -> false)
                return infringements @ failedInfringementsOnUserFetch                     
            } 
        printfn "Done, elapsed %s" (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------" 
        let infringements = 
            infringements 
            @ failedInfringementsOnDhcp
            @ failedInfringementsOnNat
            @ failedInfringementsOnParse
        infringements |> List.iter(string >> printfn "%s")
    } |> Async.RunSynchronously
    0
    with e -> 
        eprintfn "Error: %A" e
        1
