module SinkholeAlerter.App
open System.IO
open System
open System.Runtime.Serialization.Json

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
    let reqId = System.Guid.NewGuid() //this we use for temp tables in MySQL
    let stopwatch = System.Diagnostics.Stopwatch()        
    //async is kind of deferred computation, usually used for IO, or parallel threading in F#
    //async execution does not start at point of declaration
    //To start it we use Async.Start, Async.RunSynchronously, let!, use!, do!
    //this is similar concept to 
    // 1. C/C++ (new standard) - coroutines 
    // 2. C# - async/await 
    // 3. EcmaScript 6 (JavaScript) - async/await 
    async { 
        //here we read config from file and parse it to object of type Config: see Types.fs        
        let! config = async {
            let! configText = Async.AwaitTask(File.ReadAllTextAsync(configFileName))
            let configTextBytes = System.Text.Encoding.UTF8.GetBytes configText
            use memory = new MemoryStream(configTextBytes)
            let serializer = DataContractJsonSerializer(typeof<Types.Config>)
            return serializer.ReadObject(memory) :?> Types.Config
        }        
        stopwatch.Start()
        printfn "----------------------------------------"        
        printfn "Reading infringements from notices..."
        //parsing noticesFolder notices      
        let! infringements = NoticeXmlParsing.parseManyAsync config.noticesFolder  
        //from infringements we build map natLogFileName --> list of corresponding infringements
        //at same time we filter failed infringements on parse out of processing
        let infringementsByNatLog, failedInfringementsOnParse, noticeCount, natLogs = 
            infringements |> Array.fold(fun (infringementsByNatLog, failedInfringements, noticeCount, natLogs) infringement -> 
                match infringement.error with
                | "" -> 
                    let natLogFile = Path.Combine(config.natLogFolder, infringement.natLogFileName)
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
        printfn "Searching NAT logs in parallel (Chunk size: %dMB)..." config.natChunkSize
        natLogs |> List.distinct |> List.iter(printfn "\t%s")

        //here we search natlogs - 5 files in parallel at a time (in order to avoid OutOfMemoryException or exhausting amount of file handlers)
        let! infringements = 
            infringementsByNatLog
            |> Map.fold(fun acc natLogFileName infringements -> 
                (NatLogSearch.searchNatLogForManyAsync config.natChunkSize config.natTimeDelta natLogFileName infringements)::acc) []
            |> Seq.chunkBySize 5
            |> Seq.fold(fun acc asyncs -> 
                async {
                    let! prevResults = acc 
                    let! newResults = asyncs |> Async.Parallel
                    let newResults = newResults |> Seq.collect id 
                    return [ yield! prevResults; yield! newResults ]
                }) (async.Return [])
        
        //again, filter out fails in search
        let infringements, failedInfringementsOnNat = 
            infringements
            |> List.partition(function {error=""} -> true | _ -> false)
        printfn "Search done: %d found, %d has errors, %d filtered in total, elapsed %s"
            infringements.Length failedInfringementsOnNat.Length (failedInfringementsOnNat.Length + failedInfringementsOnParse.Length)
            (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------"    
        printfn "DHCP db search..."        

        //here we search Dhcp MySQL table      
        let! infringements = DhcpDbSearch.findMacInDhcpAsync reqId config.connectionString infringements

        //filtering out errors again
        let infringements, failedInfringementsOnDhcp =
            infringements
            |> List.partition(function {error=""} -> true | _ -> false)
        printfn "Search done: %d found, %d has errors, %d filtered in total, elapsed %s"
            infringements.Length failedInfringementsOnDhcp.Length (failedInfringementsOnDhcp.Length + failedInfringementsOnNat.Length + failedInfringementsOnParse.Length)  
            (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------"          

        //if we have any infringements on this stage, we should search user tables to find user name
        //it is done in UserNameDbSearch.searchAsync
        let! infringements = async {
            match infringements with
            | [] -> return []
            | _ ->                  
                printfn "Fetching user info data..."
                let! infringements = UserNameDbSearch.searchAsync reqId config.connectionString infringements
                let infringements, failedInfringementsOnUserFetch = 
                    infringements |> List.partition (function {error=""} -> true | _ -> false)
                return infringements @ failedInfringementsOnUserFetch                     
            } 
        printfn "Done, elapsed %s" (stopwatch.Elapsed.ToString(@"mm\:ss"))
        printfn "----------------------------------------" 

        //combine all together for report
        let infringements = 
            infringements 
            @ failedInfringementsOnDhcp
            @ failedInfringementsOnNat
            @ failedInfringementsOnParse
        infringements |> List.iter(string >> printfn "%s")
    } |> Async.RunSynchronously //start in main thread - another case - to start inside some multithreaded environment in ThreadPool
    0
    with e -> 
        eprintfn "Error: %A" e
        1
