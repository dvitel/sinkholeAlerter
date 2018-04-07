module SinkholeAlerter.App
open System.IO

[<EntryPoint>]
let main argv =
    try
    if argv.Length < 1 then 
        printfn "Usage: dotnet <thisdll> <path to notices folder>"
        exit 1
    let folderPath = argv.[0]
    async {
        printfn "----------------------------------------"        
        printfn "Reading infringements from notices..."        
        let! infringements = NoticeXmlParsing.parseManyAsync folderPath            
        let infringementsByNatLog = 
            infringements |> List.fold(fun acc infringement -> 
                let natLogFile = Path.Combine(".", "nat_logs", NatLogSearch.getNatLogFileName infringement)
                match Map.tryFind natLogFile acc with
                | None -> 
                    Map.add natLogFile [infringement] acc
                | Some infringements -> 
                    Map.add natLogFile (infringement::infringements) acc) Map.empty
        infringementsByNatLog
        |> Map.iter(fun natLogFile infringements ->  

            printfn "\tFor %s"  natLogFile
            infringements |> List.iter(string >> printfn "\t\t%s")
        )
        printfn "----------------------------------------"    
        printfn "Searching NAT logs..." 
        let! infringements = 
            infringementsByNatLog
            |> Map.fold(fun acc natLogFileName infringements -> 
                (async {
                    let! res = NatLogSearch.searchNatLogForManyAsync natLogFileName infringements
                    return natLogFileName, res, infringements
                 })::acc) []
            |> Async.Parallel
        let infringements = 
            infringements
            |> Seq.fold(fun acc (natLogFile, res, originalInfringements) ->
                match res with
                | NatLogSearch.NatLogSearchResult.Processed (foundInfringements, []) ->
                    printfn "\t%s: all infringements found" natLogFile
                    foundInfringements
                    |> List.iter(string >> printfn "\t\t%s")
                    foundInfringements @ acc
                | NatLogSearch.NatLogSearchResult.Processed (foundInfringements, toFind) ->
                    printfn "\t%s: misses infringements" natLogFile
                    toFind
                    |> List.iter(string >> printfn "\t\t%s")
                    printfn "\t%s: infringements found" natLogFile
                    foundInfringements
                    |> List.iter(string >> printfn "\t\t%s")                    
                    foundInfringements @ acc
                | NatLogSearch.NatLogSearchResult.FileNotFound -> 
                    printfn "\t%s: file not found" natLogFile
                    originalInfringements
                    |> List.iter(string >> printfn "\t\t%s") 
                    acc
                | NatLogSearch.NatLogSearchResult.Error msg -> 
                    printfn "\t%s: %s" natLogFile msg
                    originalInfringements
                    |> List.iter(string >> printfn "\t\t%s")                     
                    acc
            ) []
        printfn "----------------------------------------"    
        printfn "DHCP db search..."             
        let! infringementsOpt = DhcpDbSearch.findMacInDhcpAsync infringements
        let infringements =
            match infringementsOpt with
            | DhcpDbSearch.DhcpSearchResult.Processed (infringementsWithMac, []) -> 
                infringementsWithMac
                |> List.iter(string >> printfn "\t\t%s")
                infringementsWithMac
            | DhcpDbSearch.DhcpSearchResult.Processed (infringementsWithMac, infringementsWithoutMac) -> 
                printfn "\tNo Mac was found for next:"
                infringementsWithoutMac
                |> List.iter(string >> printfn "\t\t%s")
                match infringementsWithMac with 
                | [] -> ()
                | _ -> 
                    printfn "\tContinue for:"
                    infringementsWithMac
                    |> List.iter(string >> printfn "\t\t%s")
                infringementsWithMac
            | DhcpDbSearch.DhcpSearchResult.Error msg -> 
                eprintfn "\tDB error: %s" msg
                exit 1
        let! infringements = async {
            match infringements with
            | [] -> return []
            | _ -> 
                printfn "----------------------------------------"    
                printfn "Fetching user info data..."
                let! radiusInfringementsOpt, nonradiusInfringementsOpt = UserNameDbSearch.searchAsync infringements
                let radiusInfringements = 
                    match radiusInfringementsOpt with
                    | UserNameDbSearch.Error msg, infringements ->
                        printfn "RADIUS fetch error: %A" msg
                        infringements |> List.iter(string >> printfn "\t\t%s")
                        []
                    | UserNameDbSearch.Processed (withName, withoutName), _ -> 
                        withName @ withoutName
                    | _ -> []
                let nonradiusInfringements = 
                    match nonradiusInfringementsOpt with
                    | UserNameDbSearch.Error msg, infringements ->
                        printfn "non-RADIUS fetch error: %A" msg
                        infringements |> List.iter(string >> printfn "\t\t%s")
                        []
                    | UserNameDbSearch.Processed (withName, withoutName), _ -> 
                        withName @ withoutName
                    | _ -> []   
                return radiusInfringements @ nonradiusInfringements                     
            }                     
        printfn "----------------------------------------"  
        printfn "Done."
        printfn ""
        match infringements with
        | [] -> ()
        | _ -> 
            infringements |> List.iter(string >> printfn "%s")
    } |> Async.RunSynchronously
    0
    with e -> 
        eprintfn "Error: %A" e
        1
