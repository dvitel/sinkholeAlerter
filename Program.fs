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
        let! infringements = NoticeXmlParsing.parseManyAsync folderPath
        let infringementsByNatLog = 
            infringements |> List.fold(fun acc infringement -> 
                let natLogFile = Path.Combine(".", "nat_logs", NatLogSearch.getNatLogFileName infringement)
                match Map.tryFind natLogFile acc with
                | None -> 
                    Map.add natLogFile [infringement] acc
                | Some infringements -> 
                    Map.add natLogFile (infringement::infringements) acc) Map.empty
        let! infringements = 
            infringementsByNatLog
            |> Map.fold(fun acc natLogFileName infringements -> 
                (NatLogSearch.searchNatLogForManyAsync natLogFileName infringements)::acc) []
            |> Async.Parallel
        let infringements = infringements |> Seq.collect id |> List.ofSeq        
        let! infringements = DhcpDbSearch.findMacInDhcpAsync infringements
        let! infringements = UserNameDbSearch.searchAsync infringements
        match infringements with
        | [] -> ()
        | _ -> 
            printfn "Found all info for next infringements: "
            infringements |> List.iter(string >> printfn "%s")
    } |> Async.RunSynchronously
    0
    with e -> 
        eprintfn "Error: %A" e
        1
