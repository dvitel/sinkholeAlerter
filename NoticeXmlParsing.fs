module SinkholeAlerter.NoticeXmlParsing

open System
open SinkholeAlerter.Types
open System.Text.RegularExpressions
open System.IO
open System.Net
open SinkholeAlerter.Utils
open System.Xml.Linq

let noticePattern = Regex("""(?<notice>\<Infringement\s(.|\n)*\<\/Infringement\>)""", RegexOptions.IgnoreCase)

let localTimeZone = 
    lazy 
        TimeZoneInfo.FindSystemTimeZoneById (if linuxLikeOs then "US/Eastern" else "Eastern Standard Time")

let parseAsync filePath = async {
    try
    let! noticeText = Async.AwaitTask(File.ReadAllTextAsync(filePath, Text.Encoding.UTF8))
    let m = noticePattern.Match(noticeText)
    if m.Success then 
        let xmlns = XNamespace.op_Implicit "http://www.acns.net/ACNS"
        let infringementXml = XDocument.Parse(m.Groups.["notice"].Value, LoadOptions.None)
        //infringementXml.Root.Name <- xmlns + infringementXml.Root.Name.LocalName
        let sourceElement = 
            "Source"
            |> (+) xmlns
            |> infringementXml.Root.Element
        let timeStamp: DateTime = 
            "TimeStamp"
            |> (+) xmlns
            |> sourceElement.Element
            |> XElement.op_Explicit
        let postNatIp: string = 
            "IP_Address"
            |> (+) xmlns
            |> sourceElement.Element
            |> XElement.op_Explicit   
        let postNatPort: int = 
            "Port"
            |> (+) xmlns
            |> sourceElement.Element
            |> XElement.op_Explicit   
        let remoteIp: string = 
            "Destination_IP"
            |> (+) xmlns
            |> sourceElement.Element
            |> XElement.op_Explicit
        let remotePort: int = 
            "Destination_Port"
            |> (+) xmlns
            |> sourceElement.Element
            |> XElement.op_Explicit            
        return 
            Choice1Of2 
                {
                    userName = "" //we did not find this field yet
                    mac = ""
                    preNatIp = IPAddress.None
                    preNatIpDecimal = 0u
                    preNatPort = 0
                    utcTimeStamp = timeStamp //here it is UTC
                    localTimeStamp = 
                        TimeZoneInfo.ConvertTimeFromUtc(timeStamp, localTimeZone.Value)
                    postNatIp = postNatIp
                    postNatPort = postNatPort
                    remoteIp = remoteIp
                    remotePort = remotePort
                }            
    else 
        return Choice2Of2 (sprintf "WARN: Cannot find xml in notice '%s'" filePath)
    with
        | :? FileNotFoundException -> 
            return Choice2Of2 (sprintf "Notice file '%s' does not exist" filePath)
        | e -> 
            let e = 
                match e with 
                | :? AggregateException as e -> 
                    e.InnerException
                | _ -> e
            return Choice2Of2 (sprintf "WARN: Notice file '%s' error: %s. Skipped" filePath e.Message)
}
let parseManyAsync folderPath = async { 
    try
    //parse infringements in parallel
    let! infringementsOpt =
        Directory.EnumerateFiles(folderPath, "*.txt")
        |> Seq.map(parseAsync)
        |> Async.Parallel
    let infringements = 
        infringementsOpt
        |> Array.fold(fun acc infringementOpt -> 
            match infringementOpt with
            | Choice1Of2 infringement -> 
                infringement::acc
            | Choice2Of2 errorMessage -> 
                eprintfn "%s" errorMessage
                acc
        ) []
    return infringements    
    with 
        | :? DirectoryNotFoundException -> 
            eprintfn "Directory for notice '%s' was not found" folderPath
            return exit 1        
        | :? Security.SecurityException
        | :? UnauthorizedAccessException -> 
            eprintfn "Permission denied for notice folder '%s'" folderPath
            return exit 1
        | e -> 
            eprintfn "Error: %A" e
            return exit 1
}        
    

