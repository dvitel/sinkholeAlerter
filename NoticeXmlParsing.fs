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

let getNatLogFileName (localTimeStamp: DateTime) =
    let hour = localTimeStamp.Hour + 1
    sprintf "nat.csv.%s%s.csv.gz" 
        (localTimeStamp.ToString("yyyyMMdd"))
        (if hour < 10 then sprintf "0%d" hour else string hour)  

//parsing XML files
let parseAsync filePath = async {
    try
    let! noticeText = Async.AwaitTask(File.ReadAllTextAsync(filePath, Text.Encoding.UTF8))
    let m = noticePattern.Match(noticeText) //use regex
    if m.Success then 
        let xmlns = XNamespace.op_Implicit "http://www.acns.net/ACNS"
        let infringementXml = XDocument.Parse(m.Groups.["notice"].Value, LoadOptions.None) //use XDOcument
        //infringementXml.Root.Name <- xmlns + infringementXml.Root.Name.LocalName
        let sourceElement = 
            "Source"
            |> (+) xmlns
            |> infringementXml.Root.Element
        let timeStampOpt: DateTime option= 
            "TimeStamp"
            |> (+) xmlns
            |> sourceElement.Element
            |> function 
                | null -> None
                | element -> Some(XElement.op_Explicit element)
        let postNatIpOpt: string option = 
            "IP_Address"
            |> (+) xmlns
            |> sourceElement.Element            
            |> function 
                | null -> None
                | element -> Some(XElement.op_Explicit element)
        let postNatPortOpt: int option = 
            "Port"
            |> (+) xmlns
            |> sourceElement.Element
            |> function 
                | null -> None
                | element -> Some(XElement.op_Explicit element)
        let remoteIpOpt: string option = 
            "Destination_IP"
            |> (+) xmlns
            |> sourceElement.Element
            |> function 
                | null -> None
                | element -> Some(XElement.op_Explicit element)
        let remotePortOpt: string option = 
            "Destination_Port"
            |> (+) xmlns
            |> sourceElement.Element
            |> function 
                | null -> None
                | element -> Some(XElement.op_Explicit element)    
        match timeStampOpt, postNatIpOpt, postNatPortOpt with
        | Some timeStamp, Some postNatIp, Some postNatPort -> 
            let localTimeStamp = TimeZoneInfo.ConvertTimeFromUtc(timeStamp, localTimeZone.Value)
            return 
                {
                    userName = "" //we did not find this field yet
                    mac = ""
                    preNatIp = IPAddress.None
                    preNatIpDecimal = 0u
                    preNatPort = 0
                    utcTimeStamp = timeStamp //here it is UTC
                    localTimeStamp = localTimeStamp                    
                    postNatIp = postNatIp
                    postNatPort = postNatPort
                    remoteIp = 
                        match remoteIpOpt with
                        | None -> "<no remote ip>"
                        | Some ip -> ip
                    remotePort = 
                        match remotePortOpt with
                        | None -> "<no remote port>"
                        | Some port -> port
                    noticeFileName = Path.GetFileName filePath
                    natLogFileName = getNatLogFileName localTimeStamp
                    error = ""
                    natLogFilePosition = 0UL
                }            
        | _, _, _ -> 
            return 
                {
                    Infringement.Empty with
                        noticeFileName = Path.GetFileName filePath
                        error = "Cannot find timeStamp/postNatIp/postNatPort in notice"
                }
    else 
        return 
            {
                Infringement.Empty with
                    noticeFileName = Path.GetFileName filePath
                    error = "File does not contain Infringement xml"
            }
    with
        | :? FileNotFoundException -> 
            return 
                {
                    Infringement.Empty with
                        noticeFileName = Path.GetFileName filePath
                        error = "Notice file does not exist"
                }
        | e -> 
            let e = 
                match e with 
                | :? AggregateException as e -> 
                    e.InnerException
                | _ -> e
            return 
                {
                    Infringement.Empty with
                        noticeFileName = Path.GetFileName filePath
                        error = e.Message
                }
}

///<summary>
///this function reads and parses notices in parallel 
///</summary>
///<param name="folderPath">string, folder of notices</param>
///<returns>Infringement list - read infringements</param>
let parseManyAsync folderPath = async { 
    try
    //parse infringements in parallel
    let! infringements =
        Directory.EnumerateFiles(folderPath, "*.txt")
        |> Seq.map(parseAsync)
        |> Async.Parallel
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
    

