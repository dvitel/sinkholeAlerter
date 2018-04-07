open System
open System.IO
open System.IO.Compression
open System.Text
open System.Text.RegularExpressions
open FSharp.Data
open FSharp.Data.Sql
open System.Linq
open System.Net

//we will gather all info parts in this structure
type Infringement = {
    userName: string
    mac: string
    preNatIp: IPAddress 
    preNatIpDecimal: uint32
    preNatPort: int
    utcTimeStamp: DateTime
    localTimeStamp: DateTime
    postNatIp: string
    postNatPort: int
    remoteIp: string
    remotePort: int
}    
    with 
        override infringement.ToString() = 
            sprintf "%s, %s --> %A:%d --> %s:%d --> %s:%d, %s" 
                (if infringement.userName="" then "<no name>" else infringement.userName)
                infringement.mac
                infringement.preNatIp
                infringement.preNatPort
                infringement.postNatIp
                infringement.postNatPort
                infringement.remoteIp
                infringement.remotePort
                (infringement.localTimeStamp.ToString("yyyy-MM-dd HH:mm:ss"))
let noticePattern = Regex("""(?<notice>\<Infringement\s(.|\n)*\<\/Infringement\>)""", RegexOptions.IgnoreCase)

type Notice = XmlProvider<"""
<Infringement xmlns="http://www.acns.net/ACNS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.acns.net/ACNS http://www.acns.net/v1.2/ACNS2v1_2.xsd">
   <Case>
     <ID>418830724</ID>
     <Status>Open</Status>
     <Severity>Normal</Severity>
   </Case>
   <Complainant>
     <Entity>Argus, Inc.</Entity>
     <Contact>argus - Compliance</Contact>
     <Address>1234 E Fowler Ave Tampa FL 33613 United States of America</Address>
     <Phone>+1 (123) 456 7890</Phone>
     <Email>botnet@argus.com</Email>
   </Complainant>
   <Service_Provider>
     <Entity>American University</Entity>
     <Email>contact@amu.edu</Email>
   </Service_Provider>
   <Source>
     <TimeStamp>2016-03-21T14:54:27Z</TimeStamp>
     <IP_Address>192.168.226.52</IP_Address>
     <Port>33631</Port>
     <Destination_IP>195.22.28.196</Destination_IP>
     <Destination_Port>1</Destination_Port>
   </Source>
</Infringement>
    """>

let linuxLikeOs =
    match Environment.OSVersion.Platform with
    | PlatformID.Unix | PlatformID.MacOSX -> true
    | v when (int) v = 128 -> true
    | _ -> false    
let localTimeZone = 
    lazy 
        TimeZoneInfo.FindSystemTimeZoneById (if linuxLikeOs then "US/Eastern" else "Eastern Standard Time")

let parseNotice filePath = async {
    try
    let! noticeText = Async.AwaitTask(File.ReadAllTextAsync(filePath, Text.Encoding.UTF8))
    let m = noticePattern.Match(noticeText)
    if m.Success then 
        let infringement = Notice.Parse(m.Groups.["notice"].Value)
        return 
            Choice1Of2 
                {
                    userName = "" //we did not find this field yet
                    mac = ""
                    preNatIp = IPAddress.None
                    preNatIpDecimal = 0u
                    preNatPort = 0
                    utcTimeStamp = infringement.Source.TimeStamp //here it is UTC
                    localTimeStamp = 
                        TimeZoneInfo.ConvertTimeFromUtc(infringement.Source.TimeStamp, localTimeZone.Value)
                    postNatIp = infringement.Source.IpAddress
                    postNatPort = infringement.Source.Port
                    remoteIp = infringement.Source.DestinationIp
                    remotePort = infringement.Source.DestinationPort
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
let parseNotices folderPath = async { 
    try
    //parse infringements in parallel
    let! infringementsOpt =
        Directory.EnumerateFiles(folderPath, "*.txt")
        |> Seq.map(parseNotice)
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

type NatRecord = CsvProvider<"""
2016-03-20T16:00:01.460-04:00,1,172.21.132.88,40500,150.242.106.14,20613,192.168.224.132,54408,17,1,132,0,0
2016-03-20T16:00:01.460-04:00,1,172.26.245.253,22129,37.236.132.176,11428,192.168.244.245,43081,17,1,48,0,0
2016-03-20T16:00:01.460-04:00,1,172.19.166.70,37358,190.46.179.137,1051,192.168.226.166,62180,17,1,48,0,0
2016-03-20T16:00:01.460-04:00,1,172.19.214.203,27426,188.25.49.169,60509,192.168.226.214,53255,17,1,101,0,0""",
                                Schema="TimeStamp (date), unknown1, PreNatIp (string), PreNatPort (int), RemoteIp (string), RemotePort (int), PostNatIp (string), PostNatPort (int), unknown2, unknown3, unknown4, unknown5, unknown6 (int64)">    

[<Literal>]
let timeDelta = 3.

let getNatLogFileName (infringement: Infringement) =
    let hour = infringement.localTimeStamp.Hour + 1
    sprintf "nat.csv.%s%s.csv.gz" 
        (infringement.localTimeStamp.ToString("yyyyMMdd"))
        (if hour < 10 then sprintf "0%d" hour else string hour)

let ipToDecimal (ip: System.Net.IPAddress) =
    let ipDecimalBytes = ip.GetAddressBytes()
    ipDecimalBytes |> Array.mapi(fun i b -> 
        (b, ipDecimalBytes.Length - i - 1))
    |> Array.fold(fun acc (b, i) -> 
        let tmp = Array.replicate i 256u 
                  |> Array.fold(*) 1u
        acc + (uint32 b) * tmp) 0u

// type BufferProcessorMsg = 
//     | NewBuffer of byte[]
//     | Processed of Infringement option 
//     | AwaitResult of AsyncReplyChannel<Choice<Infringement option, >>

// let createBufferProcessor (infringement: Infringement) =
//     let timePattern = infringement.localTimeStamp.ToString("yyyy-MM-ddTHH:mm:")
//     let endTimePattern = infringement.localTimeStamp.ToString("yyyy-MM-ddTHH:")
//     MailboxProcessor.Start(fun inbox -> 
//         let rec loop activeBuffers = async {
//             let! msg = inbox.Receive()
//             match msg with            
//             | NewBuffer buffer -> 
//                 return! loop (buffer::activeBuffers)
//             | Processed line
//         }
//     )

let rec searchArrayForPattern (buffer: byte[]) startIndex endIndex (pattern: byte[]) = 
    if pattern.Length > (endIndex - startIndex) then 
        -1
    else
        let res = 
            Seq.compareWith (fun b1 b2 -> int b1 - int b2) 
                (seq { for i in startIndex..startIndex + pattern.Length - 1 -> buffer.[i]})
                pattern
        if res = 0 then 
            startIndex
        else 
            searchArrayForPattern buffer (startIndex + 1) endIndex pattern

let rec backwardSearchArrayForPattern (buffer: byte[]) startIndex endIndex (pattern: byte[]) = 
    if pattern.Length > (endIndex - startIndex) then 
        -1
    else
        let res = 
            Seq.compareWith (fun b1 b2 -> int b1 - int b2) 
                (seq { for i in endIndex - pattern.Length..endIndex - 1 -> buffer.[i]})
                pattern
        if res = 0 then 
            endIndex - pattern.Length
        else 
            backwardSearchArrayForPattern buffer startIndex (endIndex - 1) pattern            

let searchNatLog natLogFilePath (infringement: Infringement) = async {
    try
    let newLinePattern = 
        "\n" |> Encoding.ASCII.GetBytes
    let ipsBytePattern = 
        sprintf ",%s,%d,%s,%d," infringement.remoteIp infringement.remotePort
            infringement.postNatIp infringement.postNatPort
        |> Encoding.ASCII.GetBytes
    let sizeOfDateTimePattern = "\nyyyy-MM-ddTHH:mm:ss.".Length
    let minTime = infringement.localTimeStamp.AddMinutes(-timeDelta)
    let maxTime = infringement.localTimeStamp.AddMinutes(timeDelta)
    use fileStream = new FileStream(natLogFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize=4096, useAsync=true)
    use memStream = new MemoryStream(int fileStream.Length)
    do! Async.AwaitTask(fileStream.CopyToAsync(memStream))
    do! Async.AwaitTask(memStream.FlushAsync())
    memStream.Seek(0L, SeekOrigin.Begin) |> ignore
    use unzippedFileStream = new GZipStream(memStream, CompressionMode.Decompress)
    let bufferSize = 4*1024*1024 //4MB block
    let buffer = Array.zeroCreate<byte> bufferSize
    let rec searchPattern offset = async {
        let toRead = bufferSize - offset  
        let rec readSeveralBlocks offset readCount toRead = async {
            if toRead < 1024 then 
                return offset, readCount
            else 
                let! rc = Async.AwaitTask(unzippedFileStream.ReadAsync(buffer, offset, toRead))
                if rc = 0 then 
                    return offset, readCount
                else 
                    let offset = rc + offset
                    let toRead = toRead - rc
                    return! readSeveralBlocks offset (readCount+rc) toRead
        }
        let! offset, readCount = readSeveralBlocks offset 0 toRead
        if readCount = 0 then 
            eprintfn "EOF reached. No record found in NAT log"
            exit 1        
        match backwardSearchArrayForPattern buffer 0 offset newLinePattern with
        | -1 ->   
            //we can happen here beacuase we are not reading gzip not by precise chunks
            //debugging line
            printfn "Skipping block, too small. Read: %d, length: %d" readCount offset
            return! searchPattern offset
        | lastNewLineIndex ->
            match backwardSearchArrayForPattern buffer 0 lastNewLineIndex newLinePattern with
            | -1 -> 
                //also, we can happen here beacuase we are not reading gzip not by precise chunks
                //debugging line
                printfn "Skipping block, too small, no second new line. Read: %d, length: %d" readCount offset
                return! searchPattern offset
            | newLineIndexBeforeLastNewLine -> 
                let lastDateInReadBytes = DateTime.Parse(Encoding.ASCII.GetString(buffer.[newLineIndexBeforeLastNewLine+1..newLineIndexBeforeLastNewLine+sizeOfDateTimePattern-2]))
                if lastDateInReadBytes < minTime then
                    //skip this block entirely  
                    //next line is for debug                    
                    printfn "Skipping block, max date: %s. Read: %d" (lastDateInReadBytes.ToString("yyyy-MM-dd HH:mm:ss")) readCount
                    let prevBufferPart = buffer.[lastNewLineIndex+1..]         
                    Array.Copy(prevBufferPart, buffer, prevBufferPart.Length)
                    return! searchPattern prevBufferPart.Length
                else 
                    let dateString = Encoding.ASCII.GetString(buffer.[..sizeOfDateTimePattern-6])
                    let firstDateInReadBytes = DateTime.Parse(dateString)
                    if firstDateInReadBytes > maxTime then
                        //found nothing
                        eprintfn "No NAT records found for infringement:\n%s\nTried in diapasone: %s, %s" (string infringement)
                            (minTime.ToString("yyyy-MM-dd HH:mm:ss")) (maxTime.ToString("yyyy-MM-dd HH:mm:ss"))
                        return exit 1
                    else 
                        //search for byte pattern
                        match backwardSearchArrayForPattern buffer 0 lastNewLineIndex ipsBytePattern with
                        | -1 -> 
                            //not found in current block - try next                       
                            //next line is for debug
                            printfn "No ipPattern in current block. Read: %d" readCount
                            let prevBufferPart = buffer.[lastNewLineIndex+1..]         
                            Array.Copy(prevBufferPart, buffer, prevBufferPart.Length)
                            return! searchPattern prevBufferPart.Length                                                        
                        | ipPatternIndex -> 
                            //found something interesting
                            printfn "Found ip pattern. Read: %d" readCount //for debugging
                            let candidateBytes = 
                                match backwardSearchArrayForPattern buffer 0 ipPatternIndex newLinePattern with
                                | -1 -> buffer.[..ipPatternIndex-1]
                                | newLineIndex -> buffer.[newLineIndex+1..ipPatternIndex-1]
                            let line = Encoding.ASCII.GetString(candidateBytes)
                            let parts = line.Split(',', StringSplitOptions.RemoveEmptyEntries)
                            //because we were searching pattern ',<remote_ip>,<remote_port>,<postNat_ip>,<postNat_port>,'
                            //we can say for sure that if pattern found, string before it will
                            //correspond to at log format <date>,---,<preNatIp>,<preNatPort>
                            //there is no chance that preNatIp could be mistreated as remote_ip
                            try                                
                            let preNatPort = int(parts.[3])
                            let preNatIp = IPAddress.Parse(parts.[2])
                            return 
                                {
                                    infringement with 
                                        preNatPort = preNatPort
                                        preNatIp = preNatIp
                                        preNatIpDecimal = ipToDecimal preNatIp
                                }
                            with _ -> 
                                //should be never here, but just in case
                                eprintfn "Found line which does not correspond to nat format: %s" line
                                return exit 1                    
    }
    return! searchPattern 0    
    with 
        :? FileNotFoundException -> 
            eprintfn "Nat log '%s' was not found" natLogFilePath
            return exit 1
        | e -> 
            eprintfn "Error: %A" e
            return exit 1    
}   

let searchNatLogForMany natLogFilePath (infringements: Infringement list) = async {
    try
    let newLinePattern = 
        "\n" |> Encoding.ASCII.GetBytes
    let infringementsWithBytePatternAndMinMaxTime = 
        infringements
        |> List.fold(fun acc infringement -> 
            let bytePattern = 
                sprintf ",%s,%d,%s,%d," infringement.remoteIp infringement.remotePort
                    infringement.postNatIp infringement.postNatPort
                |> Encoding.ASCII.GetBytes
            let minTime = infringement.localTimeStamp.AddMinutes(-timeDelta)
            let maxTime = infringement.localTimeStamp.AddMinutes(timeDelta)                
            (infringement, bytePattern, minTime, maxTime)::acc) []
    let sizeOfDateTimePattern = "\nyyyy-MM-ddTHH:mm:ss.".Length
    use fileStream = new FileStream(natLogFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize=4096, useAsync=true)
    use memStream = new MemoryStream(int fileStream.Length)
    do! Async.AwaitTask(fileStream.CopyToAsync(memStream))
    do! Async.AwaitTask(memStream.FlushAsync())
    memStream.Seek(0L, SeekOrigin.Begin) |> ignore
    use unzippedFileStream = new GZipStream(memStream, CompressionMode.Decompress)
    let bufferSize = 4*1024*1024 //4MB block
    let buffer = Array.zeroCreate<byte> bufferSize
    let rec readSeveralBlocks offset readCount toRead = async {
        if toRead = 0 then 
            return offset, readCount
        else 
            let! rc = Async.AwaitTask(unzippedFileStream.ReadAsync(buffer, offset, toRead))
            if rc = 0 then 
                return offset, readCount
            else 
                let offset = rc + offset
                let toRead = toRead - rc
                return! readSeveralBlocks offset (readCount+rc) toRead
    }    
    let rec searchPattern foundInfringements toFindInfringements offset = async {
        match toFindInfringements with
        | [] -> 
            //debug message
            printfn "Nat log '%s' processed" natLogFilePath
            return foundInfringements
        | _ -> 
            let toRead = bufferSize - offset  
            let! offset, readCount = readSeveralBlocks offset 0 toRead
            if readCount = 0 then 
                //debug output
                printfn "\tWARN. EOF reached. Next records were missed from nat log\n\t%s" natLogFilePath
                toFindInfringements
                |> List.iter(string >> printfn "%s")
                return foundInfringements 
            else  
                match backwardSearchArrayForPattern buffer 0 offset newLinePattern with
                | -1 ->   
                    //we can happen here beacuase we are not reading gzip not by precise chunks
                    //debugging line
                    printfn "Skipping block, too small. Read: %d, length: %d" readCount offset
                    return! searchPattern foundInfringements toFindInfringements offset
                | lastNewLineIndex ->
                    match backwardSearchArrayForPattern buffer 0 lastNewLineIndex newLinePattern with
                    | -1 -> 
                        //also, we can happen here beacuase we are not reading gzip not by precise chunks
                        //debugging line
                        printfn "Skipping block, too small, no second new line. Read: %d, length: %d" readCount offset
                        return! searchPattern foundInfringements toFindInfringements offset
                    | newLineIndexBeforeLastNewLine -> 
                        let lastDateInReadBytes = DateTime.Parse(Encoding.ASCII.GetString(buffer.[newLineIndexBeforeLastNewLine+1..newLineIndexBeforeLastNewLine+sizeOfDateTimePattern-2]))
                        //find infringement in current block
                        let searchInfringement ((infringement, ipsBytePattern, minTime, maxTime) as infringementData) = async {
                            if lastDateInReadBytes < minTime then
                                return Choice1Of3 infringementData //This is choice of skipping current block
                            else 
                                //TODO: this 2 lines could be done once - not in each parallel thread
                                let dateString = Encoding.ASCII.GetString(buffer.[..sizeOfDateTimePattern-6])
                                let firstDateInReadBytes = DateTime.Parse(dateString)
                                if firstDateInReadBytes > maxTime then
                                    let msg = 
                                        sprintf "No NAT records found for infringement:\n%s\nTried in diapasone: %s, %s" 
                                            (string infringement)
                                            (minTime.ToString("yyyy-MM-dd HH:mm:ss")) (maxTime.ToString("yyyy-MM-dd HH:mm:ss"))
                                    return Choice2Of3 msg //This choice means that we read all data for current infringement
                                        //and did not find record                                        
                                else 
                                    //search for byte pattern
                                    match backwardSearchArrayForPattern buffer 0 lastNewLineIndex ipsBytePattern with
                                    | -1 -> 
                                        //not found in current block - try next                       
                                        return Choice1Of3 infringementData                                      
                                    | ipPatternIndex -> 
                                        //found something interesting
                                        //printfn "Found ip pattern. Read: %d" readCount //for debugging
                                        let candidateBytes = 
                                            match backwardSearchArrayForPattern buffer 0 ipPatternIndex newLinePattern with
                                            | -1 -> buffer.[..ipPatternIndex-1]
                                            | newLineIndex -> buffer.[newLineIndex+1..ipPatternIndex-1]
                                        let line = Encoding.ASCII.GetString(candidateBytes)
                                        let parts = line.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                        //because we were searching pattern ',<remote_ip>,<remote_port>,<postNat_ip>,<postNat_port>,'
                                        //we can say for sure that if pattern found, string before it will
                                        //correspond to at log format <date>,---,<preNatIp>,<preNatPort>
                                        //there is no chance that preNatIp could be mistreated as remote_ip
                                        try                                
                                        let preNatPort = int(parts.[3])
                                        let preNatIp = IPAddress.Parse(parts.[2])
                                        return 
                                            Choice3Of3
                                                {
                                                    infringement with 
                                                        preNatPort = preNatPort
                                                        preNatIp = preNatIp
                                                        preNatIpDecimal = ipToDecimal preNatIp
                                                }
                                        with _ -> 
                                            //should be never here, but just in case
                                            let msg = sprintf "Found line which does not correspond to nat format: %s" line
                                            return Choice2Of3 msg
                        }                                    
                        let! newlyFoundInfringementsOpt = 
                            toFindInfringements
                            |> List.map(searchInfringement)
                            |> Async.Parallel
                        let foundInfringements, toFindInfringements = 
                            newlyFoundInfringementsOpt
                            |> Array.fold(fun (foundInfringements, toFindInfringements) -> 
                                function
                                | Choice1Of3 infringementData ->
                                    foundInfringements, infringementData::toFindInfringements
                                | Choice2Of3 msg -> 
                                    eprintfn "%s" msg
                                    foundInfringements, toFindInfringements
                                | Choice3Of3 infringement -> 
                                    infringement::foundInfringements, toFindInfringements) ([], [])
                        let prevBufferPart = buffer.[lastNewLineIndex+1..]         
                        Array.Copy(prevBufferPart, buffer, prevBufferPart.Length)
                        return! searchPattern foundInfringements toFindInfringements prevBufferPart.Length                                    
    }
    return! searchPattern [] infringementsWithBytePatternAndMinMaxTime 0  
    with 
        :? FileNotFoundException -> 
            eprintfn "Nat log '%s' was not found" natLogFilePath
            return exit 1
        | e -> 
            eprintfn "Error: %A" e
            return exit 1    
}                     

[<Literal>]
let resolutionPath = __SOURCE_DIRECTORY__ + "/lib"

[<Literal>]
let connectionString = "Server=localhost;Database=logs_db;Uid=cyber;Pwd=u30530631;Auto Enlist=false;Convert Zero Datetime=true;"
type LogsDb = 
    SqlDataProvider<
        DatabaseVendor = Common.DatabaseProviderTypes.MYSQL,
        ConnectionString = connectionString,
        IndividualsAmount = 1000,
        UseOptionTypes = true,
        ResolutionPath = connectionString,
        Owner = "logs_db"> 

//type NugetStats = HtmlProvider<"""https://www.nuget.org/packages/FSharp.Data""">

// let findMacInDhcp (infringement: Infringement) = 
//     let db = LogsDb.GetDataContext()
//     SqlMethods.
//     let macString =
//         query {
//             for record in db.LogsDb.Dhcp do
//             where (record.IpDecimal = infringement.preNatIpDecimal)
//             select record.MacString
//             headOrDefault
//         } |> Seq.executeQueryAsync
//     if macString = null then 
//         eprintfn "Could not find DHCP record for infringement"
//         exit 1
//     else 
//         { infringement with
//             mac = macString}

let createDhcpQuery ipDecimalWithTimeStamp = 
    let reqId = Guid.NewGuid().ToString().Replace("-", "_") |> sprintf "dhcp_%s"
    let reqValues
    sprintf "
CREATE TEMPORARY TABLE %s (
    ip int(10) NOT NULL PRIMARY KEY UNIQUE,
    timeStamp timestamp NOT NULL);
        
INSERT INTO %s        
    VALUES %s;
        " reqId reqId reqValues

let findMacInDhcpForMany (infringements: Infringement list) = async {
    let db = LogsDb.GetDataContext(SelectOperations.DatabaseSide)
    let preNatIpDecimals = 
        infringements |> List.map(fun infringement -> infringement.preNatIpDecimal)
    let! ipDecimalToMacMapping =
        query {
            for record in db.LogsDb.Dhcp do
            where (preNatIpDecimals.Contains(record.IpDecimal))
            select (record.IpDecimal, record.MacString, record.Timestamp)
        } 
        |> Seq.executeQueryAsync
    let ipDecimalToMacMapping =
        ipDecimalToMacMapping    
        |> Seq.fold(fun acc (ipDecimal, mac, timeStamp) -> 
            match Map.tryFind ipDecimal acc with
            | None -> Map.add ipDecimal [timeStamp, mac] acc
            | Some timeSpanMacs -> Map.add ipDecimal ((timeStamp, mac)::timeSpanMacs) acc
        ) Map.empty
    infringements
    |> List.map(fun infringement -> 
        match Map.tryFind infringement.preNatIpDecimal ipDecimalToMacMapping with
        | None -> 
            eprintfn "Could not find DHCP record for infringement: %s" (string infringement)
        | Some timeStampMacList -> 
            let infringementLocalTime
    )
    if macString = null then         
        exit 1
    else 
        { infringement with
            mac = macString}     
}               

let findContactInfo (infringement: Infringement) = 
    let db = LogsDb.GetDataContext()
    match infringement.preNatIp.GetAddressBytes() with
    | [| 172uy; 19uy; _; _ |] -> 
        //RADIUS ip
        let ip = string infringement.preNatIp
        let username = 
            query {
                for record in db.LogsDb.Radacct do
                where (record.FramedIpAddress=ip && record.CallingStationId=infringement.mac)
                select record.Username
                headOrDefault
            }
        if username = null then 
            eprintfn "No radius user info for ip: %s, mac: %s" ip infringement.mac
            infringement            
        else 
            {infringement with
                userName = username}
    | _ -> 
        //other IP
        let username = 
            query {
                for record in db.LogsDb.Contactinfo do
                where (record.MacString = infringement.mac)
                select record.Contact
                headOrDefault
            }
        if username = null then 
            eprintfn "No non-radius info wa found for mac: %s" infringement.mac
            infringement
        else 
            {infringement with
                userName = username}
    

[<EntryPoint>]
let main argv =
    try
    if argv.Length < 1 then 
        printfn "Usage: dotnet <thisdll> <path to notices folder>"
        exit 1
    let folderPath = argv.[0]
    let infringements = parseNotices folderPath |> Async.RunSynchronously
    let infringementsByNatLog = 
        infringements |> List.fold(fun acc infringement -> 
            let natLogFile = Path.Combine(".", "nat_logs", getNatLogFileName infringement)
            match Map.tryFind natLogFile acc with
            | None -> 
                Map.add natLogFile [infringement] acc
            | Some infringements -> 
                Map.add natLogFile (infringement::infringements) acc) Map.empty
    let foundInfringements = 
        infringementsByNatLog
        |> Map.fold(fun acc natLogFileName infringements -> 
            (searchNatLogForMany natLogFileName infringements)::acc) []
        |> Async.Parallel
        |> Async.RunSynchronously
        |> Seq.collect id
    //let infringement = searchNatLog natLogFilePath infringement |> Async.RunSynchronously
    let infringement = findMacInDhcp infringement
    let infringement = findContactInfo infringement        
    printfn "%s" (infringement.ToString())
    0
    with e -> 
        eprintfn "Error: %A" e
        1
