module SinkholeAlerter.NatLogSearch

open System
open SinkholeAlerter.Types
open SinkholeAlerter.Utils
open System.Text
open System.IO
open System.IO.Compression
open System.Net

///this parameter defines range of searching in nat log file in minutes
[<Literal>] 
let TimeDelta = 3. 

let getNatLogFileName (infringement: Infringement) =
    let hour = infringement.localTimeStamp.Hour + 1
    sprintf "nat.csv.%s%s.csv.gz" 
        (infringement.localTimeStamp.ToString("yyyyMMdd"))
        (if hour < 10 then sprintf "0%d" hour else string hour)       

let searchNatLogAsync natLogFilePath (infringement: Infringement) = async {
    try
    let newLinePattern = 
        "\n" |> Encoding.ASCII.GetBytes
    let ipsBytePattern = 
        sprintf ",%s,%d,%s,%d," infringement.remoteIp infringement.remotePort                                                                                                                                   
            infringement.postNatIp infringement.postNatPort
        |> Encoding.ASCII.GetBytes
    let sizeOfDateTimePattern = "\nyyyy-MM-ddTHH:mm:ss.".Length
    let minTime = infringement.localTimeStamp.AddMinutes(-TimeDelta)
    let maxTime = infringement.localTimeStamp.AddMinutes(TimeDelta)
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

let searchNatLogForManyAsync natLogFilePath (infringements: Infringement list) = async {
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
            let minTime = infringement.localTimeStamp.AddMinutes(-TimeDelta)
            let maxTime = infringement.localTimeStamp.AddMinutes(TimeDelta)                
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
