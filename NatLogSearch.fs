module SinkholeAlerter.NatLogSearch

//This module is searching nat logs for infringement data (preNat ip and port)

open System
open SinkholeAlerter.Types
open SinkholeAlerter.Utils
open System.Text
open System.IO
open System.IO.Compression
open System.Net

///<param name='chunkSize'>
///We read natLog file by chunkSize. It is usually 4, 8MB
///</param>
///<param name='timeDelta'>
///In minutes, define diapasone of infringement data lookup
///When scanning nat log we will analyze in detail data with timeStamp: (infringementTimeStamp - timeDelta, infringementTimeStamp + timeDelta)
///It is usually 3min. If it is small, it will speedup search but increase a chance of missing infringement data
///</param>
///<param name='natLogFilePath'>
///Path to gzipped nat log file.
///This function will unzip it on run
///</param>
///<param name='infringements'>
///Infringements which should be looked for in the nat log
///</param>
///
///<summary>
///Search for infringement data in nat logs.
///Procedure (simplified explanation) is next:
/// 0. For each infringement we define minTime, maxTime and ipPattern
///    minTime = timeStamp - timeDelta, maxTime = timeStamp + timeDelta
///        - this is diapasone of infringement search
///    ipPattern is byte array which contains ASCII for <postNatIP>:<postNatPort>
/// 1. Function reads chunkSize block of bytes
/// 2. Then it checks last date in the block. 
/// 3. If it is less then minDate, block is discarded and execution goes to step 1
/// 4. If it is greater then minDate, we read first date in chuckSize block
/// 5. If it is greater then maxDate, we mark infringement as processed (record not found) and exclude it from next searches. Goto 9 
/// 6. In other case we perform scanning of ther block for byte ipPattern.
///    We are searching for index of first match of subsequence to sequence of pattern in the block 
/// 7. If we find such match in the block, from that point we search backward for pattern of '\n' and parse ASCII string between two found indexes.
///    In parsed string we find preNatIp and preNatPort because nat log format is fixed.   
///    We mark infringement as processed and exclude it for future searches
/// 8. If we do not find the pattern, we skip the block and goto 1.
/// 9. If all infringements were processed, return. In other case goto 1.
/// This is simplified view of what is happenning here.
/// In reality, algorithm cannot read chunk block preciselly on edges of '\n'
/// Thus, partially read nat line is placed in buffer which is carried over to next chunkSize read
/// this buffer is located then at start of our file reading buffer and next read puts bytes by given offset
/// Another aspect that was not mentioned is that algorithm does not perform scan from start to end or from end to start immediatelly.
/// Next optimization was made.
/// For each infringement we store two list of buffers (buffersBeforeTimeStamp, buffersAfterTimeStamp)
/// While scanning we put all read chunkSize buffers which firstRecordTimeStamp < infringementTimeStamp into buffersBeforeTimeStamp
/// Same we do for buffers with firstRecordTimeStamp >= infringementTimeStamp but put them into buffersAfterTimeSpan
/// When we reach the point when firstRecordTimeStamp > maxTime we start search in buffers starting from that ones that are closer to timeStamp
///</summary>
let searchNatLogForManyAsync chunkSize timeDelta natLogFilePath (infringements: Infringement list) = async {
    try
    let newLinePattern = "\n" |> Encoding.ASCII.GetBytes
    let infringementsWithBytePatternAndMinMaxTime = 
        infringements
        |> List.fold(fun acc infringement -> 
            let bytePattern = 
                sprintf ",%s,%d," infringement.postNatIp infringement.postNatPort
                |> Encoding.ASCII.GetBytes
            let minTime = infringement.localTimeStamp.AddMinutes(-timeDelta)
            let maxTime = infringement.localTimeStamp.AddMinutes(timeDelta)                
            (infringement, bytePattern, minTime, maxTime, [], [])::acc) []
    let sizeOfDateTimePattern = "\nyyyy-MM-ddTHH:mm:ss.".Length
    use fileStream = new FileStream(natLogFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize=4096, useAsync=true)
    use memStream = new MemoryStream(int fileStream.Length)
    do! Async.AwaitTask(fileStream.CopyToAsync(memStream))
    do! Async.AwaitTask(memStream.FlushAsync())
    memStream.Seek(0L, SeekOrigin.Begin) |> ignore
    use unzippedFileStream = new GZipStream(memStream, CompressionMode.Decompress)
    let bufferSize = chunkSize*1024*1024 //8MB block -- todo: experiment more to find ideal tradeoff and speedout
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
            return foundInfringements
        | _ -> 
            let rec scanIpPattern searchArrayForPattern (buffer: byte[]) infringement ipsBytePattern =
                //search for byte pattern
                match searchArrayForPattern buffer 0 buffer.Length ipsBytePattern with
                | -1 -> 
                    //not found in current block - try next                
                    //printfn "!!! Searching byte pattern: %s" natLogFilePath       
                    None
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
                    Some
                        {
                            infringement with 
                                preNatPort = preNatPort
                                preNatIp = preNatIp
                                preNatIpDecimal = ipToDecimal preNatIp
                        }
                    with _ -> 
                        //should be never here, but just in case
                        eprintfn "Found line which does not correspond to nat format: %s" line
                        exit(1)    
        
            let toRead = bufferSize - offset  
            let! offset, readCount = readSeveralBlocks offset 0 toRead
            if readCount = 0 then 
                let bufferLeft = 
                    if offset > 0 then (buffer.[0..offset - 1]) 
                    else Array.empty               
                return 
                    toFindInfringements |> List.fold(fun acc (i, ipsBytePattern, minTime, maxTime, bufferBeforeTimePoint, bufferAfterTimePoint) -> 
                        let bufferAfterTimePoint = bufferLeft::bufferAfterTimePoint
                        let infringementOpt = 
                            bufferBeforeTimePoint |> List.tryPick(fun buffer -> 
                                scanIpPattern backwardSearchArrayForPattern buffer i ipsBytePattern
                            )     
                        let infringementOpt = 
                            match infringementOpt with
                            | None ->       
                                bufferAfterTimePoint |> List.rev |> List.tryPick(fun buffer -> 
                                    scanIpPattern searchArrayForPattern buffer i ipsBytePattern
                                )          
                            | v -> v
                        match infringementOpt with
                        | None -> 
                            {i with error=sprintf "NAT record not found. Scanned up to %d min above" (int timeDelta)}::acc
                        | Some infringement -> infringement::acc) foundInfringements
            else  
                match backwardSearchArrayForPattern buffer 0 offset newLinePattern with
                | -1 ->   
                    return! searchPattern foundInfringements toFindInfringements offset
                | lastNewLineIndex ->
                    match backwardSearchArrayForPattern buffer 0 lastNewLineIndex newLinePattern with
                    | -1 -> 
                        //also, we can happen here beacuase we are not reading gzip not by precise chunks
                        //debugging line
                        //printfn "Skipping block, too small, no second new line. Read: %d, length: %d" readCount offset
                        return! searchPattern foundInfringements toFindInfringements offset
                    | newLineIndexBeforeLastNewLine -> 
                        let lastDateInReadBytes = DateTime.Parse(Encoding.ASCII.GetString(buffer.[newLineIndexBeforeLastNewLine+1..newLineIndexBeforeLastNewLine+sizeOfDateTimePattern-2]))
                        let firstDateInReadBytes = lazy DateTime.Parse(Encoding.ASCII.GetString(buffer.[..sizeOfDateTimePattern-6]))
                        let newBuffer = lazy buffer.[..lastNewLineIndex-1]
                        //find infringement in current block
                        let searchInfringement ((infringement, ipsBytePattern, minTime, maxTime, bufferBeforeTimePoint, bufferAfterTimePoint) as infringementData) = async {
                            if lastDateInReadBytes < minTime then
                                return Choice1Of2 infringementData //This is choice of skipping current block
                            else 
                                //TODO: this 2 lines could be done once - not in each parallel thread
                                if firstDateInReadBytes.Value > maxTime then
                                    let! infringementOpt = 
                                        seq {
                                            yield 
                                                async {    
                                                    return 
                                                        bufferBeforeTimePoint |> List.tryPick(fun buffer -> 
                                                            scanIpPattern backwardSearchArrayForPattern buffer infringement ipsBytePattern
                                                        )     
                                                }
                                            yield 
                                                async {    
                                                    return 
                                                        bufferAfterTimePoint |> List.rev |> List.tryPick(fun buffer -> 
                                                            scanIpPattern searchArrayForPattern buffer infringement ipsBytePattern
                                                        )
                                                }
                                        } |> Async.Choice
                                    match infringementOpt with
                                    | None -> 
                                        return Choice2Of2 {infringement with error=sprintf "NAT record not found. Scanned up to %d min above" (int timeDelta)}
                                    | Some infringement -> return Choice2Of2 infringement
                                        //and did not find record                                        
                                else 
                                    if firstDateInReadBytes.Value > infringement.localTimeStamp then
                                        return Choice1Of2 ((infringement, ipsBytePattern, minTime, maxTime, bufferBeforeTimePoint, newBuffer.Value::bufferAfterTimePoint))
                                    else 
                                        return Choice1Of2 ((infringement, ipsBytePattern, minTime, maxTime, newBuffer.Value::bufferBeforeTimePoint, bufferAfterTimePoint))
                        }                                    
                        let! newlyFoundInfringementsOpt = 
                            toFindInfringements
                            |> List.map(searchInfringement)
                            |> Async.Parallel
                        let foundInfringements, toFindInfringements = 
                            newlyFoundInfringementsOpt
                            |> Array.fold(fun (foundInfringements, toFindInfringements) -> 
                                function
                                | Choice1Of2 infringementData ->
                                    foundInfringements, infringementData::toFindInfringements
                                | Choice2Of2 infringement -> 
                                    infringement::foundInfringements, toFindInfringements) (foundInfringements, [])
                        let prevBufferPart = buffer.[lastNewLineIndex+1..]         
                        Array.Copy(prevBufferPart, buffer, prevBufferPart.Length)
                        return! searchPattern foundInfringements toFindInfringements prevBufferPart.Length                                    
    }
    return! searchPattern [] infringementsWithBytePatternAndMinMaxTime 0  
    with 
        :? FileNotFoundException -> 
            return 
                infringements
                |> List.map(fun infringement -> 
                    {
                        infringement with error="NAT file not found"
                    })
        | e -> 
            let e = 
                match e with
                | :? AggregateException as e -> e.InnerException
                | e -> e
            return 
                infringements
                |> List.map(fun infringement -> 
                    {
                        infringement with error=e.Message
                    })
}
