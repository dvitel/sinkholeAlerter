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

let searchNatLogForManyAsync chunkSize natLogFilePath (infringements: Infringement list) = async {
    try
    let newLinePattern = "\n" |> Encoding.ASCII.GetBytes
    let infringementsWithBytePatternAndMinMaxTime = 
        infringements
        |> List.fold(fun acc infringement -> 
            let bytePattern = 
                sprintf ",%s,%d," infringement.postNatIp infringement.postNatPort
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
            let toRead = bufferSize - offset  
            let! offset, readCount = readSeveralBlocks offset 0 toRead
            if readCount = 0 then 
                return 
                    toFindInfringements |> List.fold(fun acc (i, _, _, _) -> 
                        {
                            i with error = "NAT record not found"
                        }::acc) foundInfringements
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
                        //find infringement in current block
                        let searchInfringement ((infringement, ipsBytePattern, minTime, maxTime) as infringementData) = async {
                            if lastDateInReadBytes < minTime then
                                return Choice1Of2 infringementData //This is choice of skipping current block
                            else 
                                //TODO: this 2 lines could be done once - not in each parallel thread
                                let dateString = Encoding.ASCII.GetString(buffer.[..sizeOfDateTimePattern-6])
                                let firstDateInReadBytes = DateTime.Parse(dateString)
                                if firstDateInReadBytes > maxTime then
                                    return Choice2Of2 {infringement with error=sprintf "NAT record not found. Scanned up to %d min above" (int TimeDelta)} //This choice means that we read all data for current infringement
                                        //and did not find record                                        
                                else 
                                    let rec scanIpPattern lastIndex = async {
                                        //search for byte pattern
                                        match backwardSearchArrayForPattern buffer 0 lastIndex ipsBytePattern with
                                        | -1 -> 
                                            //not found in current block - try next                       
                                            return Choice1Of2 infringementData                                      
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
                                            let resOpt = 
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
                                                    None
                                            match resOpt with
                                            | None -> 
                                                return! scanIpPattern (ipPatternIndex-1)
                                            | Some res -> return Choice2Of2 res
                                    }                                            
                                    return! scanIpPattern lastNewLineIndex
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
                                    infringement::foundInfringements, toFindInfringements) ([], [])
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
