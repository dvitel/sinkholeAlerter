namespace SinkholeAlerter.Types
open System
open System.Net
open System.Runtime.Serialization

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
    remotePort: string
    noticeFileName: string
    natLogFileName: string
    natLogFilePosition: uint64 //byte position in nat log file
    error: string
}    
    with 
        static member Empty = 
            {
                userName = ""
                mac = ""
                preNatIp = IPAddress.None
                preNatIpDecimal = 0u
                preNatPort = 0
                utcTimeStamp = DateTime.MinValue
                localTimeStamp = DateTime.MinValue
                postNatIp = ""
                postNatPort = 0
                remoteIp = ""
                remotePort = ""
                noticeFileName = ""
                error = ""
                natLogFileName = ""
                natLogFilePosition = 0UL
            }
        override infringement.ToString() = 
            sprintf "notice: %s%s\t%s, %s --> %s --> %s:%d --> %s:%s, %s%s%s" 
                infringement.noticeFileName
                Environment.NewLine
                (if infringement.userName="" then "<no name>" else infringement.userName)
                (if infringement.mac="" then "<no mac>" else infringement.mac)
                (if infringement.preNatPort = 0 then "<no preNat>" else 
                    sprintf "%A:%d" infringement.preNatIp infringement.preNatPort)
                infringement.postNatIp
                infringement.postNatPort
                infringement.remoteIp
                infringement.remotePort
                (infringement.localTimeStamp.ToString("yyyy-MM-dd HH:mm:ss"))
                (if infringement.error = "" then "" else sprintf "%s\terror: %s" Environment.NewLine infringement.error)
                (if infringement.natLogFileName = "" then "" else 
                    sprintf "%s\tnat: %s %s" 
                        Environment.NewLine infringement.natLogFileName 
                        (if infringement.natLogFilePosition = 0UL then "" else sprintf "@ %d" infringement.natLogFilePosition))

[<DataContract>]                
type Config() = 
    [<DataMember>] member val noticesFolder = "" with get, set
    [<DataMember>] member val natLogFolder = "" with get, set
    [<DataMember>] member val connectionString = "" with get, set
    [<DataMember>] member val natChunkSize = 4 with get, set
    [<DataMember>] member val natTimeDelta = 3.0 with get, set
                