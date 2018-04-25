namespace SinkholeAlerter.Types
open System
open System.Net
open System.Runtime.Serialization

//we will gather all info parts in this structure
type Infringement = {
    userName: string //gathered from MySQL contactinfo or radacct
    mac: string //gathered from DHCP MySQL
    preNatIp: IPAddress  //gathered from Nat logs
    preNatIpDecimal: uint32 //same
    preNatPort: int //same
    utcTimeStamp: DateTime //gathered from notices
    localTimeStamp: DateTime //converted from utc
    postNatIp: string //from notices
    postNatPort: int //from notices
    remoteIp: string //opt, from notices
    remotePort: string //opt, from notices
    noticeFileName: string //initial data 
    natLogFileName: String //decided from localTimeStamp
    natLogFilePosition: uint64 //byte position in nat log file, found in nat search for debugging
    error: string //on any stage if something goes wrong
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
        override infringement.ToString() = //formatting
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

//this is class representation of config.json
[<DataContract>]                
type Config() = 
    [<DataMember>] member val noticesFolder = "" with get, set
    [<DataMember>] member val natLogFolder = "" with get, set
    [<DataMember>] member val connectionString = "" with get, set
    [<DataMember>] member val natChunkSize = 4 with get, set
    [<DataMember>] member val natTimeDelta = 3.0 with get, set
                