namespace SinkholeAlerter.Types
open System
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

// type LogsDb = 
//     SqlDataProvider<
//         DatabaseVendor = Common.DatabaseProviderTypes.MYSQL,
//         ConnectionString = connectionString,
//         IndividualsAmount = 1000,
//         UseOptionTypes = true,
//         ResolutionPath = connectionString,
//         Owner = "logs_db"> 

// type LogsDb() =
    
//     implement IDisposable with
//         override x.Dispose() = 

                