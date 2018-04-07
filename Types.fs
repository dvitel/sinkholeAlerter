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
            sprintf "%s, %s --> %s --> %s:%d --> %s:%d, %s" 
                (if infringement.userName="" then "<no name>" else infringement.userName)
                (if infringement.mac="" then "<no mac>" else infringement.mac)
                (if infringement.preNatPort = 0 then "<no preNat>" else 
                    sprintf "%A:%d" infringement.preNatIp infringement.preNatPort)
                infringement.postNatIp
                infringement.postNatPort
                infringement.remoteIp
                infringement.remotePort
                (infringement.localTimeStamp.ToString("yyyy-MM-dd HH:mm:ss"))
                