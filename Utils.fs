module SinkholeAlerter.Utils 
open System
open System.Net

///search array for binary pattern recursivelly 
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

///search array for binary pattern recursivelly from back to start
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

//convert ipToDecimal analysing 
let ipToDecimal (ip: System.Net.IPAddress) =
    let ipDecimalBytes = ip.GetAddressBytes()
    ipDecimalBytes |> Array.mapi(fun i b -> 
        (b, ipDecimalBytes.Length - i - 1))
    |> Array.fold(fun acc (b, i) -> 
        let tmp = Array.replicate i 256u 
                  |> Array.fold(*) 1u
        acc + (uint32 b) * tmp) 0u        

let linuxLikeOs =
    match Environment.OSVersion.Platform with
    | PlatformID.Unix | PlatformID.MacOSX -> true
    | v when (int) v = 128 -> true
    | _ -> false                    