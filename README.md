# sinkholeAlerter
USF Practical Cybersecurity final project. \
Mining of nat, dhcp, radius logs for infringement data given by sinkhole providers

### Requirements
Project is based on .NET Core 2.0, and, thus, could be launched on every platform: linux, osx, win. \
In order to build and run, you need to install dotnet cli. 
Follow [these instructions](https://docs.microsoft.com/en-us/dotnet/core/linux-prerequisites?tabs=netcore2x) to install .NET Core 2.0.

### Build and run from sources
0. **git clone** https://github.com/dvitel/sinkholeAlerter.git
1. **dotnet build** in root of source tree to build
2. Prepare config for run. See _config.json_:

  * _noticesFolder_ - folder with notices

  * _natLogFolder_ - folder with nat gzip logs

  * _connectionString_ - mysql server db connection string.    
      In the case of localhost server just change username and password.

  * _natChunkSize_ - size in MB of chunks that program reads from nat logs.   
    Idea here to skip unnecessary parts of big nat.gz files by reading the chunk, analysing last date in it, \
    and deciding should we process it or discard entirelly. Tests showed that the best performance is obtained when \
    this parameter ~4MB. Having it bigger slows down search process in one chunk, while having it lower slows down search \
    because of greater iterations for file processing.
3. **dotnet run** <path to custom config.json> - to run.
  Parameter _<path to custom config.json>_ is optional, and if not provided, program will search for config.json in current directory of run.

### Run from published deploy package
.Net Core provides 2 ways to execute dlls on target platforms. \
If you completed section Requirements and installed dotnet cli, you can execute small deployment package \
which contains main dll and next dependencies:

1. _sinkholeAlerter.dll_ - main dll
2. _FSharp.Core.dll_ - F# language standard library
3. _MySqlConnector.dll_ - Database provider for MySQL
4. _sinkholeAlerter.runtimeconfig.json_ - runtime configuration for dotnet core (required)
5. _sinkholeAlerter.deps.json_ - .NET Core app dependencies
6. _config.json_ - config of application, see above

To obtain minified package go to https://github.com/dvitel/sinkholeAlerter/blob/master/pack/sinkholeAlerter.tar.gz \
Download tar.gz and unzip it. After that, configure config.json to point to your notices, nat logs and db. \
Then, execute **dotnet sinkholeAlerter.dll** \
As it was explained you can provide custom configs like this **dotnet sinkholeAlerter.dll myconfig1.json**

Another way to publish this app is through self-contained packaging. \
Result package is much bigger, but in this case installation of .NET Core is not required on target machine \
(note: small dependencies still exist. See [this again](https://docs.microsoft.com/en-us/dotnet/core/linux-prerequisites?tabs=netcore2x#linux-distribution-dependencies))


### Output example
```
----------------------------------------
Reading infringements from notices...
Parse done: 5 to search, 0 notices unparsable, elapsed 00:00
----------------------------------------
Searching NAT logs in parallel (Chunk size: 4MB)...
        nat.csv.2016032122.csv.gz
        nat.csv.2016032017.csv.gz
        nat.csv.2016032111.csv.gz
        nat.csv.2016032112.csv.gz
        nat.csv.2016032120.csv.gz
Search done: 4 found, 1 has errors, 1 filtered in total, elapsed 00:21
----------------------------------------
DHCP db search...
Search done: 4 found, 0 has errors, 1 filtered in total, elapsed 00:22
----------------------------------------
Fetching user info data...
Done, elapsed 00:39
----------------------------------------
notice: notice1-hzmavog.txt
        hzmavog, d3:1e:c8:b4:59:47 --> 172.19.52.38:65149 --> 192.168.226.52:33631 --> 195.22.28.196:1, 2016-03-21 10:54:27
        nat: nat.csv.2016032111.csv.gz
notice: dmca_notice_2-qhvirmh.txt
        qhvirmh, 3e:5f:74:9f:57:98 --> 172.19.172.127:22222 --> 192.168.226.172:42351 --> <no remote ip>:<no remote port>, 2016-03-21 21:14:39
        nat: nat.csv.2016032122.csv.gz
notice: dmca_notice_1-svnuxum.txt
        svnuxum, d2:84:b7:b1:a5:af --> 172.21.63.24:59014 --> 192.168.224.63:39713 --> <no remote ip>:<no remote port>, 2016-03-21 11:30:27
        nat: nat.csv.2016032112.csv.gz
notice: notice2-zkpgkan.txt
        zkpgkan, 09:0b:34:ae:fd:93 --> 172.21.192.187:50524 --> 192.168.226.192:63432 --> 195.22.28.198:80, 2016-03-21 19:53:07
        nat: nat.csv.2016032120.csv.gz
notice: dmca_notice_3-false_positive.txt
        <no name>, <no mac> --> <no preNat> --> 192.168.226.153:51857 --> <no remote ip>:<no remote port>, 2016-03-20 16:01:50
        error: NAT record not found. Scanned up to 3 min above
        nat: nat.csv.2016032017.csv.gz
```

Output provides timing. Script above ended in ~40 seconds providing expected information for test cases. 

### Optmizations
1. Creating index on MySQl side for Radacct query (execution time goes from 40s to ~25s): 
```
CREATE INDEX IX_radacct_2 ON radacct (FramedIPAddress, CallingStationId);
```

2. Changes in nat log search. 

   From localTimeStamp we define (minTime, maxTime) for all infringements for current nat files. \
   Then, we read sequentially 4MB blocks of gzip stream. If last date in the block is less then minTime, block is discurded. \
   In other case we begin to cache blocks in memory for each infringement (they share same blocks). \
   When we reach a block with first date in it which is greater then maxTime for selected infringement, all blocks of it are processed. \
   Blocks are saved in tuple (blocksBeforeLocalTimeStamp, blocksAfterLocalTimeStamp). \
   At this point, we are searching for post nat ip pattern starting in the middle of the range (minTime, maxTime) near localTimeStamp. \
   Thus, we speedup the search (by the cost of memory). Time goes down from 25s to 12s in Debug.

### Optimized output (11 seconds)
```
----------------------------------------
Reading infringements from notices...
Parse done: 5 to search, 0 notices unparsable, elapsed 00:00
----------------------------------------
Searching NAT logs in parallel (Chunk size: 4MB)...
        nat.csv.2016032122.csv.gz
        nat.csv.2016032017.csv.gz
        nat.csv.2016032111.csv.gz
        nat.csv.2016032112.csv.gz
        nat.csv.2016032120.csv.gz
Search done: 4 found, 1 has errors, 1 filtered in total, elapsed 00:11
----------------------------------------
DHCP db search...
Search done: 4 found, 0 has errors, 1 filtered in total, elapsed 00:11
----------------------------------------
Fetching user info data...
Done, elapsed 00:11
----------------------------------------
notice: notice1-hzmavog.txt
        hzmavog, d3:1e:c8:b4:59:47 --> 172.19.52.38:65149 --> 192.168.226.52:33631 --> 195.22.28.196:1, 2016-03-21 10:54:27
        nat: nat.csv.2016032111.csv.gz
notice: dmca_notice_2-qhvirmh.txt
        qhvirmh, 3e:5f:74:9f:57:98 --> 172.19.172.127:22222 --> 192.168.226.172:42351 --> <no remote ip>:<no remote port>, 2016-03-21 21:14:39
        nat: nat.csv.2016032122.csv.gz
notice: dmca_notice_1-svnuxum.txt
        svnuxum, d2:84:b7:b1:a5:af --> 172.21.63.24:59014 --> 192.168.224.63:39713 --> <no remote ip>:<no remote port>, 2016-03-21 11:30:27
        nat: nat.csv.2016032112.csv.gz
notice: notice2-zkpgkan.txt
        zkpgkan, 09:0b:34:ae:fd:93 --> 172.21.192.187:50524 --> 192.168.226.192:63432 --> 195.22.28.198:80, 2016-03-21 19:53:07
        nat: nat.csv.2016032120.csv.gz
notice: dmca_notice_3-false_positive.txt
        <no name>, <no mac> --> <no preNat> --> 192.168.226.153:51857 --> <no remote ip>:<no remote port>, 2016-03-20 16:01:50
        error: NAT record not found. Scanned up to 2 min above
        nat: nat.csv.2016032017.csv.gz
```
