AC-Logging.ps1 - PowerShell module for enabling/disabling AnyConnect SWG and KDF logging

Usage:  
Run as Administrator
```
powershell -ep bypass
```
Load PowerShell module to memory
```
. ./AC-Logging.ps1
```

Cmdlets:  
 Enable-SWGMaxDebug  Enables max debug logging for Cisco AnyConnect SWG module.  
 Disable-SWGMaxDebug  Disables max debug logging for Cisco AnyConnect SWG module.   
 Verify-SWGMaxDebug Verifies if SWG maximum debug logging is enabled succesfully.  
 Enable-KDFDebug Enables KDF(Kernel Driver Framework) logs for Cisco AnyConnect.  
 Disable-KDFDebug Disable-KDFDebug  
 Restart-AC Restarts Anyconnect services   
 Enable-WPFLogging  Enables Windows Filtering Platform Auditing for Success and Failure events  
 Disable-WPFLogging  Disables Windows Filtering Platform Auditing for Success and Failure events  
 Verify-WPFLogging  rints last 50 events from Security log with EventID 5157 and 5152 to verify if WPF Auditing enabled succesfully  

Examples:  

Enable-SWGMaxDebug  
```
PS C:\Utils> Enable-SWGMaxDebug
- SWG maximum debug logging enabled


exceptionList  : {10.in-addr.arpa, *.10.in-addr.arpa, 16.172.in-addr.arpa, *.16.172.in-addr.arpa...}
failOpen       : 1
swgAnycast     : 146.112.255.50
swgDomain      : swg-url-proxy-https.sigproxy.qq.opendns.com
swgEchoService : http://www.msftconnecttest.com/connecttest.txt
swgHonorTND    : 1
logLevel       : 1
```
Restart-AC
```
PS C:\Utils> Restart-AC
WARNING: Waiting for service 'Cisco AnyConnect Secure Mobility Agent (vpnagent)' to stop...
WARNING: Waiting for service 'Cisco AnyConnect Secure Mobility Agent (vpnagent)' to stop...
WARNING: Waiting for service 'Cisco AnyConnect Secure Mobility Agent (vpnagent)' to stop...
WARNING: Waiting for service 'Cisco AnyConnect Secure Mobility Agent (vpnagent)' to stop...
- AC vpnagent service restarted
- AC acsock service restarted
```

Verify-SWGMaxDebug  

Not enabled:  
```
PS C:\Utils> Verify-SWGMaxDebug
There is no debug events still.
Please give more time to service to start or try to open some websites in browser to generate events
```

Enabled:  
```
PS C:\Utils> Verify-SWGMaxDebug
Looks like SWG Max debug logging enabled and we see web traffic redirection events
Here is last 50 events from event log

   Index Time          EntryType   Source                 InstanceID Message
   ----- ----          ---------   ------                 ---------- -------
16450606 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | SetGUID 'd241dd0748c31ad43c33efc992a21fc6d236ecd2'
16450605 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | EPOC time '1667473889'
16450604 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | Connection : succesfully initialized umbrellaLicInfo
16450603 Nov 03 12:11  Information acswgagent             1140916480 BRIDGE | Thread 1ef0 | CDnConnectionThread::EndSetConnectTime 52
16450602 Nov 03 12:11  Information acswgagent             1140916480 BRIDGE | Thread 1ef0 | Connection : Connecting to 146.112.9.200:443
16450601 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | Connection : Success in converting domain name to IP
16450600 Nov 03 12:11  Information acswgagent             1140916480 BRIDGE | Thread 1ef0 | Connection : Resolved IP from 'swg-url-proxy-https.sigproxy.qq.opendns.com' is 146.112.9.200, using index = 0
16450599 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 1ef0 | DNSLookup : address lookup took 31 [ms], error = 0
16450598 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 153c | Thread : Starting thread CDnLookupThread
16450597 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | Thread : Created new thread ID = 153c CDnLookupThread
16450596 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 788 | Thread : Starting thread ThreadPool
16450595 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | CDnThreadPoolThread : GetThread - idles 0 actives 0
16450594 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | Thread : Created new thread ID = 788 ThreadPool
16450593 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 1ef0 | Connection : Checking for host-exclusion...
16450592 Nov 03 12:11  Information acswgagent             1140916480 BRIDGE | Thread 1ef0 | Connection : Selected modes - CMode : 1, TMode : 1
16450591 Nov 03 12:11  Information acswgagent             1140916480 BRIDGE | Thread 1ef0 | Connection : Port = 443. CMode : 1, TMode : 1
16450590 Nov 03 12:11  Information acswgagent             1140916480 LISTEN | Thread 1ef0 | Connection : Hostnames from KDF are
16450589 Nov 03 12:11  Information acswgagent             1140916480 LISTEN | Thread 1ef0 | Connection: orig dst_addr=135.148.137.214 and dst_port=443 from kdf
16450588 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 6f8 | Thread : Starting thread CDnConnectionThread
16450587 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 15a4 | Thread : Created new thread ID = 6f8 CDnConnectionThread
16450586 Nov 03 12:11  Information acswgagent             1140916480 LISTEN | Thread 15a4 | Listener : Connection started
16450585 Nov 03 12:11  Information acswgagent             1140916480 LISTEN | Thread 15a4 | Listener : Starting connection thread 1ef0
16450582 Nov 03 12:11  Information acswgagent             1140916480 IPC | Thread 265c | ServerComm : msgid COMM_MSG_SWG_STATE
16450581 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 2730 | MonitorConfigChangesProc: waiting on events....
16450580 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | CSWGAgent: State cjson object is {"version":1,"swg_protection_state":"protected"}
16450579 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | OnBackoffStateChange: KDF started successfully.
16450578 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 2730 | InitialiseRedirectorInterface
16450577 Nov 03 12:11  Information acswgagent             1140916480 THREAD | Thread 2730 | SocketRedirectorApi->Start success
16450576 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | SetRedirects returned 0
16450575 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=1 peerport=0 redirectport=0
16450574 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=1 peerport=0 redirectport=0
16450573 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=1 peerport=0 redirectport=0
16450572 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=1 peerport=0 redirectport=0
16450571 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=2 peerport=443 redirectport=5002
16450570 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=2 peerport=443 redirectport=5002
16450569 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=2 peerport=80 redirectport=5002
16450568 Nov 03 12:11  Information acswgagent             1140916480 TRACE | Thread 2730 | redirectInfoList iteration: op=2 peerport=80 redirectport=5002
```

Disable-SWGMaxDebug
```
PS C:\Utils> Disable-SWGMaxDebug
- SWG maximum debug logging disabled
```


Enable-KDFDebug 0x70C01FF
```
PS C:\Utils> Enable-KDFDebug 0x70C01FF


DebugFlags   : 118227455
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acsock
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
PSChildName  : acsock
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry

- KDF logging enabled
```

Disable-KDFDebug
```
PS C:\Utils> Disable-KDFDebug
- KDF logging disabled
```


Enable-WPFLogging  

```
PS C:\Utils> Enable-WPFLogging
The command was successfully executed.
The command was successfully executed.
System audit policy

Category/Subcategory                      Setting
Object Access
  Filtering Platform Packet Drop          Success and Failure

WPF Logging enabled succesfully
```

Disable-WPFLogging  

```
PS C:\Utils> Disable-WPFLogging
The command was successfully executed.
The command was successfully executed.
System audit policy

Category/Subcategory                      Setting
Object Access
  Filtering Platform Packet Drop          No Auditing

WPF Logging disabled
```  

Verify-WPFLogging  

```
Message       : The Windows Filtering Platform has blocked a packet.

                Application Information:
                        Process ID:             6476
                        Application Name:       \device\harddiskvolume4\program files (x86)\cisco\cisco anyconnect secure mobility
                client\dnscrypt-proxy.exe

                Network Information:
                        Direction:              %%14593
                        Source Address:         192.168.1.81
                        Source Port:            63924
                        Destination Address:    208.67.221.76
                        Destination Port:               443
                        Protocol:               17

                Filter Information:
                        Filter Run-Time ID:     84442
                        Layer Name:             %%14611
                        Layer Run-Time ID:      48
```




