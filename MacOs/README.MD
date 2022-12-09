
Bash script to enable/disable extended Anyconnect Umbrella Roaming module extended logging

Installation:  
Clone git repository 
```
git clone https://github.com/olegunza/ac.git  
```

Go to MacOs folder and make script executable

```  
sudo chmod +x ./umbrellalogctl
```

Run with sudo rights

```
Usage: umbrellalogctl [-s|-e|-e swg|-e kdf|-d|-d swg|-d kdf|-l|-u|-r|-h]  
    -s, --status      Print Anyconnect service status and logging enabled  
    -e, --enable      Enable logging feature  
        --enable swg  Enable SWG maximum debug logging  
        --enable kdf 0xffffffff Enable KDF debug logging with debug flags set to 0xffffffff  
    -d, --disable     Disable logging feature  
        --disable swg Disable SWG maximum debug logging  
        --disable kdf Disable KDF debug logging  
    -l, --load        Load/Register Anyconnect service  
    -u, --unload      Unload/Unregister Anyconect service  
    -r, --restart     Reload/Restart Umbrella Roaming Module  
    -h, --help        Show this message.  
```


Example scenario:  

Enable Max SWG logs, KDF logs, restart AC and verify if extended logging is enabled  

```
[admin@admins-Mac] ac % sudo ./umbrellalogctl -e swg  
+ SWG Max debug logging has ENABLED  

[admin@admins-Mac] ac % sudo ./umbrellalogctl -e kdf 0xffffffff  
debug=0xffffffff  
+ KDF logs has enabled  

[admin@admins-Mac] ac % sudo ./umbrellalogctl -r  
AnyConnect service has been STOPPED  
AnyConnect has been STARTED.  

[admin@admins-Mac] ac % sudo ./umbrellalogctl -s  
+ swg_org_config.flag found  
+ Looks like SWG Max debug logging enabled and we see redirection events  

You can run next command to manually verify if we see SWG maximum debug logs:  
log show --predicate subsystem contains "com.cisco.anyconnect.swg" ||senderImagePath endwith "acswgagent" --debug --info --last 5m  
+ KDF debug flags file found  
+ Looks like KDF Logs enabled and we see debug events  

You can run next command to manually verify if we see KDF logs:  
log show --predicate subsystem contains "comcisco.anyconnect.acsock" --debug --info --last 5m  
+ Anyconnect service is ENABLED and RUNNING  
```


