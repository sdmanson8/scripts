# script

#Run "Set-ExecutionPolicy Unrestricted" if you get an error

#Depending on the options selected you might require editing the script which will automatically download and open on your system

#Requires Powershell 5.0 and later in an elavated Powershell Window
        
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)


Preview of Script Menu

![image](https://user-images.githubusercontent.com/90516190/133615353-e812e076-652a-4419-ada7-d3be10285c6d.png)
