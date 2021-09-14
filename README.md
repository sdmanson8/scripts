# script

#Run "Set-ExecutionPolicy Unrestricted" if you get an error

#Depending on the options selected you might require editing the script which will automatically download and open on your system

#Requires Powershell 5.0 and later in an elavated Powershell Window
        
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
