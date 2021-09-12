# script

#Run the script in an elavated Powershell Window
    Set-ExecutionPolicy Unrestricted
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
