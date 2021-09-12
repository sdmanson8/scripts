# script

#Run Set-ExecutionPolicy Unrestricted before opening script if you get an error
#Run the script in an elavated Powershell Window
        
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
