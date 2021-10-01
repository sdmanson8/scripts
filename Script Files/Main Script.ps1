    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
