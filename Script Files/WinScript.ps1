    Write-Host "Opening Script... Please Wait"
    Start-Sleep -Seconds 1
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)

