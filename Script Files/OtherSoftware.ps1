    # HP Driver Pack
    Write-Host "Opening Webpage to Download Drivers [Search for correct Laptop]"
    Start-Process "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/HP_Driverpack_Matrix_x64.html"
    PAUSE
    Write-Host "Installing HP Drivers"
    Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\sp*.exe"
    Remove-Item "$env:USERPROFILE\Downloads\sp*.exe"
    Remove-Item C:\SWSetup

    # HP Software Framework
    Write-Host "Downloading HP Software Framework"
    Invoke-WebRequest -Uri "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/softpaq/CASLSetup.exe" -OutFile "C:\CASLSetup.exe"
    Write-Host "Installing HP Software Framework"
    Start-Process -Wait -FilePath "C:\CASLSetup.exe"
    Remove-Item "C:\CASLSetup.exe"

    # HP Support Assistant
    Write-Host "Opening Webpage to Download HP Support Assistant"
    Start-Process "https://support.hp.com/us-en/help/hp-support-assistant"
    PAUSE
    Write-Host "Installing HP Support Assistant"
    Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\sp*.exe"
    Remove-Item "$env:USERPROFILE\Downloads\sp*.exe"
    Remove-Item C:\SWSetup

    # Dashlane Desktop
    Write-Host "Opening Webpage to Download Dashlane Desktop"
    Start-Process "https://www.dashlane.com/download/desktop#downloaded"
    PAUSE
    Write-Host "Installing Dashlane Desktop"
    Start-Process -FilePath "$env:USERPROFILE\Downloads\DashlaneInst.exe"
    PAUSE
    Remove-Item "$env:USERPROFILE\Downloads\DashlaneInst.exe"
    Write-Host "Opening Webpage to Setup Dashlane Addon for Microsoft Edge"
    Start-Process "https://microsoftedge.microsoft.com/addons/detail/dashlane-password-manag/gehmmocbbkpblljhkekmfhjpfbkclbph"

    # Grammarly
    Write-Output "Downloading Grammarly for Windows"
    Invoke-WebRequest -Uri "https://download-editor.grammarly.com/windows/GrammarlySetup.exe" -OutFile "C:\GrammarlySetup.exe"
    Write-Host "Installing Grammarly"
    Start-Process -FilePath "C:\GrammarlySetup.exe"
    PAUSE
    Remove-Item "C:\GrammarlySetup.exe"
    Write-Output "Downloading Grammarly for Microsoft Office"
    Invoke-WebRequest -Uri "https://download-office.grammarly.com/latest/GrammarlyAddInSetup.exe" -OutFile "C:\GrammarlyAddInSetup.exe"
    Write-Host "Installing Grammarly for Microsoft Office"
    Start-Process -Wait -FilePath "C:\GrammarlyAddInSetup.exe"
    PAUSE
    Remove-Item C:\GrammarlyAddInSetup.exe
    Write-Host "Opening Webpage to Setup Grammarly Addon for Microsoft Edge"
    Start-Process "https://microsoftedge.microsoft.com/addons/detail/grammarly-for-microsoft-e/cnlefmmeadmemmdciolhbnfeacpdfbkd"
$msg     = 'Do you want to Install Google Chrome? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
    # Install Google Chrome
    Write-Output "Installing Google Chrome"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
        }
} until ($response -eq 'n')
$msg     = 'Do you want to Install Firefox? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
    # Install Firefox
    Write-Output "Downloading Firefox"
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "C:\firefox-latest.exe"
    Write-Host "Installing Firefox"
    Start-Process -Wait -FilePath "C:\firefox-latest.exe"
    Remove-Item "C:\firefox-latest.exe"
        }
} until ($response -eq 'n')
    # Install Microsoft Edge
    Write-Output "Downloading Microsoft Edge"
    Invoke-WebRequest -Uri "https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en" -OutFile "C:\MicrosoftEdgeSetup.exe"
    Write-Host "Installing Microsoft Edge"
    Start-Process -Wait -FilePath "C:\MicrosoftEdgeSetup.exe"
    Remove-Item "C:\MicrosoftEdgeSetup.exe"

    # Google Drive
    Write-Host "Downloading Google Drive"
    Invoke-WebRequest -Uri "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe" -OutFile "C:\GoogleDriveSetup.exe"
    Write-Host "Installing Google Drive"
    Start-Process -Wait -FilePath "C:\GoogleDriveSetup.exe"
    Remove-Item "C:\GoogleDriveSetup.exe"
