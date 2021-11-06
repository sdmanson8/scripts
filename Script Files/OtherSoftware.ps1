#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Install Other Software"

########################### Script Starting ###################################
###############################################################################

Clear-Host

    # Dashlane Desktop
    Write-Host "Opening Webpage to Download Dashlane Desktop"
    Start-Process "https://www.dashlane.com/download/desktop#downloaded"
    PAUSE
    Write-Host "Installing Dashlane Desktop"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -FilePath "$downloads\DashlaneInst.exe"
    PAUSE
    Remove-Item "$downloads\DashlaneInst.exe"
    Write-Host "Opening Webpage to Setup Dashlane Addon for Microsoft Edge"
    Start-Process "https://microsoftedge.microsoft.com/addons/detail/dashlane-password-manag/gehmmocbbkpblljhkekmfhjpfbkclbph"

    # Grammarly
    Write-Output "Downloading Grammarly for Windows"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://download-editor.grammarly.com/windows/GrammarlySetup.exe" -OutFile "$downloads\GrammarlySetup.exe" -UseBasicParsing
    Write-Host "Installing Grammarly"
    Start-Process -FilePath "$downloads\GrammarlySetup.exe"
    PAUSE
    Remove-Item "$downloads\GrammarlySetup.exe"
    Write-Output "Downloading Grammarly for Microsoft Office"
    Invoke-WebRequest -Uri "https://download-office.grammarly.com/latest/GrammarlyAddInSetup.exe" -OutFile "$downloads\GrammarlyAddInSetup.exe" -UseBasicParsing
    Write-Host "Installing Grammarly for Microsoft Office"
    Start-Process -Wait -FilePath "$downloads\GrammarlyAddInSetup.exe"
    PAUSE
    Remove-Item $downloads\GrammarlyAddInSetup.exe
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
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "$downloads\firefox-latest.exe"
    Write-Host "Installing Firefox"
    Start-Process -Wait -FilePath "$downloads\firefox-latest.exe"
    Remove-Item "$downloads\firefox-latest.exe"
        }
} until ($response -eq 'n')
    # Install Microsoft Edge
    Write-Output "Downloading Microsoft Edge"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en" -OutFile "$downloads\MicrosoftEdgeSetup.exe"
    Write-Host "Installing Microsoft Edge"
    Start-Process -Wait -FilePath "$downloads\MicrosoftEdgeSetup.exe"
    Remove-Item "$downloads\MicrosoftEdgeSetup.exe"

    # Google Drive
    Write-Host "Downloading Google Drive"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe" -OutFile "$downloads\GoogleDriveSetup.exe"
    Write-Host "Installing Google Drive"
    Start-Process -Wait -FilePath "$downloads\GoogleDriveSetup.exe"
    Remove-Item "$downloads\GoogleDriveSetup.exe"

    # Tree Size
    Write-Host "Downloading Tree Size"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://downloads.jam-software.de/treesize_free/TreeSizeFreeSetup.exe" -OutFile "$downloads\TreeSizeFreeSetup.exe"
    Write-Host "Installing Tree Size"
    Start-Process -Wait -FilePath "$downloads\TreeSizeFreeSetup.exe"
    Remove-Item "$downloads\TreeSizeFreeSetup.exe"
