#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Disable Windows Update"

########################### Script Starting ###################################
###############################################################################

Clear-Host

# Disable Windows Update
Write-Host Download Sledgehammer 2.7.2

Invoke-WebRequest -Uri "https://softpedia-secure-download.com/dl/1a7c5e5049efb235f7ec9c59bc143923/6184ea19/100258453/software/system/Sledgehammer_2.7.2.zip" -OutFile $env:USERPROFILE\Downloads\Sledgehammer_2.7.2.zip  -UseBasicParsing

PAUSE
Write-Host Extracting release files
Expand-Archive "$env:USERPROFILE\Downloads\Sledgehammer_2.7.2.zip" -DestinationPath "$env:USERPROFILE\Downloads\Sledgehammer_2.7.2"
Remove-Item $env:USERPROFILE\Downloads\Sledgehammer_2.7.2.zip

PAUSE
Write-Host Run Sledgehammer
& "$env:USERPROFILE\Downloads\Sledgehammer_2.7.2\Portable\Sledgehammer\Sledgehammer.cmd"

PAUSE
Removing Sledgehammer folders
Remove-Item "$env:USERPROFILE\Downloads\Sledgehammer_2.7.2"
