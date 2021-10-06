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

Invoke-WebRequest -Uri https://files2.majorgeeks.com/cc8d575f44ca82d499ecb31c9ac59fa4a50be0aa/system/Sledgehammer_2.7.2.zip -OutFile $env:USERPROFILE\Downloads\Sledgehammer_2.7.2.zip

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
