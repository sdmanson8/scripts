#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Join Domain"

########################### Script Starting ###################################
###############################################################################

Clear-Host
Write-Host Joining PC to Domain

# Edit domain name and credentials
    
$hostname = Read-Host "Enter your New Computer Name WITHOUT "" "" ..."
$Domain = Read-Host "Enter your domain name WITHOUT "" "" ..."
$Credential = Get-Credential

Rename-Computer $hostname
Add-Computer -Domain $Domain -NewName $hostname -Credential $Credential -Restart -Force
