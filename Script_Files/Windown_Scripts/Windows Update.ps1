#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Windows PSUpdate"

########################### Script Starting ###################################
###############################################################################

Clear-Host

# Run PSWindowsUpdate
Write-Host "`nPreparing to Configure your Computer.. Please Wait`n"
Start-Sleep -Seconds 1

    # Run PSWindowsUpdate

    Write-Host Installing PSWindowsUpdate module
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

    ECHO Y | powershell Install-Module -Name PSWindowsUpdate -Force
    ECHO Y | powershell Import-Module -Name PSWindowsUpdate
    ECHO Y | powershell Add-WUServiceManager -MicrosoftUpdate

    #Install all available Updates & Reboot if Required
    Write-Host Install Windows Updates
    Install-WindowsUpdate -AcceptAll -AutoReboot


