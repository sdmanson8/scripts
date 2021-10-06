#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Removal of Windows.Old Folder"

########################### Script Starting ###################################
###############################################################################


takeown /F c:\Windows.old\* /R /A /D Y
cacls c:\Windows.old\*.* /T /grant administrators:F
Remove-Item c:\Windows.old\ -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false

echo "Clearing Component Store (WinSxS)"
timeout 5
dism /online /cleanup-image /StartComponentCleanup /ResetBase
