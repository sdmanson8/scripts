#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Reset Windows Update"

########################### Script Starting ###################################
###############################################################################

Clear-Host

  # Delete Windows Updates Folder (SoftwareDistribution) and reset the Windows Update Service

        Write-Host -ForegroundColor Yellow "Restarting Windows Update Service and Deleting SoftwareDistribution Folder`n"
        # Stop the Windows Update service
        try {
            Stop-Service -Name wuauserv
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage" 
        }
        # Delete the folder
        Remove-Item "C:\Windows\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
        Start-Sleep -s 3

        # Start the Windows Update service
        try {
            Start-Service -Name wuauserv
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage" 
        }
        Write-Host -ForegroundColor Yellow "Done..."
        Write-Host -ForegroundColor Yellow "Please rerun Windows Update to pull down the latest updates `n"
