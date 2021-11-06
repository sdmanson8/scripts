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
$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
Invoke-WebRequest -Uri "https://softpedia-secure-download.com/dl/1a7c5e5049efb235f7ec9c59bc143923/6184ea19/100258453/software/system/Sledgehammer_2.7.2.zip" -OutFile $downloads\Sledgehammer_2.7.2.zip  -UseBasicParsing

PAUSE
Write-Host Extracting release files
Expand-Archive "$downloads\Sledgehammer_2.7.2.zip" -DestinationPath "$downloads\Sledgehammer_2.7.2"
Remove-Item $downloads\Sledgehammer_2.7.2.zip

PAUSE
Write-Host Run Sledgehammer
& "$downloads\Sledgehammer_2.7.2\Portable\Sledgehammer\Sledgehammer.cmd"

PAUSE
Removing Sledgehammer folders
Remove-Item "$downloads\Sledgehammer_2.7.2"
