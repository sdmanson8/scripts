#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Uninstall Microsoft Edge"

########################### Script Starting ###################################
###############################################################################

Clear-Host

#Create Restore Point
Checkpoint-Computer -Description "Removal of Microsoft Edge" -RestorePointType MODIFY_SETTINGS

Clear-Host
Write-Host Downloading Edge Legacy Uninstaller
$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
Invoke-WebRequest -Uri https://gorazy.com/it-support/downloads/uninstall_edge.zip -OutFile $downloads\uninstall_edge.zip -UseBasicParsing -UseBasicParsing

Write-Host Extracting files
Expand-Archive "$downloads\uninstall_edge.zip" -DestinationPath "$downloads\uninstall_edge"
Clear-Host
Remove-Item $env:USERPROFILE\Downloads\uninstall_edge.zip

Write-Host Run Edge Legacy Uninstaller
& "$downloads\uninstall_edge\Uninstall Edge.cmd"

PAUSE
Clear-Host
Write-Host Removing Edge Legacy Uninstaller folders
Remove-Item "$downloads\uninstall_edge" -Recurse -ErrorAction SilentlyContinue -Confirm:$false

$sysapppath = "$env:systemroot\SystemApps"
$sysapps = @(
    "Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
    )

Write-Host "Killing Microsoft Edge Process"
Get-Process *msedge* | Stop-Process -Force
Write-Host "Moving Folders"
foreach ($sysapp in $sysapps) {
    [int]$i = "1"
    $dis = "_disabled"
    $moveto = "$sysapppath\$sysapp$dis"
    $movefrom = "$sysapppath\$sysapp"
    if (Test-Path $sysapppath\$sysapp) {
        if (Test-Path $moveto) {
            do {
                Write-Host "WARN: folder already exists"
                Write-Host "Moving app $sysapp to $moveto$i"
                mv $sysapppath\$sysapp $moveto$i -EA SilentlyContinue
                $i++
                }
            until (!(Test-Path $sysapppath\$sysapp))
        }
        else {
            mv $sysapppath\$sysapp $moveto
            Write-Host "Moving app $sysapp to $moveto"
        }
    }
}

Write-Host Uninstalling Microsoft Chromium Edge
$DIR = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
cd $DIR\[0-9]*\Installer
.\setup.exe --uninstall --system-level --verbose-logging --force-uninstall

<#
Clear-Host
    Write-Host Downloading Geek Uninstaller
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri https://geekuninstaller.com/geek.zip -OutFile $downloads\geek.zip -UseBasicParsing
    
    PAUSE
    Write-Host Extracting files
    Expand-Archive "$downloads\geek.zip" -DestinationPath "$downloads\Geek Uninstaller"
    Remove-Item $downloads\geek.zip
    
    PAUSE
    Write-Host Running Geek Uninstaller PS!! RIGHT CLICK ON ALL MICROSOFT EDGE INSTANCES AND SELECT "FORCE REMOVAL"
    & "$downloads\Geek Uninstaller\geek.exe"

    PAUSE
    Write-Host Removing Edge Legacy Uninstaller folders
    Remove-Item "$downloads\Geek Uninstaller"  -Recurse -ErrorAction SilentlyContinue -Confirm:$false
#>

