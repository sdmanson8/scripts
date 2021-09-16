#Create Restore Point
#Checkpoint-Computer -Description "Removal of Microsoft Edge" -RestorePointType MODIFY_SETTINGS
# Uninstall Edge

Write-Host Downloading Edge Legacy Uninstaller
Invoke-WebRequest -Uri https://gorazy.com/it-support/downloads/uninstall_edge.zip -OutFile C:\uninstall_edge.zip

Write-Host Extracting files
Expand-Archive "C:\uninstall_edge.zip" -DestinationPath "C:\uninstall_edge"
Clear-Host
Remove-Item C:\uninstall_edge.zip

Write-Host Run Edge Legacy Uninstaller
& "C:\uninstall_edge\Uninstall Edge.cmd"

PAUSE
Clear-Host
Write-Host Removing Edge Legacy Uninstaller folders
Remove-Item "C:\uninstall_edge"

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
$DIR = "C:\Program Files (x86)\Microsoft\Edge\Application"
cd $DIR\[0-9]*\Installer
.\setup.exe --uninstall --system-level --verbose-logging --force-uninstall

<#
Clear-Host
    Write-Host Downloading Geek Uninstaller
    Invoke-WebRequest -Uri https://geekuninstaller.com/geek.zip -OutFile C:\geek.zip
    
    PAUSE
    Write-Host Extracting files
    Expand-Archive "C:\geek.zip" -DestinationPath "C:\Geek Uninstaller"
    Remove-Item C:\geek.zip
    
    PAUSE
    Write-Host Running Geek Uninstaller PS!! RIGHT CLICK ON ALL MICROSOFT EDGE INSTANCES AND SELECT "FORCE REMOVAL"
    & "C:\Geek Uninstaller\geek.exe"

    PAUSE
    Write-Host Removing Edge Legacy Uninstaller folders
    Remove-Item "C:\Geek Uninstaller"
#>

