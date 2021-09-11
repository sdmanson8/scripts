# Uninstall Edge

Write-Host Downloading Edge Legacy Uninstaller
Invoke-WebRequest -Uri https://gorazy.com/it-support/downloads/uninstall_edge.zip -OutFile C:\uninstall_edge.zip

PAUSE
Write-Host Extracting files
Expand-Archive "C:\uninstall_edge.zip" -DestinationPath "C:\uninstall_edge"
Remove-Item C:\uninstall_edge.zip

PAUSE
Write-Host Run Edge Legacy Uninstaller
& "C:\uninstall_edge\Uninstall Edge.cmd"

PAUSE
Write-Host Removing Edge Legacy Uninstaller folders
Remove-Item "C:\uninstall_edge"

$msg     = 'Do you want to uninstall Microsoft Chromium Edge using Geek Uninstaller? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run (Beginner) Remove Windows Bloatware by ChrisTitusTech
    
    PAUSE
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
    }
} until ($response -eq 'n')
