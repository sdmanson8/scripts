# Uninstall Edge

Write-Host Downloading Edge Legacy Uninstaller
Invoke-WebRequest -Uri https://gorazy.com/it-support/downloads/uninstall_edge.zip -OutFile C:\uninstall_edge.zip

PAUSE
Write-Host Extracting release files
Expand-Archive "C:\uninstall_edge.zip" -DestinationPath "C:\uninstall_edge"
Remove-Item C:\uninstall_edge.zip

PAUSE
Write-Host Run Edge Legacy Uninstaller
& "C:\uninstall_edge\Uninstall Edge.cmd"

PAUSE
Removing Edge Legacy Uninstaller folders
Remove-Item "C:\uninstall_edge"

PAUSE
Write-Host Uninstalling Edge Latest
& "C:\Program Files (x86)\Microsoft\Edge\Application\9*\Installer\setup.exe" --uninstall --system-level --verbose-logging --force-uninstall
