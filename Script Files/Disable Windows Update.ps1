# Disable Windows Update
Write-Host Download Sledgehammer 2.7.2

Invoke-WebRequest -Uri https://files2.majorgeeks.com/cc8d575f44ca82d499ecb31c9ac59fa4a50be0aa/system/Sledgehammer_2.7.2.zip -OutFile C:\Sledgehammer_2.7.2.zip

PAUSE
Write-Host Extracting release files
Expand-Archive "C:\Sledgehammer_2.7.2.zip" -DestinationPath "C:\Sledgehammer_2.7.2"
Remove-Item C:\Sledgehammer_2.7.2.zip

PAUSE
Write-Host Run Sledgehammer
& "C:\Sledgehammer_2.7.2\Portable\Sledgehammer\Sledgehammer.cmd"

PAUSE
Removing Sledgehammer folders
Remove-Item "C:\Sledgehammer_2.7.2"