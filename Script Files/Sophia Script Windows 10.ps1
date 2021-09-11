# Download latest Sophia Script release from github

$url = 'https://github.com/farag2/Sophia-Script-for-Windows/archive/refs/heads/master.zip'
$fileName = "Sophia Script Master.zip"

Write-Host Downloading Sophia Script
#Write-Host Downloading Sophia Script
Invoke-WebRequest -Uri $url -OutFile $env:TEMP/$fileName

# temp dir
$TempDir = [System.IO.Path]::GetTempPath()

PAUSE
Write-Host Extracting release files
Expand-Archive -path "$TempDir\$fileName" -DestinationPath "C:\Sophia Script Master"
Remove-Item $TempDir\$fileName

#Open Sophia Script File (Powershell)
#PAUSE
#& "C:\Program Files\Notepad++\notepad++.exe" "C:\Sophia Script Master\Sophia-Script-for-Windows-master\Sophia\PowerShell 7\Sophia.ps1"

#Write-Host Running Sophia Script (Powershell)
#Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#& 'C:\Sophia Script Master\Sophia-Script-for-Windows-master\Sophia\PowerShell 7\Sophia.ps1'

#Open Wrapper (GUI)
Write-Host Openning Wrapper (GUI)
Start-Process -FilePath 'C:\Sophia Script Master\Sophia-Script-for-Windows-master\Wrapper\SophiaScriptWrapper.exe'

PAUSE
Write-Host Removing Sophia Script Folder
Remove-Item 'C:\Sophia Script Master'
