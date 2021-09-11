# Download latest Sophia Script release from github

$url = 'https://github.com/farag2/Sophia-Script-for-Windows/releases/latest'
$request = [System.Net.WebRequest]::Create($url)
$response = $request.GetResponse()
$realTagUrl = $response.ResponseUri.OriginalString
$version = $realTagUrl.split('/')[-1].Trim('v')
$fileName = "Sophia.Script.v$version.zip"
$realDownloadUrl = $realTagUrl.Replace('tag', 'download') + '/' + $fileName

Write-Host Downloading Sophia Script
#Write-Host Downloading Sophia Script v$version
Invoke-WebRequest -Uri $realDownloadUrl -OutFile $env:TEMP/$fileName

# temp dir
$TempDir = [System.IO.Path]::GetTempPath()

PAUSE
Write-Host Extracting release files
Expand-Archive -path "$TempDir\$fileName" -DestinationPath "C:\Sophia Script v$version"
Remove-Item $TempDir\$fileName

#Open Sophia Script File
PAUSE
& "C:\Program Files\Notepad++\notepad++.exe" "C:\Sophia Script v$version\Sophia Script v$version\Sophia.ps1"

#Write-Host Running Sophia Script
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
& 'C:\Sophia Script*\Sophia Script*\Sophia.ps1'

PAUSE
Write-Host Removing Sophia Script Folder
Remove-Item 'C:\Sophia Script*'