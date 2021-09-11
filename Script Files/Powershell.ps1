# Download latest Powershell release from github

$url = 'https://github.com/PowerShell/PowerShell/releases/latest'
$request = [System.Net.WebRequest]::Create($url)
$response = $request.GetResponse()
$realTagUrl = $response.ResponseUri.OriginalString
$version = $realTagUrl.split('/')[-1].Trim('v')
$fileName = "PowerShell-$version-win-x64.msi"
$realDownloadUrl = $realTagUrl.Replace('tag', 'download') + '/' + $fileName

Write-Host Dowloading latest Powershell release

Invoke-WebRequest -Uri $realDownloadUrl -OutFile $env:TEMP/$fileName

# Moving from temp dir to target dir
$TempDir = [System.IO.Path]::GetTempPath()

Write-Host Moving $fileName
Move-Item -Path $TempDir\$fileName -Destination C:\$fileName -Force

Write-Host Updating Powershell to $version
msiexec.exe /i "C:\$fileName" /passive /qf

PAUSE
Write-Host Removing Powershell Setup File
Remove-Item 'C:\PowerShell*'