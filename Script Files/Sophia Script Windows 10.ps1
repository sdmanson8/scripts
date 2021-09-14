# Download latest Sophia Script release from github

$url = 'https://github.com/farag2/Sophia-Script-for-Windows/archive/refs/heads/master.zip'
$fileName = "Sophia Script Master.zip"

Write-Host Downloading Sophia Script
#Write-Host Downloading Sophia Script
Invoke-WebRequest -Uri $url -OutFile $env:TEMP/$fileName

# temp dir
$TempDir = [System.IO.Path]::GetTempPath()

#Remove Previous Leftover Folders
Remove-Item 'C:\Sophia Script Master' -Recurse -Force -Confirm:$false

PAUSE
Write-Host Extracting release files
Expand-Archive -path "$TempDir\$fileName" -DestinationPath "C:\Sophia Script Master"
Remove-Item $TempDir\$fileName

Write-Host Is Notepad++ Installed?
$w64=Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object DisplayName -like 'NotePad++*'
$w32=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | where-Object DisplayName -like 'NotePad++*'
if ($w64 -or $w32)
{
    Write-output "Notepad++ is already installed on your machine."
}
Else{
    Write-Output "Notepad++ is not installed on your machine."
    Write-Host "Silently Installing Notepad++ ... Please wait..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$homeUrl = 'https://notepad-plus-plus.org'
$res = Invoke-WebRequest -UseBasicParsing $homeUrl
if ($res.StatusCode -ne 200) {throw ("status code to getDownloadUrl was not 200: "+$res.StatusCode)}
$tempUrl = ($res.Links | Where-Object {$_.outerHTML -like "*Current Version *"})[0].href
if ($tempUrl.StartsWith("/")) { $tempUrl = "$homeUrl$tempUrl" }
$res = Invoke-WebRequest -UseBasicParsing $tempUrl
if ($res.StatusCode -ne 200) {throw ("status code to getDownloadUrl was not 200: "+$res.StatusCode)}
$dlUrl = ($res.Links | Where-Object {$_.href -like "*x64.exe"})[0].href
if ($dlUrl.StartsWith("/")) { $dlUrl = "$homeUrl$dlUrl" }
$installerPath = Join-Path $env:TEMP (Split-Path $dlUrl -Leaf)
Invoke-WebRequest $dlUrl -OutFile $installerPath
Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
Remove-Item $installerPath
Write-Host Notepad++ Installed
} 

#Open Sophia Script File
Write-Host Opening Sophia Script File
& "C:\Program Files\Notepad++\notepad++.exe" "C:\Sophia Script Master\Sophia-Script-for-Windows-master\Sophia\PowerShell 7\Sophia.ps1"

PAUSE
#Is Powershell 7 Installed
Write-Host "Is Powershell 7 Installed?"
Write-Host Is Powershell 7 Installed?
$w64=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
$w32=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
if ($w64 -or $w32)
{
    Write-output "Powershell 7 is already installed on your machine."
}
Else{
    Write-Output "Powershell 7 is not installed on your machine."
    Write-Host "Preparing to Install Powershell 7 ... Please wait..."
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
    Write-Host Powershell 7 Installed
}

Write-Host Running Sophia Script
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
pwsh.exe "C:\Sophia Script Master\Sophia-Script-for-Windows-master\Sophia\PowerShell 7\Sophia.ps1"

#Open Wrapper from Windows Explorer
#cd 'C:\Sophia Script Master\Sophia-Script-for-Windows-master\Wrapper'
#ii .

PAUSE
Write-Host Removing Sophia Script Folder
Remove-Item 'C:\Sophia Script Master' -Recurse -Force -Confirm:$false
