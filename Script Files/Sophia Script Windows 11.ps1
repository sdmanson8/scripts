#requires -version 5.1
#Calling Powershell as Admin and setting Execution Policy to Bypass to avoid Cannot run Scripts error
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  Start-Process powershell -Verb runAs -ArgumentList ("&'" +$myinvocation.mycommand.definition + "'")
# Check if Windows Terminal is Running, Stop Windows Terminal if Running
    if((get-process "WindowsTerminal" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "WindowsTerminal"
        }
# Check if CMD is Running, Stop CMD if Running
    if((get-process "cmd" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "cmd"
        }
# Check if Powershell is Running, Stop Powershell if Running
    if((get-process "powershell" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "powershell"
        }
  Break
    }
Clear-Host

# Download latest Sophia Script release from github

$url = 'https://github.com/farag2/Sophia-Script-for-Windows/archive/refs/heads/master.zip'
$fileName = "Sophia Script Master.zip"

Write-Host Downloading Sophia Script
#Write-Host Downloading Sophia Script
Invoke-WebRequest -Uri $url -OutFile $env:TEMP/$fileName

# temp dir
$TempDir = [System.IO.Path]::GetTempPath()

#Remove Previous Leftover Folders
Remove-Item 'C:\Sophia Script Master' -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue

PAUSE
Write-Host Extracting release files
Expand-Archive -path "$TempDir\$fileName" -DestinationPath "C:\Sophia Script Master"
Remove-Item $TempDir\$fileName

Write-Host Is Notepad++ Installed?
$w64=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { try { $_.DisplayName -match "NotePad++" } catch { $false } }
$w32=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object { try { $_.DisplayName -match "NotePad++" } catch { $false } }
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
PAUSE
#Open Sophia Script File
Write-Host Opening Sophia Script File
& "C:\Program Files\Notepad++\notepad++.exe" "C:\Sophia Script Master\Sophia-Script-for-Windows-master\Sophia Script\Sophia Script for Windows 11\Sophia.ps1"

PAUSE
Write-Host Running Sophia Script
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Powershell.exe "& 'C:\Sophia Script Master\Sophia-Script-for-Windows-master\Sophia Script\Sophia Script for Windows 11\Sophia.ps1'"

PAUSE
#Open Wrapper from Windows Explorer
#cd 'C:\Sophia Script Master\Sophia-Script-for-Windows-master\Wrapper'
#ii .

PAUSE
Write-Host Removing Sophia Script Folder
Remove-Item 'C:\Sophia Script Master' -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
