clear
Set-ExecutionPolicy Unrestricted

clear
$msg     = 'Do you want to run Windows Update? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Windows Update
    Write-Output "Running Windows Update"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20Update.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to Disable Windows Update? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to Disable Windows Update
    Write-Output "Running Sledgehammer 2.7.2 (Disable Windows Update)"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Disable%20Windows%20Update.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to update Powershell? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to update Powershell
    Write-Output "Updating Powershell"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Powershell.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to download PatchMyPC? [Type Y/N?]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to download PatchMyPC
    Write-Output "Downloading PatchMyPC"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PatchMyPC.bat
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to run Microsoft Edge Uninstaller? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Microsoft Edge Uninstaller
    Write-Output "Running Microsoft Edge Uninstaller"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Uninstall%20Edge.ps1
	    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to run (Moderate-Advanced) Sophia Script for Windows 10? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Sophia Script for Windows 10
    Write-Output "Running Sophia Script for Windows 10"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Sophia%20Script%20Windows%2010.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to run (Moderate-Advanced) Sophia Script for Windows 11? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Sophia Script for Windows 11
    Write-Output "Running Sophia Script for Windows 11"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Sophia%20Script%20Windows%2011.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = "Do you want to run (Moderate-Advanced) Windows Optimization Script for Windows? [Type Y/N]"
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Windows Optimization for Windows
    Write-Output "Running Windows Optimization for Windows"
    Write-Host Downloading 1st Optimizer Script File
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Optimizer.bat -OutFile C:\Optimizer.bat
    #1st Optimizer Script File
    PAUSE
    Write-Host Edit 1st Optimizer Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\Optimizer.bat"
	PAUSE
    Write-Host Downloading 2st Optimizer Script File
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20Optimization.ps1 -OutFile "C:\Windows Optimizer.ps1"
    #2nd Optimizer Script File
    PAUSE
    Write-Host Edit 2nd Optimizer Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\Windows Optimizer.ps1"
    PAUSE 
    Write-Host Running Optimizer Scripts
    & "C:\Windows Optimizer.ps1"
    PAUSE
	Remove-Item "C:\Windows Optimizer.ps1"
    Remove-Item "C:\Optimizer.bat"
    explorer.exe 
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to run (Moderate) Remove-Windows10-Bloat by matthewjberger? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Remove-Windows10-Bloat by matthewjberger
    Write-Output "Running Remove-Windows10-Bloat by matthewjberger"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Remove-Windows10-Bloat.bat
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to run (Beginner) Remove Windows Bloatware by ChrisTitusTech? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run (Beginner) Remove Windows Bloatware by ChrisTitusTech
    Write-Output "Running (Beginner) Remove Windows Bloatware by ChrisTitusTech"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/debloat.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to Cleanup Windows.Old folder? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to Cleanup Windows.Old
    Write-Output "Cleanup Windows.Old"
    schtasks.exe /Run /TN “\Microsoft\Windows\Servicing\StartComponentCleanup”
    }
} until ($response -eq 'n')

clear
$msg     = 'Do you want to reboot your PC (RECOMMENDED IF CHANGES WERE MADE)? [Type Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to reboot machine
    Write-Output "Restarting PC"
    shutdown -r -t 00
    }
} until ($response -eq 'n')