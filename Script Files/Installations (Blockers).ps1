    # Install Cold Turkey Blocker
	
    Write-Host Opening Webpage to Download Cold Turkey Blocker
    Start-Process "https://getcoldturkey.com/download/win/"
    PAUSE
    Write-Host "Installing Cold Turkey Blocker"
    Start-Process C:\Users\sheldonm\Downloads\Cold_Turkey_Installer.exe
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item C:\Users\sheldonm\Downloads\Cold_Turkey_Installer.exe
	
    # Install Truple
	
    Write-Host "Opening Webpage to Download Truple"
    Start-Process "https://support.truple.io/articles/windows/windows-setup-guide"
    PAUSE
    Write-Host "Installing Truple"
    Start-Process C:\Users\sheldonm\Downloads\truple*
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item C:\Users\sheldonm\Downloads\truple*
	
    # Install Qustodio
	
    Write-Host "Installing Qustodio"
    $ProcName = "QustodioInstaller.exe"
    $WebFile = "https://family.qustodio.com/download/windows"
    (New-Object System.Net.WebClient).DownloadFile($WebFile,"$env:APPDATA\$ProcName")
    Start-Process ("$env:APPDATA\$ProcName")
    PAUSE
$appdata = Get-Childitem env:APPDATA | %{ $_.Value }
    Write-Host "Removing Setup File"
    Remove-Item $appdata\QustodioInstaller.exe
	
    # Install CleanBrowsing
	
    Write-Host "Opening Webpage to Download CleanBrowsing"
    Start-Process "https://cleanbrowsing.org/guides/windows/"
    PAUSE
    Write-Host "Installing CleanBrowsing"
    Start-Process C:\Users\sheldonm\Downloads\CleanBrowsing*
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item C:\Users\sheldonm\Downloads\CleanBrowsing*
	
    # Add Safe Search to Hosts File
	
    Write-Output "Adding Safe Search Value to Hosts File"
    Add-Content C:\Windows\System32\drivers\etc\hosts "216.239.38.120 www.google.com         #forcesafesearch"
	
    # Modify Chrome Settings
	
    Write-Host Is chrome Installed?
    $w64=Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object DisplayName -like 'google chrome*'
    $w32=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | where-Object DisplayName -like 'google chrome*'
    if ($w64 -or $w32)
    {
    Write-output "Google Chrome is already installed on your machine."
    }
    Else{
    Write-Output "Google Chrome is not installed on your machine."
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
    } 
    # Check if Chrome is Running, Stop Chrome if Running
    Write-Host "Is Chrome Running?"
    if((get-process "chrome" -ea SilentlyContinue) -eq $Null){ 
        echo "Not Running" 
    }
    else{ 
    echo "Running, Stopping Process"
    Stop-Process -processname "chrome"
        }
    # Tweak Chrome
    Write-Host "Disabling Guest Mode"
    REG ADD HKLM\SOFTWARE\Policies\Google\Chrome /v BrowserGuestModeEnabled /t REG_DWORD /d 0
    #Write-Host "Disabling Add Profile"
    #REG ADD HKLM\SOFTWARE\Policies\Google\Chrome /v BrowserAddPersonEnabled /t REG_DWORD /d 0
    Write-Host "Disabling Incognito"
    REG ADD HKLM\SOFTWARE\Policies\Google\Chrome /v IncognitoModeAvailability /t REG_DWORD /d 1
	
    # Check if Microsoft Edge is Running, Stop Microsoft Edge if Running
	
    Write-Host "Is Microsoft Edge Running?"
    if((get-process "msedge" -ea SilentlyContinue) -eq $Null){ 
        echo "Not Running" 
    }
    else{ 
    echo "Running, Stopping Process"
    Stop-Process -processname "msedge"
        }
    # Tweak Microsoft Edge
    Write-Host "Disabling Guest Mode"
    REG ADD HKLM\SOFTWARE\Policies\Microsoft\Edge /v BrowserGuestModeEnabled /t REG_DWORD /d 0
    Write-Host "Disabling Add Profile"
    REG ADD HKLM\SOFTWARE\Policies\Microsoft\Edge /v BrowserAddProfileEnabled /t REG_DWORD /d 0
    Write-Host "Disabling Incognito"
    REG ADD HKLM\SOFTWARE\Policies\Microsoft\Edge /v InPrivateModeAvailability /t REG_DWORD /d 1