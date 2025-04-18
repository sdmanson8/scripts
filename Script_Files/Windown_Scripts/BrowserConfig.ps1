#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Modify Browser Settings (Filtering)"

########################### Script Starting ###################################
###############################################################################

Clear-Host

# Ask for confirmation to Modify Chrome
    $ModifyChrome = Read-Host "Would you like to Modify Chrome? (Y/N)"
    if ($ModifyChrome -eq 'Y') { 
    # Modify Chrome Settings
    Write-Host Is Chrome Installed?
    $w64=Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object DisplayName -like 'google chrome*'
    $w32=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | where-Object DisplayName -like 'google chrome*'
    if ($w64 -or $w32)
    {
    Write-output "Google Chrome is already installed on your machine."
    }
    Else{
    Write-Output "Google Chrome is not installed on your machine."
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.ps1 -UseBasicParsing
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
    Write-Output "Setting Chrome as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Google Chrome"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
	
    Write-Host "Disabling Guest Mode"
    REG ADD HKLM\SOFTWARE\Policies\Google\Chrome /v BrowserGuestModeEnabled /t REG_DWORD /d 0
    #Write-Host "Disabling Add Profile"
    #REG ADD HKLM\SOFTWARE\Policies\Google\Chrome /v BrowserAddPersonEnabled /t REG_DWORD /d 0
    Write-Host "Disabling Incognito"
    REG ADD HKLM\SOFTWARE\Policies\Google\Chrome /v IncognitoModeAvailability /t REG_DWORD /d 1
         }
# Ask for confirmation to Modify Firefox
    $ModifyFirefox = Read-Host "Would you like to Modify Firefox? (Y/N)"
    if ($ModifyFirefox -eq 'Y') { 
    # Modify Firefox Settings
    Write-Host Is Firefox Installed?
    $w64=Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object DisplayName -like '*Firefox*'
    $w32=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | where-Object DisplayName -like '*Firefox*'
    if ($w64 -or $w32)
    {
    Write-output "Firefox is already installed on your machine."
    }
    Else{
    Write-Output "Firefox is not installed on your machine." 
    Write-Output "Downloading Firefox"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "$downloads\firefox-latest.exe" -UseBasicParsing
    Write-Host "Installing Firefox"
    Start-Process -Wait -FilePath "$downloads\firefox-latest.exe"
    Remove-Item "$downloads\firefox-latest.exe"
}
   # Check if Firefox is Running, Stop Firefox if Running
    Write-Host "Is Firefox Running?"
    if((get-process "firefox" -ea SilentlyContinue) -eq $Null){ 
        echo "Not Running" 
    }
    else{ 
    echo "Running, Stopping Process"
    Stop-Process -processname "firefox"
        }
    # Tweak Firefox
	Write-Output "Setting Firefox as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Firefox-308046B0AF4A39CB"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
	
    Write-Host "Disabling Incognito"
    REG ADD HKLM\SOFTWARE\Policies\Mozilla\Firefox /v DisablePrivateBrowsing /t REG_DWORD /d 1
        }
    # Modify Microsoft Edge Settings
    Write-Host Is Microsoft Edge Installed?
    $DIR = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
    if (Test-Path -Path $DIR)
    {
    Write-output "Microsoft Edge is already installed on your machine."
    }
    Else{
    Write-Output "Microsoft Edge is not installed on your machine."
    Write-Output "Downloading Microsoft Edge"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en" -OutFile "$downloads\MicrosoftEdgeSetup.exe" -UseBasicParsing
    Write-Host "Installing Microsoft Edge"
    Start-Process -Wait -FilePath "$downloads\MicrosoftEdgeSetup.exe"
    Remove-Item "$downloads\MicrosoftEdgeSetup.exe"
   }
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
    Write-Output "Setting Microsoft Edge as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Microsoft Edge"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
	
    Write-Host "Disabling Guest Mode"
    REG ADD HKLM\SOFTWARE\Policies\Microsoft\Edge /v BrowserGuestModeEnabled /t REG_DWORD /d 0
    Write-Host "Disabling Add Profile"
    REG ADD HKLM\SOFTWARE\Policies\Microsoft\Edge /v BrowserAddProfileEnabled /t REG_DWORD /d 0
    Write-Host "Disabling Incognito"
    REG ADD HKLM\SOFTWARE\Policies\Microsoft\Edge /v InPrivateModeAvailability /t REG_DWORD /d 1
 
