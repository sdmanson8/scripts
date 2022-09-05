#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Content Blockers (Adult, Social, Gambling,etc)"

########################### Script Starting ###################################
###############################################################################

Clear-Host

#Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                                } 
  #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 Clear-Host  
 echo "---------------------------------------------------------"  
 echo "     Content Blockers (Adult, Social, Gambling,etc)"
 echo ""
 echo ""  
 echo "    1. Install Cold Turkey Blocker"
 echo "    2. Install Truple"
 echo "    3. Install Qustodio"
 echo "    4. Install CleanBrowsing"
 echo "    5. Add Safe Search to Hosts File" 
 echo ""
 echo "    6. Complete All of the Above" 
 echo ""
 echo "    7. Modify Browser Settings (Filtering)"
 echo ""
 echo "    8. Previous Menu"
 echo ""
 echo "    9. exit"
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  

 if ($answer -eq 1){
    Clear-Host
    # Install Cold Turkey Blocker
    Write-Host Preparing to Download Cold Turkey Blocker
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "https://getcoldturkey.com/download/win/"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "https://getcoldturkey.com/download/win/"
}
function Pause{ $null = Read-Host 'Press Enter if Application downloaded' }
	Pause
    Write-Host "Installing Cold Turkey Blocker"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process $downloads\Cold_Turkey_Installer.exe
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item $downloads\Cold_Turkey_Installer.exe
 }  
 if ($answer -eq 2){
    Clear-Host
    # Install Truple
    Write-Host "Preparing to Download Truple"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "https://support.truple.io/articles/windows/windows-setup-guide"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "https://support.truple.io/articles/windows/windows-setup-guide"
}
function Pause{ $null = Read-Host 'Press Enter if Application downloaded' }
	Pause
    Write-Host "Installing Truple"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process $downloads\truple*
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item $downloads\truple*
 }  
 if ($answer -eq 3){
    Clear-Host
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
}
  if ($answer -eq 4){
    Clear-Host
    # Install CleanBrowsing
    Write-Host "Preparing to Download CleanBrowsing"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "https://cleanbrowsing.org/guides/windows/"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "https://cleanbrowsing.org/guides/windows/"
}
function Pause{ $null = Read-Host 'Press Enter if Application downloaded' }
	Pause
    Write-Host "Installing CleanBrowsing"
    Start-Process $downloads\CleanBrowsing*
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item $downloads\CleanBrowsing*
 }
  if ($answer -eq 5){
    Clear-Host
    # Add Safe Search to Hosts File
    Write-Output "Adding Safe Search Value to Hosts File"
    Add-Content $env:WINDIR\System32\drivers\etc\hosts "216.239.38.120 www.google.com         #forcesafesearch"
 }
    if ($answer -eq 6){
    Clear-Host
    # Complete All of the Above
    Write-Output "Installating Blocker Software AIO"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Installations%20(Blockers).ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 7){
    # Modify Browser Settings (Filtering)
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/BrowserSettings.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
 if ($answer -eq 8){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
 if ($answer -eq 9){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
