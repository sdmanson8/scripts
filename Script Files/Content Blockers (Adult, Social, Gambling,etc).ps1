#requires -version 5.1
#Calling Powershell as Admin and setting Execution Policy to Bypass to avoid Cannot run Scripts error
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
#Is Powershell 7 Installed
  $w64=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
  $w32=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
if ($w64 -or $w32)
{
  Start-Process pwsh.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
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
# Check if Powershell 7 is Running, Stop Powershell 7 if Running
    if((get-process "pwsh" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "pwsh"
        }
}
Else{
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
}

Clear-Host
#Requires -RunAsAdministrator

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
    Write-Host Opening Webpage to Download Cold Turkey Blocker
    Start-Process "https://getcoldturkey.com/download/win/"
    PAUSE
    Write-Host "Installing Cold Turkey Blocker"
    Start-Process $env:USERPROFILE\Downloads\Cold_Turkey_Installer.exe
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item $env:USERPROFILE\Downloads\Cold_Turkey_Installer.exe
 }  
 if ($answer -eq 2){
    Clear-Host
    # Install Truple
    Write-Host "Opening Webpage to Download Truple"
    Start-Process "https://support.truple.io/articles/windows/windows-setup-guide"
    PAUSE
    Write-Host "Installing Truple"
    Start-Process $env:USERPROFILE\Downloads\truple*
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item $env:USERPROFILE\Downloads\truple*
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
    Write-Host "Opening Webpage to Download CleanBrowsing"
    Start-Process "https://cleanbrowsing.org/guides/windows/"
    PAUSE
    Write-Host "Installing CleanBrowsing"
    Start-Process $env:USERPROFILE\Downloads\CleanBrowsing*
    PAUSE
    Write-Host "Removing Setup File"
    Remove-Item $env:USERPROFILE\Downloads\CleanBrowsing*
 }
  if ($answer -eq 5){
    Clear-Host
    # Add Safe Search to Hosts File
    Write-Output "Adding Safe Search Value to Hosts File"
    Add-Content C:\Windows\System32\drivers\etc\hosts "216.239.38.120 www.google.com         #forcesafesearch"
 }
    if ($answer -eq 6){
    Clear-Host
    # Complete All of the Above
    Write-Output "Installating Blocker Software AIO"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Installations%20(Blockers).ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 7){
    # Modify Browser Settings (Filtering)
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/BrowserSettings.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
 if ($answer -eq 8){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
 if ($answer -eq 9){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
