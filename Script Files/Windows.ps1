#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Windows Main Script"

########################### Script Starting ###################################
###############################################################################

Clear-Host

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 0 /f

 #Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
           else {write-host -foregroundcolor red "Invalid Selection"    
                 areyousure  
                }  
                     } 
 
 #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 clear  
 echo "---------------------------------------------------------"  
 echo "                     WINDOWS SCRIPT MENU"
 echo ""
 echo ""  
 echo "    1. Windows First Run (Post Clean Install) Tweaks"
 echo "    2. Setup and configure for Domain Policies"
 echo "    3. Content Blockers (Adult, Social, Gambling,etc)"
 echo "    4. Install HP Software + Drivers"
 echo "    5. Software"
 echo "    6. Windows 10/11 Admin Tools"
 echo ""
 echo "    7. Previous Menu"
 echo ""
 echo "    8. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  

if ($answer -eq 1){
    Clear-Host
    # Windows First Run (Post Clean Install) Tweaks
    Write-Output "Windows First Run (Post Clean Install) Tweaks"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20First%20Run%20Script.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    Clear-Host
    # Setup and configure for Domain Policies
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Setup%20and%20Configure%20for%20Domain%20Policies.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
  if ($answer -eq 3){
    Clear-Host
    # "Content Blockers (Adult, Social, Gambling,etc)"
    Write-Output "Content Blockers (Adult, Social, Gambling,etc)"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Content%20Blockers%20(Adult%2C%20Social%2C%20Gambling%2Cetc).ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
}
   if ($answer -eq 4){
    Clear-Host
    # "Install HP Software and Drivers"
    Write-Output "Install HP Software and Drivers"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/InstallHPDriversandSoftware.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
   if ($answer -eq 5){
    Clear-Host
    # Software
    Write-Output "Software"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Software.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
}
   if ($answer -eq 6){
    Clear-Host
    # Windows 10/11 Admin Tools
    Write-Output "Windows 10/11 Admin Tools"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/WinAdminTools.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
}
  if ($answer -eq 7){
    Clear-Host
    # Previous Menu
    Write-Output "Previous Menu"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
}
 if ($answer -eq 8){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
