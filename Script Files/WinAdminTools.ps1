#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Windows Admin Tools"

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
 echo "       WINDOWS ADMIN TOOLS"
 echo ""
 echo ""  
 echo "    1. Run Windows Update" 
 echo "    2. Disable Windows Update" 
 echo "    2. Cleanup Windows.Old folder"
 echo "    3. Cleanup Temporary Files"
 echo "    4. Reset the Windows Update Service"
 echo "    5. Uninstall Microsoft Edge" 
 echo ""
 echo "    6. Previous Menu"
 echo ""
 echo "    7. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # prompt to run Windows Update
    Write-Output "Running Windows Update"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20Update.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
  if ($answer -eq 2){
    Clear-Host
    # prompt to Disable Windows Update
    Write-Output "Running Sledgehammer 2.7.2 (Disable Windows Update)"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Disable%20Windows%20Update.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 3){
    Clear-Host
    # prompt to Cleanup Windows.Old
    Write-Output "Cleanup Windows.Old"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/WindowsOld.bat -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)  
 }  
  if ($answer -eq 4){
    Clear-Host
    # prompt to Cleanup Temporary Files
    Write-Output "Cleanup Temporary Files"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/CleanTempFiles.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)  
 } 
  if ($answer -eq 5){
    Clear-Host
    # prompt to run Microsoft Edge Uninstaller
    Write-Output "Running Microsoft Edge Uninstaller"  
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Uninstall%20Edge.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
   if ($answer -eq 6){
    Clear-Host
    # prompt to Reset the Windows Update Service
    Write-Output "Reset the Windows Update Service"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/ResetWinUpdates.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)  
 } 

 if ($answer -eq 7){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 7){areyousure}  
       sleep 5  
       mainmenu  
                   }  
 mainmenu 
