#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Windows First Run Script"

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
 echo "    WINDOWS FIRST RUN (CLEAN INSTALL) SCRIPT"
 echo ""
 echo ""  
 echo "    1. Run Windows Update"  
 echo "    2. Disable Windows Update"  
 echo "    3. Update Powershell"  
 echo "    4. Download PatchMyPC"
 echo "    5. Uninstall Microsoft Edge"
 echo "    6. Optimizor, Hardening and Bloatware Removal Script for Windows 10"
 echo "    7. New User Script Windows 10"
 echo "    8. Optimizor, Hardening and Bloatware Removal Script for Windows 11"
 echo "    9. New User Script Windows 11"
 echo "    10. (Beginner) Remove Windows Bloatware by ChrisTitusTech"
 echo "    11. Cleanup Windows.Old folder"
 echo "    12. Restart Computer (RECOMMENDED IF CHANGES WERE MADE)"
 echo ""
 echo "    13. Previous Menu"
 echo ""
 echo "    14. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # prompt to run Windows Update
    Write-Output "Running Windows Update"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20Update.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    Clear-Host
    # prompt to Disable Windows Update
    Write-Output "Running Sledgehammer 2.7.2 (Disable Windows Update)"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Disable%20Windows%20Update.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 3){
    Clear-Host
    # prompt to update Powershell
    Write-Host "Preparing to Update Powershell ... Please wait..."
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
 }  
 if ($answer -eq 4){
    Clear-Host
    # prompt to download PatchMyPC
    Write-Output "Downloading PatchMyPC"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PatchMyPC.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 5){
    Clear-Host
    # prompt to run Microsoft Edge Uninstaller
    Write-Output "Running Microsoft Edge Uninstaller"  
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Uninstall%20Edge.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 6){
    Clear-Host
    # Optimizor, Hardening and Bloatware Removal Script for Windows 10
    Write-Output "Optimizor, Hardening and Bloatware Removal Script for Windows 10"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win10/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
  if ($answer -eq 7){
    Clear-Host
    # New User Script Windows 10
    Write-Output "New User Script Windows 10"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win10/NewUserScript-Win10.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)   
 }
 if ($answer -eq 8){
    Clear-Host
    # Optimizor, Hardening and Bloatware Removal Script for Windows 11
    Write-Output "Optimizor, Hardening and Bloatware Removal Script for Windows 11"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win11/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 9){
    Clear-Host
    # New User Script Windows 11
    Write-Output "New User Script Windows 11"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win11/NewUserScript-Win11.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)   
 }  
 if ($answer -eq 10){
    Clear-Host
    # prompt to run (Beginner) Remove Windows Bloatware by ChrisTitusTech
    Write-Output "Running (Beginner) Remove Windows Bloatware by ChrisTitusTech"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/debloat.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)   
 }  
 if ($answer -eq 11){
    Clear-Host
    # prompt to Cleanup Windows.Old
    Write-Output "Cleanup Windows.Old"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/WindowsOld.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)  
 }  
 if ($answer -eq 12){
    Clear-Host
    # prompt to reboot machine
    Write-Output "Restarting PC"
    shutdown -r -t 00
} 
 if ($answer -eq 13){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 14){areyousure}  
       sleep 5 
       mainmenu  
                   }  
 mainmenu 
