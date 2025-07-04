#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Windows 10/11 (After Clean Install) Tweaks"

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
 echo "    Windows 10/11 (After Clean Install) Tweaks"
 echo ""
 Write-Host "The following first 4 scripts have been slightly modified for my own personal use" -ForegroundColor Red
 Write-Host "Credit goes to the following sources:" -ForegroundColor Red
 Write-Host "1. https://github.com/Disassembler0/Win10-Initial-Setup-Script" -ForegroundColor Yellow
 Write-Host "2. https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6" -ForegroundColor Yellow
 Write-Host "3. https://github.com/farag2/Sophia-Script-for-Windows" -ForegroundColor Yellow
 echo ""
 echo ""
 echo ""   
 echo "    1. Optimizor, Hardening and Bloatware Removal Script for Windows 10 x64"
 echo "    2. New User Script Windows 10 x64"
 echo ""
 echo "    3. Optimizor, Hardening and Bloatware Removal Script for Windows 11 x64"
 echo "    4. New User Script Windows 11 x64"
 echo ""
 echo "    5. (Beginner) Remove Windows Bloatware by ChrisTitusTech"
 Write-Host "    https://github.com/ChrisTitusTech/winutil" -ForegroundColor Yellow
 echo "    6. (Beginner) SophiApp" 
 Write-Host "    https://github.com/Sophia-Community/SophiApp" -ForegroundColor Yellow
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
    # Optimizor, Hardening and Bloatware Removal Script for Windows 10
    Write-Output "Optimizor, Hardening and Bloatware Removal Script for Windows 10"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win10/Script.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
  if ($answer -eq 2){
    Clear-Host
    # New User Script Windows 10
    Write-Output "New User Script Windows 10"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win10/NewUserScript-Win10.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)   
 }
 if ($answer -eq 3){
    Clear-Host
    # Optimizor, Hardening and Bloatware Removal Script for Windows 11
    Write-Output "Optimizor, Hardening and Bloatware Removal Script for Windows 11"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win11/Script.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 4){
    Clear-Host
    # New User Script Windows 11
    Write-Output "New User Script Windows 11"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Win10-11OptimizeHardenDebloat/Win11/NewUserScript-Win11.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)   
 }  
 if ($answer -eq 5){
    Clear-Host
    # prompt to run (Beginner) Remove Windows Bloatware by ChrisTitusTech
    Write-Output "Running (Beginner) Remove Windows Bloatware by ChrisTitusTech"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/ChrisTitusTech/winutil/main/winutil.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)    
 }  
 if ($answer -eq 6){
    Clear-Host
    # prompt to run (Beginner) SophiApp
    Write-Output "Running (Beginner) SophiApp"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/Sophia-Community/SophiApp/master/Download_SophiApp.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)        
 }  
 if ($answer -eq 7){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 8){areyousure}  
       sleep 5 
       mainmenu  
                   }  
 mainmenu 
