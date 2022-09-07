#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        #Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Main Script for Windows"

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
 echo "                     SCRIPT MENU"
 echo ""
 echo ""  
 echo "    1. Windows 10/11"
 echo "    2. Configure Linux to use Docker"
 echo ""
 echo "    3. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # Windows 10/11
    Write-Output "Windows 10/11"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    Clear-Host
    # Configure Linux to use Docker
    Write-Output "Configure Linux to use Docker"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/ConfigureLinuxForDocker.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
}
 if ($answer -eq 3){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      } 
                }  
                
 mainmenu  
