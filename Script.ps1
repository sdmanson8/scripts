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
 cls  
 echo "---------------------------------------------------------"  
 echo "                     SCRIPT MENU"
 echo ""
 echo ""  
 echo "    1. Windows First Run (Clean Install) Script"
 echo "    2. Setup and configure for Domain Policies"
 echo "    3. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    clear
    # Windows First Run (Clean Install) Script
    Write-Output "Windows First Run (Clean Install) Script"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20First%20Run%20Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    clear
    # Setup and configure for Domain Policies
    Write-Output "Setup and configure for Domain Policies"
    $ScriptFromGithHub = Invoke-WebRequest https://
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 3){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  