#requires -version 5.0
#Requires -RunAsAdministrator

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
 echo "    1. Update System and Install Required Apps"
 echo "    2. Setup Rclone and MergerFS (Systemd)"
 echo ""
 echo "    3. Previous Menu"
 echo ""
 echo "    4. exit" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # Update System and Install Required Apps
    Write-Output "Update System and Install Required Apps"
    wget -O - "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PrepLinuxForDocker.sh" | bash
 }  
  if ($answer -eq 2){
    Clear-Host
    # Setup Rclone and MergerFS (Systemd)
    Write-Output "Setup Rclone and MergerFS (Systemd)"
    wget -O - "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/ConfgureRclone_MergerFS.sh" | bash
 }  
 if ($answer -eq 3){
    Clear-Host
    # Previous Menu
    Write-Output "Previous Menu"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
}
 if ($answer -eq 4){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      } 
                }  
                
 mainmenu 
