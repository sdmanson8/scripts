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
 echo "    1. Windows First Run (Clean Install) Script"
 echo "    2. Setup and configure for Domain Policies"
 echo "    3. Content Blockers (Adult, Social, Gambling,etc)"
 echo ""
 echo "    4. Install Other Software"
 echo ""
 echo "    5. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # Windows First Run (Clean Install) Script
    Write-Output "Windows First Run (Clean Install) Script"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20First%20Run%20Script.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    Clear-Host
    Remove-Item "C:\ConfigureDomainPolicies.ps1"
    # Setup and configure for Domain Policies
    Write-Output "Downloading ConfigureDomainPolicies Script File"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Setup%20and%20Configure%20for%20Domain%20Policies.ps1" -OutFile C:\ConfigureDomainPolicies.ps1
    # ConfigureDomainPolicies Script File
    PAUSE
    Write-Host Edit ConfigureDomainPolicies Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\ConfigureDomainPolicies.ps1"
    PAUSE
    Write-Host Running ConfigureDomainPolicies Script
    Clear-Host
    & C:\ConfigureDomainPolicies.ps1
    PAUSE
    Write-Host Removing Leftover Files
    Remove-Item "C:\ConfigureDomainPolicies.ps1"
 }  
  if ($answer -eq 3){
    Clear-Host
    # "Content Blockers (Adult, Social, Gambling,etc)"
    Write-Output "Content Blockers (Adult, Social, Gambling,etc)"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Content%20Blockers%20(Adult%2C%20Social%2C%20Gambling%2Cetc).ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
}
   if ($answer -eq 4){
    Clear-Host
    # "Install Other Software"
    Write-Output "Install Other Software"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Install%20Other%20Software.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 5){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
