 #Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                     }                   
#Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 clear  
 echo "---------------------------------------------------------"  
 echo "    WINDOWS FIRST RUN (CLEAN INSTALL) SCRIPT"
 echo ""
 echo ""  
 echo "    1. Run Windows Update"  
 echo "    2. Disable Windows Update"  
 echo "    3. Update Powershell"  
 echo "    4. Download PatchMyPC"
 echo "    5. Uninstall Microsoft Edge"
 echo "    6. (Moderate-Advanced) Sophia Script to Tweak Windows 10"
 echo "    7. (Moderate-Advanced) Sophia Script to Tweak Windows 11"
 echo "    8. (Moderate) Windows Optimization Script for Windows"
 echo "    9. (Moderate) Remove-Windows10-Bloat by matthewjberger"
 echo "    10. (Beginner) Remove Windows Bloatware by ChrisTitusTech"
 echo "    11. Cleanup Windows.Old folder"
 echo "    12. Restart Computer (RECOMMENDED IF CHANGES WERE MADE)"
 echo "    13. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    clear
    # prompt to run Windows Update
    Write-Output "Running Windows Update"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows%20Update.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    clear
    # prompt to Disable Windows Update
    Write-Output "Running Sledgehammer 2.7.2 (Disable Windows Update)"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Disable%20Windows%20Update.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 3){
    clear
    # prompt to update Powershell
    Write-Output "Updating Powershell"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Powershell.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 4){
    clear
    # prompt to download PatchMyPC
    Write-Output "Downloading PatchMyPC"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PatchMyPC.bat
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 5){
    clear
    # prompt to run Microsoft Edge Uninstaller
    Write-Output "Running Microsoft Edge Uninstaller"
    #Create a restore point
    powershell.exe -ExecutionPolicy Bypass -NoExit -Command "Checkpoint-Computer -Description 'Uninstall Microsoft Edge' -RestorePointType 'MODIFY_SETTINGS'"    
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Uninstall%20Edge.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 6){
    clear
    # prompt to run Sophia Script for Windows 10
    Write-Output "Running Sophia Script for Windows 10"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Sophia%20Script%20Windows%2010.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 } 
 if ($answer -eq 7){
    clear
    # prompt to run Sophia Script for Windows 11
    Write-Output "Running Sophia Script for Windows 11"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Sophia%20Script%20Windows%2011.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 8){
    clear
    # prompt to run Windows Optimization for Windows
    Write-Output "Running Windows Optimization for Windows"
    Write-Host Downloading Optimizer Script File
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Optimizer.bat -OutFile C:\Optimizer.bat
    Write-Host Setting Execution Policy to Unrestricted
    Set-ExecutionPolicy Unrestricted
    # Optimizer Script File
    PAUSE
    Write-Host Edit Optimizer Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\Optimizer.bat"
    PAUSE
    #Create a restore point
    powershell.exe -ExecutionPolicy Bypass -NoExit -Command "Checkpoint-Computer -Description 'Optimizer Script' -RestorePointType 'MODIFY_SETTINGS'"
    PAUSE
    Write-Host Running Optimizer Script
    Start-Process C:\Optimizer.bat
    PAUSE
    Write-Host Removing Leftover Files
    Remove-Item "C:\Optimizer.bat"
    Write-Host Restarting PC 
    #Force restart in 5 seconds
    shutdown /r /f /t 5 
 }  
 if ($answer -eq 9){
    clear
    # prompt to run Remove-Windows10-Bloat by matthewjberger
    Write-Output "Running Remove-Windows10-Bloat by matthewjberger"
    #Create a restore point
    powershell.exe -ExecutionPolicy Bypass -NoExit -Command "Checkpoint-Computer -Description 'Remove Bloatware' -RestorePointType 'MODIFY_SETTINGS'"    
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Remove-Windows10-Bloat.bat
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 10){
    clear
    # prompt to run (Beginner) Remove Windows Bloatware by ChrisTitusTech
    Write-Output "Running (Beginner) Remove Windows Bloatware by ChrisTitusTech"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/debloat.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 11){
    clear
    # prompt to Cleanup Windows.Old
    Write-Output "Cleanup Windows.Old"
    schtasks.exe /Run /TN  \Microsoft\Windows\Servicing\StartComponentCleanup
 }  
 if ($answer -eq 12){
    clear
    # prompt to reboot machine
    Write-Output "Restarting PC"
    shutdown -r -t 00
} 
 if ($answer -eq 13){areyousure}  
       sleep 5  
       mainmenu  
                   }  
 mainmenu 
