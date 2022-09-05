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
 echo "    3. Cleanup Windows.Old folder"
 echo "    4. Cleanup Temporary Files"
 echo "    5. Reset the Windows Update Service"
 echo "    6. Uninstall Microsoft Edge" 
 echo "	   7. Make Google Chrome the default Browser"
 echo "	   8. Make Firefox the default Browser"
 echo "	   9. Make Microsoft Edge the default Browser"
 echo ""
 echo "    10. Previous Menu"
 echo ""
 echo "    11. exit" 
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
    Clear-Host
    # prompt to Make Google Chrome the default Browser
    Write-Output "Setting Google Chrome to be the default Browser"
    Write-Output "Setting Chrome as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Google Chrome"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
 } 
    if ($answer -eq 8){
    Clear-Host
    # prompt to Make Firefox the default Browser
    Write-Output "Setting Firefox to be the default Browser"
	Write-Output "Setting Firefox as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Firefox-308046B0AF4A39CB"
    Remove-Item "$downloads\SetDefaultBrowser.exe" 
 } 
    if ($answer -eq 9){
    Clear-Host
    # prompt to Make Microsoft Edge the default Browser
    Write-Output "Setting Microsoft Edge to be the default Browser"
    Write-Output "Setting Microsoft Edge as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Microsoft Edge"
    Remove-Item "$downloads\SetDefaultBrowser.exe" 
 } 
 if ($answer -eq 10){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 11){areyousure}  
       sleep 5  
       mainmenu  
                   }  
 mainmenu 
