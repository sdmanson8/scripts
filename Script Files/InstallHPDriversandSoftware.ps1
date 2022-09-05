#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Install HP Drivers and Software"

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
 echo "        Install HP Software and Drivers"
 echo ""
 echo ""  
 echo "    1. HP Driver Pack"
 echo "    2. HP Software Framework"
 echo "    3. HP Support Assistant"
 echo ""
 echo "    4. Install All of the Above"
 echo ""
 echo "    5. Previous Menu"
 echo ""
 echo "    6. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # HP Driver Pack
    Write-Host "Preparing to Download Drivers [Search for correct Laptop]"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/HP_Driverpack_Matrix_x64.html"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/HP_Driverpack_Matrix_x64.html"
Exit
}
    PAUSE
    Write-Host "Installing HP Drivers"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -Wait -FilePath "$downloads\sp*.exe"
    Remove-Item "$downloads\sp*.exe"
    Remove-Item $env:SystemRoot\SWSetup -Force -ErrorAction SilentlyContinue -Confirm:$false
}  
 if ($answer -eq 2){
    Clear-Host
    # HP Software Framework
    Write-Host "Downloading HP Software Framework"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/softpaq/CASLSetup.exe" -OutFile "$downloads\CASLSetup.exe" -UseBasicParsing
    Write-Host "Installing HP Software Framework"
    Start-Process -Wait -FilePath $downloads\CASLSetup.exe
    Remove-Item "$downloads\CASLSetup.exe" -Force -ErrorAction SilentlyContinue -Confirm:$false
 }  
 if ($answer -eq 3){
    Clear-Host
    # HP Support Assistant
    Write-Host "Preparing to Download HP Support Assistant"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "https://support.hp.com/us-en/help/hp-support-assistant"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "https://support.hp.com/us-en/help/hp-support-assistant"
}
    PAUSE
    Write-Host "Installing HP Support Assistant"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -Wait -FilePath "$downloads\sp*.exe"
    Remove-Item "$downloads\sp*.exe" -Force -ErrorAction SilentlyContinue -Confirm:$false
 }
  if ($answer -eq 4){
    Clear-Host
    # Install All of the Above
    Write-Output "Install All of the Above"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/HPSoftwareDrivers.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 5){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 6){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
