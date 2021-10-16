#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Install Required Domain Apps"

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
 echo "        Install Required Domain Apps"
 echo ""
 echo ""  
 echo "    1. Avaya Agent Desktop"
 echo "    2. Office 365 Work or School (Sign in to download Licensed version)"
 echo "    3. Install Avaya Workspace"
 echo "    4. Install Ninja"
 echo "    5. Install ESET"
 echo "    6. Install Seco VPN"
 echo "    7. Install Reflex Remote Support"
 echo ""
 echo "    8. Install All of the Above"
 echo ""
 echo "    9. Previous Menu"
 echo "" 
 echo "    10. exit" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  

# Ask for confirmation to Create a VPN Profile
    $ConnectVPNProfile = Read-Host "Would you like to Connect to a VPN Profile? (Y/N)"
    if ($ConnectVPNProfile -eq 'Y') { 
        $vpnname = Read-Host ""Enter the Configured VPN Name"" "WITHOUT "" "" ..."
        $vpnusername = Read-Host "Enter your Domain Username WITHOUT "" "" ..."
        $vpnpassword = Read-Host "Enter your Domain Password" -AsSecureString;
        $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($vpnpassword);
        $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            Write-Host Connecting to VPN configuration
            $vpn = Get-VpnConnection | where {$_.Name -eq "$vpnname"}
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname"" $vpnusername $password"
                Invoke-Expression -Command $expression 
            }
}

 if ($answer -eq 1){
    Clear-Host
    # Avaya Agent Desktop
    Write-Host Opening Webpage to Download Prerequisites
    Start-Process http://avaya-accs/agentdesktop/setup.exe
    PAUSE
    Write-Host "Installing Avaya Agent Prerequisites"
    Start-Process $env:USERPROFILE\Downloads\setup.exe
    PAUSE
    Remove-Item $env:USERPROFILE\Downloads\setup.exe
    Write-Host Opening Webpage to Download Avaya Agent Desktop
    Start-Process http://avaya-accs/agentdesktop/CCADClickOnce.application
 }  
 if ($answer -eq 2){
    Clear-Host
    # Office 365 Work or School (Sign in to download Licensed version)
    Write-Host "Opening Webpage to Download Office 365"
    Start-Process "https://aka.ms/office-install"
    Write-Host "Sign in and Select Install Office"
    PAUSE
    Write-Host "Installing Office 365"
    Start-Process $env:USERPROFILE\Downloads\OfficeSetup.exe
    PAUSE
    Remove-Item $env:USERPROFILE\Downloads\OfficeSetup.exe -Force 
 }  
 if ($answer -eq 3){
    Clear-Host
    # Install Avaya Workplace
    Write-Output "Installing Avaya Workplace"
    msiexec.exe /i '\\reflex.co.za\Shared\Company Folder\Avaya IX Workplace Setup 3.8.0.136.14.msi' 
 }
  if ($answer -eq 4){
    Clear-Host
    # Install Ninja
    Write-Output "Installing Ninja"
    msiexec.exe /i '\\reflex.co.za\Shared\Company Folder\BU - EUC\BU - Managed Services\#Software\#NINJA_INSTALLS\REFLEX\reflexsolutionsworkstationmainoffice-4.4.6012-windows-installer.msi'
 }
  if ($answer -eq 5){
    Clear-Host
    # Install ESET
    Write-Output "Installing ESET"
    Start-Process -Wait -FilePath '\\reflex.co.za\Shared\Company Folder\BU - EUC\BU - Managed Services\#Software\ESET\AIO_FOR_ALL_CLIENTS\_WORK_STATION_AIO_ALL_CLIENTS_x64_en_US.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 6){
    Clear-Host
    # Install Seco VPN
    Write-Output "Installing Seco VPN"
    Start-Process -Wait -FilePath '\\reflex.co.za\Shared\Company Folder\secoclient-win-64-7.0.5.1.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 7){
    Clear-Host
    # Install Reflex Remote Support
    Write-Output "Installing Reflex Remote Support"
    msiexec.exe /i '\\reflex.co.za\Shared\Company Folder\BU - EUC\BU - Managed Services\#Software\RS\Reflex Internal\Reflex_RS_PCs.msi'
 }
   if ($answer -eq 8){
    Clear-Host
    Write-Output "Installating All Required Software... Please Wait..."
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/DomainApps.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
   if ($answer -eq 9){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Setup%20and%20Configure%20for%20Domain%20Policies.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 10){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
