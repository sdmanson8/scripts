#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Setup and Configure for Domain Policies"

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
 echo "        Setup and Configure for Domain Policies"
 echo ""
 echo ""  
 echo "    1. Configure/Connect to Domain VPN"
 echo "    2. Join Domain Network"
 echo "    3. Domain GPUpdate"
 echo "    4. MDM Enrolment"
 echo "    5. Install Required Domain Apps"
 echo ""
 echo "    6. Previous Menu"
 echo ""
 echo "    7. exit" 
 echo "" 
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
    # Configure/Connect to Domain VPN
    Write-Output "Downloading VPN Script File"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/vpn.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    Clear-Host
    # Join Domain Network
    Write-Output "Downloading JoinDomain Script File"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/join%20domain.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 3){
    Clear-Host
    # Domain GPUpdate
    Write-Output "Domain GPUpdate"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/gpupdate.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 4){
    Clear-Host
    # Setup and configure MDM
    Write-Output "Downloading MDMEnrolment Script File"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/MDM.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
   if ($answer -eq 5){
    Clear-Host
    # Install Required Domain Apps
    Write-Output "Install Required Domain Apps"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Install%20Required%20Domain%20Apps.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 6){
    # Previous Menu
    Clear-Host
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 7){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
