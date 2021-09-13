 #Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                                } 
  #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 clear  
 echo "---------------------------------------------------------"  
 echo "        Setup and Configure for Domain Policies"
 echo ""
 echo ""  
 echo "    1. Avaya Agent Desktop"
 echo "    2. Office 365 (Unlicensed)"
 echo "    3. Install Avaya Workspace"
 echo "    4. Install Ninja"
 echo "    5. Install ESET"
 echo "    6. Install FortiClient VPN"
 echo "    7. Install Reflex Remote Support"
 echo "    8. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
            $vpnname = "Reflex VPN"
            $address = "vpn.reflex.co.za"
            $vpnusername = "sheldonm"
            $vpnpassword = "ccrse3a6ti"

$msg     = 'Do you want to check if Domain VPN is connected? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
            Write-Host Connect to VPN configuration
            $vpn = Get-VpnConnection | where {$_.Name -eq "$vpnname"}
            }
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname"" $vpnusername $vpnpassword"
                Invoke-Expression -Command $expression 
            }
} until ($response -eq 'n')

 if ($answer -eq 1){
    clear
    # Avaya Agent Desktop
	Write-Host Opening Webpage to Download Prerequisites
	Start-Process http://avaya-accs/agentdesktop/setup.exe
    PAUSE
    Write-Host Opening Webpage to Download Avaya Agent Desktop
    Start-Process http://avaya-accs/agentdesktop/CCADClickOnce.application
 }  
 if ($answer -eq 2){
    clear
    # Office 365 (Unlicensed)
    Write-Output "Opening Webpage to Download Office 365 (Unlicensed)"
    Start-Process https://c2rsetup.officeapps.live.com/c2r/download.aspx?productReleaseID=O365ProPlusRetail&platform=X64&language=en-us&TaxRegion=db&correlationId=738b3e5c-6a37-4a2b-8f20-3cdd08477dd8&token=0d16b52a-7f7c-4147-8e28-50e755b1eb69&version=O16GA&source=O15OLSO365&Br=2
 }  
 if ($answer -eq 3){
    clear
    # Install Avaya Workplace
    Write-Output "Install Avaya Workplace"
    Start-Process -Wait -FilePath 'Z:\Avaya IX Workplace Setup 3.8.0.136.14.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 4){
    clear
    # Install Ninja
    Write-Output "Install Ninja"
    Start-Process -Wait -FilePath 'Z:\BU - EUC\BU - Managed Services\#Software\#NINJA_INSTALLS\REFLEX\reflexsolutionsworkstationmainoffice-4.4.6012-windows-installer.msi' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 5){
    clear
    # Install ESET
    Write-Output "Install ESET"
    Start-Process -Wait -FilePath 'Z:\BU - EUC\BU - Managed Services\#Software\ESET\AIO_FOR_ALL_CLIENTS\_WORK_STATION_AIO_ALL_CLIENTS_x64_en_US.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 6){
    clear
    # Install FortiClient VPN
    Write-Output "Install FortiClient VPN"
    Start-Process -Wait -FilePath 'Z:\BU - EUC\BU - Managed Services\#Software\Fortinet\FortiClientVPNOnlineInstaller_6.2.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 7){
    clear
    # Install Reflex Remote Support
    Write-Output "Install Reflex Remote Support"
    Start-Process -Wait -FilePath 'Z:\BU - EUC\BU - Managed Services\#Software\RS\Reflex Internal\Reflex_RS_PCs.msi' -ArgumentList '/S' -PassThru
 }
 if ($answer -eq 8){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  