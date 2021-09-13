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
 echo "    1. Configure/Connect to Domain VPN"
 echo "    2. Join Domain Network"
 echo "    3. Domain GPUpdate"
 echo "    4. MDM Enrolment"
 echo "    5. Install Required Domain Apps"
 echo "    6. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
$answer = read-host "Please Make a Selection"  
            $vpnname = "VPN"
            $address = "vpn.example.com"
            $vpnusername = "username"
            $vpnpassword = "password"

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
    # Configure/Connect to Domain VPN
    Write-Output "Configure/Connect to Domain VPN"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/vpn.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 2){
    clear
    # Join Domain Network
    Write-Output "Join Domain Network"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/join%20domain.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
 if ($answer -eq 3){
    clear
    # Domain GPUpdate
    Write-Output "Domain GPUpdate"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/gpupdate.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 4){
    clear
    # MDM Enrolment
    Write-Output "MDM Enrolment"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/MDM.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
   if ($answer -eq 5){
    clear
    # Install Required Domain Apps
    Write-Output "Install Required Domain Apps"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Install%20Required%20Domain%20Apps.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 6){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
