#requires -version 5.1
#Calling Powershell as Admin and setting Execution Policy to Bypass to avoid Cannot run Scripts error
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
#Is Powershell 7 Installed
  $w64=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
  $w32=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
if ($w64 -or $w32)
{
  Start-Process pwsh.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
# Check if Windows Terminal is Running, Stop Windows Terminal if Running
    if((get-process "WindowsTerminal" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "WindowsTerminal"
        }
# Check if CMD is Running, Stop CMD if Running
    if((get-process "cmd" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "cmd"
        }
# Check if Powershell is Running, Stop Powershell if Running
    if((get-process "powershell" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "powershell"
        }
# Check if Powershell 7 is Running, Stop Powershell 7 if Running
    if((get-process "pwsh" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "pwsh"
        }
}
Else{
  Start-Process powershell -Verb runAs -ArgumentList ("&'" +$myinvocation.mycommand.definition + "'")
# Check if Windows Terminal is Running, Stop Windows Terminal if Running
    if((get-process "WindowsTerminal" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "WindowsTerminal"
        }
# Check if CMD is Running, Stop CMD if Running
    if((get-process "cmd" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "cmd"
        }
# Check if Powershell is Running, Stop Powershell if Running
    if((get-process "powershell" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else{ 
    Stop-Process -processname "powershell"
        }
  Break
    }
}

Clear-Host
#Requires -RunAsAdministrator

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

# Edit VPN Name, Address, Username, Password
            $vpnname = "VPN"
            $address = "vpn.example.com"
            $vpnusername = "username"
            $vpnpassword = "password"

# Ask for confirmation to Connect to a VPN Profile
    $ConnectVPNProfile = Read-Host "Would you like to Connect to a VPN Profile? (Y/N)"
    if ($ConnectVPNProfile -eq 'Y') { 
            $vpn = Get-VpnConnection | where {$_.Name -eq "$vpnname"}
            }
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "e\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname"" $vpnusername $vpnpassword"
                Invoke-Expression -Command $expression 
            }

 if ($answer -eq 1){
    Clear-Host
    # Configure/Connect to Domain VPN
    Remove-Item "C:\vpn.ps1"
    Write-Output "Downloading VPN Script File"
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/vpn.ps1 -OutFile C:\vpn.ps1
    # VPN Script File
    PAUSE
    Write-Host Edit VPN Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\vpn.ps1"
    PAUSE
    Write-Host Running VPN Script
    Clear-Host
    & C:\vpn.ps1
    PAUSE
    Write-Host Removing Leftover Files
    Remove-Item "C:\vpn.ps1"
 }  
 if ($answer -eq 2){
    Clear-Host
    # Join Domain Network
    Remove-Item "C:\joindomain.ps1"
    Write-Output "Downloading JoinDomain Script File"
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/join%20domain.ps1 -OutFile C:\joindomain.ps1
    # JoinDomain Script File
    PAUSE
    Write-Host Edit JoinDomain Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\joindomain.ps1"
    PAUSE
    Write-Host Running JoinDomain Script
    Clear-Host
    & C:\joindomain.ps1
    PAUSE
    Write-Host Removing Leftover Files
    Remove-Item "C:\joindomain.ps1"
 }  
 if ($answer -eq 3){
    Clear-Host
    # Domain GPUpdate
    Write-Output "Domain GPUpdate"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/gpupdate.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 4){
    Clear-Host
    Remove-Item "C:\MDMEnrolment.ps1"
    Clear-Host
    # Setup and configure MDM
    Write-Output "Downloading MDMEnrolment Script File"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/MDM.ps1" -OutFile C:\MDMEnrolment.ps1
    # MDMEnrolment Script File
    PAUSE
    Write-Host Edit MDMEnrolment Script File
    & "C:\Program Files\Notepad++\notepad++.exe" "C:\MDMEnrolment.ps1"
    PAUSE
    Write-Host Running MDMEnrolment Script
    Clear-Host
    & C:\MDMEnrolment.ps1
    PAUSE
    Write-Host Removing Leftover Files
    Remove-Item "C:\MDMEnrolment.ps1"
 }
   if ($answer -eq 5){
    Clear-Host
    # Install Required Domain Apps
    Write-Output "Install Required Domain Apps"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Install%20Required%20Domain%20Apps.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
  if ($answer -eq 6){
    # Previous Menu
    Clear-Host
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 7){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
