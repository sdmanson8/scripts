#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Configure VPN"

########################### Script Starting ###################################
###############################################################################

Clear-Host

# Ask for confirmation to Create a VPN Profile
    $CreateVPNProfile = Read-Host "Would you like to Create a VPN Profile? (Y/N)"
    if ($CreateVPNProfile -eq 'Y') { 
# Edit VPN Name, Address, Username, Password
        $vpnname = Read-Host "Enter the VPN Name 'Example: VPN' WITHOUT "" "" ..."
        $address = Read-Host "Enter the VPN Server Address 'Example: vpn.example.com' WITHOUT "" "" ..."
        Write-Host Add VPN configuration
        Add-VpnConnection -Name "$vpnname" -ServerAddress "$address" -TunnelType Pptp -EncryptionLevel Required -RememberCredential -PassThru
            }

# Edit VPN Name, Address, Username, Password
        $vpnname = Read-Host ""Enter the VPN Name"" "WITHOUT "" "" ..."
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

