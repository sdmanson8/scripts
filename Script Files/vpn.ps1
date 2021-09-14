Clear-Host
$msg     = 'Do you create a VPN Profile? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
            Write-Host Add VPN configuration
            Add-VpnConnection -Name "$vpnname" -ServerAddress "$address" -TunnelType PPTP -EncryptionLevel Required -RememberCredential -PassThru
        }
} until ($response -eq 'n')
PAUSE

# Edit VPN Name, Address, Username, Password

        $vpnname = "VPN"
        $address = "vpn.example.com"
        $vpnusername = "password"
        $vpnpassword = "password"
            Write-Host Connecting to VPN configuration
            $vpn = Get-VpnConnection | where {$_.Name -eq "$vpnname"}
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname""  $vpnusername $vpnpassword"
                Invoke-Expression -Command $expression 
            }
