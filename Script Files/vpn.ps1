$msg     = 'Do you create a VPN Profile? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
            Write-Host Add VPN configuration
            Add-VpnConnection -Name "$vpnname" -ServerAddress "$address" -TunnelType PPTP -EncryptionLevel Required -RememberCredential -PassThru
        }
} until ($response -eq 'n')
PAUSE
        $vpnname = "Reflex VPN"
        $address = "vpn.reflex.co.za"
        $vpnusername = "sheldonm"
        $vpnpassword = "ccrse3a6ti"
            Write-Host Connecting to VPN configuration
            $vpn = Get-VpnConnection | where {$_.Name -eq "Reflex VPN"}
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname"" sheldonm ccrse3a6ti"
                Invoke-Expression -Command $expression 
            }
