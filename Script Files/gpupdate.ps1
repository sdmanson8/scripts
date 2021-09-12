while ($true)
        {
            $vpnname = "Reflex VPN"
            $address = "vpn.reflex.co.za"
            $vpnusername = "sheldonm"
            $vpnpassword = "ccrse3a6ti"

$msg     = 'Do you want to check if Domain VPN is connected? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
            Write-Host Connect to VPN configuration
            $vpn = Get-VpnConnection | where {$_.Name -eq "Reflex VPN"}
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname"" sheldonm ccrse3a6ti"
                Invoke-Expression -Command $expression 
            }
            PAUSE
            Write-Host Updating Domain Group Policy
            gpupdate /force /boot
      }
} until ($response -eq 'n')
}
