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
            }
            if ($vpn.ConnectionStatus -eq "Disconnected")
            {
                $cmd = $env:WINDIR + "\System32\rasdial.exe"
                $expression = "$cmd ""$vpnname"" sheldonm ccrse3a6ti"
                Invoke-Expression -Command $expression 
            }
} until ($response -eq 'n')
Write-Host Adding Domain User to Local Admin group
Add-LocalGroupMember -Group "Administrators" -Member "reflex\sheldonm"

PAUSE
$msg     = 'Do you want to do MDM Enrolment? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
            #MDM Enrolment
            Write-Host Starting Device Enrolment
            Start-Process ms-device-enrollment:?mode=mdm"&"username=sheldonm@reflex.co.za}
} until ($response -eq 'n')

PAUSE
Write-Host Enabling Bitlocker
Get-BitLockerVolume | Enable-BitLocker -EncryptionMethod Aes128 -RecoveryKeyPath "E:\" -RecoveryKeyProtector

PAUSE
Write-Host Encryption Progress
do 
{
    $Volume = Get-BitLockerVolume -MountPoint C:
    Write-Progress -Activity "Encrypting volume $($Volume.MountPoint)" -Status "Encryption Progress:" -PercentComplete $Volume.EncryptionPercentage
    Start-Sleep -Seconds 1
}
until ($Volume.VolumeStatus -eq 'FullyEncrypted')
Write-Progress -Activity "Encrypting volume $($Volume.MountPoint)" -Status "Encryption Progress:" -Completed

PAUSE
Write-Host Backing up Recovery Key to AD DS
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
$BLV = Get-BitLockerVolume -MountPoint "C:"
BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[0].KeyProtectorId
