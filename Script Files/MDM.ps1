# Edit Member, Group, and username for MDM

Write-Host Adding Domain User to Local Admin group
Add-LocalGroupMember -Group "Administrators" -Member "example\user"

PAUSE
$msg     = 'Do you want to do MDM Enrolment? [Type Y/N]'
do {
            $response = Read-Host -Prompt $msg
            if ($response -eq 'y') {
            #MDM Enrolment
            Write-Host Starting Device Enrolment
            Start-Process ms-device-enrollment:?mode=mdm"&"username=user@example.com}
} until ($response -eq 'n')

PAUSE
Write-Host "Opening Manage Bitlocker in Control Panel"
control /name Microsoft.BitLockerDriveEncryption

PAUSE
Write-Host "Sign out of Current User Account in 5 seconds"
Start-Sleep -Seconds 5
#Sign Out of Local Admin Account
shutdown -l 
