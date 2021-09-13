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
Write-Host "Opening Manage Bitlocker in Control Panel"
control /name Microsoft.BitLockerDriveEncryption
