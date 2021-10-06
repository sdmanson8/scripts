#requires -version 5.1
#Requires -RunAsAdministrator

# Edit Member, Group, and username for MDM

$user= Read-Host "Enter your Username 'Example: domain\user'"

Write-Host Adding Domain User to Local Admin group
Add-LocalGroupMember -Group "Administrators" -Member $user

PAUSE
#MDM Enrolment
Write-Host Starting Device Enrolment
Start-Process ms-device-enrollment:?mode=mdm"&"username=user@example.com}

PAUSE
Write-Host "Opening Manage Bitlocker in Control Panel"
control /name Microsoft.BitLockerDriveEncryption

PAUSE
Write-Host "Sign out of Current User Account in 5 seconds"
Start-Sleep -Seconds 5
#Sign Out of Local Admin Account
shutdown -l 
