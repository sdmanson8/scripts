#requires -version 5.1
#Requires -RunAsAdministrator

# Edit Member, Group, and username for MDM
# Ask for confirmation to Add User to Local Admin Group
    $MakeLocalAdmin = Read-Host "Would you like to Add User to Local Admin Group? (Y/N)"
    if ($MakeLocalAdmin -eq 'Y') { 
$user= Read-Host "Enter your Username 'Example: domain\user'"

Write-Host Adding Domain User to Local Admin group
Add-LocalGroupMember -Group "Administrators" -Member $user
}

#MDM Enrolment
Write-Host Starting Device Enrolment
Start-Process ms-device-enrollment:?mode=mdm"&"username=user@example.com

PAUSE
Write-Host "Opening Manage Bitlocker in Control Panel"
control /name Microsoft.BitLockerDriveEncryption

PAUSE
#Force Reboot Computer
Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/reboot_forced.bat" -OutFile "$env:SystemDrive\reboot_forced.bat"
cmd.exe /k "%SystemDrive%\reboot_forced.bat & del %SystemDrive%\reboot_forced.bat"
Start-Sleep -Milliseconds 400
