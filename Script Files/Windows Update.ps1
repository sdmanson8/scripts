# Run PSWindowsUpdate

Write-Host Install PSWindowsUpdate module
Install-Module -Name PSWindowsUpdate
Import-Module -Name PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate

Write-Host List Available Windows Updates
Get-WindowsUpdate

#Install all available Updates & Reboot if Required
Write-Host Install Windows Updates
Install-WindowsUpdate -AcceptAll -AutoReboot