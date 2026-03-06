using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Protection
# Create a restore point for the system drive
function CreateRestorePoint
{
	LogInfo "Creating Restore Point"
	#Clear-Host
	Write-Host "Creating System Restore Point - "-NoNewline
	$SystemDriveUniqueID = (Get-Volume | Where-Object -FilterScript {$_.DriveLetter -eq "$($env:SystemDrive[0])"}).UniqueID
	$SystemProtection = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients" -ErrorAction Ignore)."{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}") | Where-Object -FilterScript {$_ -match [regex]::Escape($SystemDriveUniqueID)}

	$Script:ComputerRestorePoint = $false

	if ($null -eq $SystemProtection)
	{
		$ComputerRestorePoint = $true
		Enable-ComputerRestore -Drive $env:SystemDrive
	}

	# Never skip creating a restore point
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 0 -Force | Out-Null

	# Get the OS version
	#$osVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
	$currentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

	# Determine if it's Windows 10 or 11 based on build number (Windows 11 builds start at 22000)
	if ([int]$currentBuild -ge 22000) {
		$osName = "Windows 11"
	} else {
		$osName = "Windows 10"
	}

	Checkpoint-Computer -Description "WinUtil Script for $osName" -RestorePointType MODIFY_SETTINGS | Out-Null

	# Revert the System Restore checkpoint creation frequency to 1440 minutes
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force | Out-Null

	# Turn off System Protection for the system drive if it was turned off before without deleting the existing restore points
	if ($Script:ComputerRestorePoint)
	{
		LogInfo "Disabling System Restore again"
		Disable-ComputerRestore -Drive $env:SystemDrive | Out-Null
	}
	Write-Host "success!" -ForegroundColor Green
}
#endregion Protection
