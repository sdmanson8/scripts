using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Protection
<#
	.SYNOPSIS
	Create a restore point for the system drive before changes are applied.

	.DESCRIPTION
	Ensures System Restore is available on the system drive, temporarily allows
	immediate restore point creation, creates a restore point named for the
	current Windows version, and restores the prior System Restore state.

	.EXAMPLE
	CreateRestorePoint

	.NOTES
	Machine-wide
#>
function CreateRestorePoint
{
	LogInfo "Creating Restore Point"
	#Clear-Host
	Write-Host "Creating System Restore Point - "-NoNewline
	try
	{
		$SystemDriveUniqueID = (Get-Volume | Where-Object -FilterScript {$_.DriveLetter -eq "$($env:SystemDrive[0])"}).UniqueID
		$SystemProtection = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients" -ErrorAction Ignore)."{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}") | Where-Object -FilterScript {$_ -match [regex]::Escape($SystemDriveUniqueID)}

		$Script:ComputerRestorePoint = $false

		if ($null -eq $SystemProtection)
		{
			$ComputerRestorePoint = $true
			Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
		}

		# Never skip creating a restore point
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null

		$osName = (Get-OSInfo).OSName

		Checkpoint-Computer -Description "WinUtil Script for $osName" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop | Out-Null

		# Revert the System Restore checkpoint creation frequency to 1440 minutes
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force -ErrorAction Stop | Out-Null

		# Turn off System Protection for the system drive if it was turned off before without deleting the existing restore points
		if ($Script:ComputerRestorePoint)
		{
			LogInfo "Disabling System Restore again"
			Disable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop | Out-Null
		}
		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to create a restore point: $($_.Exception.Message)"
	}
}
#endregion Protection
