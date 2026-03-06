using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Explorer
<#
	.SYNOPSIS
	Restore previous folder windows at logon

	.PARAMETER Disable
	Do not restore previous folder windows at logon

	.PARAMETER Enable
	Restore previous folder windows at logon

	.EXAMPLE
	RestorePreviousFolders -Disable

	.EXAMPLE
	RestorePreviousFolders -Enable

	.NOTES
	Current user
#>
function RestorePreviousFolders
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling 'restore previous folder windows at logon' - " -NoNewline
			LogInfo "Disabling 'restore previous folder windows at logon'"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name PersistBrowsers -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling 'restore previous folder windows at logon' - " -NoNewline
			LogInfo "Enabling 'restore previous folder windows at logon'"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name PersistBrowsers -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion Explorer
