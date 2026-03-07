using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Taskbar Clock
<#
	.SYNOPSIS
	Seconds on the taskbar clock

	.PARAMETER Show
	Show seconds on the taskbar clock

	.PARAMETER Hide
	Hide seconds on the taskbar clock (default value)

	.EXAMPLE
	SecondsInSystemClock -Show

	.EXAMPLE
	SecondsInSystemClock -Hide

	.NOTES
	Current user
#>
function SecondsInSystemClock
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Show"
		{
			try
			{
				Write-Host "Showing seconds on the taskbar clock - " -NoNewline
				LogInfo "Showing seconds on the taskbar clock"
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show seconds on the taskbar clock: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			try
			{
				Write-Host "Hiding seconds on the taskbar clock - " -NoNewline
				LogInfo "Hiding seconds on the taskbar clock"
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide seconds on the taskbar clock: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Time in Notification Center

	.PARAMETER Show
	Show time in Notification Center

	.PARAMETER Hide
	Hide time in Notification Center (default value)

	.EXAMPLE
	ClockInNotificationCenter -Show

	.EXAMPLE
	ClockInNotificationCenter -Hide

	.NOTES
	Current user
#>
function ClockInNotificationCenter
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Show"
		{
			try
			{
				Write-Host "Showing time in Notification Center - " -NoNewline
				LogInfo "Showing time in Notification Center"
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowClockInNotificationCenter -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show time in Notification Center: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			try
			{
				Write-Host "Hiding time in Notification Center - " -NoNewline
				LogInfo "Hiding time in Notification Center"
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowClockInNotificationCenter -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide time in Notification Center: $($_.Exception.Message)"
			}
		}
	}
}
#endregion Taskbar Clock
