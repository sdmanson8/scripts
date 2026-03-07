using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Start menu
<#
	.SYNOPSIS
	Configure Start layout

	.PARAMETER Default
	Show default Start layout (default value)

	.PARAMETER ShowMorePins
	Show more pins on Start

	.PARAMETER ShowMoreRecommendations
	Show more recommendations on Start

	.EXAMPLE
	StartLayout -Default

	.EXAMPLE
	StartLayout -ShowMorePins

	.EXAMPLE
	StartLayout -ShowMoreRecommendations

	.NOTES
	Current user
#>
function StartLayout
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "ShowMorePins"
		)]
		[switch]
		$ShowMorePins,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "ShowMoreRecommendations"
		)]
		[switch]
		$ShowMoreRecommendations
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Default"
		{
			Write-Host "Setting default Start layout - " -NoNewline
			LogInfo "Setting default Start layout"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_Layout -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set the default Start layout: $($_.Exception.Message)"
			}
		}
		"ShowMorePins"
		{
			Write-Host "Showing more pins on Start - " -NoNewline
			LogInfo "Showing more pins on Start"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_Layout -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show more pins on Start: $($_.Exception.Message)"
			}
		}
		"ShowMoreRecommendations"
		{
			Write-Host "Showing more recommendations on Start - " -NoNewline
			LogInfo "Showing more recommendations on Start"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_Layout -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show more recommendations on Start: $($_.Exception.Message)"
			}
		}
	}
}
#endregion Start menu
