using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Start menu
<#
	.SYNOPSIS
	Configure Start layout

	.PARAMETER Default
	Show default Start layout

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
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_Layout -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"ShowMorePins"
		{
			Write-Host "Showing more pins on Start - " -NoNewline
			LogInfo "Showing more pins on Start"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_Layout -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"ShowMoreRecommendations"
		{
			Write-Host "Showing more recommendations on Start - " -NoNewline
			LogInfo "Showing more recommendations on Start"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_Layout -PropertyType DWord -Value 2 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion Start menu
