using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Start Menu Apps
<#
	.SYNOPSIS
	Recently added apps on Start

	.PARAMETER Hide
	Hide recently added apps on Start

	.PARAMETER Show
	Show recently added apps in Start (default value)

	.EXAMPLE
	RecentlyAddedStartApps -Hide

	.EXAMPLE
	RecentlyAddedStartApps -Show

	.NOTES
	Current user
#>
function RecentlyAddedStartApps
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show
	)

	# Remove all policies in order to make changes visible in UI
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -Type CLEAR | Out-Null

	if (Get-Process -Name Start11Srv, StartAllBackCfg, StartMenu -ErrorAction Ignore)
	{
		LogError ($Localization.CustomStartMenu, ($Localization.Skipped -f $MyInvocation.Line.Trim()) -join " ")

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Hiding recently added apps on Start - " -NoNewline
			LogInfo "Hiding recently added apps on Start"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowRecentList -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Showing recently added apps on Start - " -NoNewline
			LogInfo "Showing recently added apps on Start"
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowRecentList -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Most used apps in Start

	.PARAMETER Hide
	Hide most used Apps in Start (default value)

	.PARAMETER Show
	Show most used Apps in Start

	.EXAMPLE
	MostUsedStartApps -Hide

	.EXAMPLE
	MostUsedStartApps -Show

	.NOTES
	Current user
#>
function MostUsedStartApps
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show
	)

	# Remove all policies in order to make changes visible in UI
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name ShowOrHideMostUsedApps -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name ShowOrHideMostUsedApps -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name ShowOrHideMostUsedApps -Type CLEAR | Out-Null

	Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoStartMenuMFUprogramsList, NoInstrumentation -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoStartMenuMFUprogramsList -Type CLEAR | Out-Null
	Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoInstrumentation -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoStartMenuMFUprogramsList -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoInstrumentation -Type CLEAR | Out-Null

	if (Get-Process -Name Start11Srv, StartAllBackCfg, StartMenu -ErrorAction Ignore)
	{
		LogError ($Localization.CustomStartMenu, ($Localization.Skipped -f $MyInvocation.Line.Trim()) -join " ")

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Hiding most used apps on Start - " -NoNewline
			LogInfo "Hiding most used apps on Start"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowFrequentList -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Showing most used apps on Start - " -NoNewline
			LogInfo "Showing most used apps on Start"
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowFrequentList -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion Start Menu Apps
