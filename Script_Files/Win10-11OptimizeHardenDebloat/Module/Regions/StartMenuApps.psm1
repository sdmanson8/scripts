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
		LogWarning ($Localization.CustomStartMenu, ($Localization.Skipped -f $MyInvocation.Line.Trim()) -join " ")

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			try
			{
				Write-Host "Hiding recently added apps on Start - " -NoNewline
				LogInfo "Hiding recently added apps on Start"
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowRecentList -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide recently added apps on Start: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			try
			{
				Write-Host "Showing recently added apps on Start - " -NoNewline
				LogInfo "Showing recently added apps on Start"
				Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowRecentList -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show recently added apps on Start: $($_.Exception.Message)"
			}
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
		LogWarning ($Localization.CustomStartMenu, ($Localization.Skipped -f $MyInvocation.Line.Trim()) -join " ")

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			try
			{
				Write-Host "Hiding most used apps on Start - " -NoNewline
				LogInfo "Hiding most used apps on Start"
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowFrequentList -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide most used apps on Start: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			try
			{
				Write-Host "Showing most used apps on Start - " -NoNewline
				LogInfo "Showing most used apps on Start"
				Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Start -Name ShowFrequentList -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show most used apps on Start: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	All section with categories in Start

	.PARAMETER Hide
	Remove the All section with categories in Start

	.PARAMETER Show
	Show the All section with categories in Start (default value)

	.EXAMPLE
	StartMenuAllSectionCategories -Hide

	.EXAMPLE
	StartMenuAllSectionCategories -Show

	.NOTES
	Current user
#>
function StartMenuAllSectionCategories
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

	$SupportedMessage = "Start menu All section categories is only supported on Windows 11 build 26200.7705 / 26H1 and newer. Skipping."

	if (-not (Test-Windows11BuildSupport -MinimumBuild 26200 -MinimumUBR 7705 -MinimumDisplayVersion '26H1'))
	{
		switch ($PSCmdlet.ParameterSetName)
		{
			"Hide"
			{
				Write-Host "Hiding the All section with categories in Start - " -NoNewline
				LogInfo "Hiding the All section with categories in Start"
			}
			"Show"
			{
				Write-Host "Showing the All section with categories in Start - " -NoNewline
				LogInfo "Showing the All section with categories in Start"
			}
		}

		Write-Host "success!" -ForegroundColor Green
		LogWarning $SupportedMessage
		return
	}

	if (Get-Process -Name Start11Srv, StartAllBackCfg, StartMenu -ErrorAction Ignore)
	{
		LogWarning ($Localization.CustomStartMenu, ($Localization.Skipped -f $MyInvocation.Line.Trim()) -join " ")

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			try
			{
				Write-Host "Hiding the All section with categories in Start - " -NoNewline
				LogInfo "Hiding the All section with categories in Start"
				Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoStartMenuMorePrograms -Type DWord -Value 1 | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide the All section with categories in Start: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			try
			{
				Write-Host "Showing the All section with categories in Start - " -NoNewline
				LogInfo "Showing the All section with categories in Start"
				Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoStartMenuMorePrograms -Type CLEAR | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the All section with categories in Start: $($_.Exception.Message)"
			}
		}
	}
}
#endregion Start Menu Apps
