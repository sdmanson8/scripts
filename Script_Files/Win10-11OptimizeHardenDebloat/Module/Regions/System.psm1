using module ..\Logging.psm1
using module ..\Helpers.psm1

#region System
<#
	.SYNOPSIS
	Enable or disable the Windows lock screen

	.PARAMETER Enable
	Enable the Windows lock screen (default value)

	.PARAMETER Disable
	Disable the Windows lock screen

	.EXAMPLE
	LockScreen -Enable

	.EXAMPLE
	LockScreen -Disable

	.NOTES
	Current user
#>
function LockScreen
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	$OS = (Get-CimInstance Win32_OperatingSystem).Caption

	if ($OS -notlike "*Windows 11*")
	{
		#LogInfo "LockScreen skipped - Not Windows 11"
		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling the Windows lockscreen"
			LogInfo "Enabling the Windows lockscreen"
			try
			{
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable the Windows lock screen: $($_.Exception.Message)"
			}
		}

		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling the Windows lockscreen"
			LogInfo "Disabling the Windows lockscreen"

			try
			{
				if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"))
				{
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable the Windows lock screen: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Enable or disable the Windows 10 RS1-style lock screen task workaround.

	.DESCRIPTION
	On supported Windows 10 systems, registers or removes the scheduled task
	workaround used by this preset to keep the lock screen disabled.

	.PARAMETER Enable
	Enable the Windows lock screen on supported Windows 10 systems.

	.PARAMETER Disable
	Disable the Windows lock screen on supported Windows 10 systems.

	.EXAMPLE
	LockScreenRS1 -Enable

	.EXAMPLE
	LockScreenRS1 -Disable

	.NOTES
	Machine-wide
#>
function LockScreenRS1
{
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	$OS = (Get-CimInstance Win32_OperatingSystem).Caption

	if ($OS -notlike "*Windows 10*")
	{
		#LogInfo "LockScreenRS1 skipped - Not Windows 10"
		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling the Windows lockscreen"
			LogInfo "Enabling the Windows lockscreen"
			try
			{
				$scheduledTask = Get-ScheduledTask -TaskName "Disable LockScreen" -ErrorAction Ignore
				if ($null -ne $scheduledTask)
				{
					Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable the Windows lock screen scheduled task workaround: $($_.Exception.Message)"
			}
		}

		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling the Windows lockscreen"
			LogInfo "Disabling the Windows lockscreen"

			try
			{
				$service = New-Object -ComObject Schedule.Service
				$service.Connect()

				$task = $service.NewTask(0)
				$task.Settings.DisallowStartIfOnBatteries = $false

				$trigger = $task.Triggers.Create(9)
				$trigger = $task.Triggers.Create(11)
				$trigger.StateChange = 8

				$action = $task.Actions.Create(0)
				$action.Path = "reg.exe"
				$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"

				$service.GetFolder("\").RegisterTaskDefinition(
					"Disable LockScreen",
					$task,
					6,
					"NT AUTHORITY\SYSTEM",
					$null,
					4
				) | Out-Null

				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable the Windows lock screen scheduled task workaround: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Show or hide network options on the lock screen

	.PARAMETER Enable
	Allow network selection from the lock screen (default value)

	.PARAMETER Disable
	Prevent network selection from the lock screen

	.EXAMPLE
	NetworkFromLockScreen -Enable

	.EXAMPLE
	NetworkFromLockScreen -Disable

	.NOTES
	Current user
#>
# Network options from Lock Screen
function NetworkFromLockScreen
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling the Network options on the lockscreen"
			LogInfo "Enabling the Network options on the lockscreen"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling the Network options on the lockscreen"
			LogInfo "Disabling the Network options on the lockscreen"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Shutdown option on the lock screen

	.PARAMETER Enable
	Allow shutdown from the lock screen (default value)

	.PARAMETER Disable
	Do not allow shutdown from the lock screen

	.EXAMPLE
	ShutdownFromLockScreen -Enable

	.EXAMPLE
	ShutdownFromLockScreen -Disable

	.NOTES
	Current user
#>
# Shutdown options from Lock Screen
function ShutdownFromLockScreen
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling the shutdown options on the lockscreen"
			LogInfo "Enabling the shutdown options on the lockscreen"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1 | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling the shutdown options on the lockscreen"
			LogInfo "Disabling the shutdown options on the lockscreen"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
    .SYNOPSIS
    Lock screen blur effect

    .PARAMETER Enable
    Enable lock screen blur effect (default value)

    .PARAMETER Disable
    Disable lock screen blur effect

    .EXAMPLE
    LockScreenBlur -Enable

    .EXAMPLE
    LockScreenBlur -Disable

    .NOTES
    Current user
#>
# Lock screen Blur - Applicable since 1903
function LockScreenBlur
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling blurring of the lockscreen"
			LogInfo "Enabling blurring of the lockscreen"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Enabling blurring of the lockscreen"
			LogInfo "Enabling blurring of the lockscreen"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value 1 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Task Manager details view in Windows 10 and later

	.PARAMETER Enable
	Always show full details view in Task Manager

	.PARAMETER Disable
	Revert Task Manager to default summary view

	.EXAMPLE
	TaskManagerDetails -Enable

	.EXAMPLE
	TaskManagerDetails -Disable

	.NOTES
	Current user
	Anniversary Update workaround. The GPO used in DisableTaskManagerDetails has been broken in 1607 and fixed again in 1803
#>
function TaskManagerDetails
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Task Manager detailed view"
			LogInfo "Enabling Task Manager detailed view"
			try
			{
				$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru -ErrorAction Stop
				$timeout = 30000
				$sleep = 100
				Do {
					Start-Sleep -Milliseconds $sleep
					$timeout -= $sleep
					$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
				} Until ($preferences -or $timeout -le 0)
				Stop-Process $taskmgr -ErrorAction SilentlyContinue | Out-Null
				If ($preferences) {
					$preferences.Preferences[28] = 0
					Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Task Manager detailed view: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Task Manager detailed view"
			LogInfo "Disabling Task Manager detailed view"
			try
			{
				$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
				If ($preferences) {
					$preferences.Preferences[28] = 1
					Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Task Manager detailed view: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	File operation progress details in File Explorer

	.PARAMETER Enable
	Show detailed file operation progress information

	.PARAMETER Disable
	Hide detailed file operation progress information

	.EXAMPLE
	FileOperationsDetails -Enable

	.EXAMPLE
	FileOperationsDetails -Disable

	.NOTES
	Current user
#>
function FileOperationsDetails
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling detailed file progress information"
			LogInfo "Enabling detailed file progress information"
			try
			{
				If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable detailed file operation information: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling detailed file progress information"
			LogInfo "Disabling detailed file progress information"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable detailed file operation information: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	File delete confirmation dialog in File Explorer

	.PARAMETER Enable
	Show confirmation dialog when deleting files

	.PARAMETER Disable
	Do not show confirmation dialog when deleting files (default value)

	.EXAMPLE
	FileDeleteConfirm -Enable

	.EXAMPLE
	FileDeleteConfirm -Disable

	.NOTES
	Current user
#>
function FileDeleteConfirm
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling confirmation dialog when deleting files"
			LogInfo "Enabling confirmation dialog when deleting files"
			try
			{
				If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable file delete confirmation: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling confirmation dialog when deleting files"
			LogInfo "Disabling confirmation dialog when deleting files"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable file delete confirmation: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Notification area tray icons visibility in Windows

	.PARAMETER Enable
	Always show all notification area tray icons

	.PARAMETER Disable
	Allow Windows to hide inactive notification area tray icons (default value)

	.EXAMPLE
	TrayIcons -Enable

	.EXAMPLE
	TrayIcons -Disable

	.NOTES
	Current user
#>
function TrayIcons
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling all notification area tray icons"
			LogInfo "Enabling all notification area tray icons"
			try
			{
				If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable all notification area tray icons: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling all notification area tray icons"
			LogInfo "Disabling all notification area tray icons"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable all notification area tray icons: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Search for apps in Microsoft Store from Open with dialog

	.PARAMETER Enable
	Allow searching for apps in Microsoft Store from Open with dialog

	.PARAMETER Disable
	Prevent searching for apps in Microsoft Store from Open with dialog

	.EXAMPLE
	SearchAppInStore -Enable

	.EXAMPLE
	SearchAppInStore -Disable

	.NOTES
	Current user
#>
function SearchAppInStore
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling searching for apps in Microsoft Store from Open with dialog"
			LogInfo "Enabling searching for apps in Microsoft Store from Open with dialog"
			try
			{
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable searching for apps in Microsoft Store from Open with dialog: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling searching for apps in Microsoft Store from Open with dialog"
			LogInfo "Disabling searching for apps in Microsoft Store from Open with dialog"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable searching for apps in Microsoft Store from Open with dialog: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	How do you want to open this file prompt in Windows

	.PARAMETER Enable
	Show How do you want to open this file prompt

	.PARAMETER Disable
	Do not show How do you want to open this file prompt

	.EXAMPLE
	NewAppPrompt -Enable

	.EXAMPLE
	NewAppPrompt -Disable

	.NOTES
	Current user
#>
function NewAppPrompt
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling 'How do you want to open this file?' prompt"
			LogInfo "Enabling 'How do you want to open this file?' prompt"
			try
			{
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable the 'How do you want to open this file?' prompt: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling 'How do you want to open this file?' prompt"
			LogInfo "Disabling 'How do you want to open this file?' prompt"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable the 'How do you want to open this file?' prompt: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Recently added apps list in Start Menu

	.PARAMETER Enable
	Show recently added apps list in Start Menu

	.PARAMETER Disable
	Hide recently added apps list in Start Menu

	.EXAMPLE
	RecentlyAddedApps -Enable

	.EXAMPLE
	RecentlyAddedApps -Disable

	.NOTES
	Current user
#>
function RecentlyAddedApps
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling recently added apps list in Start Menu"
			LogInfo "Enabling recently added apps list in Start Menu"
			try
			{
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable recently added apps in Start Menu: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling recently added apps list in Start Menu"
			LogInfo "Disabling recently added apps list in Start Menu"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable recently added apps in Start Menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Most used apps list in Start Menu

	.PARAMETER Enable
	Show most used apps list in Start Menu

	.PARAMETER Disable
	Hide most used apps list in Start Menu

	.EXAMPLE
	MostUsedApps -Enable

	.EXAMPLE
	MostUsedApps -Disable

	.NOTES
	Current user
#>
function MostUsedApps
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling most used apps list in Start Menu"
			LogInfo "Enabling most used apps list in Start Menu"
			try
			{
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable most used apps in Start Menu: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling most used apps list in Start Menu"
			LogInfo "Disabling most used apps list in Start Menu"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
					New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable most used apps in Start Menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows visual effects performance and appearance settings

	.PARAMETER Performance
	Adjust visual effects for best performance

	.PARAMETER Appearance
	Adjust visual effects for best appearance (default value)

	.EXAMPLE
	VisualFX -Performance

	.EXAMPLE
	VisualFX -Appearance

	.NOTES
	Current user
#>
function VisualFX
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Performance"
		)]
		[switch]
		$Performance,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Appearance"
		)]
		[switch]
		$Appearance
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Performance"
		# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
		{
			Write-ConsoleStatus -Action "Adjusting visual effects for performance"
			LogInfo "Adjusting visual effects for performance"
			try
			{
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0)) -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to adjust visual effects for performance: $($_.Exception.Message)"
			}
		}
		"Appearance"
		# Adjusts visual effects for appearance
		{
			Write-ConsoleStatus -Action "Adjusting visual effects for appearance"
			LogInfo "Adjusting visual effects for appearance"
			try
			{
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0)) -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to adjust visual effects for appearance: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Window title bar color adapts to the prevalent background color

	.PARAMETER Enable
	Enable title bar color to match prevalent background color

	.PARAMETER Disable
	Disable title bar color adaptation to background (default value)

	.EXAMPLE
	TitleBarColor -Enable

	.EXAMPLE
	TitleBarColor -Disable

	.NOTES
	Current user
#>
function TitleBarColor
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling title bar color adaptation to background"
			LogInfo "Enabling title bar color adaptation to background"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable title bar color adaptation: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling title bar color adaptation to background"
			LogInfo "Disabling title bar color adaptation to background"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable title bar color adaptation: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Enhanced pointer precision (mouse acceleration) settings

	.PARAMETER Enable
	Enable enhanced pointer precision

	.PARAMETER Disable
	Disable enhanced pointer precision (default value)

	.EXAMPLE
	EnhPointerPrecision -Enable

	.EXAMPLE
	EnhPointerPrecision -Disable

	.NOTES
	Current user
#>
function EnhPointerPrecision
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling enhanced pointer precision"
			LogInfo "Enabling enhanced pointer precision"
			try
			{
				Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "1" -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "6" -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "10" -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable enhanced pointer precision: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling enhanced pointer precision"
			LogInfo "Disabling enhanced pointer precision"
			try
			{
				Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0" -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0" -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0" -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable enhanced pointer precision: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Play or disable Windows startup sound

	.PARAMETER Enable
	Play Windows startup sound

	.PARAMETER Disable
	Do not play Windows startup sound (default value)

	.EXAMPLE
	StartupSound -Enable

	.EXAMPLE
	StartupSound -Disable

	.NOTES
	Current user
#>
function StartupSound
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Windows startup sound"
			LogInfo "Enabling Windows startup sound"
			try
			{
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Windows startup sound: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Windows startup sound"
			LogInfo "Disabling Windows startup sound"
			try
			{
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Windows startup sound: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Allow or prevent changing Windows sound scheme

	.PARAMETER Enable
	Allow changing Windows sound scheme (default value)

	.PARAMETER Disable
	Prevent changing Windows sound scheme

	.EXAMPLE
	ChangingSoundScheme -Enable

	.EXAMPLE
	ChangingSoundScheme -Disable

	.NOTES
	Current user
#>
function ChangingSoundScheme
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling changing Windows sound scheme"
			LogInfo "Enabling changing Windows sound scheme"
			try
			{
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable changing Windows sound scheme: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling changing Windows sound scheme"
			LogInfo "Disabling changing Windows sound scheme"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable changing Windows sound scheme: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Verbose startup and shutdown status messages

	.PARAMETER Enable
	Show detailed status messages during startup and shutdown

	.PARAMETER Disable
	Hide detailed status messages during startup and shutdown (default value)

	.EXAMPLE
	VerboseStatus -Enable

	.EXAMPLE
	VerboseStatus -Disable

	.NOTES
	Current user
#>
function VerboseStatus
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling verbose Shutdown/Startup status messages"
			LogInfo "Enabling verbose Shutdown/Startup status messages"
			try
			{
				If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
					Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				} Else {
					Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable verbose startup and shutdown status messages: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling verbose Shutdown/Startup status messages"
			LogInfo "Disabling verbose Shutdown/Startup status messages"
			try
			{
				If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
					Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue | Out-Null
				} Else {
					Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable verbose startup and shutdown status messages: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Storage Sense

	.PARAMETER Enable
	Turn on Storage Sense

	.PARAMETER Disable
	Turn off Storage Sense

	.EXAMPLE
	StorageSense -Enable

	.EXAMPLE
	StorageSense -Disable

	.NOTES
	Current user
#>
function StorageSense
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense -Name AllowStorageSenseGlobal -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\StorageSense -Name AllowStorageSenseGlobal -Type CLEAR | Out-Null

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -ItemType Directory -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Storage Sense"
			LogInfo "Enabling Storage Sense"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 30 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Storage Sense: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Storage Sense"
			LogInfo "Disabling Storage Sense"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Storage Sense: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Hibernation

	.PARAMETER Disable
	Disable hibernation

	.PARAMETER Enable
	Enable hibernation (default value)

	.EXAMPLE
	Hibernation -Enable

	.EXAMPLE
	Hibernation -Disable

	.NOTES
	It isn't recommended to turn off for laptops

	.NOTES
	Current user
#>
function Hibernation
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
			Write-ConsoleStatus -Action "Disabling Hibernation"
			LogInfo "Disabling Hibernation"
			try
			{
				POWERCFG /HIBERNATE OFF 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "powercfg returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable hibernation: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Hibernation"
			LogInfo "Enabling Hibernation"
			try
			{
				POWERCFG /HIBERNATE ON 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "powercfg returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable hibernation: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The Windows 260 character path limit

	.PARAMETER Disable
	Disable the Windows 260 character path limit

	.PARAMETER Enable
	Enable the Windows 260 character path limit (default value)

	.EXAMPLE
	Win32LongPathLimit -Disable

	.EXAMPLE
	Win32LongPathLimit -Enable

	.NOTES
	Machine-wide
#>
function Win32LongPathLimit
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
			Write-ConsoleStatus -Action "Disabling Windows 260 character path limit"
			LogInfo "Disabling Windows 260 character path limit"
			try
			{
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable the Windows 260 character path limit: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Windows 260 character path limit"
			LogInfo "Enabling Windows 260 character path limit"
			try
			{
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable the Windows 260 character path limit: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Stop error code when BSoD occurs

	.PARAMETER Enable
	Display Stop error code when BSoD occurs

	.PARAMETER Disable
	Do not display stop error code when BSoD occurs (default value)

	.EXAMPLE
	BSoDStopError -Enable

	.EXAMPLE
	BSoDStopError -Disable

	.NOTES
	Machine-wide
#>
function BSoDStopError
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling BSoD Stop Error"
			LogInfo "Enabling BSoD Stop Error"
			try
			{
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable BSoD stop error details: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling BSoD Stop Error"
			LogInfo "Disabling BSoD Stop Error"
			try
			{
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable BSoD stop error details: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The User Account Control (UAC) behavior

	.PARAMETER Never
	Never notify

	.PARAMETER Default
	Notify me only when apps try to make changes to my computer (default value)

	.EXAMPLE
	AdminApprovalMode -Never

	.EXAMPLE
	AdminApprovalMode -Default

	.NOTES
	Machine-wide
#>
function AdminApprovalMode
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Never"
		)]
		[switch]
		$Never,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorUser -PropertyType DWord -Value 3 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableInstallerDetection -PropertyType DWord -Value 1 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ValidateAdminCodeSignatures -PropertyType DWord -Value 0 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableSecureUIAPaths -PropertyType DWord -Value 1 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -PropertyType DWord -Value 1 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -PropertyType DWord -Value 1 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableVirtualization -PropertyType DWord -Value 1 -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableUIADesktopToggle -PropertyType DWord -Value 1 -Force | Out-Null

	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name FilterAdministratorToken -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorUser -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableInstallerDetection -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ValidateAdminCodeSignatures -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableSecureUIAPaths -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableVirtualization -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableUIADesktopToggle -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Never"
		{
			Write-ConsoleStatus -Action "Setting UAC to 'Never notify'"
			LogInfo "Setting UAC to 'Never notify'"
			try
			{
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to set UAC to 'Never notify': $($_.Exception.Message)"
			}
		}
		"Default"
		{
			Write-ConsoleStatus -Action "Setting UAC to 'Notify me only when apps try to make changes to my computer'"
			LogInfo "Setting UAC to 'Notify me only when apps try to make changes to my computer'"
			try
			{
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 5 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to set UAC to the default notification level: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Delivery Optimization

	.PARAMETER Disable
	Turn off Delivery Optimization

	.PARAMETER Enable
	Turn on Delivery Optimization (default value)

	.EXAMPLE
	DeliveryOptimization -Disable

	.EXAMPLE
	DeliveryOptimization -Enable

	.NOTES
	Current user
#>
function DeliveryOptimization
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Name DODownloadMode -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Name DODownloadMode -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Delivery Optimization"
			LogInfo "Disabling Delivery Optimization"
			try
			{
				New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				& {
    				$temp = [Console]::Out
    				[Console]::SetOut([System.IO.StreamWriter]::Null)
    				try {
        					Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
    					} finally {
        				[Console]::SetOut($temp)
    				}
				} *>$null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Delivery Optimization: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Delivery Optimization"
			LogInfo "Enabling Delivery Optimization"
			try
			{
				New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Delivery Optimization: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows manages my default printer

	.PARAMETER Disable
	Do not let Windows manage my default printer

	.PARAMETER Enable
	Let Windows manage my default printer (default value)

	.EXAMPLE
	WindowsManageDefaultPrinter -Disable

	.EXAMPLE
	WindowsManageDefaultPrinter -Enable

	.NOTES
	Current user
#>
function WindowsManageDefaultPrinter
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

	Set-Policy -Scope User -Path "Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LegacyDefaultPrinterMode -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling 'Let Windows manage my default printer'"
			LogInfo "Disabling 'Let Windows manage my default printer'"
			try
			{
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LegacyDefaultPrinterMode -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable 'Let Windows manage my default printer': $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling 'Let Windows manage my default printer'"
			LogInfo "Enabling 'Let Windows manage my default printer'"
			try
			{
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LegacyDefaultPrinterMode -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable 'Let Windows manage my default printer': $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows features

	.PARAMETER Disable
	Disable Windows features

	.PARAMETER Enable
	Enable Windows features

	.EXAMPLE
	WindowsFeatures -Disable

	.EXAMPLE
	WindowsFeatures -Enable

	.NOTES
	A pop-up dialog box lets a user select features

	.NOTES
	Current user
#>
function WindowsFeatures
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

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# Initialize an array list to store the selected Windows features
	$SelectedFeatures = New-Object -TypeName System.Collections.ArrayList($null)
	$UseFallbackFeaturesList = $false

	# The following Windows features will have their checkboxes checked
	[string[]]$CheckedFeatures = @(
		# Legacy Components
		"LegacyComponents",

		# PowerShell 2.0
		"MicrosoftWindowsPowerShellV2",
		"MicrosoftWindowsPowershellV2Root",

		# Microsoft XPS Document Writer
		"Printing-XPSServices-Features",

		# Recall
		"Recall"

		# Work Folders Client
		"WorkFolders-Client"
	)

	# The following Windows features will have their checkboxes unchecked
	[string[]]$UncheckedFeatures = @(
		# Media Features
		# If you want to leave "Multimedia settings" in the advanced settings of Power Options do not disable this feature
		"MediaPlayback"
	)
	#endregion Variables

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = @"
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
"@
	#endregion XAML Markup

	$Form = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML))
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions

	function Test-FeaturePatternMatch
	{
		param
		(
			[Parameter(Mandatory = $true)]
			[string]
			$FeatureName,

			[string[]]
			$Patterns
		)

		foreach ($Pattern in $Patterns)
		{
			if ($FeatureName -like $Pattern)
			{
				return $true
			}
		}

		return $false
	}

	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Feature = $Features | Where-Object -FilterScript {$_.DisplayName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedFeatures.Add($Feature)
		}
		else
		{
			[void]$SelectedFeatures.Remove($Feature)
		}
		if ($SelectedFeatures.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function DisableButton
	{
		Write-ConsoleStatus -Action "Disabling Windows features"
		LogInfo "Disabling Windows features"

		[void]$Window.Close()

		$SelectedFeatures | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue
		Write-ConsoleStatus -Status success
	}

	function EnableButton
	{
		Write-ConsoleStatus -Action "Enabling Windows features"
		LogInfo "Enabling Windows features"

		[void]$Window.Close()

		$SelectedFeatures | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue
		Write-ConsoleStatus -Status success
	}

	function Add-FeatureControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Feature
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})
			$CheckBox.ToolTip = $Feature.Description

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Feature.DisplayName
			$TextBlock.ToolTip = $Feature.Description

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			$CheckBox.IsChecked = $false

			if ($UseFallbackFeaturesList)
			{
				return
			}

			# If feature checked add to the array list
			if (Test-FeaturePatternMatch -FeatureName $Feature.FeatureName -Patterns $UncheckedFeatures)
			{
				$CheckBox.IsChecked = $false
				#  function if item is not checked
				return
			}

			$CheckBox.IsChecked = $true

			# If feature checked add to the array list
			[void]$SelectedFeatures.Add($Feature)
			$Button.IsEnabled = $true
		}
	}
	#endregion Functions

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			$State           = @("Disabled", "DisablePending")
			$ButtonContent   = $Localization.Enable
			$ButtonAdd_Click = {EnableButton}
		}
		"Disable"
		{
			$State           = @("Enabled", "EnablePending")
			$ButtonContent   = $Localization.Disable
			$ButtonAdd_Click = {DisableButton}
		}
	}

	# Getting list of all optional features according to the conditions
	try
	{
		$Features = Get-WindowsOptionalFeature -Online -ErrorAction Stop |
			Where-Object -FilterScript {
				($_.State -in $State) -and
				(
					(Test-FeaturePatternMatch -FeatureName $_.FeatureName -Patterns $UncheckedFeatures) -or
					(Test-FeaturePatternMatch -FeatureName $_.FeatureName -Patterns $CheckedFeatures)
				)
			} |
			ForEach-Object -Process {
				try
				{
					Get-WindowsOptionalFeature -FeatureName $_.FeatureName -Online -ErrorAction Stop
				}
				catch
				{
					# Ignore per-feature query failures.
					Remove-HandledErrorRecord -ErrorRecord $_
				}
			}
	}
	catch
	{
		Remove-HandledErrorRecord -ErrorRecord $_
		$Features = $null
	}

	if (-not $Features)
	{
		try
		{
			$Features = Get-WindowsOptionalFeature -Online -ErrorAction Stop |
				Where-Object -FilterScript {($_.State -in $State) -and -not [string]::IsNullOrWhiteSpace($_.DisplayName)} |
				Sort-Object -Property DisplayName
		}
		catch
		{
			Remove-HandledErrorRecord -ErrorRecord $_
			$Features = $null
		}

		if (-not $Features)
		{
			LogInfo "Windows Features:"
			LogWarning "All available Windows features already Installed/Uninstalled!"
			return
		}

		$UseFallbackFeaturesList = $true
		LogInfo "Windows Features:"
		LogWarning "No preset-matched Windows features were found. Showing all available features in the requested state."
	}

	#region Sendkey function
	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	# We cannot use Get-Process -Id $PID as script might be invoked via Terminal with different $PID
	Get-Process -Name powershell, WindowsTerminal -ErrorAction Ignore | Where-Object -FilterScript {$_.MainWindowTitle -match "WinUtil Script for Windows 10/11"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Seconds 1

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Seconds 1

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}
	#endregion Sendkey function

	$Button.IsEnabled = $false
	$Window.Add_Loaded({$Features | Add-FeatureControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = $Localization.WindowsFeaturesTitle

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
}

<#
.SYNOPSIS
	Optional features

	.PARAMETER Uninstall
	Uninstall optional features

	.PARAMETER Install
	Install optional features

	.EXAMPLE
	WindowsCapabilities -Uninstall

	.EXAMPLE
	WindowsCapabilities -Install

	.NOTES
	A pop-up dialog box lets a user select features

	.NOTES
	Current user
#>
function WindowsCapabilities
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Uninstall"
		)]
		[switch]
		$Uninstall,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Install"
		)]
		[switch]
		$Install
	)

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# Initialize an array list to store the selected optional features
	$SelectedCapabilities = New-Object -TypeName System.Collections.ArrayList($null)
	$UseFallbackCapabilitiesList = $false

	# The following optional features will have their checkboxes checked
	[string[]]$CheckedCapabilities = @(
		# Steps Recorder
		"App.StepsRecorder*"
	)

	# The following optional features will have their checkboxes unchecked
	[string[]]$UncheckedCapabilities = @(
		# Internet Explorer mode
		"Browser.InternetExplorer*",

		# Windows Media Player
		# If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not uninstall this feature
		"Media.WindowsMediaPlayer*"
	)

	# The following optional features will be excluded from the display
	[string[]]$ExcludedCapabilities = @(
		# The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
		"DirectX.Configuration.Database*",

		# Language components
		"Language.*",

		# Notepad
		"Microsoft.Windows.Notepad*",

		# Mail, contacts, and calendar sync component
		"OneCoreUAP.OneSync*",

		# Windows PowerShell Intergrated Scripting Enviroment
		"Microsoft.Windows.PowerShell.ISE*",

		# Management of printers, printer drivers, and printer servers
		"Print.Management.Console*",

		# Features critical to Windows functionality
		"Windows.Client.ShellComponents*"
	)
	#endregion Variables

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = @"
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
"@
	#endregion XAML Markup

	$Form = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML))
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions
	function Test-CapabilityPatternMatch
	{
		param
		(
			[Parameter(Mandatory = $true)]
			[string]
			$CapabilityName,

			[string[]]
			$Patterns
		)

		foreach ($Pattern in $Patterns)
		{
			if ($CapabilityName -like $Pattern)
			{
				return $true
			}
		}

		return $false
	}

	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Capability = $Capabilities | Where-Object -FilterScript {$_.DisplayName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedCapabilities.Add($Capability)
		}
		else
		{
			[void]$SelectedCapabilities.Remove($Capability)
		}

		if ($SelectedCapabilities.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function UninstallButton
	{
		Write-ConsoleStatus -Action "Uninstalling optional features"
		LogInfo "Uninstalling optional features"

		[void]$Window.Close()

		$SelectedCapabilities | Where-Object -FilterScript {$_.Name -in (Get-WindowsCapability -Online).Name} | Remove-WindowsCapability -Online | Out-Null

		if ([string]$SelectedCapabilities.Name -match "Browser.InternetExplorer")
		{
			#LogWarning $Localization.RestartWarning
		}
		Write-ConsoleStatus -Status success
	}

	function InstallButton
	{
		try
		{
			Write-ConsoleStatus -Action "Installing optional features"
			LogInfo "Installing optional features"

			[void]$Window.Close()

			$SelectedCapabilities | Where-Object -FilterScript {$_.Name -in ((Get-WindowsCapability -Online).Name)} | Add-WindowsCapability -Online | Out-Null

			if ([string]$SelectedCapabilities.Name -match "Browser.InternetExplorer")
			{
				#LogWarning $Localization.RestartWarning
			}
		}
		catch [System.Runtime.InteropServices.COMException]
		{
			#LogWarning -Message ($Localization.NoResponse -f "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice")
			LogError ($Localization.NoResponse -f "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice")
			LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
		}
		Write-ConsoleStatus -Status success
	}

	function Add-CapabilityControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Capability
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})
			$CheckBox.ToolTip = $Capability.Description

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Capability.DisplayName
			$TextBlock.ToolTip = $Capability.Description

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			$CheckBox.IsChecked = $false

			if ($UseFallbackCapabilitiesList)
			{
				return
			}

			# If capability checked add to the array list
			if (Test-CapabilityPatternMatch -CapabilityName $Capability.Name -Patterns $UncheckedCapabilities)
			{
				$CheckBox.IsChecked = $false
				#  function if item is not checked
				return
			}

			$CheckBox.IsChecked = $true

			# If capability checked add to the array list
			[void]$SelectedCapabilities.Add($Capability)
			$Button.IsEnabled = $true
		}
	}
	#endregion Functions

	switch ($PSCmdlet.ParameterSetName)
	{
		"Install"
		{
			try
			{
				$State = "NotPresent"
				$ButtonContent = $Localization.Install
				$ButtonAdd_Click = {InstallButton}
			}
			catch [System.ComponentModel.Win32Exception]
			{
				LogError ($Localization.NoResponse -f "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice")
				LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())

				return
			}
		}
		"Uninstall"
		{
			$State = "Installed"
			$ButtonContent = $Localization.Uninstall
			$ButtonAdd_Click = {UninstallButton}
		}
	}

	# Getting list of all capabilities according to the conditions
	$Capabilities = Get-WindowsCapability -Online | Where-Object -FilterScript {
		$CapabilityName = $_.Name
		($_.State -eq $State) -and
		(
			(Test-CapabilityPatternMatch -CapabilityName $CapabilityName -Patterns $UncheckedCapabilities) -or
			(Test-CapabilityPatternMatch -CapabilityName $CapabilityName -Patterns $CheckedCapabilities)
		) -and
		-not (Test-CapabilityPatternMatch -CapabilityName $CapabilityName -Patterns $ExcludedCapabilities)
	} | ForEach-Object -Process {Get-WindowsCapability -Name $_.Name -Online}

	if (-not $Capabilities)
	{
		$Capabilities = Get-WindowsCapability -Online | Where-Object -FilterScript {
			($_.State -eq $State) -and
			-not (Test-CapabilityPatternMatch -CapabilityName $_.Name -Patterns $ExcludedCapabilities) -and
			-not [string]::IsNullOrWhiteSpace($_.DisplayName)
		} | ForEach-Object -Process {Get-WindowsCapability -Name $_.Name -Online}

		if (-not $Capabilities)
		{
			LogInfo "Optional Features:"
			LogWarning "All available Optional features already Installed/Uninstalled!"

			return
		}

		$UseFallbackCapabilitiesList = $true
		LogInfo "Optional Features:"
		LogWarning "No preset-matched Optional features were found. Showing all available features in the requested state."
	}

	#region Sendkey function
	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	# We cannot use Get-Process -Id $PID as script might be invoked via Terminal with different $PID
	Get-Process -Name powershell, WindowsTerminal -ErrorAction Ignore | Where-Object -FilterScript {$_.MainWindowTitle -match "WinUtil Script for Windows 10/11"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Seconds 1

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Seconds 1

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}
	#endregion Sendkey function

	$Button.IsEnabled = $false
	$Window.Add_Loaded({$Capabilities | Add-CapabilityControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = $Localization.OptionalFeaturesTitle

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
}

<#
	.SYNOPSIS
	Set current network profile category

	.PARAMETER Private
	Set current network profile to Private

	.PARAMETER Public
	Set current network profile to Public

	.EXAMPLE
	CurrentNetwork -Private

	.EXAMPLE
	CurrentNetwork -Public

	.NOTES
	Current user
#>
function CurrentNetwork
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Private"
		)]
		[switch]
		$Private,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Public"
		)]
		[switch]
		$Public
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Private"
		{
			Write-ConsoleStatus -Action "Setting current network profile to Private"
			LogInfo "Setting current network profile to Private"
			Set-NetConnectionProfile -NetworkCategory Private | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Public"
		{
			Write-ConsoleStatus -Action "Setting current network profile to Public"
			LogInfo "Setting current network profile to Public"
			Set-NetConnectionProfile -NetworkCategory Public | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Set network category for unidentified networks

	.PARAMETER Private
	Set unidentified networks to Private profile

	.PARAMETER Public
	Set unidentified networks to Public profile (default value)

	.EXAMPLE
	UnknownNetworks -Private

	.EXAMPLE
	UnknownNetworks -Public

	.NOTES
	Current user
#>
function UnknownNetworks
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Private"
		)]
		[switch]
		$Private,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Public"
		)]
		[switch]
		$Public
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Private"
		{
			Write-ConsoleStatus -Action "Setting unidentified networks to Private profile"
			LogInfo "Setting unidentified networks to Private profile"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1 | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Public"
		{
			Write-ConsoleStatus -Action "Setting unidentified networks to Public profile"
			LogInfo "Setting unidentified networks to Public profile"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Automatic installation of network devices

	.PARAMETER Enable
	Allow automatic installation of network devices (default value)

	.PARAMETER Disable
	Prevent automatic installation of network devices

	.EXAMPLE
	NetDevicesAutoInst -Enable

	.EXAMPLE
	NetDevicesAutoInst -Disable

	.NOTES
	Current user
#>
function NetDevicesAutoInst
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling automatic installation of network devices"
			LogInfo "Enabling automatic installation of network devices"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling automatic installation of network devices"
			LogInfo "Disabling automatic installation of network devices"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	HomeGroup services configuration

	.PARAMETER Enable
	Enable HomeGroup services

	.PARAMETER Disable
	Disable HomeGroup services (default value)

	.EXAMPLE
	HomeGroups -Enable

	.EXAMPLE
	HomeGroups -Disable

	.NOTES
	Current user
	Not applicable since 1803
	Not applicable to Server
#>
function HomeGroups
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
    		Write-ConsoleStatus -Action "Enabling HomeGroup services"
    		LogInfo "Enabling HomeGroup services"

    		# Check if services exist before attempting to modify them
    		$listenerExists = Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue
    		$providerExists = Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue

    		if ($listenerExists) {
       		 	Set-Service "HomeGroupListener" -StartupType Manual -ErrorAction SilentlyContinue 2>&1 | Out-Null
    		}

    		if ($providerExists) {
        		Set-Service "HomeGroupProvider" -StartupType Manual -ErrorAction SilentlyContinue 2>&1 | Out-Null
        		Start-Service "HomeGroupProvider" -ErrorAction SilentlyContinue 2>&1 | Out-Null
    	}
    		Write-ConsoleStatus -Status success
		}
		"Disable"
		{
    		Write-ConsoleStatus -Action "Disabling HomeGroup services"
    		LogInfo "Disabling HomeGroup services"

   	 		# Check if services exist before attempting to modify them
    		$listenerExists = Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue
    		$providerExists = Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue

    		If ($listenerExists) {
        	Stop-Service "HomeGroupListener" -ErrorAction SilentlyContinue 2>&1 | Out-Null
        	Set-Service "HomeGroupListener" -StartupType Disabled -ErrorAction SilentlyContinue 2>&1 | Out-Null
    		}

    		If ($providerExists) {
        	Stop-Service "HomeGroupProvider" -ErrorAction SilentlyContinue 2>&1 | Out-Null
        	Set-Service "HomeGroupProvider" -StartupType Disabled -ErrorAction SilentlyContinue 2>&1 | Out-Null
    		}
    		Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	SMB 1.0 protocol configuration

	.PARAMETER Enable
	Enable SMB 1.0 protocol

	.PARAMETER Disable
	Disable SMB 1.0 protocol (default value)

	.EXAMPLE
	SMB1 -Enable

	.EXAMPLE
	SMB1 -Disable

	.NOTES
	Current user
#>
function SMB1
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling SMB 1.0 protocol"
			LogInfo "Enabling SMB 1.0 protocol"
			$null = Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue 2>&1
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling SMB 1.0 protocol"
			LogInfo "Disabling SMB 1.0 protocol"
			$null = Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue 2>&1
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	SMB Server file and printer sharing configuration

	.PARAMETER Enable
	Enable SMB Server file and printer sharing

	.PARAMETER Disable
	Disable SMB Server file and printer sharing

	.EXAMPLE
	SMBServer -Enable

	.EXAMPLE
	SMBServer -Disable

	.NOTES
	Current user
	Disabling prevents file and printer sharing but allows client connections
	Do not disable if using Docker with shared drives as it uses SMB internally
#>
function SMBServer
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling SMB Server file and printer sharing"
			LogInfo "Enabling SMB Server file and printer sharing"
			Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force | Out-Null
			Enable-NetAdapterBinding -Name "*" -ComponentID "ms_server" | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling SMB Server file and printer sharing"
			LogInfo "Disabling SMB Server file and printer sharing"
			Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
			Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force | Out-Null
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server" | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	NetBIOS over TCP/IP configuration on installed network interfaces

	.PARAMETER Enable
	Enable NetBIOS over TCP/IP on all installed network interfaces

	.PARAMETER Disable
	Disable NetBIOS over TCP/IP on all installed network interfaces

	.EXAMPLE
	NetBIOS -Enable

	.EXAMPLE
	NetBIOS -Disable

	.NOTES
	Current user
#>
function NetBIOS
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling NetBIOS over TCP/IP"
			LogInfo "Enabling NetBIOS over TCP/IP"
			Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0 | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling NetBIOS over TCP/IP"
			LogInfo "Disabling NetBIOS over TCP/IP"
			Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Link-Local Multicast Name Resolution (LLMNR) protocol configuration

	.PARAMETER Enable
	Enable LLMNR protocol (default value)

	.PARAMETER Disable
	Disable LLMNR protocol

	.EXAMPLE
	LLMNR -Enable

	.EXAMPLE
	LLMNR -Disable

	.NOTES
	Current user
#>
function LLMNR
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Link-Local Multicast Name Resolution (LLMNR) protocol"
			LogInfo "Enabling Link-Local Multicast Name Resolution (LLMNR) protocol"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Link-Local Multicast Name Resolution (LLMNR) protocol"
			LogInfo "Disabling Link-Local Multicast Name Resolution (LLMNR) protocol"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Client for Microsoft Networks configuration on all network interfaces

	.PARAMETER Enable
	Enable Client for Microsoft Networks on all installed network interfaces (default value)

	.PARAMETER Disable
	Disable Client for Microsoft Networks on all installed network interfaces

	.EXAMPLE
	MSNetClient -Enable

	.EXAMPLE
	MSNetClient -Disable

	.NOTES
	Current user
#>
function MSNetClient
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Microsoft Network clients on all installed network interfaces"
			LogInfo "Enabling Microsoft Network clients on all installed network interfaces"
			Enable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient" | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Microsoft Network clients on all installed network interfaces"
			LogInfo "Disabling Microsoft Network clients on all installed network interfaces"
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient" | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Quality of Service (QoS) packet scheduler configuration on all network interfaces

	.PARAMETER Enable
	Enable QoS packet scheduler on all installed network interfaces (default value)

	.PARAMETER Disable
	Disable QoS packet scheduler on all installed network interfaces

	.EXAMPLE
	QoS -Enable

	.EXAMPLE
	QoS -Disable

	.NOTES
	Current user
#>
function QoS
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Quality of Service (QoS)"
			LogInfo "Enabling Quality of Service (QoS)"
			Enable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer" | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Quality of Service (QoS)"
			LogInfo "Disabling Quality of Service (QoS)"
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer" | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Network Connectivity Status Indicator (NCSI) active probe configuration

	.PARAMETER Enable
	Enable NCSI active probe (default value)

	.PARAMETER Disable
	Disable NCSI active probe to reduce certain zero-click attack exposure

	.EXAMPLE
	NCSIProbe -Enable

	.EXAMPLE
	NCSIProbe -Disable

	.NOTES
	Current user
	Disabling may reduce OS ability to detect internet connectivity
	See https://github.com/Disassembler0/Win10-Initial-Setup-Script/pull/111 for details
#>
function NCSIProbe
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Network Connectivity Status Indicator (NCSI) active probe"
			LogInfo "Enabling Network Connectivity Status Indicator (NCSI) active probe"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Network Connectivity Status Indicator (NCSI) active probe"
			LogInfo "Disabling Network Connectivity Status Indicator (NCSI) active probe"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Internet Connection Sharing (ICS) configuration, e.g., mobile hotspot

	.PARAMETER Enable
	Allow Internet Connection Sharing

	.PARAMETER Disable
	Prevent Internet Connection Sharing (default value)

	.EXAMPLE
	ConnectionSharing -Enable

	.EXAMPLE
	ConnectionSharing -Disable

	.NOTES
	Current user
#>
function ConnectionSharing
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Internet Connection Sharing (ICS)"
			LogInfo "Enabling Internet Connection Sharing (ICS)"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Internet Connection Sharing (ICS)"
			LogInfo "Disabling Internet Connection Sharing (ICS)"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0 | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Receive updates for other Microsoft products

	.PARAMETER Enable
	Receive updates for other Microsoft products

	.PARAMETER Disable
	Do not receive updates for other Microsoft products (default value)

	.EXAMPLE
	UpdateMicrosoftProducts -Enable

	.EXAMPLE
	UpdateMicrosoftProducts -Disable

	.NOTES
	Current user
#>
function UpdateMicrosoftProducts
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AllowMUUpdateService -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AllowMUUpdateService -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling receiving updates for other Microsoft products"
			LogInfo "Enabling receiving updates for other Microsoft products"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name AllowMUUpdateService -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling receiving updates for other Microsoft products"
			LogInfo "Disabling receiving updates for other Microsoft products"
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name AllowMUUpdateService -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Notification when your PC requires a restart to finish updating

	.PARAMETER Show
	Notify me when a restart is required to finish updating

	.PARAMETER Hide
	Do not notify me when a restart is required to finish updating (default value)

	.EXAMPLE
	RestartNotification -Show

	.EXAMPLE
	RestartNotification -Hide

	.NOTES
	Machine-wide
#>
function RestartNotification
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name SetAutoRestartNotificationDisable -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name SetAutoRestartNotificationDisable -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Show"
		{
			Write-ConsoleStatus -Action "Showing notification when your PC requires a restart to finish updating"
			LogInfo "Showing notification when your PC requires a restart to finish updating"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding notification when your PC requires a restart to finish updating"
			LogInfo "Hiding notification when your PC requires a restart to finish updating"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Restart as soon as possible to finish updating

	.PARAMETER Enable
	Restart as soon as possible to finish updating

	.PARAMETER Disable
	Don't restart as soon as possible to finish updating (default value)

	.EXAMPLE
	DeviceRestartAfterUpdate -Enable

	.EXAMPLE
	DeviceRestartAfterUpdate -Disable

	.NOTES
	Machine-wide
#>
function RestartDeviceAfterUpdate
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ActiveHoursEnd, ActiveHoursStart, SetActiveHours -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ActiveHoursEnd -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ActiveHoursStart -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name SetActiveHours -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling restart as soon as possible to finish updating"
			LogInfo "Enabling restart as soon as possible to finish updating"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling restart as soon as possible to finish updating"
			LogInfo "Disabling restart as soon as possible to finish updating"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 0 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Active hours

	.PARAMETER Automatically
	Automatically adjust active hours for me based on daily usage

	.PARAMETER Manually
	Manually adjust active hours for me based on daily usage (default value)

	.EXAMPLE
	ActiveHours -Automatically

	.EXAMPLE
	ActiveHours -Manually

	.NOTES
	Machine-wide
#>
function ActiveHours
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Automatically"
		)]
		[switch]
		$Automatically,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Manually"
		)]
		[switch]
		$Manually
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoRebootWithLoggedOnUsers, AlwaysAutoRebootAtScheduledTime -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoRebootWithLoggedOnUsers -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AlwaysAutoRebootAtScheduledTime -Type CLEAR | Out-Null

	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ActiveHoursEnd, ActiveHoursStart, SetActiveHours -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ActiveHoursEnd -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ActiveHoursStart -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name SetActiveHours -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Automatically"
		{
			Write-ConsoleStatus -Action "Automatically adjusting active hours for me based on daily usage"
			LogInfo "Automatically adjusting active hours for me based on daily usage"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name SmartActiveHoursState -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Manually"
		{
			Write-ConsoleStatus -Action "Manually adjusting active hours for me based on daily usage"
			LogInfo "Manually adjusting active hours for me based on daily usage"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name SmartActiveHoursState -PropertyType DWord -Value 0 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Windows latest updates

	.PARAMETER Disable
	Do not get the latest updates as soon as they're available (default value)

	.PARAMETER Enable
	Get the latest updates as soon as they're available

	.EXAMPLE
	WindowsLatestUpdate -Disable

	.EXAMPLE
	WindowsLatestUpdate -Enable

	.NOTES
	Machine-wide
#>
function WindowsLatestUpdate
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AllowOptionalContent, SetAllowOptionalContent -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AllowOptionalContent -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name SetAllowOptionalContent -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling getting the latest updates as soon as they're available"
			LogInfo "Disabling getting the latest updates as soon as they're available"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsContinuousInnovationOptedIn -PropertyType DWord -Value 0 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling getting the latest updates as soon as they're available"
			LogInfo "Enabling getting the latest updates as soon as they're available"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsContinuousInnovationOptedIn -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Power plan

	.PARAMETER High
	Set power plan on "High performance"

	.PARAMETER Balanced
	Set power plan on "Balanced" (default value)

	.EXAMPLE
	PowerPlan -High

	.EXAMPLE
	PowerPlan -Balanced

	.NOTES
	It isn't recommended to turn on for laptops

	.NOTES
	Current user
#>
function PowerPlan
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "High"
		)]
		[switch]
		$High,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Balanced"
		)]
		[switch]
		$Balanced
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings -Name ActivePowerScheme -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Power\PowerSettings -Name ActivePowerScheme -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"High"
		{
			Write-ConsoleStatus -Action "Setting power plan to High performance"
			LogInfo "Setting power plan to High performance"
			POWERCFG /SETACTIVE SCHEME_MIN | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Balanced"
		{
			Write-ConsoleStatus -Action "Setting power plan to Balanced"
			LogInfo "Setting power plan to Balanced"
			POWERCFG /SETACTIVE SCHEME_BALANCED | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Network adapters power management

	.PARAMETER Disable
	Do not allow the computer to turn off the network adapters to save power

	.PARAMETER Enable
	Allow the computer to turn off the network adapters to save power (default value)

	.EXAMPLE
	NetworkAdaptersSavePower -Disable

	.EXAMPLE
	NetworkAdaptersSavePower -Enable

	.NOTES
	It isn't recommended to turn off for laptops

	.NOTES
	Current user
#>
function NetworkAdaptersSavePower
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

	# Checking whether there's an adapter that has AllowComputerToTurnOffDevice property to manage
	$Adapters = Get-NetAdapter -Physical | Where-Object -FilterScript {$_.MacAddress} | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
	if (-not $Adapters)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	$PhysicalAdaptersStatusUp = @(Get-NetAdapter -Physical | Where-Object -FilterScript {($_.Status -eq "Up") -and $_.MacAddress})

	# Checking whether PC is currently connected to a Wi-Fi network
	# NetConnectionStatus 2 is Wi-Fi
	$InterfaceIndex = (Get-CimInstance -ClassName Win32_NetworkAdapter -Namespace root/CIMV2 | Where-Object -FilterScript {$_.NetConnectionStatus -eq 2}).InterfaceIndex
	if (Get-NetAdapter -Physical | Where-Object -FilterScript {($_.Status -eq "Up") -and ($_.PhysicalMediaType -eq "Native 802.11") -and ($_.InterfaceIndex -eq $InterfaceIndex)})
	{
		# Get currently connected Wi-Fi network SSID
		$SSID = (Get-NetConnectionProfile).Name
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling 'allowing the computer to turn off the network adapters to save power'"
			LogInfo "Disabling 'allowing the computer to turn off the network adapters to save power'"
			foreach ($Adapter in $Adapters)
			{
				$Adapter.AllowComputerToTurnOffDevice = "Disabled"
				$Adapter | Set-NetAdapterPowerManagement | Out-Null
				Write-ConsoleStatus -Status success
			}
		}
		"Enable"
		{
			foreach ($Adapter in $Adapters)
			{
				Write-ConsoleStatus -Action "Enabling 'allowing the computer to turn off the network adapters to save power' for adapter '$($Adapter.Name)'"
				LogInfo "Enabling 'allowing the computer to turn off the network adapters to save power' for adapter '$($Adapter.Name)'"
				$Adapter.AllowComputerToTurnOffDevice = "Enabled"
				$Adapter | Set-NetAdapterPowerManagement | Out-Null
				Write-ConsoleStatus -Status success
			}
		}
	}

	# All network adapters are turned into "Disconnected" for few seconds, so we need to wait a bit to let them up
	# Otherwise functions below will indicate that there is no the Internet connection
	if ($PhysicalAdaptersStatusUp)
	{
		# If Wi-Fi network was used
		if ($SSID)
		{
			#Write-Verbose -Message $SSID -Verbose
			# Connect to it
			netsh wlan connect name="$SSID" 2>$null | Out-Null
			if ($LASTEXITCODE -ne 0)
			{
				LogWarning "Failed to reconnect to Wi-Fi network '$SSID' after adapter changes. netsh exit code: $LASTEXITCODE"
			}
		}

		while
		(
			Get-NetAdapter -Physical -Name $PhysicalAdaptersStatusUp.Name | Where-Object -FilterScript {($_.Status -eq "Disconnected") -and $_.MacAddress} | Out-Null
		)
		{
			Start-Sleep -Seconds 2
		}
	}
}

<#
	.SYNOPSIS
	Override for default input method

	.PARAMETER English
	Override for default input method: English

	.PARAMETER Default
	Override for default input method: use language list (default value)

	.EXAMPLE
	InputMethod -English

	.EXAMPLE
	InputMethod -Default

	.NOTES
	Current user
#>
function InputMethod
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "English"
		)]
		[switch]
		$English,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"English"
		{
			Write-ConsoleStatus -Action "Setting override for default input method to English"
			LogInfo "Setting override for default input method to English"
			Set-WinDefaultInputMethodOverride -InputTip "0409:00000409" | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Default"
		{
			Write-ConsoleStatus -Action "Setting override for default input method to use language list"
			LogInfo "Setting override for default input method to use language list"
			Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name InputMethodOverride -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Change User folders location

	.PARAMETER Root
	Change user folders location to the root of any drive using the interactive menu

	.PARAMETER Custom
	Select folders for user folders location manually using a folder browser dialog

	.PARAMETER Default
	Change user folders location to the default values

	.EXAMPLE
	Set-UserShellFolderLocation -Root

	.EXAMPLE
	Set-UserShellFolderLocation -Custom

	.EXAMPLE
	Set-UserShellFolderLocation -Default

	.NOTES
	User files or folders won't be moved to a new location

	.NOTES
	Current user
#>
function Set-UserShellFolderLocation
{

	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Root"
		)]
		[switch]
		$Root,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Custom"
		)]
		[switch]
		$Custom,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	<#
		.SYNOPSIS
		Change the location of the each user folder using SHSetKnownFolderPath function

		.EXAMPLE
		Set-UserShellFolder -UserFolder Desktop -FolderPath "$env:SystemDrive:\Desktop"

		.LINK
		https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath

		.NOTES
		User files or folders won't be moved to a new location
	#>
	function Set-UserShellFolder
	{
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true)]
			[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
			[string]
			$UserFolder,

			[Parameter(Mandatory = $true)]
			[string]
			$FolderPath
		)

		<#
			.SYNOPSIS
			Redirect user folders to a new location

			.EXAMPLE
			Set-KnownFolderPath -KnownFolder Desktop -Path "$env:SystemDrive:\Desktop"
		#>
		function Set-KnownFolderPath
		{
			[CmdletBinding()]
			param
			(
				[Parameter(Mandatory = $true)]
				[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
				[string]
				$KnownFolder,

				[Parameter(Mandatory = $true)]
				[string]
				$Path
			)

			$KnownFolders = @{
				"Desktop"   = @("B4BFCC3A-DB2C-424C-B029-7FE99A87C641")
				"Documents" = @("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "f42ee2d3-909f-4907-8871-4c22fc0bf756")
				"Downloads" = @("374DE290-123F-4565-9164-39C4925E467B", "7d83ee9b-2244-4e70-b1f5-5404642af1e4")
				"Music"     = @("4BD8D571-6D19-48D3-BE97-422220080E43", "a0c69a99-21c8-4671-8703-7934162fcf1d")
				"Pictures"  = @("33E28130-4E1E-4676-835A-98395C3BC3BB", "0ddd015d-b06c-45d5-8c4c-f59713854639")
				"Videos"    = @("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "35286a68-3c57-41a1-bbb1-0eae73d76c95")
			}

			$Signature = @{
				Namespace          = "WinAPI"
				Name               = "KnownFolders"
				Language           = "CSharp"
				CompilerParameters = $CompilerParameters
				MemberDefinition   = @"
[DllImport("shell32.dll")]
public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
"@
			}
			if (-not ("WinAPI.KnownFolders" -as [type]))
			{
				Add-Type @Signature
			}

			foreach ($GUID in $KnownFolders[$KnownFolder])
			{
				[WinAPI.KnownFolders]::SHSetKnownFolderPath([ref]$GUID, 0, 0, $Path)
			}
			(Get-Item -Path $Path -Force).Attributes = "ReadOnly"
		}

		$UserShellFoldersRegistryNames = @{
			"Desktop"   = "Desktop"
			"Documents" = "Personal"
			"Downloads" = "{374DE290-123F-4565-9164-39C4925E467B}"
			"Music"     = "My Music"
			"Pictures"  = "My Pictures"
			"Videos"    = "My Video"
		}

		$UserShellFoldersGUIDs = @{
			"Desktop"   = "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}"
			"Documents" = "{F42EE2D3-909F-4907-8871-4C22FC0BF756}"
			"Downloads" = "{7D83EE9B-2244-4E70-B1F5-5404642AF1E4}"
			"Music"     = "{A0C69A99-21C8-4671-8703-7934162FCF1D}"
			"Pictures"  = "{0DDD015D-B06C-45D5-8C4C-F59713854639}"
			"Videos"    = "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}"
		}

		# Contents of the hidden desktop.ini file for each type of user folders
		$DesktopINI = @{
			"Desktop"   = "",
                          "[.ShellClassInfo]",
                          "LocalizedResourceName=@%SystemRoot%\System32\shell32.dll,-21769",
                          "IconResource=%SystemRoot%\System32\imageres.dll,-183"
			"Documents" = "",
                          "[.ShellClassInfo]",
                          "LocalizedResourceName=@%SystemRoot%\System32\shell32.dll,-21770",
                          "IconResource=%SystemRoot%\System32\imageres.dll,-112",
                          "IconFile=%SystemRoot%\System32\shell32.dll",
                          "IconIndex=-235"
			"Downloads" = "",
                          "[.ShellClassInfo]",
                          "LocalizedResourceName=@%SystemRoot%\System32\shell32.dll,-21798",
                          "IconResource=%SystemRoot%\System32\imageres.dll,-184"
			"Music"     = "",
                          "[.ShellClassInfo]",
                          "LocalizedResourceName=@%SystemRoot%\System32\shell32.dll,-21790",
                          "InfoTip=@%SystemRoot%\System32\shell32.dll,-12689",
                          "IconResource=%SystemRoot%\System32\imageres.dll,-108",
                          "IconFile=%SystemRoot%\System32\shell32.dll","IconIndex=-237"
			"Pictures"  = "",
                          "[.ShellClassInfo]",
                          "LocalizedResourceName=@%SystemRoot%\System32\shell32.dll,-21779",
                          "InfoTip=@%SystemRoot%\System32\shell32.dll,-12688",
                          "IconResource=%SystemRoot%\System32\imageres.dll,-113",
                          "IconFile=%SystemRoot%\System32\shell32.dll",
                          "IconIndex=-236"
			"Videos"    = "",
                          "[.ShellClassInfo]",
                          "LocalizedResourceName=@%SystemRoot%\System32\shell32.dll,-21791",
                          "InfoTip=@%SystemRoot%\System32\shell32.dll,-12690",
                          "IconResource=%SystemRoot%\System32\imageres.dll,-189",
                          "IconFile=%SystemRoot%\System32\shell32.dll","IconIndex=-238"
		}

		# Determining the current user folder path
		$CurrentUserFolderPath = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersRegistryNames[$UserFolder]
		if ($CurrentUserFolder -ne $FolderPath)
		{
			# Creating a new folder if there is no one
			if (-not (Test-Path -Path $FolderPath))
			{
				New-Item -Path $FolderPath -ItemType Directory -Force | Out-Null
			}

			# Removing old desktop.ini
			Remove-Item -Path "$CurrentUserFolderPath\desktop.ini" -Force -ErrorAction SilentlyContinue | Out-Null

			Set-KnownFolderPath -KnownFolder $UserFolder -Path $FolderPath | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersGUIDs[$UserFolder] -PropertyType ExpandString -Value $FolderPath -Force | Out-Null

			# Save desktop.ini in the UTF-16 LE encoding
			Set-Content -Path "$FolderPath\desktop.ini" -Value $DesktopINI[$UserFolder] -Encoding Unicode -Force | Out-Null
			(Get-Item -Path "$FolderPath\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$FolderPath\desktop.ini" -Force).Refresh()

			if ((Get-ChildItem -Path $CurrentUserFolderPath -ErrorAction SilentlyContinue | Measure-Object).Count -ne 0)
			{
				LogError ($Localization.UserShellFolderNotEmpty -f $CurrentUserFolderPath)
			}
		}
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Root"
		{
			Write-Host "Changing user folders location to the root of a drive"
			LogInfo "Changing user folders location to the root of a drive"
			# Store all fixed disks' letters except C (system drive) to use them within Show-Menu function
			# https://learn.microsoft.com/en-us/dotnet/api/system.io.drivetype
			$DriveLetters = @((Get-CimInstance -ClassName CIM_LogicalDisk | Where-Object -FilterScript {($_.DriveType -eq 3) -and ($_.Name -ne $env:SystemDrive)}).DeviceID | Sort-Object)

			if (-not $DriveLetters)
			{
				LogError $Localization.UserFolderLocationMove

				return
			}

			# Desktop
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21769), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $DriveLetters -Default $DriveLetters.Count[-1] -AddSkip

				switch ($Choice)
				{
					{$DriveLetters -contains $Choice}
					{
						Set-UserShellFolder -UserFolder Desktop -FolderPath "$($Choice)\Desktop" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Documents
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Personal
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21770), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $DriveLetters -Default $DriveLetters.Count[-1] -AddSkip

				switch ($Choice)
				{
					{$DriveLetters -contains $Choice}
					{
						Set-UserShellFolder -UserFolder Documents -FolderPath "$($Choice)\Documents" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Downloads
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21798), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $DriveLetters -Default $DriveLetters.Count[-1] -AddSkip

				switch ($Choice)
				{
					{$DriveLetters -contains $Choice}
					{
						Set-UserShellFolder -UserFolder Downloads -FolderPath "$($Choice)\Downloads" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Music
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21790), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $DriveLetters -Default $DriveLetters.Count[-1] -AddSkip

				switch ($Choice)
				{
					{$DriveLetters -contains $Choice}
					{
						Set-UserShellFolder -UserFolder Music -FolderPath "$($Choice)\Music" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Pictures
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21779), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $DriveLetters -Default $DriveLetters.Count[-1] -AddSkip

				switch ($Choice)
				{
					{$DriveLetters -contains $Choice}
					{
						Set-UserShellFolder -UserFolder Pictures -FolderPath "$($Choice)\Pictures" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Videos
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21791), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $DriveLetters -Default $DriveLetters.Count[-1] -AddSkip

				switch ($Choice)
				{
					{$DriveLetters -contains $Choice}
					{
						Set-UserShellFolder -UserFolder Videos -FolderPath "$($Choice)\Videos" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)
		}
		"Custom"
		{
			Write-Host "Changing user folders location to the custom one selected"
			LogInfo "Changing user folders location to the custom one selected"
			# Desktop
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21769), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

				switch ($Choice)
				{
					$Browse
					{
						Add-Type -AssemblyName System.Windows.Forms
						$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
						$FolderBrowserDialog.Description = $Localization.FolderSelect
						$FolderBrowserDialog.RootFolder = "MyComputer"

						# Force move the open file dialog to the foreground
						$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
						$FolderBrowserDialog.ShowDialog($Focus)

						if ($FolderBrowserDialog.SelectedPath)
						{
							if ($FolderBrowserDialog.SelectedPath -eq "C:\")
							{
								continue
							}
							else
							{
								Set-UserShellFolder -UserFolder Desktop -FolderPath $FolderBrowserDialog.SelectedPath | Out-Null
							}
						}
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Documents
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Personal
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21770), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

				switch ($Choice)
				{
					$Browse
					{
						Add-Type -AssemblyName System.Windows.Forms
						$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
						$FolderBrowserDialog.Description = $Localization.FolderSelect
						$FolderBrowserDialog.RootFolder = "MyComputer"

						# Force move the open file dialog to the foreground
						$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
						$FolderBrowserDialog.ShowDialog($Focus)

						if ($FolderBrowserDialog.SelectedPath)
						{
							if ($FolderBrowserDialog.SelectedPath -eq "C:\")
							{
								continue
							}
							else
							{
								Set-UserShellFolder -UserFolder Documents -FolderPath $FolderBrowserDialog.SelectedPath | Out-Null
							}
						}
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Downloads
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21798), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

				switch ($Choice)
				{
					$Browse
					{
						Add-Type -AssemblyName System.Windows.Forms
						$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
						$FolderBrowserDialog.Description = $Localization.FolderSelect
						$FolderBrowserDialog.RootFolder = "MyComputer"

						# Force move the open file dialog to the foreground
						$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
						$FolderBrowserDialog.ShowDialog($Focus)

						if ($FolderBrowserDialog.SelectedPath)
						{
							if ($FolderBrowserDialog.SelectedPath -eq "C:\")
							{
								continue
							}
							else
							{
								Set-UserShellFolder -UserFolder Downloads -FolderPath $FolderBrowserDialog.SelectedPath | Out-Null
							}
						}
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Music
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21790), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

				switch ($Choice)
				{
					$Browse
					{
						Add-Type -AssemblyName System.Windows.Forms
						$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
						$FolderBrowserDialog.Description = $Localization.FolderSelect
						$FolderBrowserDialog.RootFolder = "MyComputer"

						# Force move the open file dialog to the foreground
						$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
						$FolderBrowserDialog.ShowDialog($Focus)

						if ($FolderBrowserDialog.SelectedPath)
						{
							if ($FolderBrowserDialog.SelectedPath -eq "C:\")
							{
								continue
							}
							else
							{
								Set-UserShellFolder -UserFolder Music -FolderPath $FolderBrowserDialog.SelectedPath | Out-Null
							}
						}
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Pictures
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21779), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

				switch ($Choice)
				{
					$Browse
					{
						Add-Type -AssemblyName System.Windows.Forms
						$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
						$FolderBrowserDialog.Description = $Localization.FolderSelect
						$FolderBrowserDialog.RootFolder = "MyComputer"

						# Force move the open file dialog to the foreground
						$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
						$FolderBrowserDialog.ShowDialog($Focus)

						if ($FolderBrowserDialog.SelectedPath)
						{
							if ($FolderBrowserDialog.SelectedPath -eq "C:\")
							{
								continue
							}
							else
							{
								Set-UserShellFolder -UserFolder Pictures -FolderPath $FolderBrowserDialog.SelectedPath | Out-Null
							}
						}
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Videos
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21791), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

				switch ($Choice)
				{
					$Browse
					{
						Add-Type -AssemblyName System.Windows.Forms
						$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
						$FolderBrowserDialog.Description = $Localization.FolderSelect
						$FolderBrowserDialog.RootFolder = "MyComputer"

						# Force move the open file dialog to the foreground
						$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
						$FolderBrowserDialog.ShowDialog($Focus)

						if ($FolderBrowserDialog.SelectedPath)
						{
							if ($FolderBrowserDialog.SelectedPath -eq "C:\")
							{
								continue
							}
							else
							{
								Set-UserShellFolder -UserFolder Videos -FolderPath $FolderBrowserDialog.SelectedPath | Out-Null
							}
						}
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)
		}
		"Default"
		{
			Write-Host "Changing user folders location to the default one"
			LogInfo "Changing user folders location to the default one"
			# Desktop
			# Extract the localized "Desktop" string from shell32.dll
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21769), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Yes -Default 1 -AddSkip

				switch ($Choice)
				{
					$Yes
					{
						Set-UserShellFolder -UserFolder Desktop -FolderPath "$env:USERPROFILE\Desktop" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Documents
			# Extract the localized "Documents" string from shell32.dll
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Personal
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21770), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Yes -Default 1 -AddSkip

				switch ($Choice)
				{
					$Yes
					{
						Set-UserShellFolder -UserFolder Documents -FolderPath "$env:USERPROFILE\Documents" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Downloads
			# Extract the localized "Downloads" string from shell32.dll
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21798), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Yes -Default 1 -AddSkip

				switch ($Choice)
				{
					$Yes
					{
						Set-UserShellFolder -UserFolder Downloads -FolderPath "$env:USERPROFILE\Downloads" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Music
			# Extract the localized "Music" string from shell32.dll
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21790), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Yes -Default 1 -AddSkip

				switch ($Choice)
				{
					$Yes
					{
						Set-UserShellFolder -UserFolder Music -FolderPath "$env:USERPROFILE\Music" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Pictures
			# Extract the localized "Pictures" string from shell32.dll
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21779), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Yes -Default 1 -AddSkip

				switch ($Choice)
				{
					$Yes
					{
						Set-UserShellFolder -UserFolder Pictures -FolderPath "$env:USERPROFILE\Pictures" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)

			# Videos
			# Extract the localized "Pictures" string from shell32.dll
			$CurrentUserFolderLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video"
			Write-Verbose -Message ($Localization.CurrentUserFolderLocation -f [WinAPI.GetStrings]::GetString(21791), $CurrentUserFolderLocation) -Verbose
			LogWarning $Localization.FilesWontBeMoved

			do
			{
				$Choice = Show-Menu -Menu $Yes -Default 1 -AddSkip

				switch ($Choice)
				{
					$Yes
					{
						Set-UserShellFolder -UserFolder Videos -FolderPath "$env:USERPROFILE\Videos" | Out-Null
					}
					$Skip
					{
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
					$KeyboardArrows {}
				}
			}
			until ($Choice -ne $KeyboardArrows)
		}
	}
}

<#
	.SYNOPSIS
	Use the latest installed .NET runtime for all apps usage

	.PARAMETER Enable
	Use the latest installed .NET runtime for all apps

	.PARAMETER Disable
	Do not use the latest installed .NET runtime for all apps (default value)

	.EXAMPLE
	LatestInstalled.NET -Enable

	.EXAMPLE
	LatestInstalled.NET -Disable

	.NOTES
	Machine-wide
#>
function LatestInstalled.NET
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling the use of the latest installed .NET runtime for all apps"
			LogInfo "Enabling the use of the latest installed .NET runtime for all apps"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-Host "Disabling the use of the latest installed .NET runtime for all apps -" -NoNewline
			LogInfo "Disabling the use of the latest installed .NET runtime for all apps"
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Force -ErrorAction Ignore | Out-Null
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	The location to save screenshots by pressing Win+PrtScr

	.PARAMETER Desktop
	Save screenshots by pressing Win+PrtScr on the Desktop

	.PARAMETER Default
	Save screenshots by pressing Win+PrtScr in the Pictures folder (default value)

	.EXAMPLE
	WinPrtScrFolder -Desktop

	.EXAMPLE
	WinPrtScrFolder -Default

	.NOTES
	The function will be applied only if the preset is configured to remove the OneDrive application, or the app was already uninstalled
	otherwise the backup functionality for the "Desktop" and "Pictures" folders in OneDrive breaks

	.NOTES
	Current user
#>
function WinPrtScrFolder
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Desktop"
		)]
		[switch]
		$Desktop,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Desktop"
		{
			Write-ConsoleStatus -Action "Setting the location to save screenshots by pressing Win+PrtScr to the Desktop"
			LogInfo "Setting the location to save screenshots by pressing Win+PrtScr to the Desktop"
			# Checking whether user is logged into OneDrive (Microsoft account)
			$UserEmail = Get-ItemProperty -Path HKCU:\Software\Microsoft\OneDrive\Accounts\Personal -Name UserEmail -ErrorAction SilentlyContinue
			if ($UserEmail)
			{
				LogError $Localization.OneDriveWarning
				LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

				return
			}

			# Checking how the script was invoked: via a preset or Functions.ps1
			# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-variable
			# This function works only if OneDrive was already uninstalled, or user is intended to uninstall "OneDrive -Uninstall" within commandline
			$PresetName = (Get-Variable -Name MyInvocation -Scope Script).Value.PSCommandPath
			$PSCallStack = (Get-PSCallStack).Position.Text
			$OneDriveInstalled = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -Force -ErrorAction Ignore

			# Checking whether function was called from Functions.ps1
			if ($PresetName -match "Functions.ps1")
			{
				# Checking whether command contains "WinPrtScrFolder -Desktop"
				if ($PSCallStack -match "WinPrtScrFolder -Desktop")
				{
					# Checking whether other commands contains "OneDrive -Uninstall" which means that user is intended to uninstall "OneDrive -Uninstall", or OneDrive was uinstalled
					if (($PSCallStack -match "OneDrive -Uninstall") -or (-not $OneDriveInstalled))
					{
						$DesktopFolder = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
						New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}" -PropertyType ExpandString -Value $DesktopFolder -Force | Out-Null
					}
					else
					{
						LogError ($Localization.OneDriveWarning -f $MyInvocation.Line.Trim())
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
				}
			}
			else
			{
				# Checking whether function was called from Win10_11Util.ps1, and preset contains the "OneDrive -Uninstall" string is uncommented that means OneDrive will be unistalled
				if (Select-String -Path $PresetName -Pattern "OneDrive -Uninstall" -SimpleMatch)
				{
					# Checking whether string exists and is uncommented
					$IsOneDriveToUninstall = (Select-String -Path $PresetName -Pattern "OneDrive -Uninstall" -SimpleMatch).Line.StartsWith("#") -eq $false
					# Checking whether string exists and is uncommented, or OneDrive was uninstalled, or user called "OneDrive -Uninstall" from Win10_11Util.ps1 alongside with "WinPrtScrFolder -Desktop"
					if ($IsOneDriveToUninstall -or (-not $OneDriveInstalled) -or ($PSCallStack -match "OneDrive -Uninstall"))
					{
						$DesktopFolder = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
						New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}" -PropertyType ExpandString -Value $DesktopFolder -Force | Out-Null
					}
					else
					{
						LogError ($Localization.OneDriveWarning -f $MyInvocation.Line.Trim())
						LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
					}
				}
			}
			Write-ConsoleStatus -Status success
		}
		"Default"
		{
			Write-ConsoleStatus -Action "Setting the location to save screenshots by pressing Win+PrtScr to the default one"
			LogInfo "Setting the location to save screenshots by pressing Win+PrtScr to the default one"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}" -Force -ErrorAction Ignore | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Recommended troubleshooter preferences

	.PARAMETER Automatically
	Run troubleshooter automatically, then notify me

	.PARAMETER Default
	Ask me before running troubleshooter (default value)

	.EXAMPLE
	RecommendedTroubleshooting -Automatically

	.EXAMPLE
	RecommendedTroubleshooting -Default

	.NOTES
	In order this feature to work Windows level of diagnostic data gathering will be set to "Optional diagnostic data" and the error reporting feature will be turned on

	.NOTES
	Machine-wide
#>
function RecommendedTroubleshooting
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Automatically"
		)]
		[switch]
		$Automatically,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name MaxTelemetryAllowed -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Name ShowedToastAtLevel -Force -ErrorAction SilentlyContinue | Out-Null

	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type CLEAR | Out-Null

	# Turn on Windows Error Reporting
	Get-ScheduledTask -TaskName QueueReporting -ErrorAction SilentlyContinue | Enable-ScheduledTask | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Force -ErrorAction SilentlyContinue | Out-Null

	Get-Service -Name WerSvc | Set-Service -StartupType Manual | Out-Null
	Get-Service -Name WerSvc | Start-Service | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Automatically"
		{
			Write-ConsoleStatus -Action "Setting troubleshooter preferences to automatically run"
			LogInfo "Setting troubleshooter preferences to automatically run"
			if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation))
			{
				New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force | Out-Null
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 3 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Default"
		{
			Write-ConsoleStatus -Action "Setting troubleshooter preferences to ask before running"
			LogInfo "Setting troubleshooter preferences to ask before running"
			if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation))
			{
				New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force | Out-Null
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 2 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Reserved storage

	.PARAMETER Disable
	Disable and delete reserved storage after the next update installation

	.PARAMETER Enable
	Enable reserved storage after the next update installation

	.EXAMPLE
	ReservedStorage -Disable

	.EXAMPLE
	ReservedStorage -Enable

	.NOTES
	Current user
#>
function ReservedStorage
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
			try
			{
				Write-ConsoleStatus -Action "Disabling reserved storage"
				LogInfo "Disabling reserved storage"
				Set-WindowsReservedStorageState -State Disabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch [System.Runtime.InteropServices.COMException]
			{
				LogError ($Localization.ReservedStorageIsInUse -f $MyInvocation.Line.Trim())
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling reserved storage"
			LogInfo "Enabling reserved storage"
			Set-WindowsReservedStorageState -State Enabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Help look up via F1

	.PARAMETER Disable
	Disable help lookup via F1

	.PARAMETER Enable
	Enable help lookup via F1 (default value)

	.EXAMPLE
	F1HelpPage -Disable

	.EXAMPLE
	F1HelpPage -Enable

	.NOTES
	Current user
#>
function F1HelpPage
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
			Write-ConsoleStatus -Action "Disabling help look up via F1"
			LogInfo "Disabling help look up via F1"
			if (-not (Test-Path -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
			{
				New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling help look up via F1"
			LogInfo "Enabling help look up via F1"
			Remove-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}" -Recurse -Force -ErrorAction Ignore | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Num Lock at startup

	.PARAMETER Enable
	Enable Num Lock at startup

	.PARAMETER Disable
	Disable Num Lock at startup (default value)

	.EXAMPLE
	NumLock -Enable

	.EXAMPLE
	NumLock -Disable

	.NOTES
	Current user
#>
function NumLock
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Num Lock at startup"
			LogInfo "Enabling Num Lock at startup"
			New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Num Lock at startup"
			LogInfo "Disabling Num Lock at startup"
			New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483648 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Caps Lock

	.PARAMETER Disable
	Disable Caps Lock

	.PARAMETER Enable
	Enable Caps Lock (default value)

	.EXAMPLE
	CapsLock -Disable

	.EXAMPLE
	CapsLock -Enable

	.NOTES
	Machine-wide
#>
function CapsLock
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

	Remove-ItemProperty -Path "HKCU:\Keyboard Layout" -Name Attributes -Force -ErrorAction SilentlyContinue | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Caps Lock"
			LogInfo "Disabling Caps Lock"
			New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" -Name "Scancode Map" -PropertyType Binary -Value ([byte[]](0,0,0,0,0,0,0,0,2,0,0,0,0,0,58,0,0,0,0,0)) -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Caps Lock"
			LogInfo "Enabling Caps Lock"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" -Name "Scancode Map" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	The shortcut to start Sticky Keys

	.PARAMETER Disable
	Turn off Sticky keys by pressing the Shift key 5 times

	.PARAMETER Enable
	Turn on Sticky keys by pressing the Shift key 5 times (default value)

	.EXAMPLE
	StickyShift -Disable

	.EXAMPLE
	StickyShift -Enable

	.NOTES
	Current user
#>
function StickyShift
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
			Write-ConsoleStatus -Action "Disabling Sticky Shift"
			LogInfo "Disabling Sticky Shift"
			New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Sticky Shift"
			LogInfo "Enabling Sticky Shift"
			New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 510 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	AutoPlay for all media and devices

	.PARAMETER Disable
	Don't use AutoPlay for all media and devices

	.PARAMETER Enable
	Use AutoPlay for all media and devices (default value)

	.EXAMPLE
	Autoplay -Disable

	.EXAMPLE
	Autoplay -Enable

	.NOTES
	Current user
#>
function Autoplay
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer, HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Type CLEAR | Out-Null
	Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling AutoPlay for all media and devices"
			LogInfo "Disabling AutoPlay for all media and devices"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling AutoPlay for all media and devices"
			LogInfo "Enabling AutoPlay for all media and devices"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 0 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Restart apps after signing in

	.PARAMETER Enable
	Automatically saving my restartable apps and restart them when I sign back in

	.PARAMETER Disable
	Turn off automatically saving my restartable apps and restart them when I sign back in (default value)

	.EXAMPLE
	SaveRestartableApps -Enable

	.EXAMPLE
	SaveRestartableApps -Disable

	.NOTES
	Current user
#>
function SaveRestartableApps
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling saving restartable apps and restarting them after signing in"
			LogInfo "Enabling saving restartable apps and restarting them after signing in"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name RestartApps -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling saving restartable apps and restarting them after signing in"
			LogInfo "Disabling saving restartable apps and restarting them after signing in"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name RestartApps -PropertyType DWord -Value 0 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Network Discovery File and Printers Sharing

	.PARAMETER Enable
	Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks

	.PARAMETER Disable
	Disable "Network Discovery" and "File and Printers Sharing" for workgroup networks (default value)

	.EXAMPLE
	NetworkDiscovery -Enable

	.EXAMPLE
	NetworkDiscovery -Disable

	.NOTES
	Current user
#>
function NetworkDiscovery
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	$FirewallRules = @(
		# File and printer sharing
		"@FirewallAPI.dll,-32752",

		# Network discovery
		"@FirewallAPI.dll,-28502"
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Network Discovery and File and Printers Sharing"
			LogInfo "Enabling Network Discovery and File and Printers Sharing"
			Set-NetFirewallRule -Group $FirewallRules -Profile Private -Enabled True | Out-Null
			Set-NetFirewallRule -Profile Private -Name FPS-SMB-In-TCP -Enabled True | Out-Null
			Set-NetConnectionProfile -NetworkCategory Private | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Network Discovery and File and Printers Sharing"
			LogInfo "Disabling Network Discovery and File and Printers Sharing"
			Set-NetFirewallRule -Group $FirewallRules -Profile Private -Enabled False | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Associate a file extension with a desktop program or ProgID.

	.DESCRIPTION
	Creates or updates the file association data for the requested extension and
	optionally sets a custom icon for the associated program.

	.PARAMETER ProgramPath
	The executable path or ProgID to associate with the file extension.

	.PARAMETER Extension
	The file extension to associate, including the leading dot.

	.PARAMETER Icon
	Optional icon resource to use for the file association.

	.EXAMPLE
	Set-Association -ProgramPath '%ProgramFiles%\\Notepad++\\notepad++.exe' -Extension .txt

	.NOTES
	Current user
#>
function Set-Association
{
	[CmdletBinding()]
	Param
	(
		[Parameter(
			Mandatory = $true,
			Position = 0
		)]
		[string]
		$ProgramPath,

		[Parameter(
			Mandatory = $true,
			Position = 1
		)]
		[string]
		$Extension,

		[Parameter(
			Mandatory = $false,
			Position = 2
		)]
		[string]
		$Icon
	)

	$TempPowerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_temp.exe"
	$AssociationFailed = $false

	# Suppress all output from the entire function
	try
	{
	$null = @(
		Write-ConsoleStatus -Action "Associating $Extension files with $ProgramPath"
		LogInfo "Associating $Extension files with $ProgramPath"

		# Microsoft has blocked write access to UserChoice key for .pdf extention and http/https protocols with KB5034765 release, so we have to write values with a copy of powershell.exe to bypass a UCPD driver restrictions
		# UCPD driver tracks all executables to block the access to the registry so all registry records will be made within powershell_temp.exe in this function just in case
		Copy-Item -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Destination $TempPowerShellPath -Force -ErrorAction Stop 2>&1 | Out-Null
		if (-not (Test-Path -Path $TempPowerShellPath))
		{
			throw "powershell_temp.exe was not created"
		}

		$ProgramPath = [System.Environment]::ExpandEnvironmentVariables($ProgramPath)

		if ($ProgramPath.Contains(":"))
		{
			# Cut string to get executable path to check
			$ProgramPath = $ProgramPath.Substring(0, $ProgramPath.IndexOf(".exe") + 4).Trim('"')
			if (-not (Test-Path -Path $ProgramPath))
			{
				# We cannot call here $MyInvocation.Line.Trim() to print function with error
				if ($Icon)
				{
					LogError ($Localization.RestartFunction -f "Set-Association -ProgramPath `"$ProgramPath`" -Extension $Extension -Icon `"$Icon`"")
				}
				else
				{
					LogError ($Localization.RestartFunction -f "Set-Association -ProgramPath `"$ProgramPath`" -Extension $Extension")
				}
				throw "Program path was not found: $ProgramPath"
			}
		}
		else
		{
			# ProgId is not registered
			if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\$ProgramPath"))
			{
				# We cannot call here $MyInvocation.Line.Trim() to print function with error
				if ($Icon)
				{
					LogError ($Localization.RestartFunction -f "Set-Association -ProgramPath `"$ProgramPath`" -Extension `"$Extension`" -Icon `"$Icon`"")
				}
				else
				{
					LogError ($Localization.RestartFunction -f "Set-Association -ProgramPath `"$ProgramPath`" -Extension `"$Extension`"")
				}
				throw "Program path or ProgID was not found: $ProgramPath"
			}
		}

		if ($Icon)
		{
			$Icon = [System.Environment]::ExpandEnvironmentVariables($Icon)
		}

		if (Test-Path -Path $ProgramPath)
		{
			# Generate ProgId
			$ProgId = (Get-Item -Path $ProgramPath).BaseName + $Extension.ToUpper()
		}
		else
		{
			$ProgId = $ProgramPath
		}

		#region functions
		$Signature = @{
			Namespace          = "WinAPI"
			Name               = "Action"
			Language           = "CSharp"
			UsingNamespace     = "System.Text", "System.Security.AccessControl", "Microsoft.Win32"
			CompilerParameters = $CompilerParameters
			MemberDefinition   = @"
[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);

[DllImport("advapi32.dll", SetLastError = true)]
private static extern int RegCloseKey(UIntPtr hKey);

[DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);

[DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKey", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
private static extern int RegQueryInfoKey(UIntPtr hkey, out StringBuilder lpClass, ref uint lpcbClass, IntPtr lpReserved,
	out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen, out uint lpcValues, out uint lpcbMaxValueNameLen,
	out uint lpcbMaxValueLen, out uint lpcbSecurityDescriptor, ref System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime);

[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

[DllImport("kernel32.dll", ExactSpelling = true)]
internal static extern IntPtr GetCurrentProcess();

[DllImport("advapi32.dll", SetLastError = true)]
internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
private static extern int RegLoadKey(uint hKey, string lpSubKey, string lpFile);

[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
private static extern int RegUnLoadKey(uint hKey, string lpSubKey);

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct TokPriv1Luid
{
	public int Count;
	public long Luid;
	public int Attr;
}

public static void DeleteKey(RegistryHive registryHive, string subkey)
{
	UIntPtr hKey = UIntPtr.Zero;

	try
	{
		var hive = new UIntPtr(unchecked((uint)registryHive));
		RegOpenKeyEx(hive, subkey, 0, 0x20019, out hKey);
		RegDeleteKey(hive, subkey);
	}
	finally
	{
		if (hKey != UIntPtr.Zero)
		{
			RegCloseKey(hKey);
		}
	}
}

private static DateTime ToDateTime(System.Runtime.InteropServices.ComTypes.FILETIME ft)
{
	IntPtr buf = IntPtr.Zero;
	try
	{
		long[] longArray = new long[1];
		int cb = Marshal.SizeOf(ft);
		buf = Marshal.AllocHGlobal(cb);
		Marshal.StructureToPtr(ft, buf, false);
		Marshal.Copy(buf, longArray, 0, 1);
		return DateTime.FromFileTime(longArray[0]);
	}
	finally
	{
		if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
	}
}

public static DateTime? GetLastModified(RegistryHive registryHive, string subKey)
{
	var lastModified = new System.Runtime.InteropServices.ComTypes.FILETIME();
	var lpcbClass = new uint();
	var lpReserved = new IntPtr();
	UIntPtr hKey = UIntPtr.Zero;

	try
	{
		try
		{
			var hive = new UIntPtr(unchecked((uint)registryHive));
			if (RegOpenKeyEx(hive, subKey, 0, (int)RegistryRights.ReadKey, out hKey) != 0)
			{
				return null;
			}

			uint lpcbSubKeys;
			uint lpcbMaxKeyLen;
			uint lpcbMaxClassLen;
			uint lpcValues;
			uint maxValueName;
			uint maxValueLen;
			uint securityDescriptor;
			StringBuilder sb;

			if (RegQueryInfoKey(hKey, out sb, ref lpcbClass, lpReserved, out lpcbSubKeys, out lpcbMaxKeyLen, out lpcbMaxClassLen,
			out lpcValues, out maxValueName, out maxValueLen, out securityDescriptor, ref lastModified) != 0)
			{
				return null;
			}

			var result = ToDateTime(lastModified);
			return result;
		}
		finally
		{
			if (hKey != UIntPtr.Zero)
			{
				RegCloseKey(hKey);
			}
		}
	}
	catch (Exception)
	{
		return null;
	}
}

internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
internal const int TOKEN_QUERY = 0x00000008;
internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

public enum RegistryHives : uint
{
	HKEY_USERS = 0x80000003,
	HKEY_LOCAL_MACHINE = 0x80000002
}

public static void AddPrivilege(string privilege)
{
	bool retVal;
	TokPriv1Luid tp;
	IntPtr hproc = GetCurrentProcess();
	IntPtr htok = IntPtr.Zero;
	retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
	tp.Count = 1;
	tp.Luid = 0;
	tp.Attr = SE_PRIVILEGE_ENABLED;
	retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
	retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
	///return retVal;
}

public static int LoadHive(RegistryHives hive, string subKey, string filePath)
{
	AddPrivilege("SeRestorePrivilege");
	AddPrivilege("SeBackupPrivilege");

	uint regHive = (uint)hive;
	int result = RegLoadKey(regHive, subKey, filePath);

	return result;
}

public static int UnloadHive(RegistryHives hive, string subKey)
{
	AddPrivilege("SeRestorePrivilege");
	AddPrivilege("SeBackupPrivilege");

	uint regHive = (uint)hive;
	int result = RegUnLoadKey(regHive, subKey);

	return result;
}
"@
		}

		if (-not ("WinAPI.Action" -as [type]))
		{
			Add-Type @Signature -ErrorAction SilentlyContinue 2>&1 | Out-Null
		}

		Clear-Variable -Name RegisteredProgIDs -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null

		[array]$Script:RegisteredProgIDs = @()

		function Write-ExtensionKeys
		{
			Param
			(
				[Parameter(
					Mandatory = $true,
					Position = 0
				)]
				[string]
				$ProgId,

				[Parameter(
					Mandatory = $true,
					Position = 1
				)]
				[string]
				$Extension
			)

			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			$OrigProgID = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$Extension", "", $null)
			if ($OrigProgID)
			{
				# Save ProgIds history with extensions or protocols for the system ProgId
				$Script:RegisteredProgIDs += $OrigProgID
			}

			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$Extension", "", $null) -ne "")
			{
				# Save possible ProgIds history with extension
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts -Name "$($ProgID)_$($Extension)" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			$Name = "{0}_$($Extension)" -f (Split-Path -Path $ProgId -Leaf)
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts -Name $Name -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null

			if ("$($ProgID)_$($Extension)" -ne $Name)
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts -Name "$($ProgID)_$($Extension)" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			# If ProgId doesn't exist set the specified ProgId for the extensions
			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if (-not [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$Extension", "", $null))
			{
				if (-not (Test-Path -Path "HKCU:\Software\Classes\$Extension"))
				{
					New-Item -Path "HKCU:\Software\Classes\$Extension" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Classes\$Extension" -Name "(default)" -PropertyType String -Value $ProgId -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			# Set the specified ProgId in the possible options for the assignment
			if (-not (Test-Path -Path "HKCU:\Software\Classes\$Extension\OpenWithProgids"))
			{
				New-Item -Path "HKCU:\Software\Classes\$Extension\OpenWithProgids" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Classes\$Extension\OpenWithProgids" -Name $ProgId -PropertyType None -Value ([byte[]]@()) -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null

			# Set the system ProgId to the extension parameters for File Explorer to the possible options for the assignment, and if absent set the specified ProgId
			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if ($OrigProgID)
			{
				if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids"))
				{
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids" -Name $OrigProgID -PropertyType None -Value ([byte[]]@()) -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			if (-not (Test-Path -Path "HKCU:\Software\Classes\$Extension\OpenWithProgids"))
			{
				New-Item -Path "HKCU:\Software\Classes\$Extension\OpenWithProgids" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Classes\$Extension\OpenWithProgids" -Name $ProgID -PropertyType None -Value ([byte[]]@()) -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null

			# A small pause added to complete all operations, unless sometimes PowerShell has not time to clear reguistry permissions
			Start-Sleep -Seconds 1

			# Removing the UserChoice key
			[WinAPI.Action]::DeleteKey([Microsoft.Win32.RegistryHive]::CurrentUser, "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice")
			Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null

			# Setting parameters in UserChoice. The key is being autocreated
			if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"))
			{
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			# We need to remove DENY permission set for user before setting a value
			if (@(".pdf", "http", "https") -contains $Extension)
			{
				# https://powertoe.wordpress.com/2010/08/28/controlling-registry-acl-permissions-with-powershell/
				$Key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
				$ACL = $key.GetAccessControl()
				$Principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				# https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights
				$Rule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList ($Principal,"FullControl","Deny")
				$ACL.RemoveAccessRule($Rule)
				$Key.SetAccessControl($ACL)

				# We need to use here an approach with "-Command & {}" as there's a variable inside
				& $TempPowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& { New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice' -Name ProgId -PropertyType String -Value '$ProgID' -Force -ErrorAction Stop | Out-Null }" 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0)
				{
					throw "powershell_temp.exe returned exit code $LASTEXITCODE while setting ProgId for $Extension"
				}
			}
			else
			{
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Name ProgId -PropertyType String -Value $ProgID -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			# Getting a hash based on the time of the section's last modification. After creating and setting the first parameter
			$ProgHash = Get-Hash -ProgId $ProgId -Extension $Extension -SubKey "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"

			if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"))
			{
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			if (@(".pdf", "http", "https") -contains $Extension)
			{
				# We need to use here an approach with "-Command & {}" as there's a variable inside
				& $TempPowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& { New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice' -Name Hash -PropertyType String -Value '$ProgHash' -Force -ErrorAction Stop | Out-Null }" 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0)
				{
					throw "powershell_temp.exe returned exit code $LASTEXITCODE while setting Hash for $Extension"
				}
			}
			else
			{
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Name Hash -PropertyType String -Value $ProgHash -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			# Setting a block on changing the UserChoice section
			# We have to use OpenSubKey() due to "Set-StrictMode -Version Latest"
			$OpenSubKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice", "ReadWriteSubTree", "TakeOwnership")
			if ($OpenSubKey)
			{
				$Acl = [System.Security.AccessControl.RegistrySecurity]::new()
				# Get current user SID
				$UserSID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
				$Acl.SetSecurityDescriptorSddlForm("O:$UserSID`G:$UserSID`D:AI(D;;DC;;;$UserSID)")
				$OpenSubKey.SetAccessControl($Acl)
				$OpenSubKey.Close()
			}
		}

		function Write-AdditionalKeys
		{
			Param
			(
				[Parameter(
					Mandatory = $true,
					Position = 0
				)]
				[string]
				$ProgId,

				[Parameter(
					Mandatory = $true,
					Position = 1
				)]
				[string]
				$Extension
			)

			# If there is the system extension ProgId, write it to the already configured by default
			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$Extension", "", $null))
			{
				if (-not (Test-Path -Path Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\FileAssociations\ProgIds))
				{
					New-Item -Path Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\FileAssociations\ProgIds -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
				}
				New-ItemProperty -Path Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\FileAssociations\ProgIds -Name "_$($Extension)" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			# Setting 'NoOpenWith' for all registered the extension ProgIDs
			# We have to check everything due to "Set-StrictMode -Version Latest"
			if (Get-Item -Path "Registry::HKEY_CLASSES_ROOT\$Extension\OpenWithProgids" -ErrorAction SilentlyContinue)
			{
				[psobject]$OpenSubkey = (Get-Item -Path "Registry::HKEY_CLASSES_ROOT\$Extension\OpenWithProgids" -ErrorAction SilentlyContinue).Property
				if ($OpenSubkey)
				{
					foreach ($AppxProgID in ($OpenSubkey | Where-Object -FilterScript {$_ -match "AppX"}))
					{
						# If an app is installed
						if (Get-ItemPropertyValue -Path "HKCU:\Software\Classes\$AppxProgID\Shell\open" -Name PackageId -ErrorAction SilentlyContinue)
						{
							# If the specified ProgId is equal to UWP installed ProgId
							if ($ProgId -eq $AppxProgID)
							{
								# Remove association limitations for this UWP apps
								Remove-ItemProperty -Path "HKCU:\Software\Classes\$AppxProgID" -Name NoOpenWith -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
								Remove-ItemProperty -Path "HKCU:\Software\Classes\$AppxProgID" -Name NoStaticDefaultVerb -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
							}
							else
							{
								New-ItemProperty -Path "HKCU:\Software\Classes\$AppxProgID" -Name NoOpenWith -PropertyType String -Value "" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
							}

							$Script:RegisteredProgIDs += $AppxProgID
						}
					}
				}
			}

			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\KindMap", $Extension, $null))
			{
				$picture = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\KindMap -Name $Extension -ErrorAction Ignore).$Extension
			}
			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PBrush\CLSID", "", $null))
			{
				$PBrush = (Get-ItemProperty -Path HKLM:\SOFTWARE\Classes\PBrush\CLSID -Name "(default)" -ErrorAction Ignore)."(default)"
			}

			# We have to check everything due to "Set-StrictMode -Version Latest"
			if (Get-Variable -Name picture -ErrorAction Ignore)
			{
				if (($picture -eq "picture") -and $PBrush)
				{
					New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts -Name "PBrush_$($Extension)" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
				}
			}

			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			if (([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\KindMap", $Extension, $null)) -eq "picture")
			{
				$Script:RegisteredProgIDs += "PBrush"
			}

			if ($Extension.Contains("."))
			{
				[string]$Associations = "FileAssociations"
			}
			else
			{
				[string]$Associations = "UrlAssociations"
			}

			foreach ($Item in @((Get-Item -Path "HKLM:\SOFTWARE\RegisteredApplications" -ErrorAction SilentlyContinue).Property))
			{
				$Subkey = (Get-ItemProperty -Path "HKLM:\SOFTWARE\RegisteredApplications" -Name $Item -ErrorAction Ignore).$Item
				if ($Subkey)
				{
					if (Test-Path -Path "HKLM:\$Subkey\$Associations")
					{
						$isProgID = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\$Subkey\$Associations", $Extension, $null)
						if ($isProgID)
						{
							$Script:RegisteredProgIDs += $isProgID
						}
					}
				}
			}

			Clear-Variable -Name UserRegisteredProgIDs -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			[array]$UserRegisteredProgIDs = @()

			foreach ($Item in (Get-Item -Path "HKCU:\Software\RegisteredApplications" -ErrorAction SilentlyContinue).Property)
			{
				$Subkey = (Get-ItemProperty -Path "HKCU:\Software\RegisteredApplications" -Name $Item -ErrorAction SilentlyContinue).$Item
				if ($Subkey)
				{
					if (Test-Path -Path "HKCU:\$Subkey\$Associations")
					{
						$isProgID = [Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\$Subkey\$Associations", $Extension, $null)
						if ($isProgID)
						{
							$UserRegisteredProgIDs += $isProgID
						}
					}
				}
			}

			$UserRegisteredProgIDs = ($Script:RegisteredProgIDs + $UserRegisteredProgIDs | Sort-Object -Unique)
			foreach ($UserProgID in $UserRegisteredProgIDs)
			{
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name "$($UserProgID)_$($Extension)" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
		}

		function Get-Hash
		{
			[CmdletBinding()]
			[OutputType([string])]
			Param
			(
				[Parameter(
					Mandatory = $true,
					Position = 0
				)]
				[string]
				$ProgId,

				[Parameter(
					Mandatory = $true,
					Position = 1
				)]
				[string]
				$Extension,

				[Parameter(
					Mandatory = $true,
					Position = 2
				)]
				[string]
				$SubKey
			)

			$Signature = @{
				Namespace          = "WinAPI"
				Name               = "PatentHash"
				Language           = "CSharp"
				CompilerParameters = $CompilerParameters
				MemberDefinition   = @"
public static uint[] WordSwap(byte[] a, int sz, byte[] md5)
{
	if (sz < 2 || (sz & 1) == 1)
	{
		throw new ArgumentException(String.Format("Invalid input size: {0}", sz), "sz");
	}

	unchecked
	{
		uint o1 = 0;
		uint o2 = 0;
		int ta = 0;
		int ts = sz;
		int ti = ((sz - 2) >> 1) + 1;

		uint c0 = (BitConverter.ToUInt32(md5, 0) | 1) + 0x69FB0000;
		uint c1 = (BitConverter.ToUInt32(md5, 4) | 1) + 0x13DB0000;

		for (uint i = (uint)ti; i > 0; i--)
		{
			uint n = BitConverter.ToUInt32(a, ta) + o1;
			ta += 8;
			ts -= 2;

			uint v1 = 0x79F8A395 * (n * c0 - 0x10FA9605 * (n >> 16)) + 0x689B6B9F * ((n * c0 - 0x10FA9605 * (n >> 16)) >> 16);
			uint v2 = 0xEA970001 * v1 - 0x3C101569 * (v1 >> 16);
			uint v3 = BitConverter.ToUInt32(a, ta - 4) + v2;
			uint v4 = v3 * c1 - 0x3CE8EC25 * (v3 >> 16);
			uint v5 = 0x59C3AF2D * v4 - 0x2232E0F1 * (v4 >> 16);

			o1 = 0x1EC90001 * v5 + 0x35BD1EC9 * (v5 >> 16);
			o2 += o1 + v2;
		}

		if (ts == 1)
		{
			uint n = BitConverter.ToUInt32(a, ta) + o1;

			uint v1 = n * c0 - 0x10FA9605 * (n >> 16);
			uint v2 = 0xEA970001 * (0x79F8A395 * v1 + 0x689B6B9F * (v1 >> 16)) - 0x3C101569 * ((0x79F8A395 * v1 + 0x689B6B9F * (v1 >> 16)) >> 16);
			uint v3 = v2 * c1 - 0x3CE8EC25 * (v2 >> 16);

			o1 = 0x1EC90001 * (0x59C3AF2D * v3 - 0x2232E0F1 * (v3 >> 16)) + 0x35BD1EC9 * ((0x59C3AF2D * v3 - 0x2232E0F1 * (v3 >> 16)) >> 16);
			o2 += o1 + v2;
		}

		uint[] ret = new uint[2];
		ret[0] = o1;
		ret[1] = o2;
		return ret;
	}
}

public static uint[] Reversible(byte[] a, int sz, byte[] md5)
{
	if (sz < 2 || (sz & 1) == 1)
	{
		throw new ArgumentException(String.Format("Invalid input size: {0}", sz), "sz");
	}

	unchecked
	{
		uint o1 = 0;
		uint o2 = 0;
		int ta = 0;
		int ts = sz;
		int ti = ((sz - 2) >> 1) + 1;

		uint c0 = BitConverter.ToUInt32(md5, 0) | 1;
		uint c1 = BitConverter.ToUInt32(md5, 4) | 1;

		for (uint i = (uint)ti; i > 0; i--)
		{
			uint n = (BitConverter.ToUInt32(a, ta) + o1) * c0;
			n = 0xB1110000 * n - 0x30674EEF * (n >> 16);
			ta += 8;
			ts -= 2;

			uint v1 = 0x5B9F0000 * n - 0x78F7A461 * (n >> 16);
			uint v2 = 0x1D830000 * (0x12CEB96D * (v1 >> 16) - 0x46930000 * v1) + 0x257E1D83 * ((0x12CEB96D * (v1 >> 16) - 0x46930000 * v1) >> 16);
			uint v3 = BitConverter.ToUInt32(a, ta - 4) + v2;

			uint v4 = 0x16F50000 * c1 * v3 - 0x5D8BE90B * (c1 * v3 >> 16);
			uint v5 = 0x2B890000 * (0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16)) + 0x7C932B89 * ((0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16)) >> 16);

			o1 = 0x9F690000 * v5 - 0x405B6097 * (v5 >> 16);
			o2 += o1 + v2;
		}

		if (ts == 1)
		{
			uint n = BitConverter.ToUInt32(a, ta) + o1;

			uint v1 = 0xB1110000 * c0 * n - 0x30674EEF * ((c0 * n) >> 16);
			uint v2 = 0x5B9F0000 * v1 - 0x78F7A461 * (v1 >> 16);
			uint v3 = 0x1D830000 * (0x12CEB96D * (v2 >> 16) - 0x46930000 * v2) + 0x257E1D83 * ((0x12CEB96D * (v2 >> 16) - 0x46930000 * v2) >> 16);
			uint v4 = 0x16F50000 * c1 * v3 - 0x5D8BE90B * ((c1 * v3) >> 16);
			uint v5 = 0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16);
			o1 = 0x9F690000 * (0x2B890000 * v5 + 0x7C932B89 * (v5 >> 16)) - 0x405B6097 * ((0x2B890000 * v5 + 0x7C932B89 * (v5 >> 16)) >> 16);
			o2 += o1 + v2;
		}

		uint[] ret = new uint[2];
		ret[0] = o1;
		ret[1] = o2;
		return ret;
	}
}

public static long MakeLong(uint left, uint right)
{
	return (long)left << 32 | (long)right;
}
"@
			}

			if (-not ("WinAPI.PatentHash" -as [type]))
			{
				Add-Type @Signature -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			function Get-KeyLastWriteTime ($SubKey)
			{
				$LastModified = [WinAPI.Action]::GetLastModified([Microsoft.Win32.RegistryHive]::CurrentUser,$SubKey)
				$FileTime = ([DateTime]::New($LastModified.Year, $LastModified.Month, $LastModified.Day, $LastModified.Hour, $LastModified.Minute, 0, $LastModified.Kind)).ToFileTime()

				return [string]::Format("{0:x8}{1:x8}", $FileTime -shr 32, $FileTime -band [uint32]::MaxValue)
			}

			function Get-DataArray
			{
				[OutputType([array])]

				# Secret static string stored in %SystemRoot%\SysWOW64\shell32.dll
				$userExperience        = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
				# Get user SID
				$userSID               = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
				$KeyLastWriteTime      = Get-KeyLastWriteTime -SubKey $SubKey
				$baseInfo              = ("{0}{1}{2}{3}{4}" -f $Extension, $userSID, $ProgId, $KeyLastWriteTime, $userExperience).ToLowerInvariant()
				$StringToUTF16LEArray  = [System.Collections.ArrayList]@([System.Text.Encoding]::Unicode.GetBytes($baseInfo))
				$StringToUTF16LEArray += (0,0)

				return $StringToUTF16LEArray
			}

			function Get-PatentHash
			{
				[OutputType([string])]
				param
				(
					[Parameter(Mandatory = $true)]
					[byte[]]
					$Array,

					[Parameter(Mandatory = $true)]
					[byte[]]
					$MD5
				)

				$Size = $Array.Count
				$ShiftedSize = ($Size -shr 2) - ($Size -shr 2 -band 1) * 1

				[uint32[]]$Array1 = [WinAPI.PatentHash]::WordSwap($Array, [int]$ShiftedSize, $MD5)
				[uint32[]]$Array2 = [WinAPI.PatentHash]::Reversible($Array, [int]$ShiftedSize, $MD5)

				$Ret = [WinAPI.PatentHash]::MakeLong($Array1[1] -bxor $Array2[1], $Array1[0] -bxor $Array2[0])

				return [System.Convert]::ToBase64String([System.BitConverter]::GetBytes([Int64]$Ret))
			}

			$DataArray = Get-DataArray
			$DataMD5   = [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash($DataArray)
			$Hash      = Get-PatentHash -Array $DataArray -MD5 $DataMD5

			return $Hash
		}
		#endregion functions

		# Register %1 argument if ProgId exists as an executable file
		if (Test-Path -Path $ProgramPath)
		{
			if (-not (Test-Path -Path "HKCU:\Software\Classes\$ProgId\shell\open\command"))
			{
				New-Item -Path "HKCU:\Software\Classes\$ProgId\shell\open\command" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			if ($ProgramPath.Contains("%1"))
			{
				New-ItemProperty -Path "HKCU:\Software\Classes\$ProgId\shell\open\command" -Name "(Default)" -PropertyType String -Value $ProgramPath -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
			else
			{
				New-ItemProperty -Path "HKCU:\Software\Classes\$ProgId\shell\open\command" -Name "(Default)" -PropertyType String -Value "`"$ProgramPath`" `"%1`"" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			$FileNameEXE = Split-Path -Path $ProgramPath -Leaf
			if (-not (Test-Path -Path "HKCU:\Software\Classes\Applications\$FileNameEXE\shell\open\command"))
			{
				New-Item -Path "HKCU:\Software\Classes\Applications\$FileNameEXE\shell\open\command" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Classes\Applications\$FileNameEXE\shell\open\command" -Name "(Default)" -PropertyType String -Value "`"$ProgramPath`" `"%1`"" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
		}

		if ($Icon)
		{
			if (-not (Test-Path -Path "HKCU:\Software\Classes\$ProgId\DefaultIcon"))
			{
				New-Item -Path "HKCU:\Software\Classes\$ProgId\DefaultIcon" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Classes\$ProgId\DefaultIcon" -Name "(default)" -PropertyType String -Value $Icon -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
		}

		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts -Name "$($ProgID)_$($Extension)"  -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null

		if ($Extension.Contains("."))
		{
			# If the file extension specified configure the extension
			Write-ExtensionKeys -ProgId $ProgId -Extension $Extension
		}
		else
		{
			[WinAPI.Action]::DeleteKey([Microsoft.Win32.RegistryHive]::CurrentUser, "Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice")

			if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"))
			{
				New-Item -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice" -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}

			$ProgHash = Get-Hash -ProgId $ProgId -Extension $Extension -SubKey "Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"

			# We need to remove DENY permission set for user before setting a value
			if (@(".pdf", "http", "https") -contains $Extension)
			{
				# https://powertoe.wordpress.com/2010/08/28/controlling-registry-acl-permissions-with-powershell/
				$Key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
				$ACL = $key.GetAccessControl()
				$Principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				# https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights
				$Rule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList ($Principal,"FullControl","Deny")
				$ACL.RemoveAccessRule($Rule)
				$Key.SetAccessControl($ACL)

				# We need to use here an approach with "-Command & {}" as there's a variable inside
				& $TempPowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& { New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice' -Name ProgId -PropertyType String -Value '$ProgID' -Force -ErrorAction Stop | Out-Null }" 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0)
				{
					throw "powershell_temp.exe returned exit code $LASTEXITCODE while setting URL ProgId for $Extension"
				}
				& $TempPowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& { New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice' -Name Hash -PropertyType String -Value '$ProgHash' -Force -ErrorAction Stop | Out-Null }" 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0)
				{
					throw "powershell_temp.exe returned exit code $LASTEXITCODE while setting URL Hash for $Extension"
				}
			}
			else
			{
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice" -Name ProgId -PropertyType String -Value $ProgId -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice" -Name Hash -PropertyType String -Value $ProgHash -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
			}
		}

		# Setting additional parameters to comply with the requirements before configuring the extension
		Write-AdditionalKeys -ProgId $ProgId -Extension $Extension

		# Refresh the desktop icons
		$Signature = @{
			Namespace          = "WinAPI"
			Name               = "Signature"
			Language           = "CSharp"
			CompilerParameters = $CompilerParameters
			MemberDefinition   = @"
[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

public static void Refresh()
{
	// Update desktop icons
	SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
}
"@
		}
		if (-not ("WinAPI.Signature" -as [type]))
		{
			Add-Type @Signature -ErrorAction SilentlyContinue 2>&1 | Out-Null
		}

		[WinAPI.Signature]::Refresh()
	) 2>&1 | Out-Null
	}
	catch
	{
		$AssociationFailed = $true
		LogError "Failed to associate $Extension files with ${ProgramPath}: $($_.Exception.Message)"
	}
	finally
	{
		Remove-Item -Path $TempPowerShellPath -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
	}

	if ($AssociationFailed)
	{
		Write-ConsoleStatus -Status failed
	}
	else
	{
		Write-ConsoleStatus -Status success
	}
}

<#
	.SYNOPSIS
	Export all Windows associations

	.EXAMPLE
	Export-Associations

	.NOTES
	Associations will be exported as Application_Associations.json file in script root folder

	.NOTES
	You need to install all apps according to an exported JSON file to restore all associations

	.NOTES
	Machine-wide
#>
function Export-Associations
{
	Write-ConsoleStatus -Action "Exporting associations"
	LogInfo "Exporting associations"
	try
	{
		Dism.exe /Online /Export-DefaultAppAssociations:"$env:TEMP\Application_Associations.xml" 2>$null | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Dism.exe returned exit code $LASTEXITCODE" }
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to export application associations: $($_.Exception.Message)"
		return
	}

	Clear-Variable -Name AllJSON, ProgramPath, Icon -ErrorAction SilentlyContinue | Out-Null

	$AllJSON = @()
	$AppxProgIds = @((Get-ChildItem -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs").PSChildName)

	[xml]$XML = Get-Content -Path "$env:TEMP\Application_Associations.xml" -Encoding UTF8 -Force
	$XML.DefaultAssociations.Association | ForEach-Object -Process {
		if ($AppxProgIds -contains $_.ProgId)
		{
			# if ProgId is a UWP app
			# ProgrammPath
			if (Test-Path -Path "HKCU:\Software\Classes\$($_.ProgId)\Shell\Open\Command")
			{

				if ([Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Classes\$($_.ProgId)\shell\open\command", "DelegateExecute", $null))
				{
					$ProgramPath, $Icon = ""
				}
			}
		}
		else
		{
			if (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\$($_.ProgId)")
			{
				# ProgrammPath
				if ([Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Classes\$($_.ProgId)\shell\open\command", "", $null))
				{
					$PartProgramPath = (Get-ItemPropertyValue -Path "HKCU:\Software\Classes\$($_.ProgId)\Shell\Open\Command" -Name "(default)").Trim()
					$Program = $PartProgramPath.Substring(0, ($PartProgramPath.IndexOf(".exe") + 4)).Trim('"')

					if ($Program)
					{
						if (Test-Path -Path $([System.Environment]::ExpandEnvironmentVariables($Program)))
						{
							$ProgramPath = $PartProgramPath
						}
					}
				}
				elseif ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$($_.ProgId)\Shell\Open\Command", "", $null))
				{
					$PartProgramPath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\$($_.ProgId)\Shell\Open\Command" -Name "(default)").Trim()
					$Program = $PartProgramPath.Substring(0, ($PartProgramPath.IndexOf(".exe") + 4)).Trim('"')

					if ($Program)
					{
						if (Test-Path -Path $([System.Environment]::ExpandEnvironmentVariables($Program)))
						{
							$ProgramPath = $PartProgramPath
						}
					}
				}

				# Icon
				if ([Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Classes\$($_.ProgId)\DefaultIcon", "", $null))
				{
					$IconPartPath = (Get-ItemPropertyValue -Path "HKCU:\Software\Classes\$($_.ProgId)\DefaultIcon" -Name "(default)")
					if ($IconPartPath.EndsWith(".ico"))
					{
						$IconPath = $IconPartPath
					}
					else
					{
						if ($IconPartPath.Contains(","))
						{
							$IconPath = $IconPartPath.Substring(0, $IconPartPath.IndexOf(",")).Trim('"')
						}
						else
						{
							$IconPath = $IconPartPath.Trim('"')
						}
					}

					if ($IconPath)
					{
						if (Test-Path -Path $([System.Environment]::ExpandEnvironmentVariables($IconPath)))
						{
							$Icon = $IconPartPath
						}
					}
				}
				elseif ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$($_.ProgId)\DefaultIcon", "", $null))
				{
					$IconPartPath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\$($_.ProgId)\DefaultIcon" -Name "(default)").Trim()
					if ($IconPartPath.EndsWith(".ico"))
					{
						$IconPath = $IconPartPath
					}
					else
					{
						if ($IconPartPath.Contains(","))
						{
							$IconPath = $IconPartPath.Substring(0, $IconPartPath.IndexOf(",")).Trim('"')
						}
						else
						{
							$IconPath = $IconPartPath.Trim('"')
						}
					}

					if ($IconPath)
					{
						if (Test-Path -Path $([System.Environment]::ExpandEnvironmentVariables($IconPath)))
						{
							$Icon = $IconPartPath
						}
					}
				}
				elseif ([Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Classes\$($_.ProgId)\shell\open\command", "", $null))
				{
					$IconPartPath = (Get-ItemPropertyValue -Path "HKCU:\Software\Classes\$($_.ProgId)\shell\open\command" -Name "(default)").Trim()
					$IconPath = $IconPartPath.Substring(0, $IconPartPath.IndexOf(".exe") + 4).Trim('"')

					if ($IconPath)
					{
						if (Test-Path -Path $([System.Environment]::ExpandEnvironmentVariables($IconPath)))
						{
							$Icon = "$IconPath,0"
						}
					}
				}
				elseif ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\$($_.ProgId)\Shell\Open\Command", "", $null))
				{
					$IconPartPath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\$($_.ProgId)\Shell\Open\Command" -Name "(default)").Trim()
					$IconPath = $IconPartPath.Substring(0, $IconPartPath.IndexOf(".exe") + 4)

					if ($IconPath)
					{
						if (Test-Path -Path $([System.Environment]::ExpandEnvironmentVariables($IconPath)))
						{
							$Icon = "$IconPath,0"
						}
					}
				}
			}
		}

		$_.ProgId = $_.ProgId.Replace("\", "\\")
		$ProgramPath = $ProgramPath.Replace("\", "\\").Replace('"', '\"')
		if ($Icon)
		{
			$Icon = $Icon.Replace("\", "\\").Replace('"', '\"')
		}

		# Create a hash table
		$JSON = @"
[
  {
     "ProgId":  "$($_.ProgId)",
     "ProgrammPath": "$ProgramPath",
     "Extension": "$($_.Identifier)",
     "Icon": "$Icon"
  }
]
"@ | ConvertFrom-JSON
		$AllJSON += $JSON
	}

	Clear-Variable -Name ProgramPath, Icon -ErrorAction SilentlyContinue | Out-Null

	# Save in UTF-8 without BOM
	$AllJSON | ConvertTo-Json | Set-Content -Path "$PSScriptRoot\..\Application_Associations.json" -Encoding Default -Force

	Remove-Item -Path "$env:TEMP\Application_Associations.xml" -Force | Out-Null
	Write-ConsoleStatus -Status success
}

<#
	.SYNOPSIS
	Import all Windows associations

	.EXAMPLE
	Import-Associations

	.NOTES
	You have to install all apps according to an exported JSON file to restore all associations

	.NOTES
	Current user
#>
function Import-Associations
{
	Write-ConsoleStatus -Action "Importing associations"
	LogInfo "Importing associations"

	Add-Type -AssemblyName System.Windows.Forms
	$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
	$OpenFileDialog.Filter = "*.json|*.json|{0} (*.*)|*.*" -f $Localization.AllFilesFilter
	$OpenFileDialog.InitialDirectory = $PSScriptRoot
	$OpenFileDialog.Multiselect = $false

	# Force move the open file dialog to the foreground
	$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
	$OpenFileDialog.ShowDialog($Focus)

	if ($OpenFileDialog.FileName)
	{
		$AppxProgIds = @((Get-ChildItem -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs").PSChildName)

		try
		{
			$JSON = Get-Content -Path $OpenFileDialog.FileName -Encoding UTF8 -Force | ConvertFrom-JSON
		}
		catch [System.Exception]
		{
			LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())

			return
		}

		$JSON | ForEach-Object -Process {
			if ($AppxProgIds -contains $_.ProgId)
			{
				Set-Association -ProgramPath $_.ProgId -Extension $_.Extension
			}
			else
			{
				Set-Association -ProgramPath $_.ProgrammPath -Extension $_.Extension -Icon $_.Icon
			}
		}
	}
	Write-ConsoleStatus -Status success
}

<#
	.SYNOPSIS
	Default terminal app

	.PARAMETER WindowsTerminal
	Set Windows Terminal as default terminal app to host the user interface for command-line applications

	.PARAMETER ConsoleHost
	Set Windows Console Host as default terminal app to host the user interface for command-line applications (default value)

	.EXAMPLE
	DefaultTerminalApp -WindowsTerminal

	.EXAMPLE
	DefaultTerminalApp -ConsoleHost

	.NOTES
	Current user
#>
function DefaultTerminalApp
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "WindowsTerminal"
		)]
		[switch]
		$WindowsTerminal,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "ConsoleHost"
		)]
		[switch]
		$ConsoleHost
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"WindowsTerminal"
		{
			if (Get-AppxPackage -Name Microsoft.WindowsTerminal)
			{
				Write-ConsoleStatus -Action "Setting Windows Terminal as default terminal app"
				LogInfo "Setting Windows Terminal as default terminal app"
				# Checking if the Terminal version supports such feature
				$TerminalVersion = (Get-AppxPackage -Name Microsoft.WindowsTerminal).Version
				if ([System.Version]$TerminalVersion -ge [System.Version]"1.11")
				{
					if (-not (Test-Path -Path "HKCU:\Console\%%Startup"))
					{
						New-Item -Path "HKCU:\Console\%%Startup" -Force -ErrorAction SilentlyContinue | Out-Null
					}

					# Find the current GUID of Windows Terminal
					$PackageFullName = (Get-AppxPackage -Name Microsoft.WindowsTerminal).PackageFullName
					Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\PackagedCom\Package\$PackageFullName\Class" | ForEach-Object -Process {
						if ((Get-ItemPropertyValue -Path $_.PSPath -Name ServerId) -eq 0)
						{
							New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name DelegationConsole -PropertyType String -Value $_.PSChildName -Force -ErrorAction SilentlyContinue | Out-Null
						}

						if ((Get-ItemPropertyValue -Path $_.PSPath -Name ServerId) -eq 1)
						{
							New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name DelegationTerminal -PropertyType String -Value $_.PSChildName -Force -ErrorAction SilentlyContinue | Out-Null
						}
					}
				}
				Write-ConsoleStatus -Status success
			}
		}
		"ConsoleHost"
		{
			Write-ConsoleStatus -Action "Setting Windows Console Host as default terminal app"
			LogInfo "Setting Windows Console Host as default terminal app"
			New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name DelegationConsole -PropertyType String -Value "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" -Force -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name DelegationTerminal -PropertyType String -Value "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Install the latest Microsoft Visual C++ Redistributable Packages 2015 - 2022 (x86/x64)

	.EXAMPLE
	Install-VCRedist -Redistributables 2015_2022_x86, 2015_2022_x64

	.LINK
	https://docs.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist

	.NOTES
	Machine-wide
#>
function ConvertTo-NormalizedVersion
{
	param
	(
		[AllowNull()]
		[string]
		$Version
	)

	if ([string]::IsNullOrWhiteSpace($Version))
	{
		return $null
	}

	$Match = [regex]::Match($Version.Trim(), "\d+(?:\.\d+){1,3}")
	if (-not $Match.Success)
	{
		return $null
	}

	$Parts = $Match.Value.Split(".")
	while ($Parts.Count -lt 4)
	{
		$Parts += "0"
	}
	if ($Parts.Count -gt 4)
	{
		$Parts = $Parts[0..3]
	}

	try
	{
		return [System.Version]($Parts -join ".")
	}
	catch
	{
		return $null
	}
}

function Get-InstalledVCRedistVersion
{
	param
	(
		[ValidateSet("x86", "x64")]
		[string]
		$Architecture
	)

	$RegistryPaths = @(
		"HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Architecture",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$Architecture"
	)

	foreach ($RegistryPath in $RegistryPaths)
	{
		try
		{
			$Runtime = Get-ItemProperty -Path $RegistryPath -ErrorAction Stop
		}
		catch
		{
			continue
		}

		if ($Runtime.Installed -eq 1)
		{
			return ConvertTo-NormalizedVersion -Version $Runtime.Version
		}
	}

	return $null
}

function Get-InstalledDotNetRuntimeVersion
{
	param
	(
		[ValidateRange(1, 99)]
		[int]
		$MajorVersion
	)

	$RegistryPaths = @(
		"HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.NETCore.App",
		"HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App",
		"HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.NETCore.App",
		"HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App"
	)

	$InstalledVersions = foreach ($RegistryPath in $RegistryPaths)
	{
		if (-not (Test-Path -Path $RegistryPath))
		{
			continue
		}

		Get-ChildItem -Path $RegistryPath -ErrorAction SilentlyContinue | ForEach-Object {
			ConvertTo-NormalizedVersion -Version $_.PSChildName
		}
	}

	$InstalledVersions = $InstalledVersions |
		Where-Object -FilterScript {$null -ne $_ -and $_.Major -eq $MajorVersion} |
		Sort-Object -Descending -Unique

	if ($InstalledVersions)
	{
		return $InstalledVersions[0]
	}

	return $null
}

function Get-LatestDotNetRuntimeRelease
{
	param
	(
		[ValidateRange(1, 99)]
		[int]
		$MajorVersion
	)

	$ReleaseMetadataUri = "https://builds.dotnet.microsoft.com/dotnet/release-metadata/$MajorVersion.0/releases.json"
	$ReleaseMetadata = Invoke-RestMethod -Uri $ReleaseMetadataUri -UseBasicParsing
	$LatestReleaseVersion = [string]$ReleaseMetadata."latest-release"
	$Release = $null

	if (-not [string]::IsNullOrWhiteSpace($LatestReleaseVersion))
	{
		$Release = $ReleaseMetadata.releases | Where-Object -FilterScript {$_."release-version" -eq $LatestReleaseVersion} | Select-Object -First 1
	}

	if ($null -eq $Release)
	{
		$Release = $ReleaseMetadata.releases | Select-Object -First 1
	}

	if ($null -eq $Release -or $null -eq $Release.runtime)
	{
		return $null
	}

	$RuntimeFile = $Release.runtime.files | Where-Object -FilterScript {$_.name -eq "dotnet-runtime-win-x64.exe"} | Select-Object -First 1
	$DownloadUrl = [string]$RuntimeFile.url

	if ([string]::IsNullOrWhiteSpace($DownloadUrl))
	{
		return $null
	}

	$DownloadUri = [uri]$DownloadUrl

	[pscustomobject]@{
		Version     = ConvertTo-NormalizedVersion -Version $Release.runtime.version
		DownloadUrl = $DownloadUrl
		FileName    = [System.IO.Path]::GetFileName($DownloadUri.AbsolutePath)
		SourceHost  = $DownloadUri.GetLeftPart([System.UriPartial]::Authority)
		MetadataUri = $ReleaseMetadataUri
	}
}

function Install-VCRedist
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Redistributables"
		)]
		[ValidateSet("2015_2022_x86", "2015_2022_x64")]
		[string[]]
		$Redistributables
	)

	$vcredistVersion = $null

	# Get latest build version
	# https://github.com/ScoopInstaller/Extras/blob/master/bucket/vcredist2022.json
	try
	{
		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/ScoopInstaller/Extras/refs/heads/master/bucket/vcredist2022.json"
			UseBasicParsing = $true
			#Verbose         = $true
		}
		$vcredistVersion = ConvertTo-NormalizedVersion -Version (Invoke-RestMethod @Parameters).version
	}
	catch [System.Net.WebException]
	{
		LogWarning "Unable to determine the latest Visual C++ Redistributable version. Installed packages will be left unchanged unless missing."
	}

	$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"

	foreach ($Redistributable in $Redistributables)
	{
		switch ($Redistributable)
		{
			2015_2022_x86
			{
				$DisplayName = "Visual C++ Redistributable (2015 - 2022) x86"
				$InstalledVersion = Get-InstalledVCRedistVersion -Architecture "x86"
				$ShouldInstall = $null -eq $InstalledVersion

				if ($null -ne $InstalledVersion -and $null -ne $vcredistVersion)
				{
					$ShouldInstall = $vcredistVersion -gt $InstalledVersion
				}

				if (-not $ShouldInstall)
				{
					LogInfo "$DisplayName already installed (version $InstalledVersion)."
					Write-ConsoleStatus -Action "Checking $DisplayName"
					Write-ConsoleStatus -Status success
					continue
				}

				if ($null -eq $InstalledVersion)
				{
					LogInfo "$DisplayName not detected. Installing it."
				}
				elseif ($null -ne $vcredistVersion)
				{
					LogInfo "$DisplayName version $InstalledVersion detected. Updating to $vcredistVersion."
				}

				try
				{
					Write-ConsoleStatus -Action "Installing $DisplayName"
					LogInfo "Installing $DisplayName"

					$Parameters = @{
						Uri             = "https://aka.ms/vs/17/release/VC_redist.x86.exe"
						OutFile         = "$DownloadsFolder\VC_redist.x86.exe"
						UseBasicParsing = $true
						#Verbose         = $true
					}
					Invoke-WebRequest @Parameters

					$VCx86Process = Start-Process -FilePath "$DownloadsFolder\VC_redist.x86.exe" -ArgumentList "/install /passive /norestart" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
					if ($VCx86Process.ExitCode -ne 0) { throw "VC_redist.x86.exe returned exit code $($VCx86Process.ExitCode)" }

					# PowerShell 5.1 (7.5 too) interprets 8.3 file name literally, if an environment variable contains a non-Latin word
					# https://github.com/PowerShell/PowerShell/issues/21070
					$Paths = @(
						"$DownloadsFolder\VC_redist.x86.exe",
						"$env:TEMP\dd_vcredist_x86_*.log"
					)
					Get-ChildItem -Path $Paths -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch [System.Net.WebException]
				{
					LogError ($Localization.NoResponse -f "https://download.visualstudio.microsoft.com")
					LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
					Write-ConsoleStatus -Status failed

					return
				}
				catch
				{
					LogError "Failed to install ${DisplayName}: $($_.Exception.Message)"
					Write-ConsoleStatus -Status failed
					continue
				}
			}
			2015_2022_x64
			{
				$DisplayName = "Visual C++ Redistributable (2015 - 2022) x64"
				$InstalledVersion = Get-InstalledVCRedistVersion -Architecture "x64"
				$ShouldInstall = $null -eq $InstalledVersion

				if ($null -ne $InstalledVersion -and $null -ne $vcredistVersion)
				{
					$ShouldInstall = $vcredistVersion -gt $InstalledVersion
				}

				if (-not $ShouldInstall)
				{
					LogInfo "$DisplayName already installed (version $InstalledVersion)."
					Write-ConsoleStatus -Action "Checking $DisplayName"
					Write-ConsoleStatus -Status success
					continue
				}

				if ($null -eq $InstalledVersion)
				{
					LogInfo "$DisplayName not detected. Installing it."
				}
				elseif ($null -ne $vcredistVersion)
				{
					LogInfo "$DisplayName version $InstalledVersion detected. Updating to $vcredistVersion."
				}

				try
				{
					Write-ConsoleStatus -Action "Installing $DisplayName"
					LogInfo "Installing $DisplayName"

					$Parameters = @{
						Uri             = "https://aka.ms/vs/17/release/VC_redist.x64.exe"
						OutFile         = "$DownloadsFolder\VC_redist.x64.exe"
						UseBasicParsing = $true
						#Verbose         = $true
					}
					Invoke-WebRequest @Parameters

					$VCx64Process = Start-Process -FilePath "$DownloadsFolder\VC_redist.x64.exe" -ArgumentList "/install /passive /norestart" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
					if ($VCx64Process.ExitCode -ne 0) { throw "VC_redist.x64.exe returned exit code $($VCx64Process.ExitCode)" }

					# PowerShell 5.1 (7.5 too) interprets 8.3 file name literally, if an environment variable contains a non-Latin word
					# https://github.com/PowerShell/PowerShell/issues/21070
					$Paths = @(
						"$DownloadsFolder\VC_redist.x64.exe",
						"$env:TEMP\dd_vcredist_amd64_*.log"
					)
					Get-ChildItem -Path $Paths -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch [System.Net.WebException]
				{
					LogError ($Localization.NoResponse -f "https://download.visualstudio.microsoft.com")
					LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
					Write-ConsoleStatus -Status failed

					return
				}
				catch
				{
					LogError "Failed to install ${DisplayName}: $($_.Exception.Message)"
					Write-ConsoleStatus -Status failed
					continue
				}
			}
		}
	}
}

<#
	.SYNOPSIS
	Install the latest .NET Desktop Runtime 8, 9 x64

	.PARAMETER NET8x64
	Install the latest .NET Desktop Runtime 8 x64

	.PARAMETER NET9x64
	Install the latest .NET Desktop Runtime 9 x64

	.EXAMPLE
	Install-DotNetRuntimes -Runtimes NET8x64, NET9x64

	.LINK
	https://dotnet.microsoft.com/en-us/download/dotnet

	.NOTES
	Machine-wide
#>
function Install-DotNetRuntimes
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Runtimes"
		)]
		[ValidateSet("NET8x64", "NET9x64")]
		[string[]]
		$Runtimes
	)

	$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"

	foreach ($Runtime in $Runtimes)
	{
		switch ($Runtime)
		{
			NET8x64
			{
				$DisplayName = ".NET 8 x64"
				$InstalledVersion = Get-InstalledDotNetRuntimeVersion -MajorVersion 8
				$NET8Version = $null
				$NET8DownloadUrl = $null
				$NET8FileName = $null
				$NET8SourceHost = "https://builds.dotnet.microsoft.com"

				try
				{
					$NET8Release = Get-LatestDotNetRuntimeRelease -MajorVersion 8
					if ($null -ne $NET8Release)
					{
						$NET8Version = $NET8Release.Version
						$NET8DownloadUrl = $NET8Release.DownloadUrl
						$NET8FileName = $NET8Release.FileName
						$NET8SourceHost = $NET8Release.SourceHost
					}
				}
				catch [System.Net.WebException]
				{
					if ($null -ne $InstalledVersion)
					{
						LogWarning "Unable to determine the latest $DisplayName version. Detected installed version $InstalledVersion, so the install will be skipped."
					}
					else
					{
						LogError ($Localization.NoResponse -f "https://builds.dotnet.microsoft.com")
						LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
						Write-ConsoleStatus -Action "Installing $DisplayName"
						Write-ConsoleStatus -Status failed

						return
					}
				}

				$ShouldInstall = $null -eq $InstalledVersion

				if ($null -ne $InstalledVersion -and $null -ne $NET8Version)
				{
					$ShouldInstall = $NET8Version -gt $InstalledVersion
				}

				if (-not $ShouldInstall)
				{
					LogInfo "$DisplayName already installed (version $InstalledVersion)."
					Write-ConsoleStatus -Action "Checking $DisplayName"
					Write-ConsoleStatus -Status success
					continue
				}

				if ($null -eq $NET8Version)
				{
					LogError "Unable to determine the latest $DisplayName version."
					Write-ConsoleStatus -Action "Installing $DisplayName"
					Write-ConsoleStatus -Status failed
					return
				}

				if ($null -eq $InstalledVersion)
				{
					LogInfo "$DisplayName not detected. Installing version $NET8Version."
				}
				else
				{
					LogInfo "$DisplayName version $InstalledVersion detected. Updating to $NET8Version."
				}

				try
				{
					Write-ConsoleStatus -Action "Installing .NET $NET8Version x64"
					LogInfo "Installing .NET $NET8Version x64"

					# Download the runtime from the release metadata entry rather than constructing the URL.
					$Parameters = @{
						Uri             = $NET8DownloadUrl
						OutFile         = "$DownloadsFolder\$NET8FileName"
						UseBasicParsing = $true
						#Verbose         = $true
					}
					Invoke-WebRequest @Parameters

					$NET8Process = Start-Process -FilePath "$DownloadsFolder\$NET8FileName" -ArgumentList "/install /passive /norestart" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
					if ($NET8Process.ExitCode -ne 0) { throw "$NET8FileName returned exit code $($NET8Process.ExitCode)" }

					# PowerShell 5.1 (7.5 too) interprets 8.3 file name literally, if an environment variable contains a non-Latin word
					# https://github.com/PowerShell/PowerShell/issues/21070
					$Paths = @(
						"$DownloadsFolder\$NET8FileName",
						"$env:TEMP\Microsoft_.NET_Runtime*.log"
					)
					Get-ChildItem -Path $Paths -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch [System.Net.WebException]
				{
					LogError ($Localization.NoResponse -f $NET8SourceHost)
					LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
					Write-ConsoleStatus -Status failed

					return
				}
				catch
				{
					LogError "Failed to install .NET $NET8Version x64: $($_.Exception.Message)"
					Write-ConsoleStatus -Status failed
					continue
				}
			}
			NET9x64
			{
				$DisplayName = ".NET 9 x64"
				$InstalledVersion = Get-InstalledDotNetRuntimeVersion -MajorVersion 9
				$NET9Version = $null
				$NET9DownloadUrl = $null
				$NET9FileName = $null
				$NET9SourceHost = "https://builds.dotnet.microsoft.com"

				try
				{
					$NET9Release = Get-LatestDotNetRuntimeRelease -MajorVersion 9
					if ($null -ne $NET9Release)
					{
						$NET9Version = $NET9Release.Version
						$NET9DownloadUrl = $NET9Release.DownloadUrl
						$NET9FileName = $NET9Release.FileName
						$NET9SourceHost = $NET9Release.SourceHost
					}
				}
				catch [System.Net.WebException]
				{
					if ($null -ne $InstalledVersion)
					{
						LogWarning "Unable to determine the latest $DisplayName version. Detected installed version $InstalledVersion, so the install will be skipped."
					}
					else
					{
						LogError ($Localization.NoResponse -f "https://builds.dotnet.microsoft.com")
						LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
						Write-ConsoleStatus -Action "Installing $DisplayName"
						Write-ConsoleStatus -Status failed

						return
					}
				}

				$ShouldInstall = $null -eq $InstalledVersion

				if ($null -ne $InstalledVersion -and $null -ne $NET9Version)
				{
					$ShouldInstall = $NET9Version -gt $InstalledVersion
				}

				if (-not $ShouldInstall)
				{
					LogInfo "$DisplayName already installed (version $InstalledVersion)."
					Write-ConsoleStatus -Action "Checking $DisplayName"
					Write-ConsoleStatus -Status success
					continue
				}

				if ($null -eq $NET9Version)
				{
					LogError "Unable to determine the latest $DisplayName version."
					Write-ConsoleStatus -Action "Installing $DisplayName"
					Write-ConsoleStatus -Status failed
					return
				}

				if ($null -eq $InstalledVersion)
				{
					LogInfo "$DisplayName not detected. Installing version $NET9Version."
				}
				else
				{
					LogInfo "$DisplayName version $InstalledVersion detected. Updating to $NET9Version."
				}

				try
				{
					Write-ConsoleStatus -Action "Installing .NET $NET9Version x64"
					LogInfo "Installing .NET $NET9Version x64"

					# Download the runtime from the release metadata entry rather than constructing the URL.
					$Parameters = @{
						Uri             = $NET9DownloadUrl
						OutFile         = "$DownloadsFolder\$NET9FileName"
						UseBasicParsing = $true
						#Verbose         = $true
					}
					Invoke-WebRequest @Parameters

					$NET9Process = Start-Process -FilePath "$DownloadsFolder\$NET9FileName" -ArgumentList "/install /passive /norestart" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
					if ($NET9Process.ExitCode -ne 0) { throw "$NET9FileName returned exit code $($NET9Process.ExitCode)" }

					# PowerShell 5.1 (7.5 too) interprets 8.3 file name literally, if an environment variable contains a non-Latin word
					# https://github.com/PowerShell/PowerShell/issues/21070
					$Paths = @(
						"$DownloadsFolder\$NET9FileName",
						"$env:TEMP\Microsoft_.NET_Runtime*.log"
					)
					Get-ChildItem -Path $Paths -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch [System.Net.WebException]
				{
					LogError ($Localization.NoResponse -f $NET9SourceHost)
					LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
					Write-ConsoleStatus -Status failed

					return
				}
				catch
				{
					LogError "Failed to install .NET $NET9Version x64: $($_.Exception.Message)"
					Write-ConsoleStatus -Status failed
					continue
				}
			}
		}
	}
}

<#
	.SYNOPSIS
	Desktop shortcut creation upon Microsoft Edge update

	.PARAMETER Channels
	List Microsoft Edge channels to prevent desktop shortcut creation upon its update

	.PARAMETER Disable
	Do not prevent desktop shortcut creation upon Microsoft Edge update (default value)

	.EXAMPLE
	PreventEdgeShortcutCreation -Channels Stable, Beta, Dev, Canary

	.EXAMPLE
	PreventEdgeShortcutCreation -Disable

	.NOTES
	Machine-wide
#>
function PreventEdgeShortcutCreation
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $false,
			ParameterSetName = "Channels"
		)]
		[ValidateSet("Stable", "Beta", "Dev", "Canary")]
		[string[]]
		$Channels,

		[Parameter(
			Mandatory = $false,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	if (-not (Get-Package -Name "Microsoft Edge" -ProviderName Programs -ErrorAction Ignore))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate))
	{
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate -Force | Out-Null
	}

	foreach ($Channel in $Channels)
	{
		switch ($Channel)
		{
			Stable
			{
				Write-ConsoleStatus -Action "Preventing desktop shortcut creation for Microsoft Edge Stable Channel"
				LogInfo "Preventing desktop shortcut creation for Microsoft Edge Stable Channel"
				if (Get-Package -Name "Microsoft Edge" -ProviderName Programs -ErrorAction SilentlyContinue)
				{
					New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -PropertyType DWord -Value 0 -Force | Out-Null
					Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Type DWORD -Value 3 | Out-Null
					Write-ConsoleStatus -Status success
				}
			}
			Beta
			{
				if (Get-Package -Name "Microsoft Edge Beta" -ProviderName Programs -ErrorAction SilentlyContinue)
				{
					Write-ConsoleStatus -Action "Preventing desktop shortcut creation for Microsoft Edge Beta Channel"
					LogInfo "Preventing desktop shortcut creation for Microsoft Edge Beta Channel"
					New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" -PropertyType DWord -Value 0 -Force | Out-Null
					Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" -Type DWORD -Value 3 | Out-Null
					Write-ConsoleStatus -Status success
				}
			}
			Dev
			{
				if (Get-Package -Name "Microsoft Edge Dev" -ProviderName Programs -ErrorAction SilentlyContinue)
				{
					Write-ConsoleStatus -Action "Preventing desktop shortcut creation for Microsoft Edge Dev Channel"
					LogInfo "Preventing desktop shortcut creation for Microsoft Edge Dev Channel"
					New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" -PropertyType DWord -Value 0 -Force | Out-Null
					Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" -Type DWORD -Value 3 | Out-Null
					Write-ConsoleStatus -Status success
				}
			}
			Canary
			{
				if (Get-Package -Name "Microsoft Edge Canary" -ProviderName Programs -ErrorAction SilentlyContinue)
				{
					Write-ConsoleStatus -Action "Preventing desktop shortcut creation for Microsoft Edge Canary Channel"
					LogInfo "Preventing desktop shortcut creation for Microsoft Edge Canary Channel"
					New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{65C35B14-6C1D-4122-AC46-7148CC9D6497}" -PropertyType DWord -Value 0 -Force | Out-Null
					Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{65C35B14-6C1D-4122-AC46-7148CC9D6497}" -Type DWORD -Value 3 | Out-Null
					Write-ConsoleStatus -Status success
				}
			}
		}
	}

	if ($Disable)
	{
		$Names = @(
			"CreateDesktopShortcut{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
			"CreateDesktopShortcut{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
			"CreateDesktopShortcut{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
			"CreateDesktopShortcut{65C35B14-6C1D-4122-AC46-7148CC9D6497}"
		)
		Write-ConsoleStatus -Action "Allowing desktop shortcut creation for Microsoft Edge upon update"
		LogInfo "Allowing desktop shortcut creation for Microsoft Edge upon update"
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate -Name $Names -Force -ErrorAction Ignore | Out-Null

		Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Type CLEAR | Out-Null
		Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" -Type CLEAR | Out-Null
		Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" -Type CLEAR | Out-Null
		Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\EdgeUpdate -Name "CreateDesktopShortcut{65C35B14-6C1D-4122-AC46-7148CC9D6497}" -Type CLEAR | Out-Null
		Write-ConsoleStatus -Status success
	}
}

<#
	.SYNOPSIS
	Back up the system registry to %SystemRoot%\System32\config\RegBack folder when PC restarts and create a RegIdleBackup in the Task Scheduler task to manage subsequent backups

	.PARAMETER Enable
	Back up the system registry to %SystemRoot%\System32\config\RegBack folder

	.PARAMETER Disable
	Do not back up the system registry to %SystemRoot%\System32\config\RegBack folder (default value)

	.EXAMPLE
	RegistryBackup -Enable

	.EXAMPLE
	RegistryBackup -Disable

	.NOTES
	Machine-wide
#>
function RegistryBackup
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling registry backup to RegBack folder 'C:\Windows\System32\config\RegBack'"
			LogInfo "Enabling registry backup to RegBack folder 'C:\Windows\System32\config\RegBack'"
			New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name EnablePeriodicBackup -Type DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling registry backup to RegBack folder 'C:\Windows\System32\config\RegBack'"
			LogInfo "Disabling registry backup to RegBack folder 'C:\Windows\System32\config\RegBack'"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name EnablePeriodicBackup -Force -ErrorAction Ignore | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}
#endregion System
