using module ..\Logging.psm1
using module ..\Helpers.psm1

#region UI & Personalization
<#
.SYNOPSIS
Enable or disable displaying full path in Explorer window title

.PARAMETER Enable
Enable displaying full path in Explorer title

.PARAMETER Disable
Disable displaying full path in Explorer title (default value)

.EXAMPLE
ExplorerTitleFullPath -Enable

.EXAMPLE
ExplorerTitleFullPath -Disable

.NOTES
Current user
#>
function ExplorerTitleFullPath
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
			Write-Host "Enabling the display of full paths in Explorer title - " -NoNewline
			LogInfo "Enabling the display of full paths in Explorer title"
			try
			{
				If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable full paths in Explorer title: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the display of full paths in Explorer title - " -NoNewline
			LogInfo "Disabling the display of full paths in Explorer title"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable full paths in Explorer title: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable showing folder merge conflict notifications

.PARAMETER Enable
Enable showing folder merge conflict notifications

.PARAMETER Disable
Disable showing folder merge conflict notifications

.EXAMPLE
MergeConflicts -Enable

.EXAMPLE
MergeConflicts -Disable

.NOTES
Current user
#>
function MergeConflicts
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
			Write-Host "Enabling folder merge conflict notifications - " -NoNewline
			LogInfo "Enabling folder merge conflict notifications"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable folder merge conflict notifications: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling folder merge conflict notifications - " -NoNewline
			LogInfo "Disabling folder merge conflict notifications"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable folder merge conflict notifications: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable showing all folders in Explorer navigation pane

.PARAMETER Enable
Enable showing all folders in navigation pane

.PARAMETER Disable
Disable showing all folders in navigation pane (default value)

.EXAMPLE
NavPaneAllFolders -Enable

.EXAMPLE
NavPaneAllFolders -Disable

.NOTES
Current user
#>
function NavPaneAllFolders
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
			Write-Host "Enabling all folders in the Explorer navigation pane - " -NoNewline
			LogInfo "Enabling all folders in the Explorer navigation pane"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable all folders in the Explorer navigation pane: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling all folders in the Explorer navigation pane - " -NoNewline
			LogInfo "Disabling all folders in the Explorer navigation pane"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable all folders in the Explorer navigation pane: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable showing Libraries in Explorer navigation pane

.PARAMETER Enable
Enable showing Libraries in navigation pane

.PARAMETER Disable
Disable showing Libraries in navigation pane (default value)

.EXAMPLE
NavPaneLibraries -Enable

.EXAMPLE
NavPaneLibraries -Disable

.NOTES
Current user
#>
function NavPaneLibraries
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
			Write-Host "Enabling Libraries in the Explorer navigation pane - " -NoNewline
			LogInfo "Enabling Libraries in the Explorer navigation pane"
			try
			{
				If (!(Test-Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}")) {
					New-Item -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable Libraries in the Explorer navigation pane: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling Libraries in the Explorer navigation pane - " -NoNewline
			LogInfo "Disabling Libraries in the Explorer navigation pane"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable Libraries in the Explorer navigation pane: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable launching folder windows in a separate process

.PARAMETER Enable
Enable launching folder windows in a separate process

.PARAMETER Disable
Disable launching folder windows in a separate process (default value)

.EXAMPLE
FldrSeparateProcess -Enable

.EXAMPLE
FldrSeparateProcess -Disable

.NOTES
Current user
#>
function FldrSeparateProcess
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
			Write-Host "Enabling launching folder windows in a separate process - " -NoNewline
			LogInfo "Enabling launching folder windows in a separate process"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable separate folder windows: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling launching folder windows in a separate process - " -NoNewline
			LogInfo "Disabling launching folder windows in a separate process"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable separate folder windows: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable restoring previous folder windows at logon

.PARAMETER Enable
Enable restoring previous folder windows at logon

.PARAMETER Disable
Disable restoring previous folder windows at logon (default value)

.EXAMPLE
RestoreFldrWindows -Enable

.EXAMPLE
RestoreFldrWindows -Disable

.NOTES
Current user
#>
function RestoreFldrWindows
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
			Write-Host "Enabling restoring previous folder windows at logon - " -NoNewline
			LogInfo "Enabling restoring previous folder windows at logon"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable restoring previous folder windows at logon: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling restoring previous folder windows at logon - " -NoNewline
			LogInfo "Disabling restoring previous folder windows at logon"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable restoring previous folder windows at logon: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)

.PARAMETER Enable
Enable coloring of encrypted or compressed NTFS files (default value)

.PARAMETER Disable
Disable coloring of encrypted or compressed NTFS files

.EXAMPLE
EncCompFilesColor -Enable

.EXAMPLE
EncCompFilesColor -Disable

.NOTES
Current user
#>
function EncCompFilesColor
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
			Write-Host "Enabling coloring of encrypted or compressed NTFS files - " -NoNewline
			LogInfo "Enabling coloring of encrypted or compressed NTFS files"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable coloring of encrypted or compressed NTFS files: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling coloring of encrypted or compressed NTFS files - " -NoNewline
			LogInfo "Disabling coloring of encrypted or compressed NTFS files"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable coloring of encrypted or compressed NTFS files: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable Sharing Wizard in Explorer

.PARAMETER Enable
Enable Sharing Wizard

.PARAMETER Disable
Disable Sharing Wizard (default value)

.EXAMPLE
SharingWizard -Enable

.EXAMPLE
SharingWizard -Disable

.NOTES
Current user
#>
function SharingWizard
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
			Write-Host "Enabling the Sharing Wizard in Explorer - " -NoNewline
			LogInfo "Enabling the Sharing Wizard in Explorer"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the Sharing Wizard in Explorer: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the Sharing Wizard in Explorer - " -NoNewline
			LogInfo "Disabling the Sharing Wizard in Explorer"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable the Sharing Wizard in Explorer: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable item selection checkboxes in Explorer

.PARAMETER Enable
Enable item selection checkboxes

.PARAMETER Disable
Disable item selection checkboxes (default value)

.EXAMPLE
SelectCheckboxes -Enable

.EXAMPLE
SelectCheckboxes -Disable

.NOTES
Current user
#>
function SelectCheckboxes
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
			Write-Host "Enabling item selection checkboxes in Explorer - " -NoNewline
			LogInfo "Enabling item selection checkboxes in Explorer"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable item selection checkboxes in Explorer: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling item selection checkboxes in Explorer - " -NoNewline
			LogInfo "Enabling item selection checkboxes in Explorer"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable item selection checkboxes in Explorer: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable sync provider notifications in Explorer

.PARAMETER Enable
Enable sync provider notifications

.PARAMETER Disable
Disable sync provider notifications (default value)

.EXAMPLE
SyncNotifications -Enable

.EXAMPLE
SyncNotifications -Disable

.NOTES
Current user
#>
function SyncNotifications
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
			Write-Host "Enabling sync provider notifications in Explorer - " -NoNewline
			LogInfo "Enabling sync provider notifications in Explorer"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable sync provider notifications in Explorer: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling sync provider notifications in Explorer - " -NoNewline
			LogInfo "Disabling sync provider notifications in Explorer"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable sync provider notifications in Explorer: $($_.Exception.Message)"
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable recently and frequently used item shortcuts in Explorer

.DESCRIPTION
Note: This is only a UI tweak to hide the shortcuts. In order to stop creating most recently used (MRU) items lists everywhere, use privacy tweak 'DisableRecentFiles' instead.

.PARAMETER Enable
Enable hiding recently and frequently used item shortcuts

.PARAMETER Disable
Disable hiding recently and frequently used item shortcuts (default value)

.EXAMPLE
RecentShortcuts -Enable

.EXAMPLE
RecentShortcuts -Disable

.NOTES
Current user
#>
function RecentShortcuts
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
			Write-Host "Enabling recently and frequently used item shortcuts in Explorer - " -NoNewline
			LogInfo "Enabling recently and frequently used item shortcuts in Explorer"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction Stop | Out-Null
				}
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable recent and frequent item shortcuts in Explorer: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling recently and frequently used item shortcuts in Explorer - " -NoNewline
			LogInfo "Disabling recently and frequently used item shortcuts in Explorer"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable recent and frequent item shortcuts in Explorer: $($_.Exception.Message)"
			}
		}
	}
}

<#
    .SYNOPSIS
    Windows build number and edition display on desktop

    .PARAMETER Enable
    Enable the build number and edition display

    .PARAMETER Disable
    Disable the build number and edition display (default value)

    .EXAMPLE
    BuildNumberOnDesktop -Enable

    .EXAMPLE
    BuildNumberOnDesktop -Disable

    .NOTES
    Current user
#>
function BuildNumberOnDesktop
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
			Write-Host "Enabling build number and edition display on the Desktop - " -NoNewline
			LogInfo "Enabling build number and edition display on the Desktop"
			try
			{
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable build number and edition display on the Desktop: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling build number and edition display on the Desktop - " -NoNewline
			LogInfo "Disabling build number and edition display on the Desktop"
			try
			{
				Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable build number and edition display on the Desktop: $($_.Exception.Message)"
			}
		}
	}
}

<#
    .SYNOPSIS
    Share context menu item

    .PARAMETER Enable
    Enable the Share context menu item (default value)

    .PARAMETER Disable
    Disable the Share context menu item

    .EXAMPLE
    ShareMenu -Enable

    .EXAMPLE
    ShareMenu -Disable

    .NOTES
    Current user
#>
function ShareMenu
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
			If (!(Test-Path "HKCR:")) {
				New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
			}
			Write-Host "Enabling the Share context menu item - " -NoNewline
			LogInfo "Enabling the Share context menu item"
			try
			{
				New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue | Out-Null
				Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -Name "(Default)" -Type String -Value "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the Share context menu item: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			If (!(Test-Path "HKCR:")) {
				New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
			}
			Write-Host "Disabling the Share context menu item - " -NoNewline
			LogInfo "Disabling the Share context menu item"
			try
			{
				if (Test-Path "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing")
				{
					Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable the Share context menu item: $($_.Exception.Message)"
			}
		}
	}
}

<#
    .SYNOPSIS
    Show thumbnails instead of file extension icons

    .PARAMETER Enable
    Show thumbnails for files

    .PARAMETER Disable
    Show only file extension icons (default value)

    .EXAMPLE
    Thumbnails -Enable

    .EXAMPLE
    Thumbnails -Disable

    .NOTES
    Current user
#>
function Thumbnails
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
			Write-Host "Enabling 'Show thumbnails instead of icons' for file extensions - " -NoNewline
			LogInfo "Enabling 'Show thumbnails instead of icons' for file extensions"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable thumbnails for file extensions: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling thumbnails, showing icons for file extensions instead - " -NoNewline
			LogInfo "Disabling thumbnails, showing icons for file extensions instead"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable thumbnails for file extensions: $($_.Exception.Message)"
			}
		}
	}
}

<#
    .SYNOPSIS
    Creation of thumbnail cache files

    .PARAMETER Enable
    Enable creation of thumbnail cache files

    .PARAMETER Disable
    Disable creation of thumbnail cache files (default value)

    .EXAMPLE
    ThumbnailCache -Enable

    .EXAMPLE
    ThumbnailCache -Disable

    .NOTES
    Current user
#>
function ThumbnailCache
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
			Write-Host "Enabling the creation of thumbnail cache files - " -NoNewline
			LogInfo "Enabling the creation of thumbnail cache files"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable thumbnail cache creation: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the creation of thumbnail cache files - " -NoNewline
			LogInfo "Disabling the creation of thumbnail cache files"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable thumbnail cache creation: $($_.Exception.Message)"
			}
		}
	}
}

<#
    .SYNOPSIS
    Creation of Thumbs.db thumbnail cache files on network folders

    .PARAMETER Enable
    Enable creation of Thumbs.db cache on network folders

    .PARAMETER Disable
    Disable creation of Thumbs.db cache on network folders (default value)

    .EXAMPLE
    ThumbsDBOnNetwork -Enable

    .EXAMPLE
    ThumbsDBOnNetwork -Disable

    .NOTES
    Current user
#>
function ThumbsDBOnNetwork
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
			Write-Host "Enabling the creation of 'Thumbs.db' cache on network folders - " -NoNewline
			LogInfo "Enabling the creation of 'Thumbs.db' cache on network folders"
			try
			{
				if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable Thumbs.db cache on network folders: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the creation of 'Thumbs.db' cache on network folders - " -NoNewline
			LogInfo "Disabling the creation of 'Thumbs.db' cache on network folders"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable Thumbs.db cache on network folders: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "This PC" icon on Desktop

	.PARAMETER Show
	Show the "This PC" icon on Desktop

	.PARAMETER Hide
	Hide the "This PC" icon on Desktop (default value)

	.EXAMPLE
	ThisPC -Show

	.EXAMPLE
	ThisPC -Hide

	.NOTES
	Current user
#>
function ThisPC
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
			Write-Host "Enabling 'This PC' icon on Desktop - " -NoNewline
			LogInfo "Enabling 'This PC' icon on Desktop"
			try
			{
				if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel))
				{
					New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the 'This PC' icon on Desktop: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			Write-Host "Disabling 'This PC' icon on Desktop - " -NoNewline
			LogInfo "Disabling 'This PC' icon on Desktop"
			try
			{
				if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Force -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide the 'This PC' icon on Desktop: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Item check boxes

	.PARAMETER Disable
	Do not use item check boxes

	.PARAMETER Enable
	Use check item check boxes (default value)

	.EXAMPLE
	CheckBoxes -Disable

	.EXAMPLE
	CheckBoxes -Enable

	.NOTES
	Current user
#>
function CheckBoxes
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
			Write-Host "Enabling item check boxes - " -NoNewline
			LogInfo "Enabling item check boxes"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable item check boxes: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling item check boxes - " -NoNewline
			LogInfo "Disabling item check boxes"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable item check boxes: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Hidden files, folders, and drives

	.PARAMETER Enable
	Show hidden files, folders, and drives

	.PARAMETER Disable
	Do not show hidden files, folders, and drives (default value)

	.EXAMPLE
	HiddenItems -Enable

	.EXAMPLE
	HiddenItems -Disable

	.NOTES
	Current user
#>
function HiddenItems
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
			Write-Host "Enabling Hidden files, folders, and drives - " -NoNewline
			LogInfo "Enabling Hidden files, folders, and drives"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show hidden files, folders, and drives: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling Hidden files, folders, and drives - " -NoNewline
			LogInfo "Disabling Hidden files, folders, and drives"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide hidden files, folders, and drives: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Show or hide protected operating system files

	.PARAMETER Enable
	Show protected operating system files

	.PARAMETER Disable
	Do not show protected operating system files (default value)

	.EXAMPLE
	SuperHiddenFiles -Enable

	.EXAMPLE
	SuperHiddenFiles -Disable

	.NOTES
	Current user
#>
function SuperHiddenFiles
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
			Write-Host "Enabling 'Show protected operating system files' - " -NoNewline
			LogInfo "Enabling 'Show protected operating system files'"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show protected operating system files: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling 'Show protected operating system files' - " -NoNewline
			LogInfo "Disabling 'Show protected operating system files'"
			try
			{
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide protected operating system files: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	File name extensions

	.PARAMETER Show
	Show file name extensions

	.PARAMETER Hide
	Hide file name extensions (default value)

	.EXAMPLE
	FileExtensions -Show

	.EXAMPLE
	FileExtensions -Hide

	.NOTES
	Current user
#>
function FileExtensions
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
			Write-Host "Enabling file name extensions - " -NoNewline
			LogInfo "Enabling file name extensions"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show file name extensions: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			Write-Host "Disabling file name extensions - " -NoNewline
			LogInfo "Disabling file name extensions"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide file name extensions: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Folder merge conflicts

	.PARAMETER Show
	Show folder merge conflicts

	.PARAMETER Hide
	Hide folder merge conflicts (default value)

	.EXAMPLE
	MergeConflicts -Show

	.EXAMPLE
	MergeConflicts -Hide

	.NOTES
	Current user
#>
function MergeConflicts
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
			Write-Host "Enabling folder merge conflicts - " -NoNewline
			LogInfo "Enabling folder merge conflicts"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show folder merge conflicts: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			Write-Host "Disabling folder merge conflicts - " -NoNewline
			LogInfo "Disabling folder merge conflicts"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide folder merge conflicts: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Configure how to open File Explorer

	.PARAMETER ThisPC
	Open File Explorer to "This PC"

	.PARAMETER QuickAccess
	Open File Explorer to Quick access (default value)

	.PARAMETER Downloads
	Open File Explorer to Downloads

	.EXAMPLE
	OpenFileExplorerTo -ThisPC

	.EXAMPLE
	OpenFileExplorerTo -QuickAccess

	.EXAMPLE
	OpenFileExplorerTo -Downloads

	.NOTES
	Current user
#>
function OpenFileExplorerTo
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "ThisPC"
		)]
		[switch]
		$ThisPC,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "QuickAccess"
		)]
		[switch]
		$QuickAccess,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Downloads"
		)]
		[switch]
		$Downloads
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"ThisPC"
		{
			Write-Host "Setting File Explorer to open to 'This PC' - " -NoNewline
			LogInfo "Setting File Explorer to open to 'This PC'"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set File Explorer to open to 'This PC': $($_.Exception.Message)"
			}
		}
		"QuickAccess"
		{
			Write-Host "Setting File Explorer to open to 'Quick Access' - " -NoNewline
			LogInfo "Setting File Explorer to open to 'Quick Access'"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set File Explorer to open to 'Quick Access': $($_.Exception.Message)"
			}
		}
		"Downloads"
		{
			Write-Host "Setting File Explorer to open to 'Downloads' - " -NoNewline
			LogInfo "Setting File Explorer to open to 'Downloads'"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 3 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set File Explorer to open to 'Downloads': $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	File Explorer mode

	.PARAMETER Disable
	Disable File Explorer compact mode (default value)

	.PARAMETER Enable
	Enable File Explorer compact mode

	.EXAMPLE
	FileExplorerCompactMode -Disable

	.EXAMPLE
	FileExplorerCompactMode -Enable

	.NOTES
	Current user
#>
function FileExplorerCompactMode
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
			Write-Host "Disabling File Explorer compact mode - " -NoNewline
			LogInfo "Disabling File Explorer compact mode"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name UseCompactMode -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable File Explorer compact mode: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-Host "Enabling File Explorer compact mode - " -NoNewline
			LogInfo "Enabling File Explorer compact mode"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name UseCompactMode -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable File Explorer compact mode: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Sync provider notification in File Explorer

	.PARAMETER Hide
	Do not show sync provider notification within File Explorer

	.PARAMETER Show
	Show sync provider notification within File Explorer (default value)

	.EXAMPLE
	OneDriveFileExplorerAd -Hide

	.EXAMPLE
	OneDriveFileExplorerAd -Show

	.NOTES
	Current user
#>
function OneDriveFileExplorerAd
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

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling sync provider notification within File Explorer - " -NoNewline
			LogInfo "Disabling sync provider notification within File Explorer"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide sync provider notification within File Explorer: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-Host "Enabling sync provider notification within File Explorer - " -NoNewline
			LogInfo "Enabling sync provider notification within File Explorer"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show sync provider notification within File Explorer: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows snapping

	.PARAMETER Disable
	When I snap a window, do not show what I can snap next to it

	.PARAMETER Enable
	When I snap a window, show what I can snap next to it (default value)

	.EXAMPLE
	SnapAssist -Disable

	.EXAMPLE
	SnapAssist -Enable

	.NOTES
	Current user
#>
function SnapAssist
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

	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WindowArrangementActive -PropertyType String -Value 1 -Force | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling 'show what I can snap next' When snapping windows - " -NoNewline
			LogInfo "Disabling 'show what I can snap next' When snapping windows"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SnapAssist -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable 'show what I can snap next' when snapping windows: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-Host "Enabling 'show what I can snap next' When snapping windows - " -NoNewline
			LogInfo "Enabling 'show what I can snap next' When snapping windows"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SnapAssist -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable 'show what I can snap next' when snapping windows: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The file transfer dialog box mode

	.PARAMETER Detailed
	Show the file transfer dialog box in the detailed mode

	.PARAMETER Compact
	Show the file transfer dialog box in the compact mode (default value)

	.EXAMPLE
	FileTransferDialog -Detailed

	.EXAMPLE
	FileTransferDialog -Compact

	.NOTES
	Current user
#>
function FileTransferDialog
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Detailed"
		)]
		[switch]
		$Detailed,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Compact"
		)]
		[switch]
		$Compact
	)

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Detailed"
		{
			Write-Host "Enabling detailed view for file transfer dialog boxes - " -NoNewline
			LogInfo "Enabling detailed view for file transfer dialog boxes"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable detailed view for file transfer dialog boxes: $($_.Exception.Message)"
			}
		}
		"Compact"
		{
			Write-Host "Enabling compact view for file transfer dialog boxes - " -NoNewline
			LogInfo "Enabling compact view for file transfer dialog boxes"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable compact view for file transfer dialog boxes: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The recycle bin files delete confirmation dialog

	.PARAMETER Enable
	Display the recycle bin files delete confirmation dialog

	.PARAMETER Disable
	Do not display the recycle bin files delete confirmation dialog (default value)

	.EXAMPLE
	RecycleBinDeleteConfirmation -Enable

	.EXAMPLE
	RecycleBinDeleteConfirmation -Disable

	.NOTES
	Current user
#>
function RecycleBinDeleteConfirmation
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
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer, HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name ConfirmFileDelete -Type CLEAR | Out-Null
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name ConfirmFileDelete -Type CLEAR | Out-Null

	$ShellState = Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling the recycle bin files delete confirmation dialog - " -NoNewline
			LogInfo "Enabling the recycle bin files delete confirmation dialog"
			try
			{
				$ShellState[4] = 51
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState -PropertyType Binary -Value $ShellState -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the recycle bin delete confirmation dialog: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the recycle bin files delete confirmation dialog - " -NoNewline
			LogInfo "Disabling the recycle bin files delete confirmation dialog"
			try
			{
				$ShellState[4] = 55
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState -PropertyType Binary -Value $ShellState -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable the recycle bin delete confirmation dialog: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Recently used files in Quick access

	.PARAMETER Hide
	Hide recently used files in Quick access

	.PARAMETER Show
	Show recently used files in Quick access (default value)

	.EXAMPLE
	QuickAccessRecentFiles -Hide

	.EXAMPLE
	QuickAccessRecentFiles -Show

	.NOTES
	Current user
#>
function QuickAccessRecentFiles
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer, HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoRecentDocsHistory -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoRecentDocsHistory -Type CLEAR | Out-Null
	Set-Policy -Scope User -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoRecentDocsHistory -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling recently used files in Quick access - " -NoNewline
			LogInfo "Disabling recently used files in Quick access"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide recently used files in Quick access: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-Host "Enabling recently used files in Quick access - " -NoNewline
			LogInfo "Enabling recently used files in Quick access"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show recently used files in Quick access: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Frequently used folders in Quick access

	.PARAMETER Hide
	Hide frequently used folders in Quick access

	.PARAMETER Show
	Show frequently used folders in Quick access (default value)

	.EXAMPLE
	QuickAccessFrequentFolders -Hide

	.EXAMPLE
	QuickAccessFrequentFolders -Show

	.NOTES
	Current user
#>
function QuickAccessFrequentFolders
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

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling frequently used folders in Quick access - " -NoNewline
			LogInfo "Disabling frequently used folders in Quick access"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide frequently used folders in Quick access: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-Host "Enabling frequently used folders in Quick access - " -NoNewline
			LogInfo "Enabling frequently used folders in Quick access"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show frequently used folders in Quick access: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The Meet Now icon in the notification area

	.PARAMETER Hide
	Hide the Meet Now icon in the notification area

	.PARAMETER Show
	Show the Meet Now icon in the notification area (default value)

	.EXAMPLE
	MeetNow -Hide

	.EXAMPLE
	MeetNow -Show

	.NOTES
	Current user only
#>
function MeetNow
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAMeetNow -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAMeetNow -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAMeetNow -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling the Meet Now icon in the notification area - " -NoNewline
			LogInfo "Disabling the Meet Now icon in the notification area"
			try
			{
				$Script:MeetNow = $false
				$Settings = Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -ErrorAction Stop
				$Settings[9] = 128
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -PropertyType Binary -Value $Settings -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide the Meet Now icon in the notification area: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-Host "Enabling the Meet Now icon in the notification area - " -NoNewline
			LogInfo "Enabling the Meet Now icon in the notification area"
			try
			{
				$Script:MeetNow = $true
				$Settings = Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -ErrorAction Stop
				$Settings[9] = 0
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -PropertyType Binary -Value $Settings -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the Meet Now icon in the notification area: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	News and Interests

	.PARAMETER Disable
	Disable "News and Interests" on the taskbar

	.PARAMETER Enable
	Enable "News and Interests" on the taskbar (default value)

	.EXAMPLE
	NewsInterests -Disable

	.EXAMPLE
	NewsInterests -Enable

	.NOTES
	https://forums.mydigitallife.net/threads/taskbarda-widgets-registry-change-is-now-blocked.88547/#post-1848877

	.NOTES
	Current user
#>
function NewsInterests
{
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable,

		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable
	)

	# Remove old policies silently
	$null = Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name EnableFeeds -Force -ErrorAction SilentlyContinue
	$null = Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" -Name value -Force -ErrorAction SilentlyContinue

	# Skip if Edge is not installed
	if (-not (Get-Package -Name "Microsoft Edge" -ProviderName Programs -ErrorAction SilentlyContinue))
	{
		LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	# Get MachineId
	$MachineId = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient", "MachineId", $null)
	if (-not $MachineId)
	{
		LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	# Add C# HashData type if missing
	if (-not ("WinAPI.Signature" -as [type]))
	{
		$Signature = @{
			Namespace          = "WinAPI"
			Name               = "Signature"
			Language           = "CSharp"
			CompilerParameters = $CompilerParameters
			MemberDefinition   = @"
[DllImport("Shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = false)]
public static extern int HashData(byte[] pbData, int cbData, byte[] piet, int outputLen);
"@
		}
		Add-Type @Signature | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling 'News and Interests' on the taskbar - " -NoNewline
			LogInfo "Disabling 'News and Interests' on the taskbar"

			$null = {
				$Combined = $MachineId + '_' + 2
				$CharArray = $Combined.ToCharArray()
				[array]::Reverse($CharArray)
				$Reverse = -join $CharArray
				$bytesIn = [System.Text.Encoding]::Unicode.GetBytes($Reverse)
				$bytesOut = [byte[]]::new(4)
				[WinAPI.Signature]::HashData($bytesIn, 0x53, $bytesOut, $bytesOut.Count)
				$DWordData = [System.BitConverter]::ToUInt32($bytesOut,0)

				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" `
								 -Name "ShellFeedsTaskbarViewMode" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" `
								 -Name "EnShellFeedsTaskbarViewMode" -PropertyType DWord -Value $DWordData -Force -ErrorAction SilentlyContinue | Out-Null
			}.Invoke()

			Write-Host "success!" -ForegroundColor Green
		}

		"Enable"
		{
			Write-Host "Enabling 'News and Interests' on the taskbar - " -NoNewline
			LogInfo "Enabling 'News and Interests' on the taskbar"

			$null = {
				$Combined = $MachineId + '_' + 0
				$CharArray = $Combined.ToCharArray()
				[array]::Reverse($CharArray)
				$Reverse = -join $CharArray
				$bytesIn = [System.Text.Encoding]::Unicode.GetBytes($Reverse)
				$bytesOut = [byte[]]::new(4)
				[WinAPI.Signature]::HashData($bytesIn, 0x53, $bytesOut, $bytesOut.Count)
				$DWordData = [System.BitConverter]::ToUInt32($bytesOut,0)

				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" `
								 -Name "ShellFeedsTaskbarViewMode" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" `
								 -Name "EnShellFeedsTaskbarViewMode" -PropertyType DWord -Value $DWordData -Force -ErrorAction SilentlyContinue | Out-Null
			}.Invoke()

			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Taskbar alignment

	.PARAMETER Left
	Set the taskbar alignment to the left

	.PARAMETER Center
	Set the taskbar alignment to the center (default value)

	.EXAMPLE
	TaskbarAlignment -Center

	.EXAMPLE
	TaskbarAlignment -Left

	.NOTES
	Current user
#>
function TaskbarAlignment
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Left"
		)]
		[switch]
		$Left,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Center"
		)]
		[switch]
		$Center
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Center"
		{
			Write-Host "Setting the taskbar alignment to the Center - " -NoNewline
			LogInfo "Setting the taskbar alignment to the Center"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarAl -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set taskbar alignment to the center: $($_.Exception.Message)"
			}
		}
		"Left"
		{
			Write-Host "Setting the taskbar alignment to the Left - " -NoNewline
			LogInfo "Setting the taskbar alignment to the Left"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarAl -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set taskbar alignment to the left: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The widgets icon on the taskbar

	.PARAMETER Hide
	Hide the widgets icon on the taskbar

	.PARAMETER Show
	Show the widgets icon on the taskbar (default value)

	.EXAMPLE
	TaskbarWidgets -Hide

	.EXAMPLE
	TaskbarWidgets -Show

	.NOTES
	Current user
#>
function TaskbarWidgets
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

	if (-not (Get-AppxPackage -Name MicrosoftWindows.Client.WebExperience))
	{
		LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
		#LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
	}

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests -Name value -Force -ErrorAction Ignore | Out-Null
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Dsh -Name AllowNewsAndInterests -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Dsh -Name AllowNewsAndInterests -Type CLEAR | Out-Null

	# We cannot set a value to TaskbarDa, having called any of APIs, except of copying powershell.exe (or any other tricks) with a different name, due to a UCPD driver tracks all executables to block the access to the registry
	Copy-Item -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Destination "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_temp.exe" -Force | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling the widgets icon on the taskbar - " -NoNewline
			LogInfo "Disabling the widgets icon on the taskbar"
			& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_temp.exe" -Command {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarDa -PropertyType DWord -Value 0 -Force} | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Enabling the widgets icon on the taskbar - " -NoNewline
			LogInfo "Enabling the widgets icon on the taskbar"
			& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_temp.exe" -Command {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarDa -PropertyType DWord -Value 1 -Force} | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}

	Remove-Item -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_temp.exe" -Force | Out-Null
}

<#
	.SYNOPSIS
	Search on the taskbar

	.PARAMETER Hide
	Hide the search on the taskbar

	.PARAMETER SearchIcon
	Show the search icon on the taskbar

	.PARAMETER SearchBox
	Show the search box on the taskbar (default value)

	.EXAMPLE
	TaskbarSearch -Hide

	.EXAMPLE
	TaskbarSearch -SearchIcon

	.EXAMPLE
	TaskbarSearch -SearchIconLabel

	.EXAMPLE
	TaskbarSearch -SearchBox

	.NOTES
	Current user
#>
function TaskbarSearch
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
			ParameterSetName = "SearchIcon"
		)]
		[switch]
		$SearchIcon,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "SearchIconLabel"
		)]
		[switch]
		$SearchIconLabel,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "SearchBox"
		)]
		[switch]
		$SearchBox
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Search\DisableSearch -Name value -PropertyType DWord -Value 0 -Force -ErrorAction Ignore | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableSearch, SearchOnTaskbarMode -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableSearch -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name SearchOnTaskbarMode -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling the search on the taskbar - " -NoNewline
			LogInfo "Disabling the search on the taskbar"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide search on the taskbar: $($_.Exception.Message)"
			}
		}
		"SearchIcon"
		{
			Write-Host "Enabling the search icon on the taskbar - " -NoNewline
			LogInfo "Enabling the search icon on the taskbar"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the search icon on the taskbar: $($_.Exception.Message)"
			}
		}
		"SearchIconLabel"
		{
			Write-Host "Enabling the search icon label on the taskbar - " -NoNewline
			LogInfo "Enabling the search icon label on the taskbar"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 3 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the search icon label on the taskbar: $($_.Exception.Message)"
			}
		}
		"SearchBox"
		{
			Write-Host "Enabling the search box on the taskbar - " -NoNewline
			LogInfo "Enabling the search box on the taskbar"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the search box on the taskbar: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Search highlights

	.PARAMETER Hide
	Hide search highlights

	.PARAMETER Show
	Show search highlights (default value)

	.EXAMPLE
	SearchHighlights -Hide

	.EXAMPLE
	SearchHighlights -Show

	.NOTES
	Current user
#>
function SearchHighlights
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name EnableDynamicContentInWSB -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name EnableDynamicContentInWSB -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling search highlights - " -NoNewline
			LogInfo "Disabling search highlights"
			# Checking whether "Ask Copilot" and "Find results in Web" were disabled. They also disable Search Highlights automatically
			# We have to use GetValue() due to "Set-StrictMode -Version Latest"
			$BingSearchEnabled = ([Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", $null))
			$DisableSearchBoxSuggestions = ([Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", $null))
			if (($BingSearchEnabled -eq 1) -or ($DisableSearchBoxSuggestions -eq 1))
			{
				LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
			}
			else
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings -Name IsDynamicSearchBoxEnabled -PropertyType DWord -Value 0 -Force | Out-Null

			}
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Enabling search highlights - " -NoNewline
			LogInfo "Enabling search highlights"
			# Enable "Ask Copilot" and "Find results in Web" icons in Windows Search in order to enable Search Highlights
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Force -ErrorAction Ignore | Out-Null
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Force -ErrorAction Ignore | Out-Null
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings -Name IsDynamicSearchBoxEnabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Task view button on the taskbar

	.PARAMETER Hide
	Hide the Task view button on the taskbar

	.PARAMETER Show
	Show the Task View button on the taskbar (default value)

	.EXAMPLE
	TaskViewButton -Hide

	.EXAMPLE
	TaskViewButton -Show

	.NOTES
	Current user
#>
function TaskViewButton
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideTaskViewButton -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name HideTaskViewButton -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideTaskViewButton -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling the Task view button on the taskbar - " -NoNewline
			LogInfo "Disabling the Task view button on the taskbar"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide the Task View button on the taskbar: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-Host "Enabling the Task view button on the taskbar - " -NoNewline
			LogInfo "Enabling the Task view button on the taskbar"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the Task View button on the taskbar: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Combine taskbar buttons and hide labels

	.PARAMETER Always
	Combine taskbar buttons and always hide labels (default value)

	.PARAMETER Full
	Combine taskbar buttons and hide labels when taskbar is full

	.PARAMETER Never
	Combine taskbar buttons and never hide labels

	.EXAMPLE
	TaskbarCombine -Always

	.EXAMPLE
	TaskbarCombine -Full

	.EXAMPLE
	TaskbarCombine -Never

	.NOTES
	Current user
#>
function TaskbarCombine
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Always"
		)]
		[switch]
		$Always,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Full"
		)]
		[switch]
		$Full,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Never"
		)]
		[switch]
		$Never
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer, HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoTaskGrouping -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoTaskGrouping -Type CLEAR | Out-Null
	Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoTaskGrouping -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Always"
		{
			Write-Host "Combine taskbar buttons and always hide labels - " -NoNewline
			LogInfo "Combine taskbar buttons and always hide labels"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarGlomLevel -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to always combine taskbar buttons and hide labels: $($_.Exception.Message)"
			}
		}
		"Full"
		{
			Write-Host "Combine taskbar buttons and hide labels when taskbar is full - " -NoNewline
			LogInfo "Combine taskbar buttons and hide labels when taskbar is full"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarGlomLevel -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to combine taskbar buttons when the taskbar is full: $($_.Exception.Message)"
			}
		}
		"Never"
		{
			Write-Host "Combine taskbar buttons and never hide labels - " -NoNewline
			LogInfo "Combine taskbar buttons and never hide labels"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarGlomLevel -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to never combine taskbar buttons and labels: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Unpin shortcuts from the taskbar

	.PARAMETER Edge
	Unpin Microsoft Edge shortcut from the taskbar

	.PARAMETER Store
	Unpin Microsoft Store from the taskbar

	.PARAMETER Outlook
	Unpin Outlook shortcut from the taskbar

	.EXAMPLE
	UnpinTaskbarShortcuts -Shortcuts Edge, Store, Outlook

	.NOTES
	Current user
#>
function UnpinTaskbarShortcuts
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet("Edge", "Store", "Outlook", "Mail")]
		[string[]]
		$Shortcuts
	)

	# Extract the localized "Unpin from taskbar" string from shell32.dll
	$LocalizedString = [WinAPI.GetStrings]::GetString(5387)

	Write-Host "Unpin Microsoft Edge, Microsoft Store, Mail, and Outlook shortcuts from the taskbar - " -NoNewline
	LogInfo "Unpin Microsoft Edge, Microsoft Store, Mail, and Outlook shortcuts from the taskbar"

	foreach ($Shortcut in $Shortcuts)
	{
		switch ($Shortcut)
		{
			Mail
			{
				$Shell = New-Object -ComObject Shell.Application
				$AppsFolder = $Shell.NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}")
				$MailApp = $AppsFolder.Items() | Where-Object { $_.Name -match "Mail" }

				if ($MailApp)
				{
    				# Extract localized "Unpin from taskbar"
    				$LocalizedString = (Get-Item "$env:SystemRoot\System32\shell32.dll").VersionInfo.FileDescription
    				# If you're already defining $LocalizedString elsewhere, keep that and remove this line
  					$MailApp.Verbs() |
        			Where-Object { $_.Name -eq $LocalizedString } |
        			ForEach-Object { $_.DoIt() } | Out-Null
				}
			}
			Edge
			{
				if (Test-Path -Path "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk")
				{
					# Call the shortcut context menu item
					$Shell = (New-Object -ComObject Shell.Application).NameSpace("$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
					$Shortcut = $Shell.ParseName("Microsoft Edge.lnk")
					# Extract the localized "Unpin from taskbar" string from shell32.dll
					$Shortcut.Verbs() | Where-Object -FilterScript {$_.Name -eq $LocalizedString} | ForEach-Object -Process {$_.DoIt()} | Out-Null
				}
			}
			Store
			{
				if ((New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items() | Where-Object -FilterScript {$_.Name -eq "Microsoft Store"})
				{
					# Extract the localized "Unpin from taskbar" string from shell32.dll
					((New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items() | Where-Object -FilterScript {
						$_.Name -eq "Microsoft Store"
					}).Verbs() | Where-Object -FilterScript {$_.Name -eq $LocalizedString} | ForEach-Object -Process {$_.DoIt()} | Out-Null
				}
			}
			Outlook
			{
				if ((New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items() | Where-Object -FilterScript {$_.Name -match "Outlook"})
				{
					# Extract the localized "Unpin from taskbar" string from shell32.dll
					((New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items() | Where-Object -FilterScript {
						$_.Name -match "Outlook"
					}).Verbs() | Where-Object -FilterScript {$_.Name -eq $LocalizedString} | ForEach-Object -Process {$_.DoIt()} | Out-Null
				}
			}
		}
	}
	Write-Host "success!" -ForegroundColor Green
}

<#
	.SYNOPSIS
	End task in taskbar by right click

	.PARAMETER Enable
	Enable end task in taskbar by right click

	.PARAMETER Disable
	Disable end task in taskbar by right click (default value)

	.EXAMPLE
	TaskbarEndTask -Enable

	.EXAMPLE
	TaskbarEndTask -Disable

	.NOTES
	Current user
#>
function TaskbarEndTask
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

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling 'End task in taskbar by right click' - " -NoNewline
			LogInfo "Enabling 'End task in taskbar by right click'"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings -Name TaskbarEndTask -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable 'End task in taskbar by right click': $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling 'End task in taskbar by right click' - " -NoNewline
			LogInfo "Disabling 'End task in taskbar by right click'"
			try
			{
				if (Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings -Name TaskbarEndTask -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings -Name TaskbarEndTask -Force -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable 'End task in taskbar by right click': $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The Control Panel icons view

	.PARAMETER Category
	View the Control Panel icons by category (default value)

	.PARAMETER LargeIcons
	View the Control Panel icons by large icons

	.PARAMETER SmallIcons
	View the Control Panel icons by Small icons

	.EXAMPLE
	ControlPanelView -Category

	.EXAMPLE
	ControlPanelView -LargeIcons

	.EXAMPLE
	ControlPanelView -SmallIcons

	.NOTES
	Current user
#>
function ControlPanelView
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Category"
		)]
		[switch]
		$Category,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "LargeIcons"
		)]
		[switch]
		$LargeIcons,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "SmallIcons"
		)]
		[switch]
		$SmallIcons
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ForceClassicControlPanel -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ForceClassicControlPanel -Type CLEAR | Out-Null

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Category"
		{
			Write-Host "Setting Control Panel to be viewed by Category - " -NoNewline
			LogInfo "Setting Control Panel to be viewed by Category"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set Control Panel view to Category: $($_.Exception.Message)"
			}
		}
		"LargeIcons"
		{
			Write-Host "Setting Control Panel to be viewed by Large Icons - " -NoNewline
			LogInfo "Setting Control Panel to be viewed by Large Icons"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set Control Panel view to Large Icons: $($_.Exception.Message)"
			}
		}
		"SmallIcons"
		{
			Write-Host "Setting Control Panel to be viewed by Small Icons - " -NoNewline
			LogInfo "Setting Control Panel to be viewed by Small Icons"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set Control Panel view to Small Icons: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The default Windows mode

	.PARAMETER Dark
	Set the default Windows mode to dark

	.PARAMETER Light
	Set the default Windows mode to light (default value)

	.EXAMPLE
	WindowsColorScheme -Dark

	.EXAMPLE
	WindowsColorScheme -Light

	.NOTES
	Current user
#>
function WindowsColorMode
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Dark"
		)]
		[switch]
		$Dark,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Light"
		)]
		[switch]
		$Light
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Dark"
		{
			Write-Host "Setting Windows to use Dark Mode - " -NoNewline
			LogInfo "Setting Windows to use Dark Mode"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set Windows color mode to Dark: $($_.Exception.Message)"
			}
		}
		"Light"
		{
			Write-Host "Setting Windows to use Light Mode - " -NoNewline
			LogInfo "Setting Windows to use Light Mode"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set Windows color mode to Light: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The default app mode

	.PARAMETER Dark
	Set the default app mode to dark

	.PARAMETER Light
	Set the default app mode to light (default value)

	.EXAMPLE
	AppColorMode -Dark

	.EXAMPLE
	AppColorMode -Light

	.NOTES
	Current user
#>
function AppColorMode
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Dark"
		)]
		[switch]
		$Dark,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Light"
		)]
		[switch]
		$Light
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Dark"
		{
			Write-Host "Setting Apps to use Dark Mode - " -NoNewline
			LogInfo "Setting Apps to use Dark Mode"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set app color mode to Dark: $($_.Exception.Message)"
			}
		}
		"Light"
		{
			Write-Host "Setting Apps to use Light Mode - " -NoNewline
			LogInfo "Setting Apps to use Light Mode"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to set app color mode to Light: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	First sign-in animation after the upgrade

	.PARAMETER Disable
	Disable first sign-in animation after the upgrade

	.PARAMETER Enable
	Enable first sign-in animation after the upgrade (default value)

	.EXAMPLE
	FirstLogonAnimation -Disable

	.EXAMPLE
	FirstLogonAnimation -Enable

	.NOTES
	Current user
#>
function FirstLogonAnimation
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
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling the first sign-in animation after upgrade - " -NoNewline
			LogInfo "Disabling the first sign-in animation after upgrade"
			try
			{
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable the first sign-in animation after upgrade: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-Host "Enabling the first sign-in animation after upgrade - " -NoNewline
			LogInfo "Enabling the first sign-in animation after upgrade"
			try
			{
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name EnableFirstLogonAnimation -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the first sign-in animation after upgrade: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The quality factor of the JPEG desktop wallpapers

	.PARAMETER Max
	Set the quality factor of the JPEG desktop wallpapers to maximum

	.PARAMETER Default
	Set the quality factor of the JPEG desktop wallpapers to default (default value)

	.EXAMPLE
	JPEGWallpapersQuality -Max

	.EXAMPLE
	JPEGWallpapersQuality -Default

	.NOTES
	Current user
#>
function JPEGWallpapersQuality
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Max"
		)]
		[switch]
		$Max,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Max"
		{
			Write-Host "Enabling the maximum quality factor of the JPEG desktop wallpapers - " -NoNewline
			LogInfo "Enabling the maximum quality factor of the JPEG desktop wallpapers"
			try
			{
				New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the maximum JPEG desktop wallpaper quality: $($_.Exception.Message)"
			}
		}
		"Default"
		{
			Write-Host "Disabling the maximum quality factor of the JPEG desktop wallpapers - " -NoNewline
			LogInfo "Disabling the maximum quality factor of the JPEG desktop wallpapers"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -Force -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to restore the default JPEG desktop wallpaper quality: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "- Shortcut" suffix adding to the name of the created shortcuts

	.PARAMETER Disable
	Do not add the "- Shortcut" suffix to the file name of created shortcuts

	.PARAMETER Enable
	Add the "- Shortcut" suffix to the file name of created shortcuts (default value)

	.EXAMPLE
	ShortcutsSuffix -Disable

	.EXAMPLE
	ShortcutsSuffix -Enable

	.NOTES
	Current user
#>
function ShortcutsSuffix
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

	Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -Force -ErrorAction Ignore | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling the '- Shortcut' suffix adding to the name of the created shortcuts - " -NoNewline
			LogInfo "Disabling the '- Shortcut' suffix adding to the name of the created shortcuts"
			try
			{
				if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates))
				{
					New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -PropertyType String -Value "%s.lnk" -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable the shortcut name suffix: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-Host "Enabling the '- Shortcut' suffix adding to the name of the created shortcuts - " -NoNewline
			LogInfo "Enabling the '- Shortcut' suffix adding to the name of the created shortcuts"
			try
			{
				if (Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -Force -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the shortcut name suffix: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Controls the display of shortcut arrow overlay on icons

	.PARAMETER Enable
	Show shortcut arrow overlay on icons (default value)

	.PARAMETER Disable
	Remove shortcut arrow overlay on icons

	.EXAMPLE
	ShortcutArrow -Enable

	.EXAMPLE
	ShortcutArrow -Disable

	.NOTES
	Current user
#>
function ShortcutArrow
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
			Write-Host "Enabling the display of shortcut arrow overlay on icons - " -NoNewline
			LogInfo "Enabling the display of shortcut arrow overlay on icons"
			try
			{
				if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction Stop | Out-Null
				}
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable the shortcut arrow overlay on icons: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the display of shortcut arrow overlay on icons - " -NoNewline
			LogInfo "Disabling the display of shortcut arrow overlay on icons"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")) {
					New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value "%SystemRoot%\System32\imageres.dll,-1015" -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable the shortcut arrow overlay on icons: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The Print screen button usage

	.PARAMETER Enable
	Use the Print screen button to open screen snipping

	.PARAMETER Disable
	Do not use the Print screen button to open screen snipping (default value)

	.EXAMPLE
	PrtScnSnippingTool -Enable

	.EXAMPLE
	PrtScnSnippingTool -Disable

	.NOTES
	Current user
#>
function PrtScnSnippingTool
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
			Write-Host "Enabling the Print screen button to open screen snipping - " -NoNewline
			LogInfo "Enabling the Print screen button to open screen snipping"
			try
			{
				New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable Print Screen for screen snipping: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling the Print screen button to open screen snipping - " -NoNewline
			LogInfo "Disabling the Print screen button to open screen snipping"
			try
			{
				New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable Print Screen for screen snipping: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	A different input method for each app window

	.PARAMETER Enable
	Let me use a different input method for each app window

	.PARAMETER Disable
	Do not use a different input method for each app window (default value)

	.EXAMPLE
	AppsLanguageSwitch -Enable

	.EXAMPLE
	AppsLanguageSwitch -Disable

	.NOTES
	Current user
#>
function AppsLanguageSwitch
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
			Write-Host "Enabling a different input method for each app window - " -NoNewline
			LogInfo "Enabling a different input method for each app window"
			try
			{
				Set-WinLanguageBarOption -UseLegacySwitchMode -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable a different input method for each app window: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling a different input method for each app window - " -NoNewline
			LogInfo "Disabling a different input method for each app window"
			try
			{
				Set-WinLanguageBarOption -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable a different input method for each app window: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Title bar window shake

	.PARAMETER Enable
	When I grab a windows's title bar and shake it, minimize all other windows

	.PARAMETER Disable
	When I grab a windows's title bar and shake it, don't minimize all other windows (default value)

	.EXAMPLE
	AeroShaking -Enable

	.EXAMPLE
	AeroShaking -Disable

	.NOTES
	Current user
#>
function AeroShaking
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
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\Software\Policies\Microsoft\Windows\Explorer -Name NoWindowMinimizingShortcuts -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name NoWindowMinimizingShortcuts -Type CLEAR | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoWindowMinimizingShortcuts -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Title bar window shake - " -NoNewline
			LogInfo "Enabling Title bar window shake"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable Title bar window shake: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-Host "Disabling Title bar window shake - " -NoNewline
			LogInfo "Disabling Title bar window shake"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable Title bar window shake: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Files and folders grouping in the Downloads folder

	.PARAMETER None
	Do not group files and folder in the Downloads folder

	.PARAMETER Default
	Group files and folder by date modified in the Downloads folder (default value)

	.EXAMPLE
	FolderGroupBy -None

	.EXAMPLE
	FolderGroupBy -Default

	.NOTES
	Current user
#>
function FolderGroupBy
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "None"
		)]
		[switch]
		$None,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"None"
		{
			Write-Host "Enabling grouping of files and folder in the Downloads folder - " -NoNewline
			LogInfo "Enabling grouping of files and folder in the Downloads folder"
			# Clear any Common Dialog views
			Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\*\Shell" -ErrorAction SilentlyContinue |
    		Where-Object { $_.PSChildName -eq "{885A186E-A440-4ADA-812B-DB871B942259}" } |
    		Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

			# https://learn.microsoft.com/en-us/windows/win32/properties/props-system-null
			if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}"))
			{
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Force | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name ColumnList -PropertyType String -Value "System.Null" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name GroupBy -PropertyType String -Value "System.Null" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name LogicalViewMode -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name Name -PropertyType String -Value NoName -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name Order -PropertyType DWord -Value 0 -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name PrimaryProperty -PropertyType String -Value "System.ItemNameDisplay" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}\TopViews\{00000000-0000-0000-0000-000000000000}" -Name SortByList -PropertyType String -Value "prop:System.ItemNameDisplay" -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Default"
		{
			Write-Host "Disabling grouping of files and folder in the Downloads folder - " -NoNewline
			LogInfo "Disabling grouping of files and folder in the Downloads folder"
			Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{885a186e-a440-4ada-812b-db871b942259}" -Recurse -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Expand to current folder in navigation pane

	.PARAMETER Disable
	Do not expand to open folder on navigation pane (default value)

	.PARAMETER Enable
	Expand to open folder on navigation pane

	.EXAMPLE
	NavigationPaneExpand -Disable

	.EXAMPLE
	NavigationPaneExpand -Enable

	.NOTES
	Current user
#>
function NavigationPaneExpand
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
			Write-Host "Disabling expand to open folder on navigation pane - " -NoNewline
			LogInfo "Disabling expand to open folder on navigation pane"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to disable expanding to the current folder in the navigation pane: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-Host "Enabling expand to open folder on navigation pane - " -NoNewline
			LogInfo "Enabling expand to open folder on navigation pane"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to enable expanding to the current folder in the navigation pane: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Recommended section in Start Menu

	.PARAMETER Hide
	Remove Recommended section in Start Menu

	.PARAMETER Show
	Do not remove Recommended section in Start Menu

	.EXAMPLE
	StartRecommendedSection -Hide

	.EXAMPLE
	StartRecommendedSection -Show

	.NOTES
	Current user
#>
function StartRecommendedSection
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

	# We cannot call [WinAPI.Winbrand]::BrandingFormatString("%WINDOWS_LONG%") here per this approach does not show a localized Windows edition name
	# Windows 11 Home not supported
	if ((Get-ComputerInfo).WindowsProductName -match "Home")
	{
		LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
	}

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling the Recommended section in the Start Menu - " -NoNewline
			LogInfo "Disabling the Recommended section in the Start Menu"
			try
			{
				if (-not (Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
				{
					New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force -ErrorAction Stop | Out-Null
				}
				if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education))
				{
					New-Item -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education -Name IsEducationEnvironment -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null

				Set-Policy -Scope User -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -Type DWORD -Value 1 | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to hide the Recommended section in the Start Menu: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-Host "Enabling the Recommended section in the Start Menu - " -NoNewline
			LogInfo "Enabling the Recommended section in the Start Menu"
			try
			{
				if (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -Force -ErrorAction Stop | Out-Null
				}
				if (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education -Name IsEducationEnvironment -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education -Name IsEducationEnvironment -Force -ErrorAction Stop | Out-Null
				}
				if (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start -Name HideRecommendedSection -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start -Name HideRecommendedSection -Force -ErrorAction Stop | Out-Null
				}
				Set-Policy -Scope User -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecommendedSection -Type CLEAR | Out-Null
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				Write-Host "Failed! Check logs for details." -ForegroundColor Red
				LogError "Failed to show the Recommended section in the Start Menu: $($_.Exception.Message)"
			}
		}
	}
}
#endregion UI & Personalization
