using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Context menu
<#
	.SYNOPSIS
	The "Extract all" item in the Windows Installer (.msi) context menu

	.PARAMETER Show
	Show the "Extract all" item in the Windows Installer (.msi) context menu

	.PARAMETER Remove
	Hide the "Extract all" item from the Windows Installer (.msi) context menu (default value)

	.EXAMPLE
	MSIExtractContext -Show

	.EXAMPLE
	MSIExtractContext -Hide

	.NOTES
	Current user
#>
function MSIExtractContext
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
			Write-ConsoleStatus -Action "Showing 'Extract all' item in the Windows Installer (.msi) context menu"
			LogInfo "Showing 'Extract all' item in the Windows Installer (.msi) context menu"
			try
			{
				if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
				{
					New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force -ErrorAction Stop | Out-Null
				}
				$Value = "msiexec.exe /a `"%1`" /qb TARGETDIR=`"%1 extracted`""
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(default)" -PropertyType String -Value $Value -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-37514" -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Extract all' in the MSI context menu: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Extract all' item from the Windows Installer (.msi) context menu"
			LogInfo "Hiding 'Extract all' item from the Windows Installer (.msi) context menu"
			try
			{
				if (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract)
				{
					Remove-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Recurse -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Extract all' from the MSI context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Install" item for the Cabinet (.cab) filenames extensions context menu

	.PARAMETER Show
	Show the "Install" item in the Cabinet (.cab) filenames extensions context menu

	.PARAMETER Hide
	Hide the "Install" item from the Cabinet (.cab) filenames extensions context menu (default value)

	.EXAMPLE
	CABInstallContext -Show

	.EXAMPLE
	CABInstallContext -Hide

	.NOTES
	Current user
#>
function CABInstallContext
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
			Write-ConsoleStatus -Action "Showing 'Install' item in the Cabinet (.cab) filenames extensions context menu"
			LogInfo "Showing 'Install' item in the Cabinet (.cab) filenames extensions context menu"
			try
			{
				if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas\Command))
				{
					New-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas\Command -Force -ErrorAction Stop | Out-Null
				}
				$Value = "cmd /c DISM.exe /Online /Add-Package /PackagePath:`"%1`" /NoRestart & pause"
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas\Command -Name "(default)" -PropertyType String -Value $Value -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas -Name MUIVerb -PropertyType String -Value "@shell32.dll,-10210" -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas -Name HasLUAShield -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Install' in the CAB context menu: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Install' item from the Cabinet (.cab) filenames extensions context menu"
			LogInfo "Hiding 'Install' item from the Cabinet (.cab) filenames extensions context menu"
			try
			{
				if (Test-Path -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas)
				{
					Remove-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\runas -Recurse -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Install' from the CAB context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Edit with Clipchamp" item in the media files context menu

	.PARAMETER Hide
	Hide the "Edit with Clipchamp" item from the media files context menu

	.PARAMETER Show
	Show the "Edit with Clipchamp" item in the media files context menu (default value)

	.EXAMPLE
	EditWithClipchampContext -Hide

	.EXAMPLE
	EditWithClipchampContext -Show

	.NOTES
	Current user
#>
function EditWithClipchampContext
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

	if (-not (Get-AppxPackage -Name Clipchamp.Clipchamp))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{8AB635F8-9A67-4698-AB99-784AD929F3B4}" -Force -ErrorAction SilentlyContinue | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Edit with Clipchamp' item from the media files context menu"
			LogInfo "Hiding 'Edit with Clipchamp' item from the media files context menu"
			try
			{
				if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
				{
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{8AB635F8-9A67-4698-AB99-784AD929F3B4}" -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Edit with Clipchamp' from the context menu: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Edit with Clipchamp' item in the media files context menu"
			LogInfo "Showing 'Edit with Clipchamp' item in the media files context menu"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{8AB635F8-9A67-4698-AB99-784AD929F3B4}" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{8AB635F8-9A67-4698-AB99-784AD929F3B4}" -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Edit with Clipchamp' in the context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Edit with Photos" item in the media files context menu

	.PARAMETER Hide
	Hide the "Edit with Photos" item from the media files context menu

	.PARAMETER Show
	Show the "Edit with Photos" item in the media files context menu (default value)

	.EXAMPLE
	EditWithPhotosContext -Hide

	.EXAMPLE
	EditWithPhotosContext -Show

	.NOTES
	Current user
#>
function EditWithPhotosContext
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

	if (-not (Get-AppxPackage -Name Microsoft.Windows.Photos))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}" -Force -ErrorAction SilentlyContinue | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Edit with Photos' item from the media files context menu"
			LogInfo "Hiding 'Edit with Photos' item from the media files context menu"
			try
			{
				if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
				{
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}" -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Edit with Photos' from the context menu: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Edit with Photos' item in the media files context menu"
			LogInfo "Showing 'Edit with Photos' item in the media files context menu"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}" -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Edit with Photos' in the context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Edit with Paint" item in the media files context menu

	.PARAMETER Hide
	Hide the "Edit with Paint" item from the media files context menu

	.PARAMETER Show
	Show the "Edit with Paint" item in the media files context menu (default value)

	.EXAMPLE
	EditWithPaintContext -Hide

	.EXAMPLE
	EditWithPaintContext -Show

	.NOTES
	Current user
#>
function EditWithPaintContext
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

	if (-not (Get-AppxPackage -Name Microsoft.Paint))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{2430F218-B743-4FD6-97BF-5C76541B4AE9}" -Force -ErrorAction SilentlyContinue | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Edit with Paint' item from the media files context menu"
			LogInfo "Hiding 'Edit with Paint' item from the media files context menu"
			try
			{
				if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
				{
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{2430F218-B743-4FD6-97BF-5C76541B4AE9}" -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Edit with Paint' from the context menu: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Edit with Paint' item in the media files context menu"
			LogInfo "Showing 'Edit with Paint' item in the media files context menu"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{2430F218-B743-4FD6-97BF-5C76541B4AE9}" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{2430F218-B743-4FD6-97BF-5C76541B4AE9}" -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Edit with Paint' in the context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Print" item in the .bat and .cmd context menu

	.PARAMETER Hide
	Hide the "Print" item from the .bat and .cmd context menu

	.PARAMETER Show
	Show the "Print" item in the .bat and .cmd context menu (default value)

	.EXAMPLE
	PrintCMDContext -Hide

	.EXAMPLE
	PrintCMDContext -Show

	.NOTES
	Current user
#>
function PrintCMDContext
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
			Write-ConsoleStatus -Action "Hiding 'Print' item from the .bat and .cmd context menu"
			LogInfo "Hiding 'Print' item from the .bat and .cmd context menu"
			try
			{
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Print' from the .bat and .cmd context menu: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Print' item in the .bat and .cmd context menu"
			LogInfo "Showing 'Print' item in the .bat and .cmd context menu"
			try
			{
				if (Get-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -Force -ErrorAction Stop | Out-Null
				}
				if (Get-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Print' in the .bat and .cmd context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Compressed (zipped) Folder" item in the "New" context menu

	.PARAMETER Hide
	Hide the "Compressed (zipped) Folder" item from the "New" context menu

	.PARAMETER Show
	Show the "Compressed (zipped) Folder" item to the "New" context menu (default value)

	.EXAMPLE
	CompressedFolderNewContext -Hide

	.EXAMPLE
	CompressedFolderNewContext -Show

	.NOTES
	Current user
#>
function CompressedFolderNewContext
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
			Write-ConsoleStatus -Action "Hiding 'Compressed (zipped) Folder' item from the 'New' context menu"
			LogInfo "Hiding 'Compressed (zipped) Folder' item from the 'New' context menu"
			try
			{
				if (Test-Path -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew)
				{
					Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Compressed (zipped) Folder' from the 'New' context menu: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Compressed (zipped) Folder' item in the 'New' context menu"
			LogInfo "Showing 'Compressed (zipped) Folder' item in the 'New' context menu"
			try
			{
				if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew))
				{
					New-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Name Data -PropertyType Binary -Value ([byte[]](80,75,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Name ItemName -PropertyType ExpandString -Value "@%SystemRoot%\System32\zipfldr.dll,-10194" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Compressed (zipped) Folder' in the 'New' context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Open", "Print", and "Edit" items if more than 15 files selected

	.PARAMETER Enable
	Enable the "Open", "Print", and "Edit" items if more than 15 files selected

	.PARAMETER Disable
	Disable the "Open", "Print", and "Edit" items if more than 15 files selected (default value)

	.EXAMPLE
	MultipleInvokeContext -Enable

	.EXAMPLE
	MultipleInvokeContext -Disable

	.NOTES
	Current user
#>
function MultipleInvokeContext
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
			Write-ConsoleStatus -Action "Enabling 'Open', 'Print', and 'Edit' items if more than 15 files selected"
			LogInfo "Enabling 'Open', 'Print', and 'Edit' items if more than 15 files selected"
			try
			{
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -PropertyType DWord -Value 300 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable multiple invoke context menu items: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling 'Open', 'Print', and 'Edit' items if more than 15 files selected"
			LogInfo "Disabling 'Open', 'Print', and 'Edit' items if more than 15 files selected"
			try
			{
				if (Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -Force -ErrorAction Stop
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable multiple invoke context menu items: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Look for an app in the Microsoft Store" item in the "Open with" dialog

	.PARAMETER Hide
	Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog

	.PARAMETER Show
	Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog (default value)

	.EXAMPLE
	UseStoreOpenWith -Hide

	.EXAMPLE
	UseStoreOpenWith -Show

	.NOTES
	Current user
#>
function UseStoreOpenWith
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
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Force -ErrorAction SilentlyContinue
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Look for an app in the Microsoft Store' item in the 'Open with' dialog"
			LogInfo "Hiding 'Look for an app in the Microsoft Store' item in the 'Open with' dialog"
			try
			{
				if (-not (Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
				{
					New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWORD -Value 1 | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Look for an app in the Microsoft Store' in the 'Open with' dialog: $($_.Exception.Message)"
			}
		}
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Look for an app in the Microsoft Store' item in the 'Open with' dialog"
			LogInfo "Showing 'Look for an app in the Microsoft Store' item in the 'Open with' dialog"
			try
			{
				if (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Force -ErrorAction Stop | Out-Null
				}
				Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type CLEAR | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Look for an app in the Microsoft Store' in the 'Open with' dialog: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The "Open in Windows Terminal" item in the folders context menu

	.PARAMETER Hide
	Hide the "Open in Windows Terminal" item in the folders context menu

	.PARAMETER Show
	Show the "Open in Windows Terminal" item in the folders context menu (default value)

	.EXAMPLE
	OpenWindowsTerminalContext -Show

	.EXAMPLE
	OpenWindowsTerminalContext -Hide

	.NOTES
	Current user
#>
function OpenWindowsTerminalContext
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

	if (-not (Get-AppxPackage -Name Microsoft.WindowsTerminal))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -Force -ErrorAction SilentlyContinue | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Show"
		{
			Write-ConsoleStatus -Action "Showing 'Open in Windows Terminal' item in the folders context menu"
			LogInfo "Showing 'Open in Windows Terminal' item in the folders context menu"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -Force -ErrorAction Stop | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to show 'Open in Windows Terminal' in the context menu: $($_.Exception.Message)"
			}
		}
		"Hide"
		{
			Write-ConsoleStatus -Action "Hiding 'Open in Windows Terminal' item from the folders context menu"
			LogInfo "Hiding 'Open in Windows Terminal' item from the folders context menu"
			try
			{
				if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
				{
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -PropertyType String -Value "" -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to hide 'Open in Windows Terminal' from the context menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Open Windows Terminal in context menu as administrator

	.PARAMETER Enable
	Open Windows Terminal in context menu as administrator by default

	.PARAMETER Disable
	Do not open Windows Terminal in context menu as administrator by default (default value)

	.EXAMPLE
	OpenWindowsTerminalAdminContext -Enable

	.EXAMPLE
	OpenWindowsTerminalAdminContext -Disable

	.NOTES
	Current user
#>
function OpenWindowsTerminalAdminContext
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

	if (-not (Get-AppxPackage -Name Microsoft.WindowsTerminal))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	if (-not (Test-Path -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"))
	{
		Start-Process -FilePath wt -PassThru | Out-Null
		Start-Sleep -Seconds 2
		Stop-Process -Name WindowsTerminal -Force -PassThru | Out-Null
	}

	try
	{
		$Terminal = Get-Content -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" -Encoding UTF8 -Force | ConvertFrom-Json
	}
	catch [System.ArgumentException]
	{
		LogWarning (($Global:Error.Exception.Message | Select-Object -First 1))
		LogError (($Global:Error.Exception.Message | Select-Object -First 1))

		Invoke-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState"
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling opening Windows Terminal in context menu as administrator by default"
			LogInfo "Enabling opening Windows Terminal in context menu as administrator by default"
			try
			{
				if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -ErrorAction Stop | Out-Null
				}
				if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -ErrorAction SilentlyContinue)
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -ErrorAction Stop | Out-Null
				}
				if ($Terminal.profiles.defaults.elevate)
				{
					$Terminal.profiles.defaults.elevate = $true
				}
				else
				{
					$Terminal.profiles.defaults | Add-Member -MemberType NoteProperty -Name elevate -Value $true -Force | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable opening Windows Terminal as administrator from the context menu: $($_.Exception.Message)"
				return
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling opening Windows Terminal in context menu as administrator by default"
			LogInfo "Disabling opening Windows Terminal in context menu as administrator by default"
			try
			{
				if ($Terminal.profiles.defaults.elevate)
				{
					$Terminal.profiles.defaults.elevate = $false
				}
				else
				{
					$Terminal.profiles.defaults | Add-Member -MemberType NoteProperty -Name elevate -Value $false -Force | Out-Null
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable opening Windows Terminal as administrator from the context menu: $($_.Exception.Message)"
				return
			}
		}
	}
	try
	{
		# Save in UTF-8 with BOM despite JSON must not has the BOM: https://datatracker.ietf.org/doc/html/rfc8259#section-8.1. Unless Terminal profile names which contains non-Latin characters will have "?" instead of titles
		ConvertTo-Json -InputObject $Terminal -Depth 4 | Set-Content -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" -Encoding UTF8 -Force -ErrorAction Stop | Out-Null
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to save Windows Terminal settings after updating context menu elevation: $($_.Exception.Message)"
	}
}
#endregion Context menu
