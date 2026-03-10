using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Microsoft Defender & Security
<#
	.SYNOPSIS
	Microsoft Defender Exploit Guard network protection

	.PARAMETER Enable
	Enable Microsoft Defender Exploit Guard network protection

	.PARAMETER Disable
	Disable Microsoft Defender Exploit Guard network protection (default value)

	.EXAMPLE
	NetworkProtection -Enable

	.EXAMPLE
	NetworkProtection -Disable

	.NOTES
	Current user
#>
function NetworkProtection
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

	if (-not $Script:DefenderEnabled)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Microsoft Defender Exploit Guard network protection"
			LogInfo "Enabling Microsoft Defender Exploit Guard network protection"
			try
			{
				Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Microsoft Defender Exploit Guard network protection: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Microsoft Defender Exploit Guard network protection"
			LogInfo "Disabling Microsoft Defender Exploit Guard network protection"
			try
			{
				Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Microsoft Defender Exploit Guard network protection: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Detection for potentially unwanted applications

	.PARAMETER Enable
	Enable detection for potentially unwanted applications and block them

	.PARAMETER Disable
	Disable detection for potentially unwanted applications and block them (default value)

	.EXAMPLE
	PUAppsDetection -Enable

	.EXAMPLE
	PUAppsDetection -Disable

	.NOTES
	Current user
#>
function PUAppsDetection
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

	if (-not $Script:DefenderEnabled)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling detection for potentially unwanted applications and blocking them"
			LogInfo "Enabling detection for potentially unwanted applications and blocking them"
			try
			{
				Set-MpPreference -PUAProtection Enabled -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable detection for potentially unwanted applications: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling detection for potentially unwanted applications and blocking them"
			LogInfo "Disabling detection for potentially unwanted applications and blocking them"
			try
			{
				Set-MpPreference -PUAProtection Disabled -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable detection for potentially unwanted applications: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Sandboxing for Microsoft Defender

	.PARAMETER Enable
	Enable sandboxing for Microsoft Defender

	.PARAMETER Disable
	Disable sandboxing for Microsoft Defender (default value)

	.EXAMPLE
	DefenderSandbox -Enable

	.EXAMPLE
	DefenderSandbox -Disable

	.NOTES
	Machine-wide
#>
function DefenderSandbox
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

	if (-not $Script:DefenderEnabled)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling sandboxing for Microsoft Defender"
			LogInfo "Enabling sandboxing for Microsoft Defender"
			try
			{
				& "$env:SystemRoot\System32\setx.exe" /M MP_FORCE_USE_SANDBOX 1 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "setx.exe returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable sandboxing for Microsoft Defender: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling sandboxing for Microsoft Defender"
			LogInfo "Disabling sandboxing for Microsoft Defender"
			try
			{
				& "$env:SystemRoot\System32\setx.exe" /M MP_FORCE_USE_SANDBOX 0 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "setx.exe returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable sandboxing for Microsoft Defender: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Dismiss the Windows Security warning about not signing in with a Microsoft account.

	.DESCRIPTION
	Sets the Windows Security Health state value that suppresses the Account
	Protection prompt about signing in with a Microsoft account.

	.EXAMPLE
	DismissMSAccount

	.NOTES
	Current user
#>
function DismissMSAccount
{
	if (-not $Script:DefenderEnabled)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Write-ConsoleStatus -Action "Dismissing Microsoft Defender offer in the Windows Security about signing in Microsoft account"
	LogInfo "Dismissing Microsoft Defender offer in the Windows Security about signing in Microsoft account"
	try
	{
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to dismiss the Microsoft account warning in Windows Security: $($_.Exception.Message)"
	}
}

<#
	.SYNOPSIS
	Dismiss the Windows Security warning about Microsoft Edge SmartScreen.

	.DESCRIPTION
	Sets the Windows Security Health state value that marks the Edge SmartScreen
	warning as dismissed.

	.EXAMPLE
	DismissSmartScreenFilter

	.NOTES
	Current user
#>
function DismissSmartScreenFilter
{
	if (-not $Script:DefenderEnabled)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Write-ConsoleStatus -Action "Disabling the SmartScreen filter for Microsoft Edge"
	LogInfo "Disabling the SmartScreen filter for Microsoft Edge"
	try
	{
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AppAndBrowser_EdgeSmartScreenOff -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to dismiss the Edge SmartScreen warning in Windows Security: $($_.Exception.Message)"
	}
}

<#
	.SYNOPSIS
	The "Process Creation" Event Viewer custom view

	.PARAMETER Enable
	Create the "Process Creation" сustom view in the Event Viewer to log executed processes and their arguments

	.PARAMETER Disable
	Remove the "Process Creation" custom view in the Event Viewer (default value)

	.EXAMPLE
	EventViewerCustomView -Enable

	.EXAMPLE
	EventViewerCustomView -Disable

	.NOTES
	In order this feature to work events auditing and command line in process creation events will be enabled

	.NOTES
	Machine-wide
#>
function EventViewerCustomView
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
			Write-ConsoleStatus -Action "Creating the 'Process Creation' custom view in the Event Viewer to log executed processes and their arguments"
			LogInfo "Creating the 'Process Creation' custom view in the Event Viewer to log executed processes and their arguments"
			try
			{
				# Enable events auditing generated when a process is created (starts)
				auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "auditpol returned exit code $LASTEXITCODE" }

				# Include command line in process creation events
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Type DWORD -Value 1 | Out-Null

				$XML = @"
<ViewerConfig>
	<QueryConfig>
		<QueryParams>
			<UserQuery />
		</QueryParams>
		<QueryNode>
			<Name>$($Localization.EventViewerCustomViewName)</Name>
			<Description>$($Localization.EventViewerCustomViewDescription)</Description>
			<QueryList>
				<Query Id="0" Path="Security">
					<Select Path="Security">*[System[(EventID=4688)]]</Select>
				</Query>
			</QueryList>
		</QueryNode>
	</QueryConfig>
</ViewerConfig>
"@

				if (-not (Test-Path -Path "$env:ProgramData\Microsoft\Event Viewer\Views"))
				{
					New-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views" -ItemType Directory -Force -ErrorAction Stop | Out-Null
				}

				# Save ProcessCreation.xml in the UTF-8 without BOM encoding
				Set-Content -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Value $XML -Encoding Default -NoNewline -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to create the 'Process Creation' Event Viewer custom view: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Removing the 'Process Creation' custom view in the Event Viewer"
			LogInfo "Removing the 'Process Creation' custom view in the Event Viewer"
			try
			{
				Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Force -ErrorAction SilentlyContinue | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Type CLEAR | Out-Null
				Remove-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Force -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to remove the 'Process Creation' Event Viewer custom view: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Logging for all Windows PowerShell modules

	.PARAMETER Enable
	Enable logging for all Windows PowerShell modules

	.PARAMETER Disable
	Disable logging for all Windows PowerShell modules (default value)

	.EXAMPLE
	PowerShellModulesLogging -Enable

	.EXAMPLE
	PowerShellModulesLogging -Disable

	.NOTES
	Machine-wide
#>
function PowerShellModulesLogging
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
			Write-ConsoleStatus -Action "Enabling logging for all Windows PowerShell modules"
			LogInfo "Enabling logging for all Windows PowerShell modules"
			try
			{
				if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames))
				{
					New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -PropertyType String -Value * -Force -ErrorAction Stop | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Type DWORD -Value 1 | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Type SZ -Value * | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable PowerShell module logging: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling logging for all Windows PowerShell modules"
			LogInfo "Disabling logging for all Windows PowerShell modules"
			try
			{
				Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Force -ErrorAction SilentlyContinue | Out-Null
				Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Force -ErrorAction SilentlyContinue | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Type CLEAR | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable PowerShell module logging: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Logging for all PowerShell scripts input to the Windows PowerShell event log

	.PARAMETER Enable
	Enable logging for all PowerShell scripts input to the Windows PowerShell event log

	.PARAMETER Disable
	Disable logging for all PowerShell scripts input to the Windows PowerShell event log (default value)

	.EXAMPLE
	PowerShellScriptsLogging -Enable

	.EXAMPLE
	PowerShellScriptsLogging -Disable

	.NOTES
	Machine-wide
#>
function PowerShellScriptsLogging
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
			Write-ConsoleStatus -Action "Enabling logging for all PowerShell scripts input to the Windows PowerShell event log"
			LogInfo "Enabling logging for all PowerShell scripts input to the Windows PowerShell event log"
			try
			{
				if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging))
				{
					New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Type DWORD -Value 1 | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable PowerShell script block logging: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling logging for all PowerShell scripts input to the Windows PowerShell event log"
			LogInfo "Disabling logging for all PowerShell scripts input to the Windows PowerShell event log"
			try
			{
				Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Force -ErrorAction SilentlyContinue | Out-Null
				Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Type CLEAR | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable PowerShell script block logging: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Microsoft Defender SmartScreen

	.PARAMETER Disable
	Disable apps and files checking within Microsoft Defender SmartScreen

	.PARAMETER Enable
	Enable apps and files checking within Microsoft Defender SmartScreen (default value)

	.EXAMPLE
	AppsSmartScreen -Disable

	.EXAMPLE
	AppsSmartScreen -Enable

	.NOTES
	Machine-wide
#>
function AppsSmartScreen
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

	if (-not $Script:DefenderEnabled)
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling apps and files checking within Microsoft Defender SmartScreen"
			LogInfo "Disabling apps and files checking within Microsoft Defender SmartScreen"
			try
			{
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Microsoft Defender SmartScreen for apps and files: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling apps and files checking within Microsoft Defender SmartScreen"
			LogInfo "Enabling apps and files checking within Microsoft Defender SmartScreen"
			try
			{
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Warn -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Microsoft Defender SmartScreen for apps and files: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	The Attachment Manager

	.PARAMETER Disable
	Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe

	.PARAMETER Enable
	Microsoft Defender SmartScreen marks downloaded files from the Internet as unsafe (default value)

	.EXAMPLE
	SaveZoneInformation -Disable

	.EXAMPLE
	SaveZoneInformation -Enable

	.NOTES
	Current user
#>
function SaveZoneInformation
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
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling marking downloaded files from the Internet as unsafe"
			LogInfo "Disabling marking downloaded files from the Internet as unsafe"
			try
			{
				if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
				{
					New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Type DWORD -Value 1 | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable saving zone information on downloaded files: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling marking downloaded files from the Internet as unsafe"
			LogInfo "Enabling marking downloaded files from the Internet as unsafe"
			try
			{
				Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Force -ErrorAction SilentlyContinue | Out-Null
				Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Type CLEAR | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable saving zone information on downloaded files: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows Script Host

	.PARAMETER Disable
	Disable Windows Script Host

	.PARAMETER Enable
	Enable Windows Script Host (default value)

	.EXAMPLE
	WindowsScriptHost -Disable

	.EXAMPLE
	WindowsScriptHost -Enable

	.NOTES
	Blocks WSH from executing .js and .vbs files

	.NOTES
	Current user
#>
function WindowsScriptHost
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
			Write-ConsoleStatus -Action "Disabling Windows Script Host"
			LogInfo "Disabling Windows Script Host"
			# Checking whether any scheduled tasks were created before, because they rely on Windows Host running vbs files
			Get-ScheduledTask -TaskName SoftwareDistribution, Temp, "Windows Cleanup", "Windows Cleanup Notification" -ErrorAction SilentlyContinue | ForEach-Object -Process {
				# Skip if a scheduled task exists
				if ($_.State -eq "Ready")
				{
					LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
					Write-ConsoleStatus -Status success
					break
				}
			}

			try
			{
				if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings"))
				{
					New-Item -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Windows Script Host: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Windows Script Host"
			LogInfo "Enabling Windows Script Host"
			try
			{
				Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Windows Script Host: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows Sandbox

	.PARAMETER Disable
	Disable Windows Sandbox (default value)

	.PARAMETER Enable
	Enable Windows Sandbox

	.EXAMPLE
	WindowsSandbox -Disable

	.EXAMPLE
	WindowsSandbox -Enable

	.NOTES
	Current user
#>
function WindowsSandbox
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

	$FeatureName = "Containers-DisposableClientVM"

	# Get Windows edition from registry instead of WinAPI
	$Edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName

	if (($Edition -notmatch "Pro") -and ($Edition -notmatch "Enterprise") -and ($Edition -notmatch "Education"))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Windows Sandbox"
			LogInfo "Disabling Windows Sandbox"
			$Feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

			if (-not $Feature)
			{
				Write-ConsoleStatus -Status warning
				LogWarning "Windows Sandbox feature is not available on this system. Skipping."
				return
			}

			if ($Feature.State -in @("Disabled", "DisablePending"))
			{
				Write-ConsoleStatus -Status success
				LogInfo "Windows Sandbox is already disabled."
				return
			}

			try
			{
				Disable-WindowsOptionalFeature -FeatureName $FeatureName -Online -NoRestart -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Windows Sandbox: $($_.Exception.Message)"
				Remove-HandledErrorRecord -ErrorRecord $_
			}
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Windows Sandbox"
			LogInfo "Enabling Windows Sandbox"
			$Feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

			if (-not $Feature)
			{
				Write-ConsoleStatus -Status warning
				LogWarning "Windows Sandbox feature is not available on this system. Skipping."
				return
			}

			if ($Feature.State -in @("Enabled", "EnablePending"))
			{
				Write-ConsoleStatus -Status success
				LogInfo "Windows Sandbox is already enabled."
				return
			}

			# Checking whether x86 virtualization is enabled in the firmware
			if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled -or (Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
			{
				try
				{
					Enable-WindowsOptionalFeature -FeatureName $FeatureName -All -Online -NoRestart -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch
				{
					Write-ConsoleStatus -Status failed
					LogError "Failed to enable Windows Sandbox: $($_.Exception.Message)"
					Remove-HandledErrorRecord -ErrorRecord $_
				}
			}
			else
			{
				Write-ConsoleStatus -Status failed
				LogError $Localization.EnableHardwareVT
				LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
			}
		}
	}
}

<#
	.SYNOPSIS
	DNS-over-HTTPS for IPv4

	.PARAMETER Enable
	Enable DNS-over-HTTPS for IPv4

	.PARAMETER Disable
	Disable DNS-over-HTTPS for IPv4 (default value)

	.EXAMPLE
	DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1

	.EXAMPLE
	DNSoverHTTPS -Disable

	.NOTES
	The valid IPv4 addresses: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9

	.LINK
	https://docs.microsoft.com/en-us/windows-server/networking/dns/doh-client-support

	.LINK
	https://www.comss.ru/page.php?id=7315

	.NOTES
	Machine-wide
#>
function DNSoverHTTPS
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(Mandatory = $false)]
		[ValidateScript({
			# Isolate IPv4 IP addresses and check whether $PrimaryDNS is not equal to $SecondaryDNS
			((@((Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers).PSChildName) | Where-Object -FilterScript {($_ -as [IPAddress]).AddressFamily -ne "InterNetworkV6"}) -contains $_) -and ($_ -ne $SecondaryDNS)
		})]
		[string]
		$PrimaryDNS,

		[Parameter(Mandatory = $false)]
		[ValidateScript({
			# Isolate IPv4 IP addresses and check whether $PrimaryDNS is not equal to $SecondaryDNS
			((@((Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers).PSChildName) | Where-Object -FilterScript {($_ -as [IPAddress]).AddressFamily -ne "InterNetworkV6"}) -contains $_) -and ($_ -ne $PrimaryDNS)
		})]
		[string]
		$SecondaryDNS,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	# Determining whether Hyper-V is enabled
	# After enabling Hyper-V feature a virtual switch breing created, so we need to use different method to isolate the proper adapter
	if (-not (Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
	{
		$InterfaceGuids = @((Get-NetAdapter -Physical).InterfaceGuid)
	}
	else
	{
		$InterfaceGuids = @((Get-NetRoute -AddressFamily IPv4 | Where-Object -FilterScript {$_.DestinationPrefix -eq "0.0.0.0/0"} | Get-NetAdapter).InterfaceGuid)
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling DNS-over-HTTPS for IPv4"
			LogInfo "Enabling DNS-over-HTTPS for IPv4"
			# Set a primary and secondary DNS servers
			if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
			{
				Get-NetRoute | Where-Object -FilterScript {$_.DestinationPrefix -eq "0.0.0.0/0"} | Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $PrimaryDNS, $SecondaryDNS | Out-Null
			}
			else
			{
				Get-NetAdapter -Physical | Get-NetIPInterface -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses $PrimaryDNS, $SecondaryDNS | Out-Null
			}

			foreach ($InterfaceGuid in $InterfaceGuids)
			{
				if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh\$PrimaryDNS"))
				{
					New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh\$PrimaryDNS" -Force | Out-Null
				}
				if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh\$SecondaryDNS"))
				{
					New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh\$SecondaryDNS" -Force | Out-Null
				}
				# Encrypted preffered, unencrypted allowed
				New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh\$PrimaryDNS" -Name DohFlags -PropertyType QWord -Value 5 -Force | Out-Null
				New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh\$SecondaryDNS" -Name DohFlags -PropertyType QWord -Value 5 -Force | Out-Null
			}
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling DNS-over-HTTPS for IPv4"
			LogInfo "Disabling DNS-over-HTTPS for IPv4"
			# Determining whether Hyper-V is enabled
			if (-not (Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
			{
				# Configure DNS servers automatically
				Get-NetAdapter -Physical | Get-NetIPInterface -AddressFamily IPv4 | Set-DnsClientServerAddress -ResetServerAddresses | Out-Null
			}
			else
			{
				# Configure DNS servers automatically
				Get-NetRoute | Where-Object -FilterScript {$_.DestinationPrefix -eq "0.0.0.0/0"} | Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses | Out-Null
			}

			foreach ($InterfaceGuid in $InterfaceGuids)
			{
				Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$InterfaceGuid\DohInterfaceSettings\Doh" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
			}
			Write-ConsoleStatus -Status success
		}
	}

	try
	{
		Clear-DnsClientCache -ErrorAction Stop
	}
	catch
	{
		LogWarning "Failed to clear the DNS client cache after updating DNS-over-HTTPS settings: $($_.Exception.Message)"
		Remove-HandledErrorRecord -ErrorRecord $_
	}

	try
	{
		Register-DnsClient -ErrorAction Stop
	}
	catch [Microsoft.Management.Infrastructure.CimException]
	{
		if ($_.Exception.Message -match "not covered by a more specific error code")
		{
			LogWarning "DNS client registration returned a generic error after updating DNS-over-HTTPS settings. The DNS server changes were applied, but dynamic DNS registration may require reconnecting the adapter or restarting Windows."
			Remove-HandledErrorRecord -ErrorRecord $_
		}
		else
		{
			LogError "Failed to register the DNS client after updating DNS-over-HTTPS settings: $($_.Exception.Message)"
		}
	}
	catch
	{
		LogWarning "Failed to register the DNS client after updating DNS-over-HTTPS settings: $($_.Exception.Message)"
		Remove-HandledErrorRecord -ErrorRecord $_
	}
}

<#
	.SYNOPSIS
	Local Security Authority protection

	.PARAMETER Enable
	Enable Local Security Authority protection to prevent code injection without UEFI lock

	.PARAMETER Disable
	Disable Local Security Authority protection

	.EXAMPLE
	LocalSecurityAuthority -Enable

	.EXAMPLE
	LocalSecurityAuthority -Disable

	.NOTES
	https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

	.NOTES
	Machine-wide
#>
function LocalSecurityAuthority
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
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name RunAsPPL -Force -ErrorAction SilentlyContinue | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\System -Name RunAsPPL -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Local Security Authority protection to prevent code injection without UEFI lock"
			LogInfo "Enabling Local Security Authority protection to prevent code injection without UEFI lock"
			# Checking whether x86 virtualization is enabled in the firmware
			if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled)
			{
				try
				{
					New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
					New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPLBoot -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch
				{
					Write-ConsoleStatus -Status failed
					LogError "Failed to enable Local Security Authority protection: $($_.Exception.Message)"
				}
			}
			else
			{
				try
				{
					# Determining whether Hyper-V is enabled
					if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
					{
						New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
						New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPLBoot -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
						Write-ConsoleStatus -Status success
					}
				}
				catch [System.Exception]
				{
					Write-ConsoleStatus -Status failed
					LogError $Localization.EnableHardwareVT
				}
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Local Security Authority protection"
			LogInfo "Disabling Local Security Authority protection"
			try
			{
				Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL, RunAsPPLBoot -Force -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Local Security Authority protection: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Sharing mapped drives between elevated and standard user sessions

	.PARAMETER Enable
	Enable sharing mapped drives between users

	.PARAMETER Disable
	Disable sharing mapped drives between users (default value)

	.EXAMPLE
	SharingMappedDrives -Enable

	.EXAMPLE
	SharingMappedDrives -Disable

	.NOTES
	Current user
#>
function SharingMappedDrives
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
			Write-ConsoleStatus -Action "Enabling sharing mapped drives between users"
			LogInfo "Enabling sharing mapped drives between users"
			try
			{
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable sharing mapped drives between users: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling sharing mapped drives between users"
			LogInfo "Disabling sharing mapped drives between users"
			try
			{
				Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable sharing mapped drives between users: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows Firewall configuration

	.PARAMETER Enable
	Enable Windows Firewall (default value)

	.PARAMETER Disable
	Disable Windows Firewall

	.EXAMPLE
	Firewall -Enable

	.EXAMPLE
	Firewall -Disable

	.NOTES
	Current user
#>
function Firewall
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
			Write-ConsoleStatus -Action "Enabling Windows Firewall"
			LogInfo "Enabling Windows Firewall"
			try
			{
				Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Windows Firewall: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Windows Firewall"
			LogInfo "Disabling Windows Firewall"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Windows Firewall: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows Defender notification area (system tray) icon configuration

	.PARAMETER Enable
	Show Windows Defender (Windows Security) system tray icon (default value)

	.PARAMETER Disable
	Hide Windows Defender (Windows Security) system tray icon

	.EXAMPLE
	DefenderTrayIcon -Enable

	.EXAMPLE
	DefenderTrayIcon -Disable

	.NOTES
	Current User
#>
function DefenderTrayIcon
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
			Write-ConsoleStatus -Action "Enabling Windows Defender SysTray icon"
			LogInfo "Enabling Windows Defender SysTray icon"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -ErrorAction SilentlyContinue | Out-Null
			If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`"" | Out-Null
			} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe" | Out-Null
			} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe" | Out-Null
			}
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Windows Defender SysTray icon"
			LogInfo "Disabling Windows Defender SysTray icon"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1 | Out-Null
			If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
				Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue | Out-Null
			} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
				Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue | Out-Null
			}
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Windows Defender Cloud-delivered protection configuration

	.PARAMETER Enable
	Enable Windows Defender cloud protection (MAPS reporting and automatic sample submission default behavior) (default value)

	.PARAMETER Disable
	Disable Windows Defender cloud protection (disable MAPS reporting and prevent automatic sample submission)

	.EXAMPLE
	DefenderCloud -Enable

	.EXAMPLE
	DefenderCloud -Disable

	.NOTES
	Current user
#>
function DefenderCloud
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
			Write-ConsoleStatus -Action "Enabling Windows Defender Cloud"
			LogInfo "Enabling Windows Defender Cloud"
			try
			{
				Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue | Out-Null
				Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Windows Defender Cloud protection: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Windows Defender Cloud"
			LogInfo "Disabling Windows Defender Cloud"
			try
			{
				If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
					New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Windows Defender Cloud protection: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Core Isolation Memory Integrity (Hypervisor-Enforced Code Integrity)

	.PARAMETER Enable
	Enable Memory Integrity (HVCI)

	.PARAMETER Disable
	Disable Memory Integrity (HVCI)

	.EXAMPLE
	CIMemoryIntegrity -Enable

	.EXAMPLE
	CIMemoryIntegrity -Disable

	.NOTES
	Current User
	Applicable since Windows 10 version 1803.
	May cause compatibility issues with old drivers and antivirus software.
#>
function CIMemoryIntegrity
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
			Write-ConsoleStatus -Action "Enabling Core Isolation Memory Integrity (HVCI)"
			LogInfo "Enabling Core Isolation Memory Integrity (HVCI)"
			try
			{
				If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
					New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Core Isolation Memory Integrity: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Core Isolation Memory Integrity (HVCI)"
			LogInfo "Disabling Core Isolation Memory Integrity (HVCI)"
			try
			{
				Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Core Isolation Memory Integrity: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Windows Defender Application Guard configuration

	.PARAMETER Enable
	Enable Windows Defender Application Guard optional feature

	.PARAMETER Disable
	Disable Windows Defender Application Guard optional feature (default value)

	.EXAMPLE
	DefenderAppGuard -Enable

	.EXAMPLE
	DefenderAppGuard -Disable

	.NOTES
	Current User
	Applicable since:
	- Windows 10 1709 (Enterprise)
	- Windows 10 1803 (Pro)
	Not applicable to Windows Server.
	Not supported on VMs or VDI environments.
#>
function DefenderAppGuard
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
			Write-ConsoleStatus -Action "Enabling Windows Defender Application Guard"
			LogInfo "Enabling Windows Defender Application Guard"
			$feature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

			if (-not $feature) {
				Write-ConsoleStatus -Status warning
				LogWarning "WDAG feature is not available on this system. Skipping."
			}
			elseif ($feature.State -eq "Disabled") {
				try {
					$null = Enable-WindowsOptionalFeature -Online `
	        			-FeatureName "Windows-Defender-ApplicationGuard" `
	        			-NoRestart `
	        			-ErrorAction Stop `
	        			-WarningAction SilentlyContinue
					Write-ConsoleStatus -Status success
				}
				catch {
					Write-ConsoleStatus -Status failed
					LogError "Failed to enable Windows Defender Application Guard: $($_.Exception.Message)"
					Remove-HandledErrorRecord -ErrorRecord $_
				}
			}
			else {
				Write-ConsoleStatus -Status success
				LogInfo "WDAG feature is already enabled."
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Windows Defender Application Guard"
			LogInfo "Disabling Windows Defender Application Guard"
			# Check if feature exists without throwing error
			$feature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

			if (-not $feature) {
				Write-ConsoleStatus -Status warning
				LogWarning "WDAG feature is not available on this system. Skipping."
			}
			elseif ($feature.State -ne "Disabled") {
				try {
					$null = Disable-WindowsOptionalFeature -Online `
	        			-FeatureName "Windows-Defender-ApplicationGuard" `
	        			-NoRestart `
	        			-ErrorAction Stop `
	        			-WarningAction SilentlyContinue
					Write-ConsoleStatus -Status success
				}
				catch {
					Write-ConsoleStatus -Status failed
					LogError "Failed to disable Windows Defender Application Guard: $($_.Exception.Message)"
					Remove-HandledErrorRecord -ErrorRecord $_
				}
			}
			else {
				Write-ConsoleStatus -Status success
				LogInfo "WDAG feature is already disabled."
			}
		}
	}
}

<#
	.SYNOPSIS
	Accounts protection warning configuration

	.PARAMETER Enable
	Enable account protection warning for Microsoft accounts

	.PARAMETER Disable
	Disable account protection warning for Microsoft accounts

	.EXAMPLE
	AccountProtectionWarn -Enable

	.EXAMPLE
	AccountProtectionWarn -Disable

	.NOTES
	Current user
#>
function AccountProtectionWarn
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
			Write-ConsoleStatus -Action "Enabling account protection warning for Microsoft accounts"
			LogInfo "Enabling account protection warning for Microsoft accounts"
			try
			{
				Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable account protection warnings: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling account protection warning for Microsoft accounts"
			LogInfo "Disabling account protection warning for Microsoft accounts"
			try
			{
				If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
					New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable account protection warnings: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Blocks or allows file downloads from the internet

	.PARAMETER Enable
	Enable blocking of file downloads (default value)

	.PARAMETER Disable
	Disable blocking of file downloads

	.EXAMPLE
	DownloadBlocking -Enable

	.EXAMPLE
	DownloadBlocking -Disable

	.NOTES
	Current user
#>
function DownloadBlocking
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
			Write-ConsoleStatus -Action "Enabling blocking of file downloads from the internet"
			LogInfo "Enabling blocking of file downloads from the internet"
			try
			{
				Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable download blocking: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling blocking of file downloads from the internet"
			LogInfo "Disabling blocking of file downloads from the internet"
			try
			{
				If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
					New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ErrorAction Stop | Out-Null
				}
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable download blocking: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Enables or disables the F8 boot menu on startup

	.PARAMETER Enable
	Enable the legacy F8 boot menu

	.PARAMETER Disable
	Disable the legacy F8 boot menu (default value)

	.EXAMPLE
	F8BootMenu -Enable

	.EXAMPLE
	F8BootMenu -Disable

	.NOTES
	Current user
#>
function F8BootMenu
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
			Write-ConsoleStatus -Action "Enabling legacy F8 boot menu"
			LogInfo "Enabling legacy F8 boot menu"
			try
			{
				bcdedit /set `{current`} BootMenuPolicy Legacy 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "bcdedit returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable the legacy F8 boot menu: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling legacy F8 boot menu"
			LogInfo "Disabling legacy F8 boot menu"
			try
			{
				bcdedit /set `{current`} BootMenuPolicy Standard 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "bcdedit returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable the legacy F8 boot menu: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Enables or disables automatic recovery mode during boot

	.PARAMETER Enable
	Enable automatic recovery mode on startup errors (default value)

	.PARAMETER Disable
	Disable automatic recovery mode on startup errors

	.EXAMPLE
	BootRecovery -Enable

	.EXAMPLE
	BootRecovery -Disable

	.NOTES
	Current user
#>
function BootRecovery
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
			Write-ConsoleStatus -Action "Enabling automatic recovery mode on startup errors"
			LogInfo "Enabling automatic recovery mode on startup errors"
			try
			{
				# This allows the boot process to automatically enter recovery mode when it detects startup errors (default behavior)
				bcdedit /deletevalue `{current`} BootStatusPolicy 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0)
				{
					$bootStatusPolicy = (bcdedit /enum `{current`} 2>$null | Out-String)
					if ($bootStatusPolicy -match "BootStatusPolicy")
					{
						throw "bcdedit returned exit code $LASTEXITCODE"
					}
				}
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable automatic recovery mode during boot: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling automatic recovery mode on startup errors"
			LogInfo "Disabling automatic recovery mode on startup errors"
			try
			{
				bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "bcdedit returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable automatic recovery mode during boot: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Enables or disables Data Execution Prevention (DEP) policy

	.PARAMETER Enable
	Sets DEP to OptIn (default for most apps) (default value)

	.PARAMETER Disable
	Sets DEP to OptOut (allows all apps without DEP)

	.EXAMPLE
	DEPOptOut -Enable

	.EXAMPLE
	DEPOptOut -Disable

	.NOTES
	Current user
#>
function DEPOptOut
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
			Write-ConsoleStatus -Action "Disabling Data Execution Prevention (DEP) policy to OptIn"
			LogInfo "Disabling Data Execution Prevention (DEP) policy to OptIn"
			try
			{
				# Setting Data Execution Prevention (DEP) policy to OptIn...
				bcdedit /set `{current`} nx OptIn 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "bcdedit returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to set DEP policy to OptIn: $($_.Exception.Message)"
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Data Execution Prevention (DEP) policy to OptOut"
			LogInfo "Disabling Data Execution Prevention (DEP) policy to OptOut"
			try
			{
				# Setting Data Execution Prevention (DEP) policy to OptOut...
				bcdedit /set `{current`} nx OptOut 2>$null | Out-Null
				if ($LASTEXITCODE -ne 0) { throw "bcdedit returned exit code $LASTEXITCODE" }
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to set DEP policy to OptOut: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Import the Microsoft Defender Exploit Protection policy.

	.DESCRIPTION
	Downloads the Microsoft demo Exploit Protection policy XML, imports it with
	Set-ProcessMitigation, and removes the temporary file.

	.EXAMPLE
	Import-ExploitProtectionPolicy

	.NOTES
	Machine-wide

	.CAUTION
	Aggressive. Imports a downloaded mitigation policy that can change exploit
	protection behavior for applications across the system.
#>
function Import-ExploitProtectionPolicy
{
	Write-ConsoleStatus -Action "Importing Exploit Protection policy"
	LogInfo "Importing Exploit Protection policy"
	try
	{
		$policyPath = Join-Path $env:TEMP "ProcessMitigation.xml"
		Invoke-WebRequest -Uri "https://demo.wd.microsoft.com/Content/ProcessMitigation.xml" -OutFile $policyPath -UseBasicParsing -ErrorAction Stop
		Set-ProcessMitigation -PolicyFilePath $policyPath -ErrorAction Stop | Out-Null
		Remove-Item -Path $policyPath -Force -ErrorAction SilentlyContinue | Out-Null
		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to import Exploit Protection policy: $($_.Exception.Message)"
	}
}

<#
	.SYNOPSIS
	Configure additional Defender Exploit Guard protections.

	.DESCRIPTION
	Updates Defender signatures, sets early launch related values, enables a set
	of ASR rules, and applies system-wide exploit mitigations.

	.EXAMPLE
	Set-DefenderExploitGuardPolicy

	.NOTES
	Machine-wide

	.CAUTION
	Aggressive. Can block legitimate applications, Office automation, admin
	tooling, scripts, or line-of-business workflows depending on how they
	interact with Defender ASR and system mitigations.
#>
function Set-DefenderExploitGuardPolicy
{
	Write-ConsoleStatus -Action "Configuring Defender Exploit Guard policies"
	LogInfo "Configuring Defender Exploit Guard policies"
	try
	{
		$mpCmdRunPath = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
		if (Test-Path $mpCmdRunPath)
		{
			& $mpCmdRunPath -SignatureUpdate | Out-Null
		}

		if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows Defender"))
		{
			New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows Defender" -Force -ErrorAction Stop | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Defender" -Name "PassiveMode" -Value 2 -ErrorAction Stop | Out-Null

		if (!(Test-Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"))
		{
			New-Item -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Force -ErrorAction Stop | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -ErrorAction Stop | Out-Null

		$rules = @(
			'D1E49AAC-8F56-4280-B9BA-993A6D',
			'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
			'75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
			'92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',
			'3B576869-A4EC-4529-8536-B80A7769E899',
			'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
			'01443614-CD74-433A-B99E-2ECDC07BFC25',
			'C1DB55AB-C21A-4637-BB3F-A12568109D35',
			'9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2',
			'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'
		)
		$actions = @('Enabled') * $rules.Count

		Set-MpPreference -AttackSurfaceReductionRules_Ids $rules -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop | Out-Null
		Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError -ErrorAction Stop | Out-Null
		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to configure Defender Exploit Guard policies: $($_.Exception.Message)"
	}
}

<#
	.SYNOPSIS
	Configure LOLBin outbound firewall block rules.

	.DESCRIPTION
	Adds outbound block rules for a large list of built-in Windows binaries that
	should not normally make network connections.

	.EXAMPLE
	Set-LOLBinFirewallRules

	.NOTES
	Machine-wide

	.CAUTION
	Aggressive. Can break administrative scripts, installers, troubleshooting
	tools, or enterprise workflows that intentionally use these binaries.
#>
function Set-LOLBinFirewallRules
{
	Write-ConsoleStatus -Action "Configuring LOLBin firewall rules"
	LogInfo "Configuring LOLBin firewall rules"
	try
	{
		$programs = @(
			'%programfiles(x86)%\\Microsoft Office\\root\\client\\AppVLP.exe',
			'%programfiles%\\Microsoft Office\\root\\client\\AppVLP.exe',
			'%systemroot%\\system32\\calc.exe',
			'%systemroot%\\SysWOW64\\calc.exe',
			'%systemroot%\\system32\\certutil.exe',
			'%systemroot%\\SysWOW64\\certutil.exe',
			'%systemroot%\\system32\\cmstp.exe',
			'%systemroot%\\SysWOW64\\cmstp.exe',
			'%systemroot%\\system32\\esentutl.exe',
			'%systemroot%\\SysWOW64\\esentutl.exe',
			'%systemroot%\\system32\\expand.exe',
			'%systemroot%\\SysWOW64\\expand.exe',
			'%systemroot%\\system32\\extrac32.exe',
			'%systemroot%\\SysWOW64\\extrac32.exe',
			'%systemroot%\\system32\\findstr.exe',
			'%systemroot%\\SysWOW64\\findstr.exe',
			'%systemroot%\\system32\\hh.exe',
			'%systemroot%\\SysWOW64\\hh.exe',
			'%systemroot%\\system32\\makecab.exe',
			'%systemroot%\\SysWOW64\\makecab.exe',
			'%systemroot%\\system32\\mshta.exe',
			'%systemroot%\\SysWOW64\\mshta.exe',
			'%systemroot%\\system32\\msiexec.exe',
			'%systemroot%\\SysWOW64\\msiexec.exe',
			'%systemroot%\\system32\\nltest.exe',
			'%systemroot%\\SysWOW64\\nltest.exe',
			'%systemroot%\\system32\\notepad.exe',
			'%systemroot%\\SysWOW64\\notepad.exe',
			'%systemroot%\\system32\\odbcconf.exe',
			'%systemroot%\\SysWOW64\\odbcconf.exe',
			'%systemroot%\\system32\\pcalua.exe',
			'%systemroot%\\SysWOW64\\pcalua.exe',
			'%systemroot%\\system32\\regasm.exe',
			'%systemroot%\\SysWOW64\\regasm.exe',
			'%systemroot%\\system32\\regsvr32.exe',
			'%systemroot%\\SysWOW64\\regsvr32.exe',
			'%systemroot%\\system32\\replace.exe',
			'%systemroot%\\SysWOW64\\replace.exe',
			'%systemroot%\\SysWOW64\\rpcping.exe',
			'%systemroot%\\system32\\rundll32.exe',
			'%systemroot%\\SysWOW64\\rundll32.exe',
			'%systemroot%\\system32\\SyncAppvPublishingServer.exe',
			'%systemroot%\\SysWOW64\\SyncAppvPublishingServer.exe',
			'%systemroot%\\system32\\wbem\\wmic.exe',
			'%systemroot%\\SysWOW64\\wbem\\wmic.exe'
		)

		foreach ($program in $programs)
		{
			$expandedProgram = [Environment]::ExpandEnvironmentVariables($program)
			$ruleName = "Block $(Split-Path $expandedProgram -Leaf) netconns"
			netsh advfirewall firewall add rule name="$ruleName" program="$expandedProgram" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
		}

		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to configure LOLBin firewall rules: $($_.Exception.Message)"
	}
}

<#
	.SYNOPSIS
	Configure Windows Firewall logging.

	.DESCRIPTION
	Configures the current firewall profile to log to pfirewall.log with a
	larger size limit and dropped-connections logging enabled.

	.EXAMPLE
	Set-WindowsFirewallLogging

	.NOTES
	Machine-wide

	.CAUTION
	Usually safe, but log file growth and storage policies should still be
	considered on managed systems.
#>
function Set-WindowsFirewallLogging
{
	Write-ConsoleStatus -Action "Configuring Windows Firewall logging"
	LogInfo "Configuring Windows Firewall logging"
	try
	{
		netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log | Out-Null
		netsh advfirewall set currentprofile logging maxfilesize 4096 | Out-Null
		netsh advfirewall set currentprofile logging droppedconnections enable | Out-Null
		Write-ConsoleStatus -Status success
	}
	catch
	{
		Write-ConsoleStatus -Status failed
		LogError "Failed to configure Windows Firewall logging: $($_.Exception.Message)"
	}
}
#endregion Microsoft Defender & Security
