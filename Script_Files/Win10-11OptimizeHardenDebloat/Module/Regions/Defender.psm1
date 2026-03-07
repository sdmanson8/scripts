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
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Microsoft Defender Exploit Guard network protection - " -NoNewline
			LogInfo "Enabling Microsoft Defender Exploit Guard network protection"
			Set-MpPreference -EnableNetworkProtection Enabled | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Microsoft Defender Exploit Guard network protection - " -NoNewline
			LogInfo "Disabling Microsoft Defender Exploit Guard network protection"
			Set-MpPreference -EnableNetworkProtection Disabled | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling detection for potentially unwanted applications and blocking them - " -NoNewline
			LogInfo "Enabling detection for potentially unwanted applications and blocking them"
			Set-MpPreference -PUAProtection Enabled | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling detection for potentially unwanted applications and blocking them - " -NoNewline
			LogInfo "Disabling detection for potentially unwanted applications and blocking them"
			Set-MpPreference -PUAProtection Disabled | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling sandboxing for Microsoft Defender - " -NoNewline
			LogInfo "Enabling sandboxing for Microsoft Defender"
			& "$env:SystemRoot\System32\setx.exe" /M MP_FORCE_USE_SANDBOX 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling sandboxing for Microsoft Defender - " -NoNewline
			LogInfo "Disabling sandboxing for Microsoft Defender"
			& "$env:SystemRoot\System32\setx.exe" /M MP_FORCE_USE_SANDBOX 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Write-Host "Dismissing Microsoft Defender offer in the Windows Security about signing in Microsoft account - " -NoNewline
	LogInfo "Dismissing Microsoft Defender offer in the Windows Security about signing in Microsoft account"
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -PropertyType DWord -Value 1 -Force | Out-Null
	Write-Host "success!" -ForegroundColor Green
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
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Write-Host "Disabling the SmartScreen filter for Microsoft Edge - " -NoNewline
	LogInfo "Disabling the SmartScreen filter for Microsoft Edge"
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AppAndBrowser_EdgeSmartScreenOff -PropertyType DWord -Value 0 -Force | Out-Null
	Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Creating the 'Process Creation' custom view in the Event Viewer to log executed processes and their arguments - " -NoNewline
			LogInfo "Creating the 'Process Creation' custom view in the Event Viewer to log executed processes and their arguments"
			# Enable events auditing generated when a process is created (starts)
			auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

			# Include command line in process creation events
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null

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
				New-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views" -ItemType Directory -Force | Out-Null
			}

			# Save ProcessCreation.xml in the UTF-8 without BOM encoding
			Set-Content -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Value $XML -Encoding Default -NoNewline -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Removing the 'Process Creation' custom view in the Event Viewer - " -NoNewline
			LogInfo "Removing the 'Process Creation' custom view in the Event Viewer"
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Type CLEAR | Out-Null
			Remove-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling logging for all Windows PowerShell modules - " -NoNewline
			LogInfo "Enabling logging for all Windows PowerShell modules"
			if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames))
			{
				New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force | Out-Null
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -PropertyType String -Value * -Force | Out-Null

			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Type DWORD -Value 1 | Out-Null
			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Type SZ -Value * | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling logging for all Windows PowerShell modules - " -NoNewline
			LogInfo "Disabling logging for all Windows PowerShell modules"
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Force -ErrorAction SilentlyContinue | Out-Null

			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Type CLEAR | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling logging for all PowerShell scripts input to the Windows PowerShell event log - " -NoNewline
			LogInfo "Enabling logging for all PowerShell scripts input to the Windows PowerShell event log"
			if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging))
			{
				New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force | Out-Null
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null

			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Type DWORD -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling logging for all PowerShell scripts input to the Windows PowerShell event log - " -NoNewline
			LogInfo "Disabling logging for all PowerShell scripts input to the Windows PowerShell event log"
			Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Type CLEAR | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling apps and files checking within Microsoft Defender SmartScreen - " -NoNewline
			LogInfo "Disabling apps and files checking within Microsoft Defender SmartScreen"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling apps and files checking within Microsoft Defender SmartScreen - " -NoNewline
			LogInfo "Enabling apps and files checking within Microsoft Defender SmartScreen"
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Warn -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Disabling marking downloaded files from the Internet as unsafe - " -NoNewline
			LogInfo "Disabling marking downloaded files from the Internet as unsafe"
			if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
			{
				New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force | Out-Null
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force | Out-Null

			Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Type DWORD -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling marking downloaded files from the Internet as unsafe - " -NoNewline
			LogInfo "Enabling marking downloaded files from the Internet as unsafe"
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope User -Path Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Type CLEAR | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Disabling Windows Script Host - " -NoNewline
			LogInfo "Disabling Windows Script Host"
			# Checking whether any scheduled tasks were created before, because they rely on Windows Host running vbs files
			Get-ScheduledTask -TaskName SoftwareDistribution, Temp, "Windows Cleanup", "Windows Cleanup Notification" -ErrorAction SilentlyContinue | ForEach-Object -Process {
				# Skip if a scheduled task exists
				if ($_.State -eq "Ready")
				{
					LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())
					Write-Host "success!" -ForegroundColor Green
					break
				}
			}

			if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings"))
			{
				New-Item -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Force | Out-Null
			}
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling Windows Script Host - " -NoNewline
			LogInfo "Enabling Windows Script Host"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
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

	# Get Windows edition from registry instead of WinAPI
	$Edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName

	if (($Edition -notmatch "Pro") -and ($Edition -notmatch "Enterprise") -and ($Edition -notmatch "Education"))
	{
		LogError ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling Windows Sandbox - " -NoNewline
			LogInfo "Disabling Windows Sandbox"
			# Checking whether x86 virtualization is enabled in the firmware
			if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled)
			{
				Write-Host "Disabling Windows Sandbox - " -NoNewline
				LogInfo "Disabling Windows Sandbox"
				Disable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online -NoRestart -ErrorAction SilentlyContinue | Out-Null
			}
			else
			{
				try
				{
					# Determining whether Hyper-V is enabled
					if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
					{
						Disable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online -NoRestart
					}
				}
				catch [System.Exception]
				{
					LogError $Localization.EnableHardwareVT
					LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
				}
			}
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling Windows Sandbox - " -NoNewline
			LogInfo "Enabling Windows Sandbox"
			# Checking whether x86 virtualization is enabled in the firmware
			if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled)
			{
				Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			}
			else
			{
				try
				{
					# Determining whether Hyper-V is enabled
					if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
					{
						Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
					}
				}
				catch [System.Exception]
				{
					LogError $Localization.EnableHardwareVT
					LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())
				}
			}
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling DNS-over-HTTPS for IPv4 - " -NoNewline
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
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling DNS-over-HTTPS for IPv4 - " -NoNewline
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
			Write-Host "success!" -ForegroundColor Green
		}
	}

	Clear-DnsClientCache
	Register-DnsClient
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
			Write-Host "Enabling Local Security Authority protection to prevent code injection without UEFI lock - " -NoNewline
			LogInfo "Enabling Local Security Authority protection to prevent code injection without UEFI lock"
			# Checking whether x86 virtualization is enabled in the firmware
			if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled)
			{
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -PropertyType DWord -Value 2 -Force | Out-Null
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPLBoot -PropertyType DWord -Value 2 -Force | Out-Null
			}
			else
			{
				try
				{
					# Determining whether Hyper-V is enabled
					if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent)
					{
						New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -PropertyType DWord -Value 2 -Force | Out-Null
						New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPLBoot -PropertyType DWord -Value 2 -Force | Out-Null
					}
				}
				catch [System.Exception]
				{
					LogError $Localization.EnableHardwareVT
				}
			}
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Local Security Authority protection - " -NoNewline
			LogInfo "Disabling Local Security Authority protection"
			Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL, RunAsPPLBoot -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling sharing mapped drives between users - " -NoNewline
			LogInfo "Enabling sharing mapped drives between users"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling sharing mapped drives between users - " -NoNewline
			LogInfo "Disabling sharing mapped drives between users"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling Windows Firewall - " -NoNewline
			LogInfo "Enabling Windows Firewall"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Windows Firewall - " -NoNewline
			LogInfo "Disabling Windows Firewall"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling Windows Defender SysTray icon - " -NoNewline
			LogInfo "Enabling Windows Defender SysTray icon"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -ErrorAction SilentlyContinue | Out-Null
			If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`"" | Out-Null
			} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe" | Out-Null
			} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe" | Out-Null
			}
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Windows Defender SysTray icon - " -NoNewline
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
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling Windows Defender Cloud - " -NoNewline
			LogInfo "Enabling Windows Defender Cloud"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue	| Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Windows Defender Cloud - " -NoNewline
			LogInfo "Disabling Windows Defender Cloud"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling Core Isolation Memory Integrity (HVCI) - " -NoNewline
			LogInfo "Enabling Core Isolation Memory Integrity (HVCI)"
			If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
				New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Core Isolation Memory Integrity (HVCI) - " -NoNewline
			LogInfo "Disabling Core Isolation Memory Integrity (HVCI)"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			$feature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

			if ($feature -and $feature.State -ne "Disabled") {
				$null = Enable-WindowsOptionalFeature -Online `
        			-FeatureName "Windows-Defender-ApplicationGuard" `
        			-NoRestart `
        			-ErrorAction SilentlyContinue `
        			-WarningAction SilentlyContinue
				Write-Host "success!" -ForegroundColor Green
			}
			else {
				LogError "WDAG feature not available on this system or already enabled."
			}
		}
		"Disable"
		{
			Write-Host "Disabling Windows Defender Application Guard - " -NoNewline
			LogInfo "Disabling Windows Defender Application Guard"
			# Check if feature exists without throwing error
			$feature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

			if ($feature -and $feature.State -ne "Disabled") {
				$null = Disable-WindowsOptionalFeature -Online `
        			-FeatureName "Windows-Defender-ApplicationGuard" `
        			-NoRestart `
        			-ErrorAction SilentlyContinue `
        			-WarningAction SilentlyContinue
				Write-Host "success!" -ForegroundColor Green
			}
			else {
				LogError "WDAG feature not available on this system or already disabled."
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
			Write-Host "Enabling account protection warning for Microsoft accounts - " -NoNewline
			LogInfo "Enabling account protection warning for Microsoft accounts"
			Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling account protection warning for Microsoft accounts - " -NoNewline
			LogInfo "Disabling account protection warning for Microsoft accounts"
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
			}
			Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling blocking of file downloads from the internet - " -NoNewline
			LogInfo "Enabling blocking of file downloads from the internet"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling blocking of file downloads from the internet - " -NoNewline
			LogInfo "Disabling blocking of file downloads from the internet"
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling legacy F8 boot menu - " -NoNewline
			LogInfo "Enabling legacy F8 boot menu"
			bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling legacy F8 boot menu - " -NoNewline
			LogInfo "Disabling legacy F8 boot menu"
			bcdedit /set `{current`} BootMenuPolicy Standard | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Enabling automatic recovery mode on startup errors - " -NoNewline
			LogInfo "Enabling automatic recovery mode on startup errors"
			# This allows the boot process to automatically enter recovery mode when it detects startup errors (default behavior)
			bcdedit /deletevalue `{current`} BootStatusPolicy | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling automatic recovery mode on startup errors - " -NoNewline
			LogInfo "Disabling automatic recovery mode on startup errors"
			bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
			Write-Host "success!" -ForegroundColor Green
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
			Write-Host "Disabling Data Execution Prevention (DEP) policy to OptIn - " -NoNewline
			LogInfo "Disabling Data Execution Prevention (DEP) policy to OptIn"
			# Setting Data Execution Prevention (DEP) policy to OptIn...
			bcdedit /set `{current`} nx OptIn | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Data Execution Prevention (DEP) policy to OptOut - " -NoNewline
			LogInfo "Disabling Data Execution Prevention (DEP) policy to OptOut"
			# Setting Data Execution Prevention (DEP) policy to OptOut...
			bcdedit /set `{current`} nx OptOut | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion Microsoft Defender & Security
