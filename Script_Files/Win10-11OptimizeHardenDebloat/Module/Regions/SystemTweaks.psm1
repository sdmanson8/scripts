using module ..\Logging.psm1
using module ..\Helpers.psm1

#region System Tweaks
<#
.SYNOPSIS
Enable or disable Cross-Device Resume

.PARAMETER Enable
Enable Cross-Device Resume

.PARAMETER Disable
Disable Cross-Device Resume

.EXAMPLE
CrossDeviceResume -Enable

.EXAMPLE
CrossDeviceResume -Disable

.NOTES
Current user
#>
function CrossDeviceResume
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
			Write-Host "Enabling Cross-Device Resume - " -NoNewline
			LogInfo "Enabling Cross-Device Resume"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" -Name "IsResumeAllowed" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Cross-Device Resume - " -NoNewline
			LogInfo "Disabling Cross-Device Resume"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" -Name "IsResumeAllowed" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable Multiplane Overlay

.PARAMETER Enable
Enable Multiplane Overlay

.PARAMETER Disable
Disable Multiplane Overlay

.EXAMPLE
MultiplaneOverlay -Enable

.EXAMPLE
MultiplaneOverlay -Disable

.NOTES
Current user
#>
function MultiplaneOverlay
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
			Write-Host "Enabling Multiplane Overlay - " -NoNewline
			LogInfo "Enabling Multiplane Overlay"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Multiplane Overlay - " -NoNewline
			LogInfo "Disabling Multiplane Overlay"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type DWord -Value 5 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable Modern Standby fix

.PARAMETER Enable
Enable Modern Standby fix

.PARAMETER Disable
Disable Modern Standby fix

.EXAMPLE
StandbyFix -Enable

.EXAMPLE
StandbyFix -Disable

.NOTES
Current user
#>
function StandbyFix
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
			Write-Host "Enabling Modern Standby fix - " -NoNewline
			LogInfo "Enabling Modern Standby fix"
			if (-not (Test-Path -Path "HKCU:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"))
			{
				New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Force -ErrorAction SilentlyContinue | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Modern Standby fix - " -NoNewline
			LogInfo "Disabling Modern Standby fix"
			Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable S3 Sleep

.PARAMETER Enable
Enable S3 Sleep

.PARAMETER Disable
Disable S3 Sleep

.EXAMPLE
S3Sleep -Enable

.EXAMPLE
S3Sleep -Disable

.NOTES
Current user
#>
function S3Sleep
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
			Write-Host "Enabling S3 Sleep - " -NoNewline
			LogInfo "Enabling S3 Sleep"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling S3 Sleep - " -NoNewline
			LogInfo "Disabling S3 Sleep"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable Explorer Automatic Folder Discovery

.PARAMETER Enable
Enable Explorer Automatic Folder Discovery

.PARAMETER Disable
Disable Explorer Automatic Folder Discovery

.EXAMPLE
ExplorerAutoDiscovery -Enable

.EXAMPLE
ExplorerAutoDiscovery -Disable

.NOTES
Current user
#>
function ExplorerAutoDiscovery
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

	$bags = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
	$bagMRU = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
	$allFolders = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell"

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Explorer Automatic Folder Discovery - " -NoNewline
			LogInfo "Enabling Explorer Automatic Folder Discovery"
			Remove-Item -Path $bags -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-Item -Path $bagMRU -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
			LogInfo "Please sign out and back in, or restart your computer to apply the changes."
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Explorer Automatic Folder Discovery - " -NoNewline
			LogInfo "Disabling Explorer Automatic Folder Discovery"
			Remove-Item -Path $bags -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-Item -Path $bagMRU -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

			if (-not (Test-Path $allFolders))
			{
				New-Item -Path $allFolders -Force -ErrorAction SilentlyContinue | Out-Null
			}

			Set-ItemProperty -Path $allFolders -Name "FolderType" -Value "NotSpecified" -Type String -Force -ErrorAction SilentlyContinue | Out-Null
			LogInfo "Please sign out and back in, or restart your computer to apply the changes."
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable Windows Platform Binary Table (WPBT)

.PARAMETER Enable
Enable Windows Platform Binary Table (WPBT)

.PARAMETER Disable
Disable Windows Platform Binary Table (WPBT)

.EXAMPLE
WPBT -Enable

.EXAMPLE
WPBT -Disable

.NOTES
Current user
#>
function WPBT
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
			Write-Host "Enabling Windows Platform Binary Table (WPBT) - " -NoNewline
			LogInfo "Enabling Windows Platform Binary Table (WPBT)"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableWpbtExecution" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Windows Platform Binary Table (WPBT) - " -NoNewline
			LogInfo "Disabling Windows Platform Binary Table (WPBT)"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableWpbtExecution" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Run Disk Cleanup on Drive C: and remove old Windows Updates

.EXAMPLE
DiskCleanup

.NOTES
Current user
#>
function DiskCleanup
{
	Write-Host "Running Disk Cleanup - " -NoNewline
	# Pass log file path to child process
	[Environment]::SetEnvironmentVariable("diskcleanup", $global:LogFilePath, "Process")

	$ScriptPath = Join-Path $PSScriptRoot "..\..\files\diskcleanup.ps1"
	$ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)

	Start-Process powershell.exe `
		-ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"" `
		-WindowStyle Normal
	Write-Host "Task is open in a new window" -ForegroundColor Yellow
}
<#
.SYNOPSIS
Enable or disable recommended Windows service startup configuration

.PARAMETER Enable
Apply recommended startup types to Windows services

.PARAMETER Disable
Restore Windows services to their original startup types

.EXAMPLE
ServicesManual -Enable

.EXAMPLE
ServicesManual -Disable

.NOTES
Current user
#>
function ServicesManual
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

	$services = @(
		@{ Name = "ALG";                        StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "AppMgmt";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "AppReadiness";               StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "AppVClient";                 StartupType = "Disabled";              OriginalType = "Disabled" }
		@{ Name = "Appinfo";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "AssignedAccessManagerSvc";   StartupType = "Disabled";              OriginalType = "Manual" }
		@{ Name = "AudioEndpointBuilder";       StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "AudioSrv";                   StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "Audiosrv";                   StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "AxInstSV";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "BDESVC";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "BITS";                       StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" }
		@{ Name = "BTAGService";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "BthAvctpSvc";                StartupType = "Automatic";             OriginalType = "Manual" }
		@{ Name = "CDPSvc";                     StartupType = "Manual";                OriginalType = "Automatic" }
		@{ Name = "COMSysApp";                  StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "CertPropSvc";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "CryptSvc";                   StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "CscService";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "DPS";                        StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "DevQueryBroker";             StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "DeviceAssociationService";   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "DeviceInstall";              StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "Dhcp";                       StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "DiagTrack";                  StartupType = "Disabled";              OriginalType = "Automatic" }
		@{ Name = "DialogBlockingService";      StartupType = "Disabled";              OriginalType = "Disabled" }
		@{ Name = "DispBrokerDesktopSvc";       StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "DisplayEnhancementService";  StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "EFS";                        StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "EapHost";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "EventLog";                   StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "EventSystem";                StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "FDResPub";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "FontCache";                  StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "FrameServer";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "FrameServerMonitor";         StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "GraphicsPerfSvc";            StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "HvHost";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "IKEEXT";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "InstallService";             StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "InventorySvc";               StartupType = "Manual";                OriginalType = "Automatic" }
		@{ Name = "IpxlatCfgSvc";               StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "KeyIso";                     StartupType = "Automatic";             OriginalType = "Manual" }
		@{ Name = "KtmRm";                      StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "LanmanServer";               StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "LanmanWorkstation";          StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "LicenseManager";             StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "LxpSvc";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "MSDTC";                      StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "MSiSCSI";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "MapsBroker";                 StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" }
		@{ Name = "McpManagementService";       StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "MicrosoftEdgeElevationService"; StartupType = "Manual";             OriginalType = "Manual" }
		@{ Name = "NaturalAuthentication";      StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "NcaSvc";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "NcbService";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "NcdAutoSetup";               StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "NetSetupSvc";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "NetTcpPortSharing";          StartupType = "Disabled";              OriginalType = "Disabled" }
		@{ Name = "Netman";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "NlaSvc";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "PcaSvc";                     StartupType = "Manual";                OriginalType = "Automatic" }
		@{ Name = "PeerDistSvc";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "PerfHost";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "PhoneSvc";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "PlugPlay";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "PolicyAgent";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "Power";                      StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "PrintNotify";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "ProfSvc";                    StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "PushToInstall";              StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "QWAVE";                      StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "RasAuto";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "RasMan";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "RemoteAccess";               StartupType = "Disabled";              OriginalType = "Disabled" }
		@{ Name = "RemoteRegistry";             StartupType = "Disabled";              OriginalType = "Disabled" }
		@{ Name = "RetailDemo";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "RmSvc";                      StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "RpcLocator";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SCPolicySvc";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SCardSvr";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SDRSVC";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SEMgrSvc";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SENS";                       StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "SNMPTRAP";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SNMPTrap";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SSDPSRV";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SamSs";                      StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "ScDeviceEnum";               StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SensorDataService";          StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SensorService";              StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SensrSvc";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SessionEnv";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "SharedAccess";               StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "ShellHWDetection";           StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "SmsRouter";                  StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "Spooler";                    StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "SstpSvc";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "StiSvc";                     StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "StorSvc";                    StartupType = "Manual";                OriginalType = "Automatic" }
		@{ Name = "SysMain";                    StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "TapiSrv";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "TermService";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "Themes";                     StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "TieringEngineService";       StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "TokenBroker";                StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "TrkWks";                     StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "TroubleshootingSvc";         StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "TrustedInstaller";           StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "UevAgentService";            StartupType = "Disabled";              OriginalType = "Disabled" }
		@{ Name = "UmRdpService";               StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "UserManager";                StartupType = "Automatic";             OriginalType = "Automatic" }
		@{ Name = "UsoSvc";                     StartupType = "Manual";                OriginalType = "Automatic" }
		@{ Name = "VSS";                        StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "VaultSvc";                   StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "W32Time";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "WEPHOSTSVC";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "WFDSConMgrSvc";              StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "WMPNetworkSvc";              StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "WManSvc";                    StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "WPDBusEnum";                 StartupType = "Manual";                OriginalType = "Manual" }
		@{ Name = "WSAIFabricSvc";              StartupType = "Manual";                OriginalType = "Automatic" }
		@{ Name = "WSearch";                    StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" }
		@{ Name = "WalletService";              StartupType = "Manual";                OriginalType = "Manual" }
	)

	Write-Host "Configuring Windows services - " -NoNewline
	LogInfo "Configuring Windows services"

	foreach ($svc in $services)
	{
		$Name = $svc.Name

		if ($Enable)
		{
			$TargetType = $svc.StartupType
			LogInfo "Setting service $Name to $TargetType"
		}
		elseif ($Disable)
		{
			$TargetType = $svc.OriginalType
			LogInfo "Restoring service $Name to $TargetType"
		}

		try
		{
			$service = Get-Service -Name $Name -ErrorAction Stop

			# Handle AutomaticDelayedStart for Windows PowerShell < 7
			if (($PSVersionTable.PSVersion.Major -lt 7) -and
				($TargetType -eq "AutomaticDelayedStart"))
			{
				sc.exe config $Name start= delayed-auto | Out-Null
				LogInfo "Service $Name configured with delayed auto start"
			}
			else
			{
				$service | Set-Service -StartupType $TargetType -ErrorAction Stop | Out-Null
				LogInfo "Service $Name configured successfully"
			}
		}
		catch
		{
			if (
				$_.FullyQualifiedErrorId -like "*NoServiceFoundForGivenName*" -or
				$_.Exception.Message -like "*Cannot find any service with service name*"
			)
			{
				LogWarning "Service $Name was not found"
			}
			else
			{
				LogError "Failed to set service $Name : $($_.Exception.Message)"
			}
		}
	}

	LogInfo "Completed service configuration"
	Write-Host "success!" -ForegroundColor Green
}

<#
	.SYNOPSIS
	Enable or disable Adobe Network Block

	.PARAMETER Enable
	Enable Adobe Network Block

	.PARAMETER Disable
	Disable Adobe Network Block

	.EXAMPLE
	AdobeNetworkBlock -Enable

	.EXAMPLE
	AdobeNetworkBlock -Disable

	.NOTES
	Current user

	CAUTION:
	Blocking Adobe network access may:
	- Prevent license validation and activation
	- Disable Creative Cloud syncing
	- Break cloud-based features (Fonts, Libraries, AI tools, etc.)
	- Trigger subscription or account errors
	- Violate Adobe license terms depending on usage

	Use only if you understand the implications.
#>
function AdobeNetworkBlock
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	$hosts = "$Env:SystemRoot\System32\drivers\etc\hosts"
	$hostsUrl = "https://github.com/Ruddernation-Designs/Adobe-URL-Block-List/raw/refs/heads/master/hosts"

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Adobe Network Block - " -NoNewline
			LogInfo "Enabling Adobe Network Block"
			try
			{
				if (Test-Path $hosts)
				{
					Copy-Item $hosts "$hosts.bak" -Force -ErrorAction SilentlyContinue | Out-Null
					LogInfo "Backed up original hosts file to $hosts.bak"
				}
				Invoke-WebRequest $hostsUrl -OutFile $hosts -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Downloaded and applied Adobe block list"
				ipconfig /flushdns | Out-Null
				LogInfo "Flushed DNS cache"
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				LogError "Failed to enable Adobe Network Block: $_"
				Write-Host "failed!" -ForegroundColor Red
			}
		}
		"Disable"
		{
			Write-Host "Disabling Adobe Network Block - " -NoNewline
			LogInfo "Disabling Adobe Network Block"
			try
			{
				if (Test-Path "$hosts.bak")
				{
					Remove-Item $hosts -Force -ErrorAction SilentlyContinue | Out-Null
					Move-Item "$hosts.bak" $hosts -Force -ErrorAction SilentlyContinue | Out-Null
					LogInfo "Restored original hosts file from backup"
				}
				ipconfig /flushdns | Out-Null
				LogInfo "Flushed DNS cache"
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				LogError "Failed to disable Adobe Network Block: $_"
				Write-Host "failed!" -ForegroundColor Red
			}
		}
	}
}

<#
	.SYNOPSIS
	Enable or disable Block Razer Software Installs

	.PARAMETER Enable
	Enable Block Razer Software Installs

	.PARAMETER Disable
	Disable Block Razer Software Installs

	.EXAMPLE
	RazerBlock -Enable

	.EXAMPLE
	RazerBlock -Disable

	.NOTES
	Current user

	CAUTION:
	Blocking Razer software installation may:
	- Prevent Razer Synapse from installing or updating
	- Disable RGB, macro, or device profile functionality
	- Stop firmware updates for Razer devices
	- Cause certain Razer peripherals to function with limited features

	Use only if you understand the implications.
#>
function RazerBlock
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	$RazerPath = "C:\Windows\Installer\Razer"

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Razer Software Block - " -NoNewline
			LogInfo "Enabling Razer Software Block"
			try
			{
				# Registry changes
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Set DriverSearching SearchOrderConfig to 0"
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -Name "DisableCoInstallers" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Set DisableCoInstallers to 1"

				# Block Razer installer directory
				if (Test-Path $RazerPath)
				{
					Remove-Item "$RazerPath\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
					LogInfo "Cleared Razer installer directory"
				}
				else
				{
					New-Item -Path $RazerPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
					LogInfo "Created Razer installer directory"
				}

				icacls $RazerPath /deny "Everyone:(W)" | Out-Null
				LogInfo "Set deny write permission on Razer directory"
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				LogError "Failed to enable Razer Software Block: $_"
				Write-Host "failed!" -ForegroundColor Red
			}
		}
		"Disable"
		{
			Write-Host "Disabling Razer Software Block - " -NoNewline
			LogInfo "Disabling Razer Software Block"
			try
			{
				# Restore registry values
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Restored DriverSearching SearchOrderConfig to 1"
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -Name "DisableCoInstallers" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Restored DisableCoInstallers to 0"

				# Remove directory deny permission
				icacls $RazerPath /remove:d Everyone | Out-Null
				LogInfo "Removed deny write permission from Razer directory"
				Write-Host "success!" -ForegroundColor Green
			}
			catch
			{
				LogError "Failed to disable Razer Software Block: $_"
				Write-Host "failed!" -ForegroundColor Red
			}
		}
	}
}

<#
.SYNOPSIS
Enable or disable Brave Debloat

.PARAMETER Enable
Enable Brave Debloat

.PARAMETER Disable
Disable Brave Debloat

.EXAMPLE
BraveDebloat -Enable

.EXAMPLE
BraveDebloat -Disable

.NOTES
Current user
#>
function BraveDebloat
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	$BravePath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Brave Debloat - " -NoNewline
			LogInfo "Enabling Brave Debloat"
			if (-not (Test-Path $BravePath))
			{
				New-Item -Path $BravePath -Force -ErrorAction SilentlyContinue | Out-Null
			}
			Set-ItemProperty -Path $BravePath -Name "BraveRewardsDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $BravePath -Name "BraveWalletDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $BravePath -Name "BraveVPNDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $BravePath -Name "BraveAIChatEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $BravePath -Name "BraveStatsPingEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			LogInfo "Brave debloat policies applied"
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Brave Debloat - " -NoNewline
			LogInfo "Disabling Brave Debloat"
			Remove-ItemProperty -Path $BravePath -Name "BraveRewardsDisabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $BravePath -Name "BraveWalletDisabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $BravePath -Name "BraveVPNDisabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $BravePath -Name "BraveAIChatEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $BravePath -Name "BraveStatsPingEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			LogInfo "Brave debloat policies removed"
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable Fullscreen Optimizations

.PARAMETER Enable
Enable Fullscreen Optimizations

.PARAMETER Disable
Disable Fullscreen Optimizations

.EXAMPLE
FullscreenOptimizations -Enable

.EXAMPLE
FullscreenOptimizations -Disable

.NOTES
Current user
#>
function FullscreenOptimizations
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Fullscreen Optimizations - " -NoNewline
			LogInfo "Enabling Fullscreen Optimizations"
			Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Fullscreen Optimizations - " -NoNewline
			LogInfo "Disabling Fullscreen Optimizations"
			Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable Teredo

.PARAMETER Enable
Enable Teredo

.PARAMETER Disable
Disable Teredo

.EXAMPLE
Teredo -Enable

.EXAMPLE
Teredo -Disable

.NOTES
Current user

.CAUTION
Teredo is an IPv6 tunneling protocol used for NAT traversal.
Disabling it may reduce network latency for some applications.
However, some games and peer-to-peer applications rely on Teredo for connectivity.
Xbox Live and certain multiplayer games may not function correctly without Teredo.
#>
function Teredo
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling Teredo - " -NoNewline
			LogInfo "Enabling Teredo"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			netsh interface teredo set state default | Out-Null
			LogInfo "Teredo enabled and set to default state"
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Teredo - " -NoNewline
			LogInfo "Disabling Teredo"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			netsh interface teredo set state disabled | Out-Null
			LogInfo "Teredo disabled"
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion System Tweaks
