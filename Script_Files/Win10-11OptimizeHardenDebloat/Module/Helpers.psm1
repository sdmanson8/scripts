<#
    .SYNOPSIS
    Helper module for Win10_11Util.

    .VERSION
	2.0.2

	.DATE
	03.10.2021 - initial version
	24.02.2026 - updated to v2.0.0 with new functions and improvements
	04.03.2026 - updated to v2.0.1 with bug fixes and optimizations
	07.03.2026 - updated to v2.0.2 with major tweaks and refinements

	.AUTHOR
	sdmanson8 - Copyright (c) 2021 - 2026

    .DESCRIPTION
    Provides shared utility functions used by the loader and region modules.
    This module currently exposes a helper for setting or clearing registry-based policy values.
#>

<#
    .SYNOPSIS
    Create, update, or clear a registry-based policy value.

    .PARAMETER Scope
    Registry root to use for the policy value: `Computer` maps to `HKLM:` and `User` maps to `HKCU:`.

    .PARAMETER Path
    Registry subkey path under the selected scope.

    .PARAMETER Name
    Name of the registry value to create, update, or remove.

    .PARAMETER Type
    Registry value type to write, or `CLEAR` to remove the value.

    .PARAMETER Value
    Value to write when `Type` is not `CLEAR`.

    .EXAMPLE
    Set-Policy -Scope User -Path 'Software\\Policies\\Microsoft\\Windows\\Explorer' -Name NoUseStoreOpenWith -Type DWord -Value 1
#>
function Set-Policy
{
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet("Computer", "User")]
		[string]
		$Scope,

		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[Parameter(Mandatory = $true)]
		[string]
		$Name,

		[Parameter(Mandatory = $true)]
		[ValidateSet("CLEAR", "String", "ExpandString", "Binary", "DWord", "MultiString", "QWord", "SZ", "EXPANDSZ", "BINARY", "DWORD", "MULTISZ", "QWORD")]
		[string]
		$Type,

		[Parameter(Mandatory = $false)]
		$Value
	)

	switch ($Scope)
	{
		"Computer" { $Root = "HKLM:\" }
		"User"     { $Root = "HKCU:\" }
	}

	# Normalize common registry type aliases so callers can use either PowerShell or registry-style names.
	switch ($Type.ToUpperInvariant())
	{
		"CLEAR"    { $MappedType = "CLEAR" }
		"STRING"   { $MappedType = "String" }
		"SZ"       { $MappedType = "String" }
		"EXPANDSTRING" { $MappedType = "ExpandString" }
		"EXPANDSZ" { $MappedType = "ExpandString" }
		"BINARY"   { $MappedType = "Binary" }
		"DWORD"    { $MappedType = "DWord" }
		"DWORD32"  { $MappedType = "DWord" }
		"MULTISTRING" { $MappedType = "MultiString" }
		"MULTISZ"  { $MappedType = "MultiString" }
		"QWORD"    { $MappedType = "QWord" }
		default    { $MappedType = $Type }
	}

	$FullPath = Join-Path $Root $Path

	if (-not (Test-Path -LiteralPath $FullPath))
	{
		New-Item -Path $FullPath -Force | Out-Null
	}

	if ($MappedType -eq "CLEAR")
	{
		Remove-ItemProperty -Path $FullPath -Name $Name -Force -ErrorAction Ignore | Out-Null
		return
	}

	New-ItemProperty -Path $FullPath -Name $Name -PropertyType $MappedType -Value $Value -Force | Out-Null
}

# Convert a PowerShell registry provider path into the format expected by reg.exe.
function ConvertTo-NativeRegistryPath
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]
		$Path
	)

	$NativePath = $Path -replace '^Registry::', ''

	switch -Regex ($NativePath)
	{
		'^HKCU:\\'
		{
			$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			return "HKU\$UserSid\$($NativePath.Substring(6))"
		}
		'^HKLM:\\'               { return "HKLM\$($NativePath.Substring(6))" }
		'^HKU:\\'                { return "HKU\$($NativePath.Substring(5))" }
		'^HKEY_CURRENT_USER\\'
		{
			$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			return "HKU\$UserSid\$($NativePath.Substring(18))"
		}
		'^HKEY_LOCAL_MACHINE\\'  { return "HKLM\$($NativePath.Substring(19))" }
		'^HKEY_USERS\\'          { return "HKU\$($NativePath.Substring(11))" }
		'^HKLM\\'                { return $NativePath }
		'^HKU\\'                 { return $NativePath }
		default                  { throw "Unsupported registry path: $Path" }
	}
}

<# 
	.SYNOPSIS
	Map a PowerShell registry value type to the type name expected by reg.exe.
#>
function ConvertTo-RegExeValueType
{
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet('DWord', 'String')]
		[string]
		$Type
	)

	switch ($Type)
	{
		'DWord' { return 'REG_DWORD' }
		'String' { return 'REG_SZ' }
	}
}

# Unload a temporary registry hive and wait for handles to clear when needed.
function Dismount-RegistryHive
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]
		$MountPath,

		[Parameter(Mandatory = $true)]
		[string]
		$PsPath,

		[int]
		$MaxAttempts = 8,

		[int]
		$DelayMilliseconds = 250
	)

	if (-not (Test-Path -Path $PsPath))
	{
		return $true
	}

	for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++)
	{
		& reg.exe UNLOAD $MountPath *> $null
		if ($LASTEXITCODE -eq 0 -or -not (Test-Path -Path $PsPath))
		{
			return $true
		}

		Start-Sleep -Milliseconds $DelayMilliseconds
	}

	return (-not (Test-Path -Path $PsPath))
}

# Load a registry hive with retries because repeated runs can leave the mount busy.
function Mount-RegistryHive
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]
		$MountPath,

		[Parameter(Mandatory = $true)]
		[string]
		$PsPath,

		[Parameter(Mandatory = $true)]
		[string]
		$HiveFile,

		[int]
		$MaxAttempts = 8,

		[int]
		$DelayMilliseconds = 500
	)

	Dismount-RegistryHive -MountPath $MountPath -PsPath $PsPath | Out-Null

	for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++)
	{
		& reg.exe LOAD $MountPath $HiveFile *> $null
		if ($LASTEXITCODE -eq 0 -and (Test-Path -Path $PsPath))
		{
			return $true
		}

		Start-Sleep -Milliseconds $DelayMilliseconds
	}

	return $false
}

function Remove-HandledErrorRecord
{
	param
	(
		[Parameter(Mandatory = $true)]
		[System.Management.Automation.ErrorRecord]
		$ErrorRecord
	)

	if (-not $Global:Error)
	{
		return
	}

	for ($Index = $Global:Error.Count - 1; $Index -ge 0; $Index--)
	{
		$Candidate = $Global:Error[$Index]
		if ($null -eq $Candidate)
		{
			continue
		}

		$SameType = $Candidate.Exception.GetType().FullName -eq $ErrorRecord.Exception.GetType().FullName
		$SameMessage = $Candidate.Exception.Message -eq $ErrorRecord.Exception.Message
		$SamePath = $Candidate.InvocationInfo.PSCommandPath -eq $ErrorRecord.InvocationInfo.PSCommandPath
		$SameLine = $Candidate.InvocationInfo.ScriptLineNumber -eq $ErrorRecord.InvocationInfo.ScriptLineNumber

		if ($SameType -and $SameMessage -and $SamePath -and $SameLine)
		{
			$Global:Error.RemoveAt($Index)
		}
	}
}

function Invoke-SilencedProgress
{
	param
	(
		[Parameter(Mandatory = $true)]
		[scriptblock]
		$ScriptBlock
	)

	$previousProgressPreference = $global:ProgressPreference
	try
	{
		$global:ProgressPreference = 'SilentlyContinue'
		& $ScriptBlock
	}
	finally
	{
		$global:ProgressPreference = $previousProgressPreference
	}
}

<# 
	.SYNOPSIS
	Create a registry key path if needed and then set the requested value.

	.PARAMETER AccessDeniedFallback
	Optional script block that receives `Path`, `Name`, `Value`, and `Type` and
	should return `$true` if it successfully handled an access denied error.

	.PARAMETER OnAccessDenied
	Optional script block that receives `Path` and `Name` when access is denied
	and the operation is being skipped.
#>
function Set-RegistryValueSafe
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[Parameter(Mandatory = $true)]
		[string]
		$Name,

		[Parameter(Mandatory = $true)]
		[object]
		$Value,

		[Parameter(Mandatory = $true)]
		[ValidateSet('DWord', 'String')]
		[string]
		$Type,

		[scriptblock]
		$AccessDeniedFallback,

		[scriptblock]
		$OnAccessDenied,

		[switch]
		$SkipOnAccessDenied
	)

	try
	{
		if (-not (Test-Path -Path $Path))
		{
			New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
		}

		if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)
		{
			Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop | Out-Null
		}
		else
		{
			New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
		}
	}
	catch [System.UnauthorizedAccessException]
	{
		$HandledError = $_
		$FallbackSucceeded = $false

		if ($AccessDeniedFallback)
		{
			try
			{
				$FallbackSucceeded = [bool](& $AccessDeniedFallback $Path $Name $Value $Type)
			}
			catch
			{
				$FallbackSucceeded = $false
			}
		}

		if ($FallbackSucceeded)
		{
			Remove-HandledErrorRecord -ErrorRecord $HandledError
			return
		}

		if ($SkipOnAccessDenied)
		{
			Remove-HandledErrorRecord -ErrorRecord $HandledError
			if ($OnAccessDenied)
			{
				& $OnAccessDenied $Path $Name | Out-Null
			}
			else
			{
				Write-Warning "Skipping registry value '$Name' at '$Path' because access was denied."
			}

			return
		}

		throw
	}
}

function Initialize-ForegroundWindowInterop
{
	if (-not ("WinAPI.ForegroundWindow" -as [type]))
	{
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace WinAPI
{
	public static class ForegroundWindow
	{
		[DllImport("user32.dll")]
		public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool SetForegroundWindow(IntPtr hWnd);
	}
}
"@ -ErrorAction Stop | Out-Null
	}
}

function Initialize-WpfWindowForeground
{
	param
	(
		[Parameter(Mandatory = $true)]
		$Window
	)

	try
	{
		$Window.ShowActivated = $true
	}
	catch
	{
		# Ignore if the supplied object is not a WPF Window.
	}

	$activationPending = $true
	$bringWindowToFront = {
		if (-not $activationPending)
		{
			return
		}

		$activationPending = $false

		try
		{
			$activateWindowAction = [Action]{
				try
				{
					Initialize-ForegroundWindowInterop

					if ($Window.WindowState -eq [System.Windows.WindowState]::Minimized)
					{
						$Window.WindowState = [System.Windows.WindowState]::Normal
					}

					$interopHelper = New-Object -TypeName System.Windows.Interop.WindowInteropHelper -ArgumentList $Window
					if ($interopHelper.Handle -ne [IntPtr]::Zero)
					{
						[WinAPI.ForegroundWindow]::ShowWindowAsync($interopHelper.Handle, 9) | Out-Null
						[WinAPI.ForegroundWindow]::SetForegroundWindow($interopHelper.Handle) | Out-Null
					}

					$originalTopmost = $Window.Topmost
					$Window.Topmost = $true
					$Window.Activate() | Out-Null
					$Window.Focus() | Out-Null

					$resetTopmostAction = [Action]{
						$Window.Topmost = $originalTopmost
					}
					$Window.Dispatcher.BeginInvoke($resetTopmostAction, [System.Windows.Threading.DispatcherPriority]::ApplicationIdle) | Out-Null
				}
				catch
				{
					try
					{
						$Window.WindowState = [System.Windows.WindowState]::Normal
						$Window.Activate() | Out-Null
						$Window.Focus() | Out-Null
					}
					catch
					{
						# Ignore foreground activation failures and allow the dialog to continue opening normally.
					}
				}
			}

			$Window.Dispatcher.BeginInvoke($activateWindowAction, [System.Windows.Threading.DispatcherPriority]::ApplicationIdle) | Out-Null
		}
		catch
		{
			try
			{
				$Window.WindowState = [System.Windows.WindowState]::Normal
				$Window.Activate() | Out-Null
				$Window.Focus() | Out-Null
			}
			catch
			{
				# Ignore foreground activation failures and allow the dialog to continue opening normally.
			}
		}
	}

	$Window.Add_Loaded($bringWindowToFront)
	$Window.Add_SourceInitialized($bringWindowToFront)
	$Window.Add_ContentRendered($bringWindowToFront)
	$Window.Add_StateChanged({
		if ($activationPending -and ($Window.WindowState -eq [System.Windows.WindowState]::Minimized))
		{
			$bringWindowToFront.Invoke()
		}
	})
}

<#
	.SYNOPSIS
	Get the current Windows version details from the registry.
#>
function Get-WindowsVersionData
{
	$CurrentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
	$CurrentBuild = [string]$CurrentVersion.CurrentBuild
	$DisplayVersion = [string]$CurrentVersion.DisplayVersion
	$ProductName = [string]$CurrentVersion.ProductName
	$InstallationType = [string]$CurrentVersion.InstallationType
	$UBR = 0
	$IsWindowsServer = $false

	if ([string]::IsNullOrWhiteSpace($CurrentBuild))
	{
		$CurrentBuild = [string]$CurrentVersion.CurrentBuildNumber
	}

	if ([string]::IsNullOrWhiteSpace($DisplayVersion))
	{
		$DisplayVersion = [string]$CurrentVersion.ReleaseId
	}

	if ($null -ne $CurrentVersion.UBR)
	{
		$UBR = [int]$CurrentVersion.UBR
	}

	if (-not [string]::IsNullOrWhiteSpace($InstallationType))
	{
		$IsWindowsServer = $InstallationType -match "Server"
	}
	elseif (-not [string]::IsNullOrWhiteSpace($ProductName))
	{
		$IsWindowsServer = $ProductName -match "Server"
	}

	[pscustomobject]@{
		IsWindows11      = ([int]$CurrentBuild -ge 22000)
		IsWindowsServer  = $IsWindowsServer
		CurrentBuild     = [int]$CurrentBuild
		UBR              = $UBR
		DisplayVersion   = $DisplayVersion
		ProductName      = $ProductName
		InstallationType = $InstallationType
	}
}

<#
	.SYNOPSIS
	Get the current OS name and whether the system is Windows 11.
#>
function Get-OSInfo
{
	$VersionData = Get-WindowsVersionData
	$OSName = if ($VersionData.IsWindowsServer)
	{
		if ([string]::IsNullOrWhiteSpace($VersionData.ProductName))
		{
			"Windows Server"
		}
		else
		{
			$VersionData.ProductName
		}
	}
	elseif ($VersionData.IsWindows11)
	{
		"Windows 11"
	}
	else
	{
		"Windows 10"
	}

	[pscustomobject]@{
		IsWindows11      = $VersionData.IsWindows11
		IsWindowsServer  = $VersionData.IsWindowsServer
		OSName           = $OSName
		CurrentBuild     = $VersionData.CurrentBuild
		UBR              = $VersionData.UBR
		DisplayVersion   = $VersionData.DisplayVersion
		ProductName      = $VersionData.ProductName
		InstallationType = $VersionData.InstallationType
	}
}


<#
	.SYNOPSIS
	Convert a Windows display version like `25H2` into a comparable integer.
#>
function ConvertTo-WindowsDisplayVersionComparable
{
	param
	(
		[string]
		$DisplayVersion
	)

	if ([string]::IsNullOrWhiteSpace($DisplayVersion))
	{
		return $null
	}

	if ($DisplayVersion -match '^(?<Year>\d{2})H(?<Half>\d)$')
	{
		return ([int]$Matches.Year * 10) + [int]$Matches.Half
	}

	return $null
}

<#
	.SYNOPSIS
	Test whether the current Windows 11 release meets one of the supplied release thresholds
	and allow any later feature update automatically.

	.PARAMETER Thresholds
	Array of hashtables containing `DisplayVersion`, `Build`, and optional `UBR`.
#>
function Test-Windows11FeatureBranchSupport
{
	param
	(
		[Parameter(Mandatory = $true)]
		[hashtable[]]
		$Thresholds
	)

	$VersionData = Get-WindowsVersionData
	if (-not $VersionData.IsWindows11)
	{
		return $false
	}

	$ParsedThresholds = $Thresholds | ForEach-Object {
		[pscustomobject]@{
			DisplayVersion = [string]$_.DisplayVersion
			Build          = [int]$_.Build
			UBR            = if ($null -ne $_.UBR) { [int]$_.UBR } else { 0 }
		}
	} | Sort-Object Build, UBR

	if (-not $ParsedThresholds)
	{
		return $false
	}

	$ApplicableThreshold = $ParsedThresholds | Where-Object -FilterScript {
		$VersionData.CurrentBuild -ge $_.Build
	} | Select-Object -Last 1

	if (-not $ApplicableThreshold)
	{
		return $false
	}

	if ($VersionData.CurrentBuild -gt $ApplicableThreshold.Build)
	{
		return $true
	}

	return ($VersionData.UBR -ge $ApplicableThreshold.UBR)
}

<#
	.SYNOPSIS
	Test whether the current OS is Windows 11 and meets a minimum build or feature update version.

	.PARAMETER MinimumBuild
	Minimum Windows build number.

	.PARAMETER MinimumUBR
	Minimum update build revision required when the build number matches `MinimumBuild`.

	.PARAMETER MinimumDisplayVersion
	Minimum Windows feature update version in the format `YYHn`, for example `26H1`.
#>
function Test-Windows11BuildSupport
{
	param
	(
		[Parameter(Mandatory = $true)]
		[int]
		$MinimumBuild,

		[int]
		$MinimumUBR = 0,

		[string]
		$MinimumDisplayVersion
	)

	$VersionData = Get-WindowsVersionData

	if (-not $VersionData.IsWindows11)
	{
		return $false
	}

	$MeetsBuildRequirement = ($VersionData.CurrentBuild -gt $MinimumBuild) -or (
		($VersionData.CurrentBuild -eq $MinimumBuild) -and
		($VersionData.UBR -ge $MinimumUBR)
	)

	if ($MeetsBuildRequirement)
	{
		return $true
	}

	if ([string]::IsNullOrWhiteSpace($MinimumDisplayVersion) -or [string]::IsNullOrWhiteSpace($VersionData.DisplayVersion))
	{
		return $false
	}

	$CurrentComparable = ConvertTo-WindowsDisplayVersionComparable -DisplayVersion $VersionData.DisplayVersion
	$MinimumComparable = ConvertTo-WindowsDisplayVersionComparable -DisplayVersion $MinimumDisplayVersion

	if (($null -ne $CurrentComparable) -and ($null -ne $MinimumComparable))
	{
		return ($CurrentComparable -ge $MinimumComparable)
	}

	return $false
}

# Export the shared helper functions used across the module set.
$ExportedFunctions = @(
	'Set-Policy'
	'ConvertTo-NativeRegistryPath'
	'ConvertTo-RegExeValueType'
	'Dismount-RegistryHive'
	'Mount-RegistryHive'
	'Remove-HandledErrorRecord'
	'Invoke-SilencedProgress'
	'Set-RegistryValueSafe'
	'Initialize-ForegroundWindowInterop'
	'Initialize-WpfWindowForeground'
	'Get-WindowsVersionData'
	'Get-OSInfo'
	'ConvertTo-WindowsDisplayVersionComparable'
	'Test-Windows11FeatureBranchSupport'
	'Test-Windows11BuildSupport'
)

Export-ModuleMember -Function $ExportedFunctions
