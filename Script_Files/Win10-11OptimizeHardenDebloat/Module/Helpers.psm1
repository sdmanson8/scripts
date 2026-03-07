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

	Copyright (c) 2021 - 2026 sdmanson8

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
			if ($Global:Error -and $Global:Error.Contains($HandledError))
			{
				[void]$Global:Error.Remove($HandledError)
			}

			return
		}

		if ($SkipOnAccessDenied)
		{
			if ($Global:Error -and $Global:Error.Contains($HandledError))
			{
				[void]$Global:Error.Remove($HandledError)
			}

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

<#
	.SYNOPSIS
	Get the current Windows version details from the registry.
#>
function Get-WindowsVersionData
{
	$CurrentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
	$DisplayVersion = [string]$CurrentVersion.DisplayVersion
	$UBR = 0

	if ([string]::IsNullOrWhiteSpace($DisplayVersion))
	{
		$DisplayVersion = [string]$CurrentVersion.ReleaseId
	}

	if ($null -ne $CurrentVersion.UBR)
	{
		$UBR = [int]$CurrentVersion.UBR
	}

	[pscustomobject]@{
		IsWindows11    = ([int]$CurrentVersion.CurrentBuild -ge 22000)
		CurrentBuild   = [int]$CurrentVersion.CurrentBuild
		UBR            = $UBR
		DisplayVersion = $DisplayVersion
	}
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

	if ($VersionData.DisplayVersion -match '^(?<Year>\d{2})H(?<Half>\d)$')
	{
		$CurrentComparable = ([int]$Matches.Year * 10) + [int]$Matches.Half

		if ($MinimumDisplayVersion -match '^(?<Year>\d{2})H(?<Half>\d)$')
		{
			$MinimumComparable = ([int]$Matches.Year * 10) + [int]$Matches.Half
			return ($CurrentComparable -ge $MinimumComparable)
		}
	}

	return $false
}

# Export the shared helper functions used across the module set.
Export-ModuleMember -Function Set-Policy, ConvertTo-NativeRegistryPath, ConvertTo-RegExeValueType, Dismount-RegistryHive, Mount-RegistryHive, Set-RegistryValueSafe, Get-WindowsVersionData, Test-Windows11BuildSupport
