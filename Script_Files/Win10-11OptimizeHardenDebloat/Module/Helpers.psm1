<#
    .SYNOPSIS
    Helper module for Win10_11Util.

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

# Export the shared helper functions used across the module set.
Export-ModuleMember -Function Set-Policy
