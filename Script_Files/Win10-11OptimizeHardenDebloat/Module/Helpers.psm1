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

Export-ModuleMember -Function Set-Policy