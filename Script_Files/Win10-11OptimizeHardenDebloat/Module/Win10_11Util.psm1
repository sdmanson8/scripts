<#
    .SYNOPSIS
    Loader module for Win10_11Util.
 
	.VERSION
	2.0.2

	.DATE
	03.10.2021 - initial version
	24.02.2026 - updated to v2.0.0 with new functions and improvements
	04.03.2026 - updated to v2.0.1 with bug fixes and optimizations
	07.03.2026 - updated to v2.0.2 with major tweaks and refinements

	Copyright (c) 2021 - 2026 sdmanson8

    .DESCRIPTION
    Imports shared modules and region modules, then exports their functions.
    This Script is a PowerShell module for Windows 10 & Windows 11 for fine-tuning and automating the routine tasks
#>

# Logging and helper functions are shared across all region modules, so we import them first to ensure they are available for use in the region modules.
# Import shared modules used by all region modules
Import-Module -Name "$PSScriptRoot\Logging.psm1" -Force -Global
Import-Module -Name "$PSScriptRoot\Helpers.psm1" -Force -Global

# Detect the OS version from the current Windows build
$currentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
if ([int]$currentBuild -ge 22000) {
    $osName = "Windows 11"
}
else {
    $osName = "Windows 10"
}
# Initialize logging and write to an OS-specific log file in %TEMP%
$global:LogFilePath = Join-Path $env:TEMP "WinUtil Script for $osName.txt"
Set-LogFile -Path $global:LogFilePath

<#
    .SYNOPSIS
    Restart the script in Windows PowerShell 5.1 when launched from PowerShell 7.

    .PARAMETER ScriptPath
    Path to the script file that should be restarted in Windows PowerShell 5.1.

    .EXAMPLE
    Restart-Script -ScriptPath $MyInvocation.MyCommand.Path
#>
function Restart-Script
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]
		$ScriptPath
	)
	if ($PSVersionTable.PSVersion.Major -ge 7)
	{
		$powershell51 = (Get-Command -Name powershell.exe -ErrorAction SilentlyContinue).Source

		if (-not $powershell51)
		{
			LogError "PowerShell 5.1 not found."
			[Environment]::Exit(1)
		}

		if (-not (Test-Path -LiteralPath $ScriptPath))
		{
			LogError "Script not found: $ScriptPath"
			[Environment]::Exit(1)
		}

		LogInfo "Restarting script in Windows PowerShell 5.1"

		$argList = @(
			'-ExecutionPolicy', 'Bypass',
			'-NoProfile',
			'-File', $ScriptPath
		)

		if ($Functions)
		{
			$argList += '-Functions'
			$argList += $Functions
		}

		Start-Process -FilePath $powershell51 -ArgumentList $argList
		[Environment]::Exit(0)
	}
}

<#
    .SYNOPSIS
    Load the region modules that provide the script's functions.

    .DESCRIPTION
    Imports Errors.psm1 and InitialActions.psm1 first because other region modules may depend on them.
    Then imports the remaining region modules from the Regions folder in name order and exports their functions through this loader module.
#>
$RegionDir = Join-Path $PSScriptRoot 'Regions'

$coreFiles = @('Errors.psm1', 'InitialActions.psm1')

foreach ($core in $coreFiles) {
    $corePath = Join-Path $RegionDir $core
    if (Test-Path -LiteralPath $corePath) {
        Import-Module -Name $corePath -Force -Global
    }
}

Get-ChildItem -Path $RegionDir -Filter '*.psm1' -File |
    Where-Object { $_.Name -notin $coreFiles } |
    Sort-Object Name |
    ForEach-Object {
        Import-Module -Name $_.FullName -Force -Global
    }

Export-ModuleMember -Function *
