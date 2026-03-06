<#
    .SYNOPSIS
    This Script is a PowerShell module for Windows 10 & Windows 11 for fine-tuning and automating the routine tasks
#>

# Import logging module
Import-Module -Name "$PSScriptRoot\Logging.psm1" -Force -Global

# Load shared helper functions
Import-Module -Name "$PSScriptRoot\Helpers.psm1" -Force -Global

# Get the OS version
$currentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

if ([int]$currentBuild -ge 22000) {
    $osName = "Windows 11"
}
else {
    $osName = "Windows 10"
}

# Set up global log file
$global:LogFilePath = Join-Path $env:TEMP "WinUtil Script for $osName.txt"
Set-LogFile -Path $global:LogFilePath

# Restart Script in Powershell 5.1 if running Powershell 7
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

# Load region modules
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