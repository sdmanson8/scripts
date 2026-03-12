<#
    .SYNOPSIS
    Runs Windows disk cleanup tasks and writes progress to the Win10_11Util log.

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
    Imports the shared logging module, selects a log file, runs Disk Cleanup in
    very low disk mode, and then runs DISM component cleanup to remove
    superseded component store files.

    .NOTES
    This script is intended to be called by Win10_11Util. If no log path is
    provided, it falls back to a temporary log file.

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\files\diskcleanup.ps1
#>

# Import the shared logging module used by Win10_11Util child scripts.
Import-Module -Name "$PSScriptRoot\..\Module\Logging.psm1" -Force

# Select the log file in this order: explicit parameter, environment variable,
# existing global log path, then a temporary fallback file.
if ($LogFilePath) {
    Set-LogFile -Path $LogFilePath
    #LogInfo "Using log file from parameter: $LogFilePath"
} elseif ($env:diskcleanup) {
    Set-LogFile -Path $env:diskcleanup
    #LogInfo "Using log file from environment: $env:diskcleanup"
} elseif ($global:LogFilePath) {
    Set-LogFile -Path $global:LogFilePath
    #LogInfo "Using log file from global: $global:LogFilePath"
} else {
    $defaultLog = Join-Path $env:TEMP "diskcleanup.txt"
    Set-LogFile -Path $defaultLog
    #LogInfo "Using default log file: $defaultLog"
}

# Return the active log file path if one has already been configured.
function Get-LogFilePath {
    if ($global:LogFilePath) { return $global:LogFilePath }
    if ($env:diskcleanup) { return $env:diskcleanup }
    return $null
}

# Write file content under a mutex so concurrent cleanup operations do not
# corrupt the log or any temporary output file.
function Write-FileSafely {
    param(
        [string]$Path,
        [string]$Value,
        [switch]$Append
    )
    
    $mutexName = "Global\diskcleanupLogLock"
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    
    $acquired = $mutex.WaitOne(5000)
    try {
        if ($acquired) {
            if ($Append) {
                Add-Content -Path $Path -Value $Value -Encoding UTF8
            } else {
                Set-Content -Path $Path -Value $Value -Encoding UTF8
            }
        }
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
    }
}

$Global:tempDir = ([System.IO.Path]::GetTempPath())

<#
.SYNOPSIS
Removes temporary and unnecessary Windows files, then cleans up superseded system components.
#>
LogInfo "Running Disk Cleanup"
Write-Host "Running Disk Cleanup... Please Wait"
Start-Process -FilePath cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -Wait -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
LogInfo "Running cleanmgr.exe completed"

# Run DISM component cleanup to remove superseded Windows component store data.
Start-Process -FilePath Dism.exe -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
LogInfo "Running DISM Component Cleanup completed"
