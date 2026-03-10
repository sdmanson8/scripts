<#
    .SYNOPSIS
    Logging module for Win10_11Util.

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
    Initializes the log file used by the script and provides helper functions for writing
    informational, warning, and error messages to that log.
#>

$script:LogFilePath = $null
$script:LogLock = New-Object System.Threading.Mutex($false, "Global\RemoveWindowsAILogLock")
$script:LogStatistics = @{
    Info = 0
    Warning = 0
    Error = 0
}

function Reset-LogStatistics {
    $script:LogStatistics = @{
        Info = 0
        Warning = 0
        Error = 0
    }
}

<#
    .SYNOPSIS
    Set the log file path used by the logging module.

    .PARAMETER Path
    Path to the log file that should receive log output.

    .PARAMETER Clear
    Clear the existing log file and start a new log header.

    .EXAMPLE
    Set-LogFile -Path $global:LogFilePath
#>
function Set-LogFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [switch]$Clear
    )
    
    $script:LogFilePath = $Path
    Reset-LogStatistics
    
    # Create directory if needed
    $dir = Split-Path $Path -Parent
    if (!(Test-Path $dir)) {
        New-Item $dir -ItemType Directory -Force | Out-Null
    }
    
    if ($Clear) {
        # Only clear if explicitly requested
        Set-Content -Path $Path -Value "=== Log Started at $(Get-Date) ==="
    } elseif (!(Test-Path $Path)) {
        # Create if doesn't exist
        Set-Content -Path $Path -Value "=== Log Started at $(Get-Date) ==="
    }
}

<#
    .SYNOPSIS
    Write a formatted message to the current log file.

    .PARAMETER Message
    Message text to write to the log.

    .PARAMETER Level
    Severity level to include in the log entry.

    .PARAMETER AddGap
    Add a blank line after the log entry.

    .PARAMETER ShowConsole
    Also display the message in the console.

    .EXAMPLE
    Write-LogMessage -Message "Import started" -Level INFO
#>
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO',
        [switch]$AddGap,
        [switch]$ShowConsole  # Changed from NoConsole to ShowConsole (default off)
    )
    
    if (-not $script:LogFilePath) { return }

    if ([string]::IsNullOrWhiteSpace($Message)) {
    return
    }

    $timestamp = Get-Date -Format "dd-MM-yyyy HH:mm"
    $logMessage = "$timestamp $Level`: $Message"
    if ($AddGap) { $logMessage += "`n" }

    switch ($Level) {
        'INFO' { $script:LogStatistics.Info++ }
        'WARNING' { $script:LogStatistics.Warning++ }
        'ERROR' { $script:LogStatistics.Error++ }
    }
    
    # Show log output in the console only when explicitly requested.
    if ($ShowConsole) {
        switch ($Level) {
            'ERROR'   { Write-Host "ERROR: $Message" -ForegroundColor Red }
            'WARNING' { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
            default   { Write-Host "INFO: $Message" }
        }
    }
    
    # Use a mutex so multiple log writes do not corrupt the log file.
    $acquired = $script:LogLock.WaitOne(5000)  # 5 second timeout
    try {
        if ($acquired) {
            Add-Content -Path $script:LogFilePath -Value $logMessage -Encoding UTF8
        } else {
            # Fallback if mutex times out
            Write-Host "WARNING: Log mutex timeout - retrying..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 100
            Add-Content -Path $script:LogFilePath -Value $logMessage -Encoding UTF8
        }
    }
    finally {
        if ($acquired) {
            $script:LogLock.ReleaseMutex()
        }
    }
}

<#
    .SYNOPSIS
    Write an informational message to the log.

    .PARAMETER Message
    Informational message text to log.

    .PARAMETER AddGap
    Add a blank line after the log entry.

    .PARAMETER ShowConsole
    Also display the message in the console.

    .EXAMPLE
    LogInfo -Message "Region modules imported"
#>
function LogInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$AddGap,
        [switch]$ShowConsole
    )
    Write-LogMessage -Message $Message -Level 'INFO' -AddGap:$AddGap -ShowConsole:$ShowConsole
}

<#
    .SYNOPSIS
    Write a warning message to the log.

    .PARAMETER Message
    Warning message text to log.

    .PARAMETER AddGap
    Add a blank line after the log entry.

    .PARAMETER ShowConsole
    Also display the message in the console.

    .EXAMPLE
    LogWarning -Message "Optional file was not found"
#>
function LogWarning {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$AddGap,
        [switch]$ShowConsole
    )
    Write-LogMessage -Message $Message -Level 'WARNING' -AddGap:$AddGap -ShowConsole:$ShowConsole
}

<#
    .SYNOPSIS
    Write an error message to the log.

    .PARAMETER Message
    Error message text to log.

    .PARAMETER AddGap
    Add a blank line after the log entry.

    .PARAMETER ShowConsole
    Also display the message in the console.

    .EXAMPLE
    LogError -Message "PowerShell 5.1 not found."
#>
function LogError {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$AddGap,
        [switch]$ShowConsole
    )
    Write-LogMessage -Message $Message -Level 'ERROR' -AddGap:$AddGap -ShowConsole:$ShowConsole
}

function Get-LogStatistics {
    return [PSCustomObject]@{
        InfoCount = $script:LogStatistics.Info
        WarningCount = $script:LogStatistics.Warning
        ErrorCount = $script:LogStatistics.Error
    }
}

function Write-ConsoleStatus {
    [CmdletBinding()]
    param(
        [string]$Action,

        [ValidateSet('success', 'failed', 'warning')]
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Action) -and [string]::IsNullOrWhiteSpace($Status)) {
        throw "Write-ConsoleStatus requires -Action, -Status, or both."
    }

    if (-not [string]::IsNullOrWhiteSpace($Action) -and [string]::IsNullOrWhiteSpace($Status)) {
        Write-Host ("{0} - " -f $Action) -NoNewline
        return
    }

    $statusText = $Status.ToLowerInvariant()
    $color = switch ($statusText) {
        'success' { 'Green' }
        'failed' { 'Red' }
        default { 'Yellow' }
    }

    if ([string]::IsNullOrWhiteSpace($Action)) {
        Write-Host ("{0}!" -f $statusText) -ForegroundColor $color
        return
    }

    Write-Host ("{0} - " -f $Action) -NoNewline
    Write-Host ("{0}!" -f $statusText) -ForegroundColor $color
}

# Export the logging functions used by the loader and region modules.
Export-ModuleMember -Function Set-LogFile, Reset-LogStatistics, Get-LogStatistics, LogInfo, LogWarning, LogError, Write-LogMessage, Write-ConsoleStatus
