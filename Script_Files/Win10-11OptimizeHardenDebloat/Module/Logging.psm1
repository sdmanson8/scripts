$script:LogFilePath = $null
$script:LogLock = New-Object System.Threading.Mutex($false, "Global\RemoveWindowsAILogLock")

function Set-LogFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [switch]$Clear
    )
    
    $script:LogFilePath = $Path
    
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

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO',
        [switch]$AddGap,
        [switch]$ShowConsole  # Changed from NoConsole to ShowConsole (default off)
    )
    
    if (!$script:LogFilePath) { return }
    
    if (-not $script:LogFilePath) { return }

    if ([string]::IsNullOrWhiteSpace($Message)) {
    return
    }

    $timestamp = Get-Date -Format "dd-MM-yyyy HH:mm"
    $logMessage = "$timestamp $Level`: $Message"
    if ($AddGap) { $logMessage += "`n" }
    
    # Write to console ONLY if explicitly requested with -ShowConsole
    if ($ShowConsole) {
        switch ($Level) {
            'ERROR'   { Write-Host "ERROR: $Message" -ForegroundColor Red }
            'WARNING' { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
            default   { Write-Host "INFO: $Message" }
        }
    }
    
    # Thread-safe file writing with mutex
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

# Convenience functions - by default, NO console output
function LogInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$AddGap,
        [switch]$ShowConsole
    )
    Write-LogMessage -Message $Message -Level 'INFO' -AddGap:$AddGap -ShowConsole:$ShowConsole
}

function LogWarning {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$AddGap,
        [switch]$ShowConsole
    )
    Write-LogMessage -Message $Message -Level 'WARNING' -AddGap:$AddGap -ShowConsole:$ShowConsole
}

function LogError {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$AddGap,
        [switch]$ShowConsole
    )
    Write-LogMessage -Message $Message -Level 'ERROR' -AddGap:$AddGap -ShowConsole:$ShowConsole
}

# Export functions
Export-ModuleMember -Function Set-LogFile, LogInfo, LogWarning, LogError, Write-LogMessage