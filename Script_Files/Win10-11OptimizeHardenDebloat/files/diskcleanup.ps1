#Log file
# Import logging module
Import-Module -Name "$PSScriptRoot\..\Module\Logging.psm1" -Force

# Set up logging - priority: parameter > environment > global > default
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

#LogInfo "Child script started with PID: $pid"
#LogInfo "Parameters: nonInteractive=$nonInteractive, revertMode=$revertMode, AllOptions=$AllOptions"

# Helper function to get current log file path
function Get-LogFilePath {
    if ($global:LogFilePath) { return $global:LogFilePath }
    if ($env:diskcleanup) { return $env:diskcleanup }
    return $null
}

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

if ($revertMode) {
    $Global:revert = 1
}
else {
    $Global:revert = 0
}

if ($backupMode) {
    $Global:backup = 1
}
else {
    $Global:backup = 0
}

$Global:tempDir = ([System.IO.Path]::GetTempPath())


LogInfo "Running Disk Cleanup"
Write-Host "Running Disk Cleanup... Please Wait"
Start-Process -FilePath cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -Wait -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
LogInfo "Running cleanmgr.exe completed"
Start-Process -FilePath Dism.exe -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
LogInfo "Running DISM Component Cleanup completed"