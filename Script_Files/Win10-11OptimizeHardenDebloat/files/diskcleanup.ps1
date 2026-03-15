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

if (-not ("WinAPI.DiskCleanupWindow" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace WinAPI
{
    public static class DiskCleanupWindow
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    }
}
"@ -ErrorAction Stop | Out-Null
}

function Set-LowDiskChecksDisabled {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Disable,

        [AllowNull()]
        [object]$RestoreValue = $null,

        [switch]$Restore
    )

    $policyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $valueName = "NoLowDiskSpaceChecks"

    if (-not (Test-Path -Path $policyPath)) {
        New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
    }

    if ($Restore) {
        if ($null -eq $RestoreValue) {
            if ($null -ne (Get-ItemProperty -Path $policyPath -Name $valueName -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $policyPath -Name $valueName -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } else {
            New-ItemProperty -Path $policyPath -Name $valueName -PropertyType DWord -Value ([int]$RestoreValue) -Force -ErrorAction Stop | Out-Null
        }
    } elseif ($Disable) {
        New-ItemProperty -Path $policyPath -Name $valueName -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    }
}

function Close-DiskSpaceNotificationWindow {
    $closed = $false
    $windowTitles = @(
        "Disk Space Notification"
    )

    foreach ($windowTitle in $windowTitles) {
        foreach ($windowHandle in @(
            [WinAPI.DiskCleanupWindow]::FindWindow($null, $windowTitle),
            [WinAPI.DiskCleanupWindow]::FindWindow("#32770", $windowTitle)
        )) {
            if ($windowHandle -ne [IntPtr]::Zero) {
                [WinAPI.DiskCleanupWindow]::PostMessage($windowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                $closed = $true
            }            
        }
    }

    return $closed
}

function Close-CleanupProcessWindow {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process
    )

    try {
        $Process.Refresh()
    } catch {
        return $false
    }

    if ($Process.HasExited) {
        return $true
    }

    if ($Process.MainWindowHandle -eq [IntPtr]::Zero) {
        return $false
    }

    return $Process.CloseMainWindow()
}

function Wait-CleanupProcessAndDismissNotification {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [int]$PostExitSeconds = 60,

        [int]$QuietAfterCloseSeconds = 2
    )

    $graceDeadline = $null
    $closeLogged = $false
    $quietDeadline = $null
    $cleanupWindowCloseRequested = $false

    while ($true) {
        $Process.Refresh()

        if ($Process.HasExited) {
            if (-not $graceDeadline) {
                $graceDeadline = (Get-Date).AddSeconds($PostExitSeconds)
            }

            if ((Get-Date) -ge $graceDeadline) {
                break
            }
        }

        if (Close-DiskSpaceNotificationWindow) {
            if (-not $closeLogged) {
                LogInfo "Closed Disk Space Notification popup automatically."
                $closeLogged = $true
            }
            $quietDeadline = (Get-Date).AddSeconds($QuietAfterCloseSeconds)
        } elseif ($quietDeadline -and (Get-Date) -ge $quietDeadline -and -not $cleanupWindowCloseRequested) {
            if (Close-CleanupProcessWindow -Process $Process) {
                $cleanupWindowCloseRequested = $true
                $quietDeadline = (Get-Date).AddSeconds($QuietAfterCloseSeconds)
            }
        } elseif ($Process.HasExited -and $quietDeadline -and (Get-Date) -ge $quietDeadline) {
            break
        }

        Start-Sleep -Milliseconds 500
    }

    try {
        $Process.Refresh()
        if (-not $Process.HasExited -and $cleanupWindowCloseRequested) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    } catch {
    }

    Close-DiskSpaceNotificationWindow | Out-Null
}

function Invoke-BuiltInSilentCleanup {
    param(
        [int]$LaunchTimeoutSeconds = 15,

        [int]$TaskTimeoutSeconds = 900
    )

    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name Start-ScheduledTask -ErrorAction SilentlyContinue)) {
        return $false
    }

    try {
        $silentCleanupTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup\" -TaskName "SilentCleanup" -ErrorAction Stop
    } catch {
        return $false
    }

    $existingProcessIds = @(Get-Process -Name cleanmgr -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)

    Start-ScheduledTask -InputObject $silentCleanupTask -ErrorAction Stop

    $launchDeadline = (Get-Date).AddSeconds($LaunchTimeoutSeconds)
    $taskDeadline = (Get-Date).AddSeconds($TaskTimeoutSeconds)
    $runningSeen = $false

    while ((Get-Date) -lt $taskDeadline) {
        $newCleanmgrProcess = Get-Process -Name cleanmgr -ErrorAction SilentlyContinue |
            Where-Object { $existingProcessIds -notcontains $_.Id } |
            Select-Object -First 1

        if ($newCleanmgrProcess) {
            Wait-CleanupProcessAndDismissNotification -Process $newCleanmgrProcess
            return $true
        }

        try {
            $taskState = (Get-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup\" -TaskName "SilentCleanup" -ErrorAction Stop).State
        } catch {
            break
        }

        if ($taskState -eq "Running") {
            $runningSeen = $true
        } elseif ($runningSeen -or (Get-Date) -ge $launchDeadline) {
            break
        }

        Start-Sleep -Milliseconds 500
    }

    return $true
}

<#
.SYNOPSIS
Removes temporary and unnecessary Windows files, then cleans up superseded system components.
#>
$lowDiskPolicyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$originalLowDiskChecksValue = Get-ItemPropertyValue -Path $lowDiskPolicyPath -Name "NoLowDiskSpaceChecks" -ErrorAction SilentlyContinue
try {
    Set-LowDiskChecksDisabled -Disable $true

    $usedSilentCleanupTask = $false
    try {
        $usedSilentCleanupTask = Invoke-BuiltInSilentCleanup
    } catch {
        LogWarning "SilentCleanup task launch failed. Falling back to direct cleanmgr.exe: $($_.Exception.Message)"
    }

    if (-not $usedSilentCleanupTask) {
        $cleanmgrProcess = Start-Process -FilePath cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -PassThru -NoNewWindow -ErrorAction SilentlyContinue
        if ($cleanmgrProcess) {
            Wait-CleanupProcessAndDismissNotification -Process $cleanmgrProcess
        }
    }
    LogInfo "Running cleanmgr.exe completed"
}
finally {
    try {
        Set-LowDiskChecksDisabled -Restore -RestoreValue $originalLowDiskChecksValue -Disable $false
    } catch {
        LogWarning "Failed to restore low disk space checks: $($_.Exception.Message)"
    }
}

# Run DISM component cleanup to remove superseded Windows component store data.
Start-Process -FilePath Dism.exe -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
LogInfo "Running DISM Component Cleanup completed"
