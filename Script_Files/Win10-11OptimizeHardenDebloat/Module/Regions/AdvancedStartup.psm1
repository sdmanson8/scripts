using module ..\Logging.psm1

function Get-AdvancedStartupDesktopDirectory {
    try {
        return [Environment]::GetFolderPath('Desktop')
    }
    catch {
        return (Join-Path $env:USERPROFILE 'Desktop')
    }
}

function Get-AdvancedStartupDownloadsDirectory {
    try {
        $downloadsFolder = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads')
        if ($downloadsFolder -and $downloadsFolder.Self -and -not [string]::IsNullOrWhiteSpace($downloadsFolder.Self.Path)) {
            return $downloadsFolder.Self.Path
        }

        return (Join-Path $HOME 'Downloads')
    }
    catch {
        return (Join-Path $HOME 'Downloads')
    }
}

function Get-AdvancedStartupAssetPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $candidatePaths = @(
        [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\files\$FileName")),
        [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\Assets\$FileName")),
        [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\..\$FileName"))
    )

    foreach ($candidatePath in $candidatePaths | Select-Object -Unique) {
        if (Test-Path -LiteralPath $candidatePath) {
            return $candidatePath
        }
    }

    return $null
}

function Get-AdvancedStartupIconLocation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DownloadsPath
    )

    $localIconPath = "$env:WINDIR\troubleshoot.ico"
    if (Test-Path -LiteralPath $localIconPath) {
        return "$localIconPath, 0"
    }

    $bundledIconPath = Get-AdvancedStartupAssetPath -FileName 'troubleshoot.ico'
    if (Test-Path -LiteralPath $bundledIconPath) {
        try {
            Copy-Item -Path $bundledIconPath -Destination $localIconPath -Force -ErrorAction Stop
            LogInfo 'Copied bundled Advanced Startup shortcut icon'
            return "$localIconPath, 0"
        }
        catch {
            LogWarning "Failed to copy bundled Advanced Startup shortcut icon: $_"
        }
    }

    try {
        $downloadedIconPath = Join-Path $DownloadsPath 'troubleshoot.ico'
        Invoke-WebRequest -Uri 'https://github.com/sdmanson8/scripts/raw/main/Script%20Files/troubleshoot.ico' `
            -OutFile $downloadedIconPath -UseBasicParsing -ErrorAction Stop
        Move-Item -Path $downloadedIconPath -Destination $localIconPath -Force -ErrorAction Stop
        LogInfo 'Downloaded Advanced Startup shortcut icon'
        return "$localIconPath, 0"
    }
    catch {
        LogInfo 'Using built-in system icon for Advanced Startup shortcut'
        return "$env:WINDIR\System32\shell32.dll,27"
    }
}

function Enable-AdvancedStartupWindowsRecoveryEnvironment {
    try {
        & reagentc.exe /enable *> $null
        if ($LASTEXITCODE -eq 0) {
            LogInfo 'Ensured Windows Recovery Environment is enabled'
            return $true
        }

        LogWarning "reagentc.exe /enable returned exit code $LASTEXITCODE"
    }
    catch {
        LogWarning "Failed to enable Windows Recovery Environment: $_"
    }

    return $false
}

function Get-AdvancedStartupCommandPath {
    $commandDirectory = Join-Path $env:ProgramData 'Win10_11Util'
    if (-not (Test-Path -LiteralPath $commandDirectory)) {
        New-Item -Path $commandDirectory -ItemType Directory -Force | Out-Null
    }

    return (Join-Path $commandDirectory 'AdvancedStartup.cmd')
}

function Set-AdvancedStartupCommandFile {
    $commandPath = Get-AdvancedStartupCommandPath
    $commandContent = @"
@echo off
"$env:WINDIR\System32\reagentc.exe" /boottore
"$env:WINDIR\System32\shutdown.exe" /r /f /t 00
"@

    Set-Content -Path $commandPath -Value $commandContent -Encoding ASCII -Force
    LogInfo "Created Advanced Startup command file at $commandPath"
    return $commandPath
}

function Get-AdvancedStartupShortcutArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandPath
    )

    $launcherScript = @"
`$shell = New-Object -ComObject Shell.Application
`$shell.ShellExecute('$CommandPath', '', '', 'runas', 0)
"@

    $encodedLauncherScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($launcherScript))
    return "-NoProfile -WindowStyle Hidden -EncodedCommand $encodedLauncherScript"
}

<#
.SYNOPSIS
Create or remove the desktop shortcut that reboots into Advanced Startup.

.EXAMPLE
AdvancedStartupShortcut -Enable

.EXAMPLE
AdvancedStartupShortcut -Disable

.NOTES
Current user
#>
function AdvancedStartupShortcut {
    [CmdletBinding(DefaultParameterSetName = 'Enable')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Enable')]
        [switch]$Enable,

        [Parameter(Mandatory = $true, ParameterSetName = 'Disable')]
        [switch]$Disable
    )

    $desktopPath = Get-AdvancedStartupDesktopDirectory
    if ([string]::IsNullOrWhiteSpace($desktopPath)) {
        Write-ConsoleStatus -Action "Configuring Advanced Startup shortcut" -Status failed
        LogError 'Unable to resolve the Desktop directory for the Advanced Startup shortcut'
        return
    }

    $shortcutPath = Join-Path $desktopPath 'Advanced Startup (REBOOT).lnk'

    if ($Disable) {
        $hadIssue = $false
        Write-ConsoleStatus -Action "Removing Advanced Startup shortcut"

        foreach ($pathToRemove in @($shortcutPath, (Get-AdvancedStartupCommandPath))) {
            try {
                if (Test-Path -LiteralPath $pathToRemove) {
                    Remove-Item -LiteralPath $pathToRemove -Force -ErrorAction Stop
                    LogInfo "Removed Advanced Startup asset: $pathToRemove"
                }
            }
            catch {
                $hadIssue = $true
                LogWarning "Failed to remove Advanced Startup asset $pathToRemove : $_"
            }
        }

        if ($hadIssue) {
            Write-ConsoleStatus -Status warning
        }
        else {
            Write-ConsoleStatus -Status success
        }

        return
    }

    $hadIssue = $false
    Write-ConsoleStatus -Action "Creating Advanced Startup shortcut"

    try {
        if (-not (Enable-AdvancedStartupWindowsRecoveryEnvironment)) {
            $hadIssue = $true
        }

        $commandPath = Set-AdvancedStartupCommandFile
        $downloadsPath = Get-AdvancedStartupDownloadsDirectory
        $iconLocation = Get-AdvancedStartupIconLocation -DownloadsPath $downloadsPath

        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
        $shortcut.Arguments = Get-AdvancedStartupShortcutArguments -CommandPath $commandPath
        $shortcut.WorkingDirectory = $env:WINDIR
        $shortcut.Description = 'Reboot directly into Advanced Startup options.'

        $iconPath = ($iconLocation -split ',', 2)[0].Trim()
        if (-not [string]::IsNullOrWhiteSpace($iconPath) -and (Test-Path -LiteralPath $iconPath)) {
            $shortcut.IconLocation = $iconLocation
        }

        $shortcut.Save()
        LogInfo 'Created Advanced Startup desktop shortcut'
    }
    catch {
        $hadIssue = $true
        LogWarning "Failed to create Advanced Startup shortcut: $_"
    }

    if ($hadIssue) {
        Write-ConsoleStatus -Status warning
    }
    else {
        Write-ConsoleStatus -Status success
    }
}

Export-ModuleMember -Function @(
    'AdvancedStartupShortcut'
)
