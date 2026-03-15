using module ..\Logging.psm1

#region Production System Optimizations

function Get-OptimizationScratchDirectory {
    $scratchDirectory = Join-Path $env:TEMP 'Win10_11Util'
    if (-not (Test-Path -LiteralPath $scratchDirectory)) {
        New-Item -Path $scratchDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    return $scratchDirectory
}

function Get-OptimizationAssetPath {
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

function Import-LegacyRegistryAsset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$ScratchPath,

        [string]$Uri
    )

    $sourcePath = Get-OptimizationAssetPath -FileName $FileName
    $targetPath = Join-Path $ScratchPath $FileName

    try {
        if ($sourcePath) {
            Copy-Item -Path $sourcePath -Destination $targetPath -Force -ErrorAction Stop
            LogInfo "Using bundled asset for $Description"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($Uri)) {
            Invoke-WebRequest -Uri $Uri -OutFile $targetPath -UseBasicParsing -ErrorAction Stop
            LogInfo "Downloaded asset for $Description"
        }
        else {
            throw "Required asset not found locally: $FileName"
        }

        Start-Process -FilePath 'regedit.exe' -ArgumentList @('/S', $targetPath) -Wait -WindowStyle Hidden -ErrorAction Stop
        LogInfo "Imported $Description"
    }
    finally {
        Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
    }
}

<#
    .SYNOPSIS
    Apply the legacy system/bootstrap optimizations from the monolithic RAM optimizer.

    .EXAMPLE
    Invoke-SystemOptimizations
#>
function Invoke-SystemOptimizations {
    LogInfo "Applying legacy system/bootstrap optimizations"

    $hadIssue = $false
    $scratchDirectory = Get-OptimizationScratchDirectory

    $regImports = @(
        @{
            Uri = 'https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/utils/lower-ram-usage.reg'
            FileName = 'ram-reducer.reg'
            Description = 'Lower RAM usage registry import'
        },
        @{
            Uri = 'https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/utils/enable-photo-viewer.reg'
            FileName = 'enable-photo-viewer.reg'
            Description = 'Enable Photo Viewer registry import'
        }
    )

    foreach ($import in $regImports) {
        try {
            Import-LegacyRegistryAsset -FileName $import.FileName `
                -Description $import.Description `
                -ScratchPath $scratchDirectory `
                -Uri $import.Uri
        }
        catch {
            $hadIssue = $true
            LogWarning "Failed to apply $($import.Description): $_"
        }
    }

    try {
        & bcdedit.exe /set '{default}' bootmenupolicy legacy *> $null
        if ($LASTEXITCODE -eq 0) {
            LogInfo 'Enabled legacy boot menu policy'
        }
        else {
            throw "bcdedit.exe returned exit code $LASTEXITCODE"
        }
    }
    catch {
        $hadIssue = $true
        LogWarning "Failed to enable legacy boot menu: $_"
    }

    $environmentVariables = @(
        @{ Name = 'ProgramFiles'; Value = $env:ProgramFiles },
        @{ Name = 'ProgramFiles86'; Value = ${env:ProgramFiles(x86)} },
        @{ Name = 'ProgramData'; Value = $env:ProgramData }
    )

    foreach ($environmentVariable in $environmentVariables) {
        try {
            if (-not [string]::IsNullOrWhiteSpace($environmentVariable.Value)) {
                & setx.exe $environmentVariable.Name $environmentVariable.Value /m *> $null
                if ($LASTEXITCODE -eq 0) {
                    LogInfo "Set system environment variable $($environmentVariable.Name)"
                }
            }
        }
        catch {
            $hadIssue = $true
            LogWarning "Failed to set environment variable $($environmentVariable.Name): $_"
        }
    }

    foreach ($command in @(
        @{ FilePath = 'attrib.exe'; Arguments = @("$env:WINDIR\PerfLogs", '+h'); Description = 'Hid PerfLogs folder' },
        @{ FilePath = 'attrib.exe'; Arguments = @("$env:PUBLIC\Desktop", '-h'); Description = 'Revealed Public Desktop folder' }
    )) {
        try {
            & $command.FilePath @($command.Arguments) *> $null
            if ($LASTEXITCODE -eq 0) {
                LogInfo $command.Description
            }
        }
        catch {
            $hadIssue = $true
            LogWarning "Failed to update file attributes for $($command.Description): $_"
        }
    }

    try {
        Remove-Item -Path (Join-Path $env:USERPROFILE 'Desktop\Your Phone.lnk') `
            -Force -ErrorAction SilentlyContinue
        LogInfo 'Removed Your Phone desktop shortcut if present'
    }
    catch {
        $hadIssue = $true
        LogWarning "Failed to remove Your Phone shortcut: $_"
    }

    if ($hadIssue) {
        Write-ConsoleStatus -Action "Applying system optimizations" -Status warning
    }
    else {
        Write-ConsoleStatus -Action "Applying system optimizations" -Status success
    }
}

#endregion Production System Optimizations

Export-ModuleMember -Function @(
    'Invoke-SystemOptimizations'
)
