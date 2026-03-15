using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Initial Setup
<#
	.SYNOPSIS
	Refresh the current process PATH from the machine and user environment blocks.
#>
function Update-ProcessPathFromRegistry
{
	$MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
	$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
	$env:Path = (@($MachinePath, $UserPath) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ";"
}

<#
	.SYNOPSIS
	Resolve the local winget.exe path without assuming the current PATH is fresh.
#>
function Resolve-WinGetExecutable
{
	Update-ProcessPathFromRegistry

	$WingetCommand = Get-Command -Name winget.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source -ErrorAction SilentlyContinue
	if (-not [string]::IsNullOrWhiteSpace($WingetCommand))
	{
		return $WingetCommand
	}

	$CandidatePaths = @(
		(Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\winget.exe")
		(Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\winget.exe")
	) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

	return ($CandidatePaths | Select-Object -First 1)
}

<#
	.SYNOPSIS
	Get the current WinGet version if winget.exe can be resolved and executed.
#>
function Get-WinGetVersion
{
	$WingetPath = Resolve-WinGetExecutable
	if (-not $WingetPath)
	{
		return $null
	}

	try
	{
		$WingetVersion = & $WingetPath --version 2>$null
		if ($LASTEXITCODE -eq 0)
		{
			$ResolvedVersion = [string]($WingetVersion | Select-Object -First 1)
			if (-not [string]::IsNullOrWhiteSpace($ResolvedVersion))
			{
				return $ResolvedVersion.Trim()
			}
		}
	}
	catch
	{
		return $null
	}

	return $null
}

<#
	.SYNOPSIS
	Check whether WinGet is installed and install it if needed.

	.DESCRIPTION
	Validates that WinGet is present and functional. If it is missing or broken,
	the function downloads a bootstrap installer script, executes it, and
	validates the WinGet installation again before continuing.

	.EXAMPLE
	CheckWinGet

	.NOTES
	Machine-wide
#>
function CheckWinGet
{   
    # Get OS information for compatibility checks.
    $osInfo = Get-OSInfo
    $osVersion = $osInfo.DisplayVersion
    $currentBuild = $osInfo.CurrentBuild
    $osName = $osInfo.OSName
    
    LogInfo "Detected OS: $osName (Build $currentBuild, Release $osVersion)"
    
    # Check if winget is already installed and working
    $wingetVersion = Get-WinGetVersion
    if ($wingetVersion) {
        Write-ConsoleStatus -Action "Checking WinGet"
        LogInfo "Checking WinGet"
        LogInfo "Winget is already installed and working. Version: $wingetVersion"
        Write-ConsoleStatus -Status success
        return
    }

    LogWarning "Winget not found or not functional"
    
    # If not working, use the asheroto installer script
    Write-ConsoleStatus -Action "Installing WinGet"
    LogInfo "Installing WinGet:"
    
    try {
        # Download the asheroto installer script from direct GitHub URL
        $installerUrl = "https://raw.githubusercontent.com/asheroto/winget-install/master/winget-install.ps1"
        $installerPath = Join-Path $env:TEMP "winget-install.ps1"
        
        LogInfo "Downloading winget installer from $installerUrl"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        LogInfo "Download completed"
        
        LogInfo "Executing installer script..."
        
        # Create temporary log files to capture output
        $stdoutLog = Join-Path $env:TEMP "winget-install-stdout.log"
        $stderrLog = Join-Path $env:TEMP "winget-install-stderr.log"
        
        # Execute the installer and capture all output
        $process = Start-Process powershell.exe -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$installerPath`"",
            "-Force"
        ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -ErrorAction Stop
        
        # Read and log the captured output
        if (Test-Path $stdoutLog) {
            Get-Content $stdoutLog | ForEach-Object {
                if ($_) { LogInfo "winget-installer: $_" }
            }
            Remove-Item $stdoutLog -Force -ErrorAction SilentlyContinue
        }
        
        if (Test-Path $stderrLog) {
            Get-Content $stderrLog | ForEach-Object {
                if ($_) { LogError "winget-installer: $_" }
            }
            Remove-Item $stderrLog -Force -ErrorAction SilentlyContinue
        }
        
        # Check process exit code
        $installerCompletedSuccessfully = ($process.ExitCode -eq 0 -or $null -eq $process.ExitCode)
        if ($installerCompletedSuccessfully) {
            LogInfo "Installer script completed successfully"
        } else {
            LogWarning "Installer script reported exit code: $($process.ExitCode)"
        }
        
        # Clean up installer script
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        
        # Final validation
        Start-Sleep -Seconds 5
        $wingetVersion = Get-WinGetVersion
        if ($wingetVersion) {
            LogInfo "Winget validation succeeded. Version: $wingetVersion"
            Write-ConsoleStatus -Status success
            return
        }

        if ($installerCompletedSuccessfully) {
            LogWarning "Winget installation completed, but winget.exe is not available in the current session yet. A new session may be required."
            Write-ConsoleStatus -Status success
            return
        }

        LogError "Winget installation failed validation after the installer completed."
        Write-ConsoleStatus -Status failed
        return
        
    } catch {
        LogError "Error during winget installation: $_"
        Write-ConsoleStatus -Status failed
        return
    }
}

<#
	.SYNOPSIS
	Install or update PowerShell 7 by using WinGet.

	.DESCRIPTION
	Checks the current PowerShell version and uses WinGet to install the latest
	Microsoft PowerShell package when PowerShell 7 is not already installed.

	.EXAMPLE
	Update-Powershell

	.NOTES
	Machine-wide
#>
Function Update-Powershell
{
    Write-ConsoleStatus -Action "Checking Powershell Installation"
    LogInfo "Checking Powershell Installation"

    function Test-InternetReachability
    {
        $testUris = @(
            'https://www.msftconnecttest.com/connecttest.txt',
            'https://github.com'
        )

        foreach ($testUri in $testUris)
        {
            try
            {
                Invoke-WebRequest -Uri $testUri -Method Head -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop | Out-Null
                return $true
            }
            catch
            {
                continue
            }
        }

        return $false
    }

    function Test-PwshInstalled
    {
        @(
            (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
            (Join-Path ${env:ProgramFiles(x86)} 'PowerShell\7\pwsh.exe')
            (Get-Command -Name pwsh.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    }

    function Install-PowerShellViaMsi
    {
        param
        (
            [Parameter(Mandatory = $true)]
            [string]
            $Version
        )

        $normalizedVersion = ($Version -replace '\.0$', '')
        $msiUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$normalizedVersion/PowerShell-$normalizedVersion-win-x64.msi"
        $msiPath = Join-Path $env:TEMP "PowerShell-$normalizedVersion-win-x64.msi"

        LogInfo "Downloading PowerShell MSI from $msiUrl"
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop

        try
        {
            $msiProcess = Start-Process -FilePath msiexec.exe -ArgumentList '/i', "`"$msiPath`"", '/qn', '/norestart' -Verb RunAs -Wait -PassThru -ErrorAction Stop
            if ($msiProcess.ExitCode -ne 0)
            {
                throw "MSI installer returned exit code $($msiProcess.ExitCode)."
            }
        }
        finally
        {
            Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
        }
    }

    function Get-LatestPowerShellVersion
    {
        $wingetPath = Resolve-WinGetExecutable
        if ($wingetPath)
        {
            try
            {
                $wingetShowOutput = & $wingetPath show --id Microsoft.PowerShell --accept-source-agreements 2>$null
                if ($LASTEXITCODE -eq 0)
                {
                    $wingetVersion = ($wingetShowOutput | Select-String -Pattern "Version:" | ForEach-Object { $_.ToString().Split()[-1] }).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($wingetVersion))
                    {
                        return $wingetVersion
                    }
                }
            }
            catch
            {
                LogWarning "winget metadata lookup failed: $($_.Exception.Message)"
            }
        }
        else
        {
            LogWarning "winget.exe was not found. Falling back to direct PowerShell release lookup."
        }

        try
        {
            $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -Headers @{ "User-Agent" = "Win10_11Util" } -ErrorAction Stop
            $tagName = [string]$releaseInfo.tag_name
            if (-not [string]::IsNullOrWhiteSpace($tagName))
            {
                return $tagName.TrimStart('v')
            }
        }
        catch
        {
            LogWarning "GitHub release lookup failed: $($_.Exception.Message)"
        }

        return $null
    }

    [string[]]$pwshCandidatePaths = @(
        (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
        (Join-Path ${env:ProgramFiles(x86)} 'PowerShell\7\pwsh.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    if ($pwshCandidatePaths)
    {
        try
        {
            $installedPwshVersion = (Get-Item -LiteralPath $pwshCandidatePaths[0]).VersionInfo.ProductVersion
        }
        catch
        {
            $installedPwshVersion = $null
        }

        if ($installedPwshVersion)
        {
            LogInfo "PowerShell 7 is already installed (Version: $installedPwshVersion)."
        }
        else
        {
            LogInfo "PowerShell 7 is already installed."
        }

        Write-ConsoleStatus -Status success
        return
    }

    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7)
		{
		$latestVersion = Get-LatestPowerShellVersion

		if (-not $latestVersion) {
			LogError "Failed to retrieve the latest PowerShell version from winget or GitHub."
            Write-ConsoleStatus -Status failed
			return
		}

		Write-ConsoleStatus -Action "`rInstalling PowerShell $latestVersion"
		LogInfo "Installing PowerShell $latestVersion"
		try
		{
			$wingetPath = Resolve-WinGetExecutable
			if ($wingetPath)
			{
				$wingetArgs = @(
					'install',
					'--id', 'Microsoft.PowerShell',
					'--accept-package-agreements',
					'--accept-source-agreements'
				)

				# Launch WinGet in its own elevated process so its output does not pollute the active console.
				# Any native installer/progress UI remains visible in the spawned window.
				$PowerShellInstallProcess = Start-Process -FilePath $wingetPath -ArgumentList $wingetArgs -Verb RunAs -Wait -PassThru -ErrorAction Stop
				if ($PowerShellInstallProcess.ExitCode -ne 0)
				{
					$wingetExitCodeHex = ('0x{0:X8}' -f ($PowerShellInstallProcess.ExitCode -band 0xFFFFFFFF))
					LogWarning "PowerShell 7 installation via WinGet failed with exit code $($PowerShellInstallProcess.ExitCode) ($wingetExitCodeHex)."

					if (-not (Test-InternetReachability))
					{
						LogError "PowerShell 7 installation failed and no internet connectivity was detected."
						Write-ConsoleStatus -Status failed
						return
					}

					if ($wingetExitCodeHex -eq '0x8A15005E')
					{
						LogWarning "WinGet source certificate validation failed. Resetting sources and retrying once."
						try
						{
							Start-Process -FilePath $wingetPath -ArgumentList @('source', 'reset', '--force') -Verb RunAs -Wait -PassThru -ErrorAction Stop | Out-Null
							Start-Process -FilePath $wingetPath -ArgumentList @('source', 'update') -Verb RunAs -Wait -PassThru -ErrorAction Stop | Out-Null
							$PowerShellInstallProcess = Start-Process -FilePath $wingetPath -ArgumentList $wingetArgs -Verb RunAs -Wait -PassThru -ErrorAction Stop
						}
						catch
						{
							LogWarning "WinGet source repair failed: $($_.Exception.Message)"
						}
					}

					if ($PowerShellInstallProcess.ExitCode -ne 0)
					{
						LogWarning "Falling back to direct MSI installation for PowerShell $latestVersion."
						Install-PowerShellViaMsi -Version $latestVersion
					}
				}
			}
			else
			{
				if (-not (Test-InternetReachability))
				{
					LogError "winget.exe was not found and no internet connectivity was detected for MSI fallback."
					Write-ConsoleStatus -Status failed
					return
				}

				LogWarning "winget.exe was not found. Falling back directly to MSI installation for PowerShell $latestVersion."
				Install-PowerShellViaMsi -Version $latestVersion
			}

			[string[]]$pwshInstalled = @(Test-PwshInstalled)

			if (-not $pwshInstalled)
			{
				LogError "PowerShell 7 installation completed, but pwsh.exe was not found afterward."
				Write-ConsoleStatus -Status failed
				return
			}

			Write-ConsoleStatus -Status success
		}
		catch
		{
            LogError "Failed to install PowerShell $latestVersion. $($_.Exception.Message)"
            Write-ConsoleStatus -Status failed
		}
    }
	else
	{
        $currentPSVersion = $psVersion.ToString()
        LogInfo "PowerShell 7 is already installed (Version: $currentPSVersion)."
        Write-ConsoleStatus -Status success
	}
}

<#
	.SYNOPSIS
	Hide the Spotlight "About this picture" desktop icon.

	.DESCRIPTION
	Removes the Spotlight namespace entry from the desktop and sets the matching
	HideDesktopIcons value so the icon stays hidden for the current user.

	.EXAMPLE
	Update-DesktopRegistry

	.NOTES
	Current user
#>
function Update-DesktopRegistry
{
	Write-Host 'Removing "About this Picture" from Desktop - ' -NoNewline
	LogInfo 'Removing "About this Picture" from Desktop'
    # Define registry paths and key/value
    $namespaceKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"
    $hideIconsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    $valueName = "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"
    $valueData = 1

    # Remove the specified namespace registry key
    try
	{
        Remove-Item -Path $namespaceKeyPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
	catch
	{
        LogError "Registry key not found or could not be removed: $namespaceKeyPath"
    }

    # Ensure the HideDesktopIcons path exists and set the DWORD value
    try
	{
        if (-not (Test-Path -Path $hideIconsPath))
		{
            New-Item -Path $hideIconsPath -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $hideIconsPath -Name $valueName -Value $valueData -Type DWord -ErrorAction Stop | Out-Null
		Write-ConsoleStatus -Status success
    }
	catch
	{
        Write-ConsoleStatus -Status failed
        LogError "Failed to set registry value: $valueName"
    }
}

<#
	.SYNOPSIS
	Restart File Explorer so desktop and shell changes apply immediately.

	.DESCRIPTION
	Stops the Explorer foreground process so desktop, taskbar, and File Explorer
	changes can be reloaded by the shell.

	.EXAMPLE
	Stop-Foreground

	.NOTES
	Current user
#>
function Stop-Foreground
{
    Stop-Process -Name "explorer" -Force | Out-Null
}
#endregion Initial Setup
