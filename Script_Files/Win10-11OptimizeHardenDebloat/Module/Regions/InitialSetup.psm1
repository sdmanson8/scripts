using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Initial Setup
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
    try {
        $wingetVersion = winget --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-ConsoleStatus -Action "Checking WinGet"
        LogInfo "Checking WinGet"
        LogInfo "Winget is already installed and working. Version: $wingetVersion"
        Write-ConsoleStatus -Status success
        return
    }
    } catch {
        LogWarning "Winget not found or not functional"
    }
    
    # If not working, use the asheroto installer script
    Write-Host "Installing WinGet:" -NoNewline
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
        if ($process.ExitCode -eq 0 -or $null -eq $process.ExitCode) {
            LogInfo "Installer script completed successfully"
        } else {
            LogWarning "Installer script reported exit code: $($process.ExitCode)"
        }
        
        # Clean up installer script
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        
        # Final validation
        Start-Sleep -Seconds 5
        try {
            $wingetVersion = winget --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-ConsoleStatus -Status success
            return
        } else {
                throw "Winget validation failed"
            }
        } catch {
            LogError "Winget installation failed validation: $_"
            Write-ConsoleStatus -Status failed
            return $false
        }
        
    } catch {
        LogError "Error during winget installation: $_"
        Write-ConsoleStatus -Status failed
        return $false
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

    $pwshCandidatePaths = @(
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
		# Get the latest version of PowerShell 7 from winget
		$wingetShowOutput = winget show --id Microsoft.PowerShell --accept-source-agreements 2>$null
		if ($LASTEXITCODE -ne 0)
		{
			LogError "winget show failed to retrieve Microsoft.PowerShell metadata. Exit code: $LASTEXITCODE"
            Write-ConsoleStatus -Status failed
			return
		}

		$latestVersion = ($wingetShowOutput | Select-String -Pattern "Version:" | ForEach-Object { $_.ToString().Split()[-1] }).Trim()

		if (-not $latestVersion) {
			LogError "Failed to retrieve the latest PowerShell version."
            Write-ConsoleStatus -Status failed
			return
		}

		Write-ConsoleStatus -Action "`rInstalling PowerShell $latestVersion"
		LogInfo "Installing PowerShell $latestVersion"
		try
		{
			$wingetStdOutPath = Join-Path $env:TEMP "WinUtil-PowerShellInstall.stdout.log"
			$wingetStdErrPath = Join-Path $env:TEMP "WinUtil-PowerShellInstall.stderr.log"
			Remove-Item -Path $wingetStdOutPath, $wingetStdErrPath -Force -ErrorAction SilentlyContinue | Out-Null

			# Run winget command as administrator to install PowerShell
			$PowerShellInstallProcess = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy Bypass', '-Command winget install --id Microsoft.PowerShell --silent --accept-package-agreements --accept-source-agreements' -Verb RunAs -Wait -PassThru -RedirectStandardOutput $wingetStdOutPath -RedirectStandardError $wingetStdErrPath -ErrorAction Stop
			if ($PowerShellInstallProcess.ExitCode -ne 0)
			{
				$wingetStdOut = if (Test-Path $wingetStdOutPath) { (Get-Content -Path $wingetStdOutPath -Raw -ErrorAction SilentlyContinue).Trim() } else { "" }
				$wingetStdErr = if (Test-Path $wingetStdErrPath) { (Get-Content -Path $wingetStdErrPath -Raw -ErrorAction SilentlyContinue).Trim() } else { "" }
				$wingetDetails = @($wingetStdErr, $wingetStdOut) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

				LogError "PowerShell 7 installation failed. WinGet returned exit code $($PowerShellInstallProcess.ExitCode)."
				if ($wingetDetails)
				{
					LogError "WinGet said: $wingetDetails"
				}
				else
				{
					LogError "WinGet did not provide a readable error message. This is usually a source, package manager, or elevation problem."
				}
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
