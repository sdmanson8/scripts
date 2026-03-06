using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Initial Setup
function CheckWinGet
{
	Write-Host "Checking WinGet - " -NoNewline
    LogInfo "Checking WinGet:"
    
    # Get OS information for compatibility checks
    $osVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    $currentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    
    # Determine Windows version
    if ([int]$currentBuild -ge 22000) {
        $osName = "Windows 11"
    } else {
        $osName = "Windows 10"
    }
    
    LogInfo "Detected OS: $osName (Build $currentBuild, Release $osVersion)"
    
    # Check if winget is already installed and working
    try {
        $wingetVersion = winget --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        LogInfo "Winget is already installed and working. Version: $wingetVersion"
        Write-Host "success!" -ForegroundColor Green
        return
    }
    } catch {
        LogWarning "Winget not found or not functional"
    }
    
    # If not working, use the asheroto installer script
    LogInfo "Preparing to download and install Winget using asheroto installer..."
    
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
        ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
        
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
            Write-Host "success!" -ForegroundColor Green
            return
        } else {
                throw "Winget validation failed"
            }
        } catch {
            LogError "Winget installation failed validation: $_"
            return $false
        }
        
    } catch {
        LogError "Error during winget installation: $_"
        return $false
    }
}

Function Update-Powershell
{
    # Check if PowerShell 7 is installed
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7)
	{
		# Get the latest version of PowerShell 7 from winget
		$latestVersion = (winget show --id Microsoft.PowerShell --accept-source-agreements | Select-String -Pattern "Version:" | ForEach-Object { $_.ToString().Split()[-1] }).Trim()

		if (-not $latestVersion) {
			LogError "Failed to retrieve the latest PowerShell version."
		}

		Write-Host "Installing PowerShell $latestVersion - " -NoNewline
		LogInfo "Installing PowerShell $latestVersion"
		# Run winget command as administrator to install PowerShell
		powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy Bypass', '-Command winget install --id Microsoft.PowerShell --silent --accept-package-agreements --accept-source-agreements' -Verb RunAs -Wait"
		Write-Host "success!" -ForegroundColor Green

        # Check if the installation was successful
        if ($LASTEXITCODE -eq 0)
		{
            #
        }
		else
		{
            LogError "Failed to install PowerShell $latestVersion. Please check the logs and try again." -ForegroundColor Red
        }
    }
	else
	{
        $currentPSVersion = $psVersion.ToString()
        LogWarning "PowerShell 7 is already installed (Version: $currentPSVersion)."
	}
}

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
            New-Item -Path $hideIconsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $hideIconsPath -Name $valueName -Value $valueData -Type DWord | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
	catch
	{
        LogError "Failed to set registry value: $valueName"
    }
}

function Stop-Foreground
{
    Stop-Process -Name "explorer" -Force | Out-Null
}
#endregion Initial Setup
