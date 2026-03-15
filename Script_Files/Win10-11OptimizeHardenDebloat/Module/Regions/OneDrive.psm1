using module ..\Logging.psm1
using module ..\Helpers.psm1

#region OneDrive
<#
	.SYNOPSIS
	OneDrive

	.PARAMETER Uninstall
	Uninstall OneDrive

	.PARAMETER Install
	Install OneDrive 64-bit depending which installer is triggered

	.PARAMETER Install -AllUsers
	Install OneDrive 64-bit for all users to %ProgramFiles% depending which installer is triggered

	.EXAMPLE
	OneDrive -Uninstall

	.EXAMPLE
	OneDrive -Install

	.EXAMPLE
	OneDrive -Install -AllUsers

	.NOTES
	The OneDrive user folder won't be removed

	.NOTES
	Machine-wide
#>
function OneDrive
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Uninstall"
		)]
		[switch]
		$Uninstall,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Install"
		)]
		[switch]
		$Install,

		[switch]
		$AllUsers
	)

	function Get-OneDriveSetupPath
	{
		$preferredPaths = @()

		if ([Environment]::Is64BitOperatingSystem)
		{
			$preferredPaths += Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'
			$preferredPaths += Join-Path $env:SystemRoot 'Sysnative\OneDriveSetup.exe'

			if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles))
			{
				$preferredPaths += Join-Path $env:ProgramFiles 'Microsoft OneDrive\OneDriveSetup.exe'
			}

			if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)}))
			{
				$preferredPaths += Join-Path ${env:ProgramFiles(x86)} 'Microsoft OneDrive\OneDriveSetup.exe'
				$preferredPaths += Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe'
			}
		}
		else
		{
			$preferredPaths += Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'
		}

		$preferredPaths | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
	}

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Uninstall"
		{
			Write-ConsoleStatus -Action "Uninstalling One Drive"
			LogInfo "Uninstalling One Drive"
			try
			{
				$resolvedOneDriveSetup = Get-OneDriveSetupPath

				# Ensure UninstallString exists
				[string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore |
   				ForEach-Object { $_.Meta.Attributes["UninstallString"] }

				if (-not $UninstallString) {
    				LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
					Write-ConsoleStatus -Status success
   				 	return
				}

				# Check user login
				$UserEmail = Get-ItemProperty -Path HKCU:\Software\Microsoft\OneDrive\Accounts\Personal -Name UserEmail -ErrorAction Ignore
				if ($UserEmail) {
    				LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
    				return
				}

				# Kill OneDrive processes safely
				Stop-Process -Name OneDrive, OneDriveSetup, FileCoAuth -Force -ErrorAction SilentlyContinue | Out-Null

		        # Prefer a locally resolved setup executable so ARM64 does not inherit an incompatible uninstall path.
				if ($resolvedOneDriveSetup)
				{
		            $OneDriveUninstallProcess = Start-Process -FilePath $resolvedOneDriveSetup -ArgumentList '/uninstall' -Wait -PassThru -ErrorAction Stop
					if ($OneDriveUninstallProcess.ExitCode -ne 0) { throw "OneDrive uninstaller returned exit code $($OneDriveUninstallProcess.ExitCode)" }
		        }
				else
				{
		        	[string[]]$OneDriveSetup = ($UninstallString -replace("\s*/", ",/")).Split(",") | ForEach-Object { $_.Trim(' ', '"') }
		        	$Arguments = if ($OneDriveSetup.Count -gt 1) { $OneDriveSetup[1..($OneDriveSetup.Count-1)] } else { @('/uninstall') }

		        	if ($OneDriveSetup -and $OneDriveSetup[0]) {
		            	$OneDriveUninstallProcess = Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $Arguments -Wait -PassThru -ErrorAction Stop
						if ($OneDriveUninstallProcess.ExitCode -ne 0) { throw "OneDrive uninstaller returned exit code $($OneDriveUninstallProcess.ExitCode)" }
		        	}
				}

				# Safely remove OneDrive user folder if exists
				if ($env:OneDrive -and (Test-Path -Path $env:OneDrive)) {
	  	    		if ((Get-ChildItem -Path $env:OneDrive -ErrorAction Ignore | Measure-Object).Count -eq 0) {
	        			Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
	    			} else {
	           			Start-Process -FilePath explorer -ArgumentList $env:OneDrive -ErrorAction SilentlyContinue | Out-Null
	    			}
				}

				# Clean registry and leftover paths safely
				$PathsToRemove = @(
	    			"HKCU:\Software\Microsoft\OneDrive",
	    			"$env:ProgramData\Microsoft OneDrive",
	    			"$env:SystemDrive\OneDriveTemp"
				)
				Remove-Item -Path $PathsToRemove -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
				Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction SilentlyContinue | Out-Null
				Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to uninstall OneDrive: $($_.Exception.Message)"
			}
		}
		"Install"
		{
			Write-ConsoleStatus -Action "Installing One Drive"
			LogInfo "Installing One Drive"
			try
			{
				$resolvedOneDriveSetup = Get-OneDriveSetupPath
				$OneDrive = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -Force -ErrorAction Ignore
				if ($OneDrive)
				{
					LogInfo ($Localization.Skipped -f $MyInvocation.Line.Trim())
				}

				if ($resolvedOneDriveSetup)
				{
					LogInfo $Localization.OneDriveInstalling

					if ($AllUsers)
					{
						# Install OneDrive for all users
						$OneDriveInstallProcess = Start-Process -FilePath $resolvedOneDriveSetup -ArgumentList "/allusers" -Wait -PassThru -ErrorAction Stop
						if ($OneDriveInstallProcess.ExitCode -ne 0) { throw "OneDriveSetup.exe returned exit code $($OneDriveInstallProcess.ExitCode)" }
					}
					else
					{
						$OneDriveInstallProcess = Start-Process -FilePath $resolvedOneDriveSetup -Wait -PassThru -ErrorAction Stop
						if ($OneDriveInstallProcess.ExitCode -ne 0) { throw "OneDriveSetup.exe returned exit code $($OneDriveInstallProcess.ExitCode)" }
					}
				}
				else
				{
					try
					{
		       			# Direct download URL for OneDrive
        				$OneDriveURL = "https://go.microsoft.com/fwlink/?linkid=844652"

        				$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}" -ErrorAction SilentlyContinue
        				if (-not $DownloadsFolder) {
           	 				$DownloadsFolder = "$env:USERPROFILE\Downloads"
        				}

        				$Parameters = @{
            				Uri             = $OneDriveURL
            				OutFile         = "$DownloadsFolder\OneDriveSetup.exe"
       	 				}
        				Invoke-WebRequest @Parameters -ErrorAction Stop

						if ($AllUsers)
						{
							& "$DownloadsFolder\OneDriveSetup.exe" /allusers 2>$null | Out-Null
							if ($LASTEXITCODE -ne 0) { throw "Downloaded OneDriveSetup.exe returned exit code $LASTEXITCODE" }
						}
						else
						{
							$DownloadedOneDriveProcess = Start-Process -FilePath "$DownloadsFolder\OneDriveSetup.exe" -Wait -PassThru -ErrorAction Stop
							if ($DownloadedOneDriveProcess.ExitCode -ne 0) { throw "Downloaded OneDriveSetup.exe returned exit code $($DownloadedOneDriveProcess.ExitCode)" }
						}

						Start-Sleep -Seconds 3

						Get-Process -Name OneDriveSetup -ErrorAction SilentlyContinue | Stop-Process -Force
						Remove-Item -Path "$DownloadsFolder\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue | Out-Null
					}
					catch [System.Net.WebException]
					{
						LogError (($Localization.NoResponse -f "https://oneclient.sfx.ms"), ($Localization.RestartFunction -f $MyInvocation.Line.Trim()) -join " ")

						return
					}
				}

				# Save screenshots in the Pictures folder when pressing Windows+PrtScr or using Windows+Shift+S
				Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}" -Force -ErrorAction SilentlyContinue | Out-Null

				Get-ScheduledTask -TaskName "Onedrive* Update*" | Enable-ScheduledTask
				Get-ScheduledTask -TaskName "Onedrive* Update*" | Start-ScheduledTask
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to install OneDrive: $($_.Exception.Message)"
			}
		}
	}
}
#endregion OneDrive
