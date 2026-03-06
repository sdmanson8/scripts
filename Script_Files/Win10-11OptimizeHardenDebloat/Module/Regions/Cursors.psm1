using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Cursors
<#
	.SYNOPSIS
	Free "Windows 11 Cursors Concept" cursors from Jepri Creations

	.PARAMETER Dark
	Download and install free dark "Windows 11 Cursors Concept" cursors from Jepri Creations

	.PARAMETER Light
	Download and install free light "Windows 11 Cursors Concept" cursors from Jepri Creations

	.PARAMETER Default
	Set default cursors

	.EXAMPLE
	Install-Cursors -Dark

	.EXAMPLE
	Install-Cursors -Light

	.EXAMPLE
	Install-Cursors -Default

	.LINK
	https://www.deviantart.com/jepricreations/art/Windows-11-Cursors-Concept-886489356

	.NOTES
	The 14/12/24 version

	.NOTES
	Current user
#>
function Install-Cursors
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Dark"
		)]
		[switch]
		$Dark,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Light"
		)]
		[switch]
		$Light,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	if (-not $Default)
	{
		$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"

		try
		{
			# Download cursors
			# The archive was saved in the "Cursors" folder using DeviantArt API via GitHub CI/CD
			# https://github.com/farag2/Sophia-Script-for-Windows/tree/master/Cursors
			# https://github.com/farag2/Sophia-Script-for-Windows/blob/master/.github/workflows/Cursors.yml
			$Parameters = @{
				Uri             = "https://raw.githubusercontent.com/farag2/Sophia-Script-for-Windows/refs/heads/master/Cursors/Windows11Cursors.zip"
				OutFile         = "$DownloadsFolder\Windows11Cursors.zip"
				UseBasicParsing = $true
				#Verbose         = $true
			}
			Invoke-WebRequest @Parameters
		}
		catch [System.Net.WebException]
		{
			LogError (($Localization.NoResponse -f "https://raw.githubusercontent.com"), ($Localization.RestartFunction -f $MyInvocation.Line.Trim()) -join " ")

			return
		}
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Dark"
		{
			Write-Host "Installing 'Windows 11 Cursors Concept' dark cursors - " -NoNewline
			LogInfo "Installing 'Windows 11 Cursors Concept' dark cursors"
			if (-not (Test-Path -Path "$env:SystemRoot\Cursors\W11 Cursor Dark Free"))
			{
				New-Item -Path "$env:SystemRoot\Cursors\W11 Cursor Dark Free" -ItemType Directory -Force | Out-Null
			}

			# Extract archive from "dark" folder only
			& "$env:SystemRoot\System32\tar.exe" -xf "$DownloadsFolder\Windows11Cursors.zip" -C "$env:SystemRoot\Cursors\W11 Cursor Dark Free" --strip-components=1 dark/ | Out-Null

			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "(default)" -PropertyType String -Value "W11 Cursor Dark Free by Jepri Creations" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name AppStarting -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\appstarting.ani" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Arrow -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\arrow.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Crosshair -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\crosshair.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Hand -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\hand.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Help -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\help.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name IBeam -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\ibeam.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name No -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\no.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name NWPen -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\nwpen.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Person -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\person.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Pin -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\pin.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Scheme Source" -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeAll -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\sizeall.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNESW -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\sizenesw.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNS -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\sizens.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNWSE -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\sizenwse.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeWE -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\sizewe.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name UpArrow -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\uparrow.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Wait -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Dark Free\wait.ani" -Force | Out-Null

			if (-not (Test-Path -Path "HKCU:\Control Panel\Cursors\Schemes"))
			{
				New-Item -Path "HKCU:\Control Panel\Cursors\Schemes" -Force | Out-Null
			}
			[string[]]$Schemes = (
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\arrow.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\help.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\appstarting.ani",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\wait.ani",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\crosshair.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\ibeam.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\nwpen.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\no.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\sizens.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\sizewe.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\sizenwse.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\sizenesw.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\sizeall.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\uparrow.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\hand.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\person.cur",
				"%SystemRoot%\Cursors\W11 Cursor Dark Free\pin.cur"
			) -join ","
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors\Schemes" -Name "W11 Cursor Dark Free by Jepri Creations" -PropertyType String -Value $Schemes -Force | Out-Null

			Start-Sleep -Seconds 1

			Remove-Item -Path "$DownloadsFolder\Windows11Cursors.zip", "$env:SystemRoot\Cursors\W11 Cursor Dark Free\Install.inf" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Light"
		{
			Write-Host "Installing 'Windows 11 Cursors Concept' light cursors - " -NoNewline
			LogInfo "Installing 'Windows 11 Cursors Concept' light cursors"
			if (-not (Test-Path -Path "$env:SystemRoot\Cursors\W11 Cursor Light Free"))
			{
				New-Item -Path "$env:SystemRoot\Cursors\W11 Cursor Light Free" -ItemType Directory -Force | Out-Null
			}

			# Extract archive from "light" folder only
			& "$env:SystemRoot\System32\tar.exe" -xf "$DownloadsFolder\Windows11Cursors.zip" -C "$env:SystemRoot\Cursors\W11 Cursor Light Free" --strip-components=1 light/ | Out-Null

			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "(default)" -PropertyType String -Value "W11 Cursor Light Free by Jepri Creations" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name AppStarting -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\appstarting.ani" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Arrow -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\arrow.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Crosshair -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\crosshair.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Hand -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\hand.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Help -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\help.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name IBeam -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\ibeam.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name No -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\no.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name NWPen -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\nwpen.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Person -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\person.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Pin -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\pin.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Scheme Source" -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeAll -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\sizeall.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNESW -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\sizenesw.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNS -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\sizens.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNWSE -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\sizenwse.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeWE -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\sizewe.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name UpArrow -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\uparrow.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Wait -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11 Cursor Light Free\wait.ani" -Force | Out-Null

			if (-not (Test-Path -Path "HKCU:\Control Panel\Cursors\Schemes"))
			{
				New-Item -Path "HKCU:\Control Panel\Cursors\Schemes" -Force | Out-Null
			}
			[string[]]$Schemes = (
				"%SystemRoot%\Cursors\W11 Cursor Light Free\arrow.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\help.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\appstarting.ani",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\wait.ani",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\crosshair.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\ibeam.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\nwpen.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\no.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\sizens.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\sizewe.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\sizenwse.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\sizenesw.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\sizeall.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\uparrow.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\hand.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\person.cur",
				"%SystemRoot%\Cursors\W11 Cursor Light Free\pin.cur"
			) -join ","
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors\Schemes" -Name "W11 Cursor Light Free by Jepri Creations" -PropertyType String -Value $Schemes -Force | Out-Null

			Start-Sleep -Seconds 1

			Remove-Item -Path "$DownloadsFolder\Windows11Cursors.zip", "$env:SystemRoot\Cursors\W11 Cursor Light Free\Install.inf" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Default"
		{
			Write-Host "Setting default cursors - " -NoNewline
			LogInfo "Setting default cursors"
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "(default)" -PropertyType String -Value "" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name AppStarting -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_working.ani" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Arrow -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_arrow.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Crosshair -PropertyType ExpandString -Value "" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Hand -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_link.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Help -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_helpsel.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name IBeam -PropertyType ExpandString -Value "" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name No -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_unavail.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name NWPen -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_pen.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Person -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_person.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Pin -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_pin.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Scheme Source" -PropertyType DWord -Value 2 -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeAll -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_move.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNESW -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_nesw.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNS -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_ns.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNWSE -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_nwse.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeWE -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_ew.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name UpArrow -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_up.cur" -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Wait -PropertyType ExpandString -Value "%SystemRoot%\cursors\aero_up.cur" -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}

	# Reload cursor on-the-fly
	$Signature = @{
		Namespace          = "WinAPI"
		Name               = "Cursor"
		Language           = "CSharp"
		CompilerParameters = $CompilerParameters
		MemberDefinition   = @"
[DllImport("user32.dll", EntryPoint = "SystemParametersInfo")]
public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, uint pvParam, uint fWinIni);
"@
	}
	if (-not ("WinAPI.Cursor" -as [type]))
	{
		Add-Type @Signature
	}
	[void][WinAPI.Cursor]::SystemParametersInfo(0x0057, 0, $null, 0)
}
#endregion Cursors
