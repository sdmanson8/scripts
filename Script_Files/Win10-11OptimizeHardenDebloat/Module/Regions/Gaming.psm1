using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Gaming
<#
	.SYNOPSIS
	Xbox Game Bar

	.PARAMETER Disable
	Disable Xbox Game Bar

	.PARAMETER Enable
	Enable Xbox Game Bar (default value)

	.EXAMPLE
	XboxGameBar -Disable

	.EXAMPLE
	XboxGameBar -Enable

	.NOTES
	To prevent popping up the "You'll need a new app to open this ms-gamingoverlay" warning, you need to disable the Xbox Game Bar app, even if you uninstalled it before

	.NOTES
	Current user
#>
function XboxGameBar
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			try
			{
				$GameDvrPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
				$GameConfigStorePath = "HKCU:\System\GameConfigStore"
				Write-ConsoleStatus -Action "Disabling Xbox Game Bar"
				LogInfo "Disabling Xbox Game Bar"
				if (-not (Test-Path -Path $GameDvrPath))
				{
					New-Item -Path $GameDvrPath -Force -ErrorAction Stop | Out-Null
				}
				if (-not (Test-Path -Path $GameConfigStorePath))
				{
					New-Item -Path $GameConfigStorePath -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path $GameDvrPath -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path $GameConfigStorePath -Name GameDVR_Enabled -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Xbox Game Bar: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			try
			{
				$GameDvrPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
				$GameConfigStorePath = "HKCU:\System\GameConfigStore"
				Write-ConsoleStatus -Action "Enabling Xbox Game Bar"
				LogInfo "Enabling Xbox Game Bar"
				if (-not (Test-Path -Path $GameDvrPath))
				{
					New-Item -Path $GameDvrPath -Force -ErrorAction Stop | Out-Null
				}
				if (-not (Test-Path -Path $GameConfigStorePath))
				{
					New-Item -Path $GameConfigStorePath -Force -ErrorAction Stop | Out-Null
				}
				New-ItemProperty -Path $GameDvrPath -Name AppCaptureEnabled -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				New-ItemProperty -Path $GameConfigStorePath -Name GameDVR_Enabled -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Xbox Game Bar: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Xbox Game Bar tips

	.PARAMETER Disable
	Disable Xbox Game Bar tips

	.PARAMETER Enable
	Enable Xbox Game Bar tips

	.EXAMPLE
	XboxGameTips -Disable

	.EXAMPLE
	XboxGameTips -Enable

	.NOTES
	Current user
#>
function XboxGameTips
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	if (-not (Get-AppxPackage -Name Microsoft.GamingApp))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			try
			{
				Write-ConsoleStatus -Action "Disabling Xbox Game Bar tips"
				LogInfo "Disabling Xbox Game Bar tips"
				New-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable Xbox Game Bar tips: $($_.Exception.Message)"
			}
		}
		"Enable"
		{
			try
			{
				Write-ConsoleStatus -Action "Enabling Xbox Game Bar tips"
				LogInfo "Enabling Xbox Game Bar tips"
				New-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to enable Xbox Game Bar tips: $($_.Exception.Message)"
			}
		}
	}
}

<#
	.SYNOPSIS
	Choose an app and set the "High performance" graphics performance for it

	.EXAMPLE
	Set-AppGraphicsPerformance

	.NOTES
	Works only with a dedicated GPU

	.NOTES
	Current user
#>
function Set-AppGraphicsPerformance
{
	if (Get-CimInstance -ClassName Win32_VideoController | Where-Object -FilterScript {($_.AdapterDACType -ne "Internal") -and ($null -ne $_.AdapterDACType)})
	{
		Write-ConsoleStatus -Action "Selecting an app to set the 'High performance' graphics performance"
		LogInfo "Selecting an app to set the 'High performance' graphics performance"
		do
		{
			$Choice = Show-Menu -Menu $Browse -Default 1 -AddSkip

			switch ($Choice)
			{
				$Browse
				{
					Add-Type -AssemblyName System.Windows.Forms
					$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
					$OpenFileDialog.Filter = "*.exe|*.exe|{0} (*.*)|*.*" -f $Localization.AllFilesFilter
					$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
					$OpenFileDialog.Multiselect = $false

					# Force move the open file dialog to the foreground
					$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
					$OpenFileDialog.ShowDialog($Focus)

					if ($OpenFileDialog.FileName)
					{
						if (-not (Test-Path -Path HKCU:\Software\Microsoft\DirectX\UserGpuPreferences))
						{
							New-Item -Path HKCU:\Software\Microsoft\DirectX\UserGpuPreferences -Force | Out-Null
						}
						New-ItemProperty -Path HKCU:\Software\Microsoft\DirectX\UserGpuPreferences -Name $OpenFileDialog.FileName -PropertyType String -Value "GpuPreference=2;" -Force | Out-Null
					}
				}
				$Skip
				{
					LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
				}
				$KeyboardArrows {}
			}
		}
		until ($Choice -ne $KeyboardArrows)
		Write-ConsoleStatus -Status success
	}
}

<#
	.SYNOPSIS
	Hardware-accelerated GPU scheduling

	.PARAMETER Enable
	Enable hardware-accelerated GPU scheduling

	.PARAMETER Disable
	Disable hardware-accelerated GPU scheduling (default value)

	.EXAMPLE
	GPUScheduling -Enable

	.EXAMPLE
	GPUScheduling -Disable

	.NOTES
	Only with a dedicated GPU and WDDM verion is 2.7 or higher. Restart needed

	.NOTES
	Current user
#>
function GPUScheduling
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling hardware-accelerated GPU scheduling"
			LogInfo "Enabling hardware-accelerated GPU scheduling"
			# Determining whether PC has an external graphics card
			$AdapterDACType = Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript {($_.AdapterDACType -ne "Internal") -and ($null -ne $_.AdapterDACType)}
			# Determining whether an OS is not installed on a virtual machine
			$ComputerSystemModel = (Get-CimInstance -ClassName CIM_ComputerSystem).Model -notmatch "Virtual"
			# Checking whether a WDDM verion is 2.7 or higher
			$WddmVersion_Min = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\FeatureSetUsage", "WddmVersion_Min", $null)

			if ($AdapterDACType -and ($ComputerSystemModel -notmatch "Virtual") -and ($WddmVersion_Min -ge 2700))
			{
				try
				{
					New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers -Name HwSchMode -PropertyType DWord -Value 2 -Force -ErrorAction Stop | Out-Null
					Write-ConsoleStatus -Status success
				}
				catch
				{
					Write-ConsoleStatus -Status failed
					LogError "Failed to enable hardware-accelerated GPU scheduling: $($_.Exception.Message)"
				}
			}
			else
			{
				Write-ConsoleStatus -Status success
				LogWarning "Hardware-accelerated GPU scheduling is not supported on this system. Skipping."
			}
		}
		"Disable"
		{
			try
			{
				Write-ConsoleStatus -Action "Disabling hardware-accelerated GPU scheduling"
				LogInfo "Disabling hardware-accelerated GPU scheduling"
				New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers -Name HwSchMode -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
				Write-ConsoleStatus -Status success
			}
			catch
			{
				Write-ConsoleStatus -Status failed
				LogError "Failed to disable hardware-accelerated GPU scheduling: $($_.Exception.Message)"
			}
		}
	}
}
#endregion Gaming
