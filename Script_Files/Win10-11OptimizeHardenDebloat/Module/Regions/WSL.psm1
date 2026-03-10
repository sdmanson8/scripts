using module ..\Logging.psm1
using module ..\Helpers.psm1

#region WSL
<#
	.SYNOPSIS
	Windows Subsystem for Linux (WSL)

	.PARAMETER
	Enable Windows Subsystem for Linux (WSL), install the latest WSL Linux kernel version, and a Linux distribution using a pop-up form

	.EXAMPLE
	Install-WSL

	.NOTES
	The "Receive updates for other Microsoft products" setting will be enabled automatically to receive kernel updates

	.NOTES
	Machine-wide
#>
function Install-WSL
{
	try
	{
		# https://github.com/microsoft/WSL/blob/master/distributions/DistributionInfo.json
		# wsl --list --online relies on Internet connection too, so it's much convenient to parse DistributionInfo.json, rather than parse a cmd output
		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json"
			UseBasicParsing = $true
			#Verbose         = $true
		}
		$Distributions = (Invoke-RestMethod @Parameters).Distributions | ForEach-Object -Process {
			[PSCustomObject]@{
				"Distribution" = $_.FriendlyName
				"Alias"        = $_.Name
			}
		}
	}
	catch [System.Net.WebException]
	{
		LogError ($Localization.NoResponse -f "https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json")
		LogError ($Localization.RestartFunction -f $MyInvocation.Line.Trim())

		return
	}

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	$CommandTag = $null

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = @"
<Window
	xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
	Name="Window"
	Title="WSL"
	MinHeight="460" MinWidth="350"
	SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
	TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
	FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
	Background="#F1F1F1" Foreground="#262626">
	<Window.Resources>
		<Style TargetType="RadioButton">
			<Setter Property="VerticalAlignment" Value="Center"/>
			<Setter Property="Margin" Value="10"/>
		</Style>
		<Style TargetType="TextBlock">
			<Setter Property="VerticalAlignment" Value="Center"/>
			<Setter Property="Margin" Value="0, 0, 0, 2"/>
		</Style>
		<Style TargetType="Button">
			<Setter Property="Margin" Value="20"/>
			<Setter Property="Padding" Value="10"/>
			<Setter Property="IsEnabled" Value="False"/>
		</Style>
	</Window.Resources>
	<Grid>
		<Grid.RowDefinitions>
			<RowDefinition Height="*"/>
			<RowDefinition Height="Auto"/>
		</Grid.RowDefinitions>
		<StackPanel Name="PanelContainer" Grid.Row="0"/>
		<Button Name="ButtonInstall" Content="Install" Grid.Row="2"/>
	</Grid>
</Window>
"@
	#endregion XAML Markup

	$Form = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML))
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	$ButtonInstall.Content = $Localization.Install
	#endregion Variables

	#region Functions
	function RadioButtonChecked
	{
		$Script:CommandTag = $_.OriginalSource.Tag
		if (-not $ButtonInstall.IsEnabled)
		{
			$ButtonInstall.IsEnabled = $true
		}
	}

	function ButtonInstallClicked
	{
		try
		{
			Write-ConsoleStatus -Action "Installing $Script:CommandTag distribution"
			LogInfo "Installing $Script:CommandTag distribution"
			$WSLProcess = Start-Process -FilePath wsl.exe -ArgumentList "--install --distribution $Script:CommandTag" -Wait -PassThru -ErrorAction Stop
			if ($WSLProcess.ExitCode -ne 0) { throw "wsl.exe returned exit code $($WSLProcess.ExitCode)" }

			$Form.Close()

			# Receive updates for other Microsoft products when you update Windows
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name AllowMUUpdateService -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null

			# Check for updates
			Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList StartInteractiveScan -WindowStyle Hidden -ErrorAction Stop | Out-Null
			Write-ConsoleStatus -Status success
		}
		catch
		{
			Write-ConsoleStatus -Status failed
			LogError "Failed to install the $Script:CommandTag WSL distribution: $($_.Exception.Message)"
		}
	}
	#endregion

	foreach ($Distribution in $Distributions)
	{
		$Panel = New-Object -TypeName System.Windows.Controls.StackPanel
		$RadioButton = New-Object -TypeName System.Windows.Controls.RadioButton
		$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
		$Panel.Orientation = "Horizontal"
		$RadioButton.GroupName = "WslDistribution"
		$RadioButton.Tag = $Distribution.Alias
		$RadioButton.Add_Checked({RadioButtonChecked})
		$TextBlock.Text = $Distribution.Distribution
		$Panel.Children.Add($RadioButton) | Out-Null
		$Panel.Children.Add($TextBlock) | Out-Null
		$PanelContainer.Children.Add($Panel) | Out-Null
	}

	$ButtonInstall.Add_Click({ButtonInstallClicked})

	#region Sendkey function
	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	# We cannot use Get-Process -Id $PID as script might be invoked via Terminal with different $PID
	Get-Process -Name powershell, WindowsTerminal -ErrorAction Ignore | Where-Object -FilterScript {$_.MainWindowTitle -match "WinUtil Script for Windows 10/11"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Seconds 1

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Seconds 1

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}
	#endregion Sendkey function

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
}
#endregion WSL
