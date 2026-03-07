using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Privacy & Telemetry
<#
	.SYNOPSIS
	The Connected User Experiences and Telemetry (DiagTrack) service

	.PARAMETER Disable
	Disable the Connected User Experiences and Telemetry (DiagTrack) service, and block connection for the Unified Telemetry Client Outbound Traffic

	.PARAMETER Enable
	Enable the Connected User Experiences and Telemetry (DiagTrack) service, and allow connection for the Unified Telemetry Client Outbound Traffic (default value)

	.EXAMPLE
	DiagTrackService -Disable

	.EXAMPLE
	DiagTrackService -Enable

	.NOTES
	Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore and affects Feedback Hub

	.NOTES
	Current user
#>
function DiagTrackService
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

	# Checking whether "InitialActions" function was removed in preset file
	if (-not ("WinAPI.GetStrings" -as [type]))
	{
		# Get the name of a preset (e.g Win10_11Util.ps1) regardless if it was renamed
		# $_.File has no EndsWith() method
		$PresetName = Split-Path -Path (((Get-PSCallStack).Position | Where-Object -FilterScript {$_.File}).File | Where-Object -FilterScript {$_.EndsWith(".ps1")}) -Leaf

		LogError ($Localization.InitialActionsCheckFailed -f $PresetName)
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			# Connected User Experiences and Telemetry
			# Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore and affects Feedback Hub
			LogInfo 'Disabling the "Connected User Experiences and Telemetry" service'
			Get-Service -Name DiagTrack -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue | Out-Null
			Get-Service -Name DiagTrack | Set-Service -StartupType Disabled | Out-Null

			# Block connection for the Unified Telemetry Client Outbound Traffic
			Get-NetFirewallRule -Group DiagTrack | Set-NetFirewallRule -Enabled True -Action Block | Out-Null
		}
		"Enable"
		{
			# Connected User Experiences and Telemetry
			LogInfo 'Enabling the "Connected User Experiences and Telemetry" service'
			Get-Service -Name DiagTrack | Set-Service -StartupType Automatic | Out-Null
			Get-Service -Name DiagTrack | Start-Service | Out-Null

			# Allow connection for the Unified Telemetry Client Outbound Traffic
			Get-NetFirewallRule -Group DiagTrack | Set-NetFirewallRule -Enabled True -Action Allow | Out-Null
		}
	}
}

<#
	.SYNOPSIS
	Diagnostic data

	.PARAMETER Minimal
	Set the diagnostic data collection to minimum

	.PARAMETER Default
	Set the diagnostic data collection to default (default value)

	.EXAMPLE
	DiagnosticDataLevel -Minimal

	.EXAMPLE
	DiagnosticDataLevel -Default

	.NOTES
	Machine-wide
#>
function DiagnosticDataLevel
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Minimal"
		)]
		[switch]
		$Minimal,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Default"
		)]
		[switch]
		$Default
	)

	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection))
	{
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Force | Out-Null
	}

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Force | Out-Null
	}

    # Get Windows edition
    $WindowsEdition = (Get-WmiObject -Class Win32_OperatingSystem).Caption

    switch ($PSCmdlet.ParameterSetName) {
        "Minimal" {
			Write-Host "Set Diagnostic Data Collection to Minimal - " -NoNewline
			LogInfo "Setting Diagnostic Data Collection to Minimal"
            if ($WindowsEdition -match "Enterprise" -or $WindowsEdition -match "Education") {
                # Diagnostic data off
                New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force | Out-Null
            } else {
                # Send required diagnostic data
                New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 1 -Force | Out-Null
            }

            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name MaxTelemetryAllowed -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Name ShowedToastAtLevel -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
        "Default" {
            # Optional diagnostic data
			Write-Host "Set Diagnostic Data Collection to Default - " -NoNewline
			LogInfo "Setting Diagnostic Data Collection to Default"
            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name MaxTelemetryAllowed -PropertyType DWord -Value 3 -Force | Out-Null
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Name ShowedToastAtLevel -PropertyType DWord -Value 3 -Force | Out-Null
            Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
    }
}

<#
	.SYNOPSIS
	Windows Error Reporting

	.PARAMETER Disable
	Turn off Windows Error Reporting

	.PARAMETER Enable
	Turn on Windows Error Reporting (default value)

	.EXAMPLE
	ErrorReporting -Disable

	.EXAMPLE
	ErrorReporting -Enable

	.NOTES
	Current user
#>
function ErrorReporting
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "HKCU:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Type CLEAR | Out-Null
	Set-Policy -Scope User -Path "Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disable Windows Error Reporting - " -NoNewline
			LogInfo "Disabling Windows Error Reporting"
			Get-ScheduledTask -TaskName QueueReporting -ErrorAction Ignore | Disable-ScheduledTask | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force | Out-Null
			Get-Service -Name WerSvc | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			Get-Service -Name WerSvc | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enable Windows Error Reporting - " -NoNewline
			LogInfo "Enabling Windows Error Reporting"
			Get-ScheduledTask -TaskName QueueReporting -ErrorAction Ignore | Enable-ScheduledTask | Out-Null
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Force -ErrorAction Ignore | Out-Null
			Get-Service -Name WerSvc | Set-Service -StartupType Manual -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			Get-Service -Name WerSvc | Start-Service -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The feedback frequency

	.PARAMETER Never
	Change the feedback frequency to "Never"

	.PARAMETER Automatically
	Change feedback frequency to "Automatically" (default value)

	.EXAMPLE
	FeedbackFrequency -Never

	.EXAMPLE
	FeedbackFrequency -Automatically

	.NOTES
	Current user
#>
function FeedbackFrequency
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Never"
		)]
		[switch]
		$Never,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Automatically"
		)]
		[switch]
		$Automatically
	)

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name DoNotShowFeedbackNotifications -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name DoNotShowFeedbackNotifications -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Never"
		{
			Write-Host "Set Feedback Frequency to Never - " -NoNewline
			LogInfo "Setting Feedback Frequency to Never"
			if (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
			{
				New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force | Out-Null
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force | Out-Null
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name PeriodInNanoSeconds -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Automatically"
		{
			Write-Host "Set Feedback Frequency to Automatic - " -NoNewline
			LogInfo "Setting Feedback Frequency to Automatic"
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name PeriodInNanoSeconds, NumberOfSIUFInPeriod -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The diagnostics tracking scheduled tasks

	.PARAMETER Disable
	Turn off the diagnostics tracking scheduled tasks

	.PARAMETER Enable
	Turn on the diagnostics tracking scheduled tasks (default value)

	.EXAMPLE
	ScheduledTasks -Disable

	.EXAMPLE
	ScheduledTasks -Enable

	.NOTES
	A pop-up dialog box lets a user select tasks

	.NOTES
	Current user
#>
function ScheduledTasks
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

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# Initialize an array list to store the selected scheduled tasks
	$SelectedTasks = New-Object -TypeName System.Collections.ArrayList($null)

	# The following tasks will have their checkboxes checked
	[string[]]$CheckedScheduledTasks = @(
		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
		"MareBackup",

		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
		"Microsoft Compatibility Appraiser",

		# Updates compatibility database
		"StartupAppTask",

		# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
		"Proxy",

		# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
		"Consolidator",

		# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft
		"UsbCeip",

		# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
		"Microsoft-Windows-DiskDiagnosticDataCollector",

		# This task shows various Map related toasts
		"MapsToastTask",

		# This task checks for updates to maps which you have downloaded for offline use
		"MapsUpdateTask",

		# Initializes Family Safety monitoring and enforcement
		"FamilySafetyMonitor",

		# Synchronizes the latest settings with the Microsoft family features service
		"FamilySafetyRefreshTask",

		# XblGameSave Standby Task
		"XblGameSaveTask"
	)
	#endregion Variables

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = @"
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
"@
	#endregion XAML Markup

	$Form = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML))
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions
	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Task = $Tasks | Where-Object -FilterScript {$_.TaskName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedTasks.Add($Task)
		}
		else
		{
			[void]$SelectedTasks.Remove($Task)
		}

		if ($SelectedTasks.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function DisableButton
	{
		[void]$Window.Close()

		#$SelectedTasks | ForEach-Object -Process {Write-Verbose -Message $_.TaskName -Verbose}
		$SelectedTasks | Disable-ScheduledTask
	}

	function EnableButton
	{
		[void]$Window.Close()

		$SelectedTasks | Enable-ScheduledTask
	}

	function Add-TaskControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Task
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Task.TaskName

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			# If task checked add to the array list
			if ($CheckedScheduledTasks | Where-Object -FilterScript {$Task.TaskName -match $_})
			{
				[void]$SelectedTasks.Add($Task)
			}
			else
			{
				$CheckBox.IsChecked = $false
			}
		}
	}
	#endregion Functions

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enable Diagnostics Tracking Scheduled Tasks - " -NoNewline
			LogInfo "Enabling Diagnostics Tracking Scheduled Tasks"
			$State           = "Disabled"
			# Extract the localized "Enable" string from shell32.dll
			$ButtonContent   = [WinAPI.GetStrings]::GetString(51472)
			$ButtonAdd_Click = {EnableButton}
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disable Diagnostics Tracking Scheduled Tasks - " -NoNewline
			LogInfo "Disabling Diagnostics Tracking Scheduled Tasks"
			$State           = "Ready"
			$ButtonContent   = $Localization.Disable
			$ButtonAdd_Click = {DisableButton}
			Write-Host "success!" -ForegroundColor Green
		}
	}

	# Getting list of all scheduled tasks according to the conditions
	$Tasks = Get-ScheduledTask | Where-Object -FilterScript {($_.State -eq $State) -and ($_.TaskName -in $CheckedScheduledTasks)}

	if (-not $Tasks)
	{
		return
	}

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

	$Window.Add_Loaded({$Tasks | Add-TaskControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = $Localization.ScheduledTasks

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null

}

<#
    .SYNOPSIS
    Manage the offering of Malicious Software Removal Tool through Windows Update settings

    .PARAMETER Enable
    Enable the offering of Malicious Software Removal Tool through Windows Update (default value)

    .PARAMETER Disable
    Disable the offering of Malicious Software Removal Tool through Windows Update

    .EXAMPLE
    UpdateMSRT -Enable

    .EXAMPLE
    UpdateMSRT -Disable

    .NOTES
    Current user
#>
function UpdateMSRT
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
			Write-Host "Enabling Malicious Software Removal Tool through Windows Update - " -NoNewline
			LogInfo "Enabling Offering of Malicious Software Removal Tool through Windows Update"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Malicious Software Removal Tool through Windows Update - " -NoNewline
			LogInfo "Disabling Offering of Malicious Software Removal Tool through Windows Update"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Offering of drivers through Windows Update settings

    .DESCRIPTION
    This script enables or disables the Offering of drivers through Windows Update

    IMPORTANT NOTE:
    This does not work properly if you use a driver intended for another hardware model
    For example, Intel I219-V on Windows Server works only with the I219-LM driver
    Therefore, Windows Update will repeatedly try and fail to install the I219-V driver indefinitely,
    even if you use this tweak

    .PARAMETER Enable
    Enable the Offering of drivers through Windows Update (default value)

    .PARAMETER Disable
    Disable the Offering of drivers through Windows Update

    .EXAMPLE
    UpdateDriver -Enable

    .EXAMPLE
    UpdateDriver -Disable

    .NOTES
    Current user
#>
function UpdateDriver
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
			Write-Host "Enabling Offering of drivers through Windows Update - " -NoNewline
			LogInfo "Enabling Offering of drivers through Windows Update"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Offering of drivers through Windows Update - " -NoNewline
			LogInfo "Disabling Offering of drivers through Windows Update"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Configure the setting to receive updates for other Microsoft products via Windows Update

.PARAMETER Enable
Enable receiving updates for other Microsoft products via Windows Update

.PARAMETER Disable
Disable receiving updates for other Microsoft products via Windows Update (default value)

.EXAMPLE
UpdateMSProducts -Enable

.EXAMPLE
UpdateMSProducts -Disable

.NOTES
Current user
#>
function UpdateMSProducts
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
			Write-Host "Enabling updates for other Microsoft products via Windows Update - " -NoNewline
			LogInfo "Enabling updates for other Microsoft products via Windows Update"
			(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling updates for other Microsoft products via Windows Update - " -NoNewline
			LogInfo "Disabling updates for other Microsoft products via Windows Update"
			If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
				(New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
			}
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Windows Update automatic downloads settings

    .PARAMETER Enable
    Enable Windows Update automatic downloads (default value)

    .PARAMETER Disable
    Disable Windows Update automatic downloads

    .EXAMPLE
    UpdateAutoDownload -Enable

    .EXAMPLE
    UpdateAutoDownload -Disable

    .NOTES
    Current user
#>
function UpdateAutoDownload
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
			Write-Host "Enabling Automatic Windows Updates - " -NoNewline
			LogInfo "Enabling Automatic Windows Updates"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Automatic Windows Updates - " -NoNewline
			LogInfo "Disabling Automatic Windows Updates"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Automatic restart after Windows Update installation settings

    .DESCRIPTION
    IMPORTANT: This tweak is experimental and should be used with caution
    It works by registering a dummy debugger for MusNotification.exe, which effectively blocks the restart prompt executable from running. This prevents the system from scheduling the automatic restart after a Windows Update installation, potentially avoiding unwanted restarts.

    .PARAMETER Enable
    Enable automatic restart after Windows Update installation (default value)

    .PARAMETER Disable
    Disable automatic restart after Windows Update installation

    .EXAMPLE
    UpdateRestart -Enable

    .EXAMPLE
    UpdateRestart -Disable

    .NOTES
    Current user
#>
function UpdateRestart
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
			Write-Host "Enabling Automatic restart after Windows Update - " -NoNewline
			LogInfo "Enabling Automatic restart after Windows Update"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Automatic restart after Windows Update - " -NoNewline
			LogInfo "Disabling Automatic restart after Windows Update"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -Type String -Value "cmd.exe" | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Nightly wake-up for Automatic Maintenance and Windows Updates

    .PARAMETER Enable
    Enable the nightly wake-up for automatic maintenance and Windows updates (default value)

    .PARAMETER Disable
    Disable the nightly wake-up for automatic maintenance and Windows updates

    .EXAMPLE
    MaintenanceWakeUp -Enable

    .EXAMPLE
    MaintenanceWakeUp -Disable

    .NOTES
    Current user
#>
function MaintenanceWakeUp
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
			Write-Host "Enabling Nightly wake-up for Automatic Maintenance and Windows Updates - " -NoNewline
			LogInfo "Enabling Nightly wake-up for Automatic Maintenance and Windows Updates"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Nightly wake-up for Automatic Maintenance and Windows Updates - " -NoNewline
			LogInfo "Disabling Nightly wake-up for Automatic Maintenance and Windows Updates"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Shared Experiences feature settings

    .PARAMETER Enable
    Enable the Shared Experiences feature

    .PARAMETER Disable
    Disable the Shared Experiences feature

    .EXAMPLE
    SharedExperiences -Enable

    .EXAMPLE
    SharedExperiences -Disable

    .NOTES
    Current user
#>
function SharedExperiences
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
			Write-Host "Enabling Shared Experiences - " -NoNewline
			LogInfo "Enabling Shared Experiences"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Shared Experiences - " -NoNewline
			LogInfo "Disabling Shared Experiences"
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Clipboard History feature settings

    .PARAMETER Enable
    Enable the Clipboard History feature

    .PARAMETER Disable
    Disable the Clipboard History feature (default value)

    .EXAMPLE
    ClipboardHistory -Enable

    .EXAMPLE
    ClipboardHistory -Disable

    .NOTES
    Current user
#>
function ClipboardHistory
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
			Write-Host "Enabling Clipboard History - " -NoNewline
			LogInfo "Enabling Clipboard History"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Clipboard History - " -NoNewline
			LogInfo "Disabling Clipboard History"
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
			}
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Superfetch service settings

    .PARAMETER Enable
    Enable the Superfetch service (default value)

    .PARAMETER Disable
    Disable the Superfetch service

    .EXAMPLE
    Superfetch -Enable

    .EXAMPLE
    Superfetch -Disable

    .NOTES
    Current user
#>
function Superfetch
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
			Write-Host "Enabling Superfetch service - " -NoNewline
			LogInfo "Enabling Superfetch service"
			Set-Service "SysMain" -StartupType Automatic | Out-Null
			Start-Service "SysMain" -WarningAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Superfetch service - " -NoNewline
			LogInfo "Disabling Superfetch service"
			Stop-Service "SysMain" -WarningAction SilentlyContinue | Out-Null
			Set-Service "SysMain" -StartupType Disabled | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
NTFS paths with length over 260 characters settings

.PARAMETER Enable
Enable NTFS paths with length over 260 characters

.PARAMETER Disable
Disable NTFS paths with length over 260 characters (default value)

.EXAMPLE
NTFSLongPaths -Enable

.EXAMPLE
NTFSLongPaths -Disable

.NOTES
Current user
#>
function NTFSLongPaths
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
			Write-Host "Enabling NTFS Long Paths - " -NoNewline
			LogInfo "Enabling NTFS Long Paths"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling NTFS Long Paths - " -NoNewline
			LogInfo "Disabling NTFS Long Paths"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Updating of NTFS last access timestamps settings

    .PARAMETER Enable
    Enable updating of NTFS last access timestamps (default value)

    .PARAMETER Disable
    Disable updating of NTFS last access timestamps

    .EXAMPLE
    NTFSLastAccess -Enable

    .EXAMPLE
    NTFSLastAccess -Disable

    .NOTES
    Current user
#>
function NTFSLastAccess
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
			Write-Host "Enable Updating of NTFS last access timestamps - " -NoNewline
			LogInfo "Enable Updating of NTFS last access timestamps"
			If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
				# System Managed, Last Access Updates Enabled
				fsutil behavior set DisableLastAccess 2 | Out-Null
			} Else {
				# Last Access Updates Enabled
				fsutil behavior set DisableLastAccess 0 | Out-Null
			}
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disable Updating of NTFS last access timestamps - " -NoNewline
			LogInfo "Disable Updating of NTFS last access timestamps"
			fsutil behavior set DisableLastAccess 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Sleep start menu and keyboard button feature settings

    .PARAMETER Enable
    Enable the Sleep start menu and keyboard button (default value)

    .PARAMETER Disable
    Disable the Sleep start menu and keyboard button

    .EXAMPLE
    SleepButton -Enable

    .EXAMPLE
    SleepButton -Disable

    .NOTES
    Current user
#>
function SleepButton
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
			Write-Host "Enabling Sleep start menu and keyboard button - " -NoNewline
			LogInfo "Enabling Sleep start menu and keyboard button"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 1 | Out-Null
			powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1 | Out-Null
			powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Sleep start menu and keyboard button - " -NoNewline
			LogInfo "Disabling Sleep start menu and keyboard button"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0 | Out-Null
			powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 | Out-Null
			powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Display and sleep mode timeouts

    .PARAMETER Enable
    Enable the display and sleep mode timeouts (default value)

    .PARAMETER Disable
    Disable the display and sleep mode timeouts

    .EXAMPLE
    SleepTimeout -Enable

    .EXAMPLE
    SleepTimeout -Disable

    .NOTES
    Current user
#>
function SleepTimeout
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
			Write-Host "Enabling sleep mode timeouts - " -NoNewline
			LogInfo "Enabling sleep mode timeouts"
			powercfg /X monitor-timeout-ac 10 | Out-Null
			powercfg /X monitor-timeout-dc 5 | Out-Null
			powercfg /X standby-timeout-ac 30 | Out-Null
			powercfg /X standby-timeout-dc 15 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling sleep mode timeouts - " -NoNewline
			LogInfo "Disabling sleep mode timeouts"
			powercfg /X monitor-timeout-ac 0 | Out-Null
			powercfg /X monitor-timeout-dc 0 | Out-Null
			powercfg /X standby-timeout-ac 0 | Out-Null
			powercfg /X standby-timeout-dc 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Fast Startup feature settings

    .PARAMETER Enable
    Enable the Fast Startup feature (default value)

    .PARAMETER Disable
    Disable the Fast Startup feature

    .EXAMPLE
    FastStartup -Enable

    .EXAMPLE
    FastStartup -Disable

    .NOTES
    Current user
#>
function FastStartup
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
			Write-Host "Enabling Fast Startup - " -NoNewline
			LogInfo "Enabling Fast Startup"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Fast Startup - " -NoNewline
			LogInfo "Disabling Fast Startup"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Automatic reboot on crash (BSOD) settings

    .PARAMETER Enable
    Enable automatic reboot on crash

    .PARAMETER Disable
    Disable automatic reboot on crash (default value)

    .EXAMPLE
    AutoRebootOnCrash -Enable

    .EXAMPLE
    AutoRebootOnCrash -Disable

    .NOTES
    Current user
#>
function AutoRebootOnCrash
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
			Write-Host "Enabling Automatically reboot on BSOD - " -NoNewline
			LogInfo "Enabling Automatically reboot on BSOD"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Automatically reboot on BSOD - " -NoNewline
			LogInfo "Disabling Automatically reboot on BSOD"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The sign-in info to automatically finish setting up device after an update

	.PARAMETER Disable
	Do not use sign-in info to automatically finish setting up device after an update

	.PARAMETER Enable
	Use sign-in info to automatically finish setting up device after an update (default value)

	.EXAMPLE
	SigninInfo -Disable

	.EXAMPLE
	SigninInfo -Enable

	.NOTES
	Current user
#>
function SigninInfo
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableAutomaticRestartSignOn -Force -ErrorAction Ignore
	Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableAutomaticRestartSignOn -Type CLEAR

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling sign-in info to automatically finish setting up device after an update - " -NoNewline
			LogInfo "Disabling sign-in info to automatically finish setting up device after an update"
			$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
			if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID"))
			{
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force | Out-Null
			}
			New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling sign-in info to automatically finish setting up device after an update - " -NoNewline
			LogInfo "Enabling sign-in info to automatically finish setting up device after an update"
			$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The provision to websites a locally relevant content by accessing my language list

	.PARAMETER Disable
	Do not let websites show me locally relevant content by accessing my language list

	.PARAMETER Enable
	Let websites show me locally relevant content by accessing my language list (default value)

	.EXAMPLE
	LanguageListAccess -Disable

	.EXAMPLE
	LanguageListAccess -Enable

	.NOTES
	Current user
#>
function LanguageListAccess
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
			Write-Host "Disabling websites showing locally relevant content by accessing language list - " -NoNewline
			LogInfo "Disabling websites showing locally relevant content by accessing language list"
			New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling websites to show locally relevant content by accessing language list - " -NoNewline
			LogInfo "Enabling websites to show locally relevant content by accessing language list"
			Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The permission for apps to show me personalized ads by using my advertising ID

	.PARAMETER Disable
	Do not let apps show me personalized ads by using my advertising ID

	.PARAMETER Enable
	Let apps show me personalized ads by using my advertising ID (default value)

	.EXAMPLE
	AdvertisingID -Disable

	.EXAMPLE
	AdvertisingID -Enable

	.NOTES
	Current user
#>
function AdvertisingID
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -Name DisabledByGroupPolicy -Force -ErrorAction Ignore
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name DisabledByGroupPolicy -Type CLEAR

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling apps showing personalized ads by using advertising ID - " -NoNewline
			LogInfo "Disabling apps showing personalized ads by using advertising ID"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling apps showing personalized ads by using advertising ID - " -NoNewline
			LogInfo "Enabling apps showing personalized ads by using advertising ID"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested

	.PARAMETER Hide
	Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested

	.PARAMETER Show
	Show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (default value)

	.EXAMPLE
	WindowsWelcomeExperience -Hide

	.EXAMPLE
	WindowsWelcomeExperience -Show

	.NOTES
	Current user
#>
function WindowsWelcomeExperience
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Show"
		{
			Write-Host "Enabling Windows welcome experience - " -NoNewline
			LogInfo "Enabling Windows welcome experience"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Hide"
		{
			Write-Host "Disabling Windows welcome experience - " -NoNewline
			LogInfo "Disabling Windows welcome experience"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Enable or disable the Windows Web Experience Pack (used for widgets and lock screen features)

    .PARAMETER Enable
    Install or re-register the Windows Web Experience Pack

    .PARAMETER Disable
    Uninstall the Windows Web Experience Pack

    .EXAMPLE
    LockWidgets -Enable

    .EXAMPLE
    LockWidgets -Disable

    .NOTES
    Affects the current user
#>
function LockWidgets {
    param (
        [Parameter(
            Mandatory = $true,
            ParameterSetName = "Disable"
        )]
        [switch] $Disable,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "Enable"
        )]
        [switch] $Enable
    )

    switch ($PSCmdlet.ParameterSetName) {
        "Enable" {
            Write-Host "Enabling Windows Web Experience Pack - " -NoNewline
            LogInfo "Enabling Windows Web Experience Pack"
            Get-AppxPackage -AllUsers *WebExperience* | ForEach-Object {
                Add-AppxPackage -Register "$($_.InstallLocation)\AppXManifest.xml" -DisableDevelopmentMode
            } | Out-Null
            Write-Host " success!" -ForegroundColor Green
        }

        "Disable" {
            Write-Host "Disabling Windows Web Experience Pack - " -NoNewline
            LogInfo "Disabling Windows Web Experience Pack"
            Get-AppxPackage *WebExperience* | Remove-AppxPackage | Out-Null
            Write-Host " success!" -ForegroundColor Green
        }
    }
}

<#
	.SYNOPSIS
	Getting tip and suggestions when I use Windows

	.PARAMETER Enable
	Get tip and suggestions when using Windows (default value)

	.PARAMETER Disable
	Do not get tip and suggestions when I use Windows

	.EXAMPLE
	WindowsTips -Enable

	.EXAMPLE
	WindowsTips -Disable

	.NOTES
	Current user
#>
function WindowsTips
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableSoftLanding -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableSoftLanding -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-Host "Enabling tip and suggestions when I use Windows - " -NoNewline
			LogInfo "Enabling tip and suggestions when I use Windows"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling tip and suggestions when I use Windows - " -NoNewline
			LogInfo "Disabling tip and suggestions when I use Windows"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Show me suggested content in the Settings app

	.PARAMETER Hide
	Hide from me suggested content in the Settings app

	.PARAMETER Show
	Show me suggested content in the Settings app (default value)

	.EXAMPLE
	SettingsSuggestedContent -Hide

	.EXAMPLE
	SettingsSuggestedContent -Show

	.NOTES
	Current user
#>
function SettingsSuggestedContent
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling suggested content in the Settings app - " -NoNewline
			LogInfo "Disabling suggested content in the Settings app"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Enabling suggested content in the Settings app - " -NoNewline
			LogInfo "Enabling suggested content in the Settings app"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 1 -Force | Out-Null
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Automatic installing suggested apps

	.PARAMETER Disable
	Turn off automatic installing suggested apps

	.PARAMETER Enable
	Turn on automatic installing suggested apps (default value)

	.EXAMPLE
	AppsSilentInstalling -Disable

	.EXAMPLE
	AppsSilentInstalling -Enable

	.NOTES
	Current user
#>
function AppsSilentInstalling
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling Automatic installing of suggested apps - " -NoNewline
			LogInfo "Disabling Automatic installing of suggested apps"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling Automatic installing of suggested apps - " -NoNewline
			LogInfo "Enabling Automatic installing of suggested apps"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Ways to get the most out of Windows and finish setting up this device

	.PARAMETER Disable
	Do not suggest ways to get the most out of Windows and finish setting up this device

	.PARAMETER Enable
	Suggest ways to get the most out of Windows and finish setting up this device (default value)

	.EXAMPLE
	WhatsNewInWindows -Disable

	.EXAMPLE
	WhatsNewInWindows -Enable

	.NOTES
	Current user
#>
function WhatsNewInWindows
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

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host 'Disabling "suggest ways to get the most out of Windows and finish setting up this device" - ' -NoNewline
			LogInfo 'Disabling "suggest ways to get the most out of Windows and finish setting up this device"'
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host 'Enabling "suggest ways to get the most out of Windows and finish setting up this device" - ' -NoNewline
			LogInfo 'Enabling "suggest ways to get the most out of Windows and finish setting up this device"'
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Tailored experiences

	.PARAMETER Disable
	Do not let Microsoft use your diagnostic data for personalized tips, ads, and recommendations

	.PARAMETER Enable
	Let Microsoft use your diagnostic data for personalized tips, ads, and recommendations (default value)

	.EXAMPLE
	TailoredExperiences -Disable

	.EXAMPLE
	TailoredExperiences -Enable

	.NOTES
	Current user
#>
function TailoredExperiences
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

	# Remove all policies in order to make changes visible in UI only if it's possible
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\CloudContent -Name DisableTailoredExperiencesWithDiagnosticData -Force -ErrorAction Ignore | Out-Null
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\CloudContent -Name DisableTailoredExperiencesWithDiagnosticData -Type CLEAR | Out-Null

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-Host "Disabling Diagnostic data for personalized tips, ads, and recommendations - " -NoNewline
			LogInfo "Disabling Diagnostic data for personalized tips, ads, and recommendations"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling Diagnostic data for personalized tips, ads, and recommendations - " -NoNewline
			LogInfo "Enabling Diagnostic data for personalized tips, ads, and recommendations"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 1 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Bing search in Start Menu

	.PARAMETER Disable
	Disable Bing search in Start Menu

	.PARAMETER Enable
	Enable Bing search in Start Menu (default value)

	.EXAMPLE
	BingSearch -Disable

	.EXAMPLE
	BingSearch -Enable

	.NOTES
	Current user
#>
function BingSearch
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
			Write-Host "Disabling Bing search in Start Menu - " -NoNewline
			LogInfo "Disabling Bing search in Start Menu"
			if (-not (Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
			{
				New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force | Out-Null
			}
			New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -PropertyType DWord -Value 1 -Force | Out-Null

			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Type DWORD -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Enable"
		{
			Write-Host "Enabling Bing search in Start Menu - " -NoNewline
			LogInfo "Enabling Bing search in Start Menu"
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Force -ErrorAction Ignore | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Type CLEAR | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Recommendations for tips, shortcuts, new apps, and more in Start menu

	.PARAMETER Hide
	Do not show recommendations for tips, shortcuts, new apps, and more in Start menu

	.PARAMETER Show
	Show recommendations for tips, shortcuts, new apps, and more in Start menu (default value)

	.EXAMPLE
	StartRecommendationsTips -Hide

	.EXAMPLE
	StartRecommendationsTips -Show

	.NOTES
	Current user
#>
function StartRecommendationsTips
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling Recommendations for tips, shortcuts, new apps, and more in Start menu - " -NoNewline
			LogInfo "Disabling Recommendations for tips, shortcuts, new apps, and more in Start menu"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_IrisRecommendations -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Enabling Recommendations for tips, shortcuts, new apps, and more in Start menu - " -NoNewline
			LogInfo "Enabling Recommendations for tips, shortcuts, new apps, and more in Start menu"
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_IrisRecommendations -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Microsoft account-related notifications on Start Menu

	.PARAMETER Hide
	Do not show Microsoft account-related notifications on Start Menu in Start menu

	.PARAMETER Show
	Show Microsoft account-related notifications on Start Menu in Start menu (default value)

	.EXAMPLE
	StartAccountNotifications -Hide

	.EXAMPLE
	StartAccountNotifications -Show

	.NOTES
	Current user
#>
function StartAccountNotifications
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Hide"
		)]
		[switch]
		$Hide,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Show"
		)]
		[switch]
		$Show
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Hide"
		{
			Write-Host "Disabling Microsoft account-related notifications on Start Menu in Start menu - " -NoNewline
			LogInfo "Disabling Microsoft account-related notifications on Start Menu in Start menu"
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_AccountNotifications -PropertyType DWord -Value 0 -Force | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Show"
		{
			Write-Host "Enabling Microsoft account-related notifications on Start Menu in Start menu - " -NoNewline
			LogInfo "Enabling Microsoft account-related notifications on Start Menu in Start menu"
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_AccountNotifications -Force -ErrorAction Ignore | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Wi-Fi Sense configuration

	.PARAMETER Disable
	Disable Wi-Fi Sense to prevent automatic connection to open hotspots and sharing of Wi-Fi networks.

	.PARAMETER Enable
	Enable Wi-Fi Sense to allow automatic connection to open hotspots and sharing of Wi-Fi networks.

	.EXAMPLE
	WiFiSense -Disable

	.EXAMPLE
	WiFiSense -Enable

	.NOTES
	Current user
#>
function WiFiSense
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
			Write-Host "Enabling Wi-Fi Sense to allow automatic connection to open hotspots and sharing of Wi-Fi networks - " -NoNewline
			LogInfo "Enabling Wi-Fi Sense to allow automatic connection to open hotspots and sharing of Wi-Fi networks"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1 | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Wi-Fi Sense to prevent automatic connection to open hotspots and sharing of Wi-Fi networks - " -NoNewline
			LogInfo "Disabling Wi-Fi Sense to prevent automatic connection to open hotspots and sharing of Wi-Fi networks"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 | Out-Null
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 | Out-Null
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Web Search functionality in the Start Menu

	.PARAMETER Disable
	Disable Web Search in the Start Menu

	.PARAMETER Enable
	Enable Web Search in the Start Menu (default value)

	.EXAMPLE
	WebSearch -Disable

	.EXAMPLE
	WebSearch -Enable

	.NOTES
	Current user
#>
function WebSearch
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
			Write-Host "Enabling Web Search in the Start Menu - " -NoNewline
			LogInfo "Enabling Web Search in the Start Menu"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1 | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Web Search in the Start Menu - " -NoNewline
			LogInfo "Disabling Web Search in the Start Menu"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0 | Out-Null
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Enable or disable Activity History-related notifications in Task View.

	.PARAMETER Enable
	Show Activity History-related notifications in Task View.

	.PARAMETER Disable
	Hide Activity History-related notifications in Task View.

	.EXAMPLE
	ActivityHistory -Enable

	.EXAMPLE
	ActivityHistory -Disable
#>
function ActivityHistory
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
			Write-Host "Enabling Activity History related notifications in Task View - " -NoNewline
			LogInfo "Enabling Activity History-related notifications in Task View"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Activity History related notifications in Task View - " -NoNewline
			LogInfo "Disabling Activity History-related notifications in Task View"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Activity History related notifications in Task View

    .PARAMETER Hide
    Do not show Activity History-related notifications in Task View

    .PARAMETER Show
    Show Activity History-related notifications in Task View

    .EXAMPLE
    ActivityHistory -Enable

    .EXAMPLE
    ActivityHistory -Disable

    .NOTES
    Current user
#>
function ActivityHistory
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
			Write-Host "Enabling Activity History related notifications in Task View - " -NoNewline
			LogInfo "Enabling Activity History-related notifications in Task View"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Activity History related notifications in Task View - " -NoNewline
			LogInfo "Disabling Activity History-related notifications in Task View"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	Controls sensor-related features, such as screen auto-rotation

	.PARAMETER Disable
	Disable sensor-related features, such as screen auto-rotation

	.PARAMETER Enable
	Enable sensor-related features, such as screen auto-rotation (default value)

	.EXAMPLE
	Sensors -Disable

	.EXAMPLE
	Sensors -Enable

	.NOTES
	Current user
#>
function Sensors
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
			Write-Host "Enabling sensor-related features, such as screen auto-rotation - " -NoNewline
			LogInfo "Enabling sensor-related features, such as screen auto-rotation"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling sensor-related features, such as screen auto-rotation - " -NoNewline
			LogInfo "Disabling sensor-related features, such as screen auto-rotation"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Location feature settings and scripting

    .PARAMETER Enable
    Enable the location feature

    .PARAMETER Disable
    Disable the location feature

    .EXAMPLE
    LocationService -Enable

    .EXAMPLE
    LocationService -Disable

    .NOTES
    Current user
#>
function LocationService
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
			Write-Host "Enabling location features - " -NoNewline
			LogInfo "Enabling the location feature for the current user"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling location features - " -NoNewline
			LogInfo "Disabling the location feature for the current user"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Automatic Map Updates settings and scripting

    .PARAMETER Enable
    Enable automatic map updates

    .PARAMETER Disable
    Disable automatic map updates

    .EXAMPLE
    MapUpdates -Enable

    .EXAMPLE
    MapUpdates -Disable

    .NOTES
    Current user
#>
function MapUpdates
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
			Write-Host "Enabling automatic map updates - " -NoNewline
			LogInfo "Enabling automatic map updates for the current user"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling automatic map updates - " -NoNewline
			LogInfo "Disabling automatic map updates for the current user"
			Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Location feature settings

    .PARAMETER Enable
    Enable the setting "Let websites provide locally relevant content by accessing my language list"

    .PARAMETER Disable
    Disable the setting "Let websites provide locally relevant content by accessing my language list"

    .EXAMPLE
    WebLangList -Enable

    .EXAMPLE
    WebLangList -Disable

    .NOTES
    Current user
#>
function WebLangList
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
			Write-Host "Enabling websites to show relevant content by accessing my language list - " -NoNewline
			LogInfo "Enabling websites to show relevant content by accessing my language list"
			Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling websites to show relevant content by accessing my language list - " -NoNewline
			LogInfo "Disabling websites to show relevant content by accessing my language list"
			Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to camera

    .DESCRIPTION
    Note: This disables access using standard Windows API. Direct access to device will still be allowed.

    .PARAMETER Enable
    Enable access to camera (default value)

    .PARAMETER Disable
    Disable access to camera

    .EXAMPLE
    Camera -Enable

    .EXAMPLE
    Camera -Disable

    .NOTES
    Current user
#>
function Camera
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
			Write-Host "Enabling Access to use the camera - " -NoNewline
			LogInfo "Enabling Access to use the camera"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Access to use the camera - " -NoNewline
			LogInfo "Disabling Access to use the camera"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to microphone settings

    .DESCRIPTION
    Note: This disables access using standard Windows API. Direct access to device will still be allowed.

    .PARAMETER Enable
    Enable access to microphone (default value)

    .PARAMETER Disable
    Disable access to microphone

    .EXAMPLE
    Microphone -Enable

    .EXAMPLE
    Microphone -Disable

    .NOTES
    Current user
#>
function Microphone
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
			Write-Host "Enabling Access to use the microphone - " -NoNewline
			LogInfo "Enabling Access to use the microphone"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Access to use the microphone - " -NoNewline
			LogInfo "Disabling Access to use the microphone"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Device Management Wireless Application Protocol (WAP) Push Service settings

    .DESCRIPTION
    Note: This service is needed for Microsoft Intune interoperability

    .PARAMETER Enable
    Enable the Device Management Wireless Application Protocol (WAP) Push Service

    .PARAMETER Disable
    Disable the Device Management Wireless Application Protocol (WAP) Push Service

    .EXAMPLE
    WAPPush -Enable

    .EXAMPLE
    WAPPush -Disable

    .NOTES
    Current user
#>
function WAPPush
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
			Write-Host "Enabling Device Management Wireless Application Protocol (WAP) Push Service - " -NoNewline
			LogInfo "Enabling Device Management Wireless Application Protocol (WAP) Push Service"
			Set-Service "dmwappushservice" -StartupType Automatic | Out-Null
			Start-Service "dmwappushservice" -WarningAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling Device Management Wireless Application Protocol (WAP) Push Service - " -NoNewline
			LogInfo "Disabling Device Management Wireless Application Protocol (WAP) Push Service"
			Stop-Service "dmwappushservice" -WarningAction SilentlyContinue | Out-Null
			Set-Service "dmwappushservice" -StartupType Disabled | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Clearing of recent files on exit

    .DESCRIPTION
    Empties most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout

    .PARAMETER Enable
    Enable the clearing of recent files on exit

    .PARAMETER Disable
    Disable the clearing of recent files on exit (default value)

    .EXAMPLE
    ClearRecentFiles -Enable

    .EXAMPLE
    ClearRecentFiles -Disable

    .NOTES
    Current user
#>
function ClearRecentFiles
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
			Write-Host "Enabling the clearing of recent files on exit - " -NoNewline
			LogInfo "Enabling the clearing of recent files on exit"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling the clearing of recent files on exit - " -NoNewline
			LogInfo "Disabling the clearing of recent files on exit"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Recent files lists settings

    .DESCRIPTION
    Most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications

    .PARAMETER Enable
    Enable the recent files lists (default value)

    .PARAMETER Disable
    Disable the recent files lists

    .EXAMPLE
    RecentFiles -Enable

    .EXAMPLE
    RecentFiles -Disable

    .NOTES
    Current user
#>
function RecentFiles
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
			Write-Host "Enabling the recent files lists - " -NoNewline
			LogInfo "Enabling the recent files lists"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling the recent files lists - " -NoNewline
			LogInfo "Disabling the recent files lists"
			If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to voice activation from UWP (Universal Windows Platform) apps

    .PARAMETER Enable
    Enable access to voice activation from UWP apps

    .PARAMETER Disable
    Disable access to voice activation from UWP apps

    .EXAMPLE
    UWPVoiceActivation -Enable

    .EXAMPLE
    UWPVoiceActivation -Disable

    .NOTES
    Current user
#>
function UWPVoiceActivation
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
			Write-Host "Enabling access to voice activation from UWP apps - " -NoNewline
			LogInfo "Enabling access to voice activation from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to voice activation from UWP apps - " -NoNewline
			LogInfo "Disabling access to voice activation from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2 | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to notifications from UWP (Universal Windows Platform) apps

    .PARAMETER Enable
    Enable access to notifications from UWP apps

    .PARAMETER Disable
    Disable access to notifications from UWP apps

    .EXAMPLE
    UWPNotifications -Enable

    .EXAMPLE
    UWPNotifications -Disable

    .NOTES
    Current user
#>
function UWPNotifications
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
			Write-Host "Enabling access to notifications from UWP apps - " -NoNewline
			LogInfo "Enabling access to notifications from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to notifications from UWP apps - " -NoNewline
			LogInfo "Disabling access to notifications from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to account info from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to account info from UWP apps

    .PARAMETER Disable
    Disable access to account info from UWP apps

    .EXAMPLE
    UWPAccountInfo -Enable

    .EXAMPLE
    UWPAccountInfo -Disable

    .NOTES
    Current user
#>
function UWPAccountInfo
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
			Write-Host "Enabling access to account info from UWP apps - " -NoNewline
			LogInfo "Enabling access to account info from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to account info from UWP apps - " -NoNewline
			LogInfo "Disabling access to account info from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to contacts from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to contacts from UWP apps

    .PARAMETER Disable
    Disable access to contacts from UWP apps

    .EXAMPLE
    UWPContacts -Enable

    .EXAMPLE
    UWPContacts -Disable

    .NOTES
    Current user
#>
function UWPContacts
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
			Write-Host "Enabling access to contacts from UWP apps - " -NoNewline
			LogInfo "Enabling access to contacts from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to contacts from UWP apps - " -NoNewline
			LogInfo "Disabling access to contacts from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to calendar from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to calendar from UWP apps

    .PARAMETER Disable
    Disable access to calendar from UWP apps

    .EXAMPLE
    UWPCalendar -Enable

    .EXAMPLE
    UWPCalendar -Disable

    .NOTES
    Current user
#>
function UWPCalendar
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
			Write-Host "Enabling access to calendar from UWP apps - " -NoNewline
			LogInfo "Enabling access to calendar from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to calendar from UWP apps - " -NoNewline
			LogInfo "Disabling access to calendar from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to phone calls from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to phone calls from UWP apps

    .PARAMETER Disable
    Disable access to phone calls from UWP apps

    .EXAMPLE
    UWPPhoneCalls -Enable

    .EXAMPLE
    UWPPhoneCalls -Disable

    .NOTES
    Current user
#>
function UWPPhoneCalls
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
			Write-Host "Enabling access to phone calls from UWP apps - " -NoNewline
			LogInfo "Enabling access to phone calls from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to phone calls from UWP apps - " -NoNewline
			LogInfo "Disabling access to phone calls from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to call history from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to call history from UWP apps

    .PARAMETER Disable
    Disable access to call history from UWP apps

    .EXAMPLE
    UWPCallHistory -Enable

    .EXAMPLE
    UWPCallHistory -Disable

    .NOTES
    Current user
#>
function UWPCallHistory
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
			Write-Host "Enabling access to call history from UWP apps - " -NoNewline
			LogInfo "Enabling access to call history from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to call history from UWP apps - " -NoNewline
			LogInfo "Disabling access to call history from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to email from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to email from UWP apps

    .PARAMETER Disable
    Disable access to email from UWP apps

    .EXAMPLE
    UWPEmail -Enable

    .EXAMPLE
    UWPEmail -Disable

    .NOTES
    Current user
#>
function UWPEmail
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
			Write-Host "Enabling access to email from UWP apps - " -NoNewline
			LogInfo "Enabling access to email from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to email from UWP apps - " -NoNewline
			LogInfo "Disabling access to email from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to tasks from UWP (Universal Windows Platform) apps

    .PARAMETER Enable
    Enable access to tasks from UWP apps

    .PARAMETER Disable
    Disable access to tasks from UWP apps

    .EXAMPLE
    UWPTasks -Enable

    .EXAMPLE
    UWPTasks -Disable

    .NOTES
    Current user
#>
function UWPTasks
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
			Write-Host "Enabling access to tasks from UWP apps - " -NoNewline
			LogInfo "Enabling access to tasks from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to tasks from UWP apps - " -NoNewline
			LogInfo "Disabling access to tasks from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to messaging (SMS, MMS) from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to messaging (SMS, MMS) from UWP apps

    .PARAMETER Disable
    Disable access to messaging (SMS, MMS) from UWP apps

    .EXAMPLE
    UWPMessaging -Enable

    .EXAMPLE
    UWPMessaging -Disable

    .NOTES
    Current user
#>
function UWPMessaging
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
			Write-Host "Enabling access to messaging (SMS, MMS) from UWP apps - " -NoNewline
			LogInfo "Enabling access to messaging (SMS, MMS) from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to messaging (SMS, MMS) from UWP apps - " -NoNewline
			LogInfo "Disabling access to messaging (SMS, MMS) from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to radios (e.g. Bluetooth) from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to radios (e.g. Bluetooth) from UWP apps

    .PARAMETER Disable
    Disable access to radios (e.g. Bluetooth) from UWP apps

    .EXAMPLE
    UWPRadios -Enable

    .EXAMPLE
    UWPRadios -Disable

    .NOTES
    Current user
#>
function UWPRadios
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
			Write-Host "Enabling access to radios (e.g. Bluetooth) from UWP apps - " -NoNewline
			LogInfo "Enabling access to radios (e.g. Bluetooth) from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to radios (e.g. Bluetooth) from UWP apps - " -NoNewline
			LogInfo "Disabling access to radios (e.g. Bluetooth) from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to other devices (unpaired, beacons, TVs etc.) from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to other devices (unpaired, beacons, TVs etc.) from UWP apps

    .PARAMETER Disable
    Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps

    .EXAMPLE
    UWPOtherDevices -Enable

    .EXAMPLE
    UWPOtherDevices -Disable

    .NOTES
    Current user
#>
function UWPOtherDevices
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
			Write-Host "Enabling access to other devices (unpaired, beacons, TVs etc.) from UWP apps - " -NoNewline
			LogInfo "Enabling access to other devices (unpaired, beacons, TVs etc.) from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to other devices (unpaired, beacons, TVs etc.) from UWP apps - " -NoNewline
			LogInfo "Disabling access to other devices (unpaired, beacons, TVs etc.) from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to diagnostic information from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to diagnostic information from UWP apps

    .PARAMETER Disable
    Disable access to diagnostic information from UWP apps

    .EXAMPLE
    UWPDiagInfo -Enable

    .EXAMPLE
    UWPDiagInfo -Disable

    .NOTES
    Current user
#>
function UWPDiagInfo
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
			Write-Host "Enabling access to diagnostic information from UWP apps - " -NoNewline
			LogInfo "Enabling access to diagnostic information from UWP apps"
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to diagnostic information from UWP apps - " -NoNewline
			LogInfo "Disabling access to diagnostic information from UWP apps"
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    Access to libraries and file system from UWP (Universal Windows Platform) apps settings

    .PARAMETER Enable
    Enable access to libraries and file system from UWP apps

    .PARAMETER Disable
    Disable access to libraries and file system from UWP apps

    .EXAMPLE
    UWPFileSystem -Enable

    .EXAMPLE
    UWPFileSystem -Disable

    .NOTES
    Current user
#>
function UWPFileSystem
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
			Write-Host "Enabling access to libraries and the file system from UWP apps - " -NoNewline
			LogInfo "Enabling access to libraries and the file system from UWP apps"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Allow" | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Allow" | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Allow" | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Allow" | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling access to libraries and the file system from UWP apps - " -NoNewline
			LogInfo "Disabling access to libraries and the file system from UWP apps"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
    .SYNOPSIS
    UWP apps swap file settings

    .DESCRIPTION
    This disables creation and use of swapfile.sys and frees 256 MB of disk space. Swapfile.sys is used only by UWP apps.
	IMPORTANT: The tweak has no effect on the real swap in pagefile.sys.

    .PARAMETER Enable
    Enable the UWP apps swap file

    .PARAMETER Disable
    Disable the UWP apps swap file

    .EXAMPLE
    UWPSwapFile -Enable

    .EXAMPLE
    UWPSwapFile -Disable

    .NOTES
    Current user
#>
function UWPSwapFile
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
			Write-Host "Enabling the UWP apps swap file - " -NoNewline
			LogInfo "Enabling the UWP apps swap file"
			Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -ErrorAction SilentlyContinue | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling the UWP apps swap file - " -NoNewline
			LogInfo "Disabling the UWP apps swap file"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0 | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
.SYNOPSIS
Enable or disable PowerShell 7 Telemetry

.PARAMETER Enable
Enable PowerShell 7 Telemetry (default value)

.PARAMETER Disable
Disable PowerShell 7 Telemetry

.EXAMPLE
Powershell7Telemetry -Enable

.EXAMPLE
Powershell7Telemetry -Disable

.NOTES
Current user
#>
function Powershell7Telemetry
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
			Write-Host "Enabling PowerShell 7 Telemetry - " -NoNewline
			LogInfo "Enabling PowerShell 7 Telemetry"
			[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '', 'Machine')
			Write-Host "success!" -ForegroundColor Green
		}
		"Disable"
		{
			Write-Host "Disabling PowerShell 7 Telemetry - " -NoNewline
			LogInfo "Disabling PowerShell 7 Telemetry"
			[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion Privacy & Telemetry
