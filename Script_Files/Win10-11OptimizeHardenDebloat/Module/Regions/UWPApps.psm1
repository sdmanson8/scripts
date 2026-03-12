using module ..\Logging.psm1
using module ..\Helpers.psm1

#region UWP apps
<#
	.SYNOPSIS
	Install or uninstall Microsoft Copilot and related Windows AI components.

	.DESCRIPTION
	Calls the RemoveWindowsAI helper script to either restore or remove the
	Windows AI components associated with Copilot, then installs or removes the
	store Copilot app itself.

	.PARAMETER Install
	Install Microsoft Copilot and restore the AI components used by it.

	.PARAMETER Uninstall
	Uninstall Microsoft Copilot and remove the AI components used by it.

	.EXAMPLE
	Copilot -Install

	.EXAMPLE
	Copilot -Uninstall

	.NOTES
	Current user

	.NOTES
	Machine-wide
#>
function Copilot
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Install"
		)]
		[switch]
		$Install,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Uninstall"
		)]
		[switch]
		$Uninstall
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Install"
		{
			Write-Host "Installing Microsoft Copilot and other AI features: "
			LogInfo "Installing Microsoft Copilot and other AI features:"
			# store in environment for child processes
			[Environment]::SetEnvironmentVariable("REMOVE_WINDOWS_AI_LOG", $global:LogFilePath, "Process")
			& "$PSScriptRoot\..\..\files\RemoveWindowsAI.ps1" -nonInteractive -revertMode -AllOptions
			Start-Sleep -Seconds 2
			winget install -s msstore -e --silent --accept-source-agreements --accept-package-agreements --id 9NHT9RB2F4HD 2>$null | Out-Null
			if ($LASTEXITCODE -ne 0)
			{
				LogError "winget failed to install Microsoft Copilot with exit code $LASTEXITCODE"
			}
		}
		"Uninstall"
		{
			Write-Host "Uninstalling Microsoft Copilot and other AI features:"
			LogInfo "Uninstalling Microsoft Copilot and other AI features:"
			# store in environment for child processes
			[Environment]::SetEnvironmentVariable("REMOVE_WINDOWS_AI_LOG", $global:LogFilePath, "Process")
			& "$PSScriptRoot\..\..\files\RemoveWindowsAI.ps1" -nonInteractive -AllOptions
		}
	}
}

<#
	.SYNOPSIS
	Install or uninstall UWP apps by using the graphical app picker.

	.DESCRIPTION
	Opens a graphical app picker that lists installable or removable Microsoft
	Store and inbox UWP packages, then applies the selected action.

	.PARAMETER Install
	Open the app picker and install the selected UWP apps.

	.PARAMETER Uninstall
	Open the app picker and uninstall the selected UWP apps.

	.PARAMETER ForAllUsers
	Apply the selected install or uninstall action for all users where supported.

	.EXAMPLE
	UWPApps -Install

	.EXAMPLE
	UWPApps -Uninstall

	.NOTES
	Current user

	.NOTES
	Use `-ForAllUsers` for machine-wide package provisioning changes where supported
#>
function UWPApps
{
	[CmdletBinding(DefaultParameterSetName = "None")]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Install")]
		[switch]
		$Install,

		[Parameter(Mandatory = $true, ParameterSetName = "Uninstall")]
		[switch]
		$Uninstall,

		[Parameter(Mandatory = $false)]
		[switch]
		$ForAllUsers
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Install"
		{
            # Show the app picker and install the packages the user selects.
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            Write-ConsoleStatus -Action "Installing UWP apps"
            LogInfo "Installing UWP apps:"

            # Check for admin rights when "All Users" is selected
            if ($ForAllUsers)
            {
                $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $IsAdmin)
                {
                    $wshell = New-Object -ComObject Wscript.Shell
                    $wshell.Popup("Installing for all users requires administrator privileges.`nPlease run PowerShell as Administrator.", 0, "Admin Required", 0)
                    return
                }
            }

            # The following UWP apps will be excluded from the display
            $ExcludedAppxPackages = @(
                # Microsoft Edge
                "Microsoft.MicrosoftEdge.Stable",
                # Microsoft Visual C++ runtime framework
                "Microsoft.VCLibs.140.00",
                # AMD Radeon Software
                "AdvancedMicroDevicesInc-2.AMDRadeonSoftware",
                # Intel Graphics Control Center
                "AppUp.IntelGraphicsControlPanel",
                "AppUp.IntelGraphicsExperience",
                # ELAN Touchpad
                "ELANMicroelectronicsCorpo.ELANTouchpadforThinkpad",
                "ELANMicroelectronicsCorpo.ELANTrackPointforThinkpa",
                # Microsoft Application Compatibility Enhancements
                "Microsoft.ApplicationCompatibilityEnhancements",
                # AVC Encoder Video Extension
                "Microsoft.AVCEncoderVideoExtension",
                # Microsoft Desktop App Installer
                "Microsoft.DesktopAppInstaller",
                # Store Experience Host
                "Microsoft.StorePurchaseApp",
                # Cross Device Experience Host
                "MicrosoftWindows.CrossDevice",
                # Notepad
                "Microsoft.WindowsNotepad",
                # Microsoft Store
                "Microsoft.WindowsStore",
                # Windows Terminal
                "Microsoft.WindowsTerminal",
                "Microsoft.WindowsTerminalPreview",
                # Web Media Extensions
                "Microsoft.WebMediaExtensions",
                # AV1 Video Extension
                "Microsoft.AV1VideoExtension",
                # Windows Subsystem for Linux
                "MicrosoftCorporationII.WindowsSubsystemForLinux",
                # HEVC Video Extensions from Device Manufacturer
                "Microsoft.HEVCVideoExtension",
                "Microsoft.HEVCVideoExtensions",
                # Raw Image Extension
                "Microsoft.RawImageExtension",
                # HEIF Image Extensions
                "Microsoft.HEIFImageExtension",
                # MPEG-2 Video Extension
                "Microsoft.MPEG2VideoExtension",
                # VP9 Video Extensions
                "Microsoft.VP9VideoExtensions",
                # Webp Image Extensions
                "Microsoft.WebpImageExtension",
                # PowerShell
                "Microsoft.PowerShell",
                # NVIDIA Control Panel
                "NVIDIACorp.NVIDIAControlPanel",
                # Realtek Audio Console
                "RealtekSemiconductorCorp.RealtekAudioControl",
                # Synaptics
                "SynapticsIncorporated.SynapticsControlPanel",
                "SynapticsIncorporated.24916F58D6E7"
            )


            #region XAML Markup
            [xml]$XAML = @"
            <Window
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                Name="Window"
                MinHeight="400" MinWidth="415"
                SizeToContent="Width" WindowStartupLocation="CenterScreen"
                TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
                FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
                Background="#F1F1F1" Foreground="#262626">
                <Window.Resources>
                        <Style TargetType="StackPanel">
                                <Setter Property="Orientation" Value="Horizontal"/>
                                <Setter Property="VerticalAlignment" Value="Top"/>
                        </Style>
                        <Style TargetType="CheckBox">
                                <Setter Property="Margin" Value="10, 13, 10, 10"/>
                                <Setter Property="IsChecked" Value="True"/>
                        </Style>
                        <Style TargetType="TextBlock">
                                <Setter Property="Margin" Value="0, 10, 10, 10"/>
                        </Style>
                        <Style TargetType="Button">
                                <Setter Property="Margin" Value="20"/>
                                <Setter Property="Padding" Value="10"/>
                                <Setter Property="IsEnabled" Value="False"/>
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
                        <Grid Grid.Row="0">
                                <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <StackPanel Name="PanelSelectAll" Grid.Column="0" HorizontalAlignment="Left">
                                        <CheckBox Name="CheckBoxSelectAll" IsChecked="False"/>
                                        <TextBlock Name="TextBlockSelectAll" Margin="10,10, 0, 10"/>
                                </StackPanel>
                                <StackPanel Name="PanelInstallForAll" Grid.Column="1" HorizontalAlignment="Right">
                                        <TextBlock Name="TextBlockInstallForAll" Margin="10,10, 0, 10"/>
                                        <CheckBox Name="CheckBoxForAllUsers" IsChecked="False"/>
                                </StackPanel>
                        </Grid>
                        <Border>
                                <ScrollViewer>
                                        <StackPanel Name="PanelContainer" Orientation="Vertical" Margin="5"/>
                                </ScrollViewer>
                        </Border>
                        <Button Name="ButtonInstall" Grid.Row="2" Content="Install" Margin="20" Padding="10" IsEnabled="False"/>
                </Grid>
            </Window>
"@
            #endregion XAML Markup

            $Form = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML))

            if ($Form -eq $null)
            {
                Write-Host "Failed to load XAML" -ForegroundColor Red
                return
            }

            $XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
                Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
            }

            $PanelContainer = $Form.FindName("PanelContainer")
            if ($PanelContainer -eq $null)
            {
                Write-Host "PanelContainer not found!" -ForegroundColor Red
                return
            }
            $Window.Title               = "Install Windows Apps"
            $ButtonInstall.Content       = "Install"
            $TextBlockInstallForAll.Text = "Install for all users"
            $TextBlockSelectAll.Text     = "Select All"

            $ButtonInstall.Add_Click({ButtonInstallClick})
            $CheckBoxForAllUsers.Add_Click({CheckBoxForAllUsersClick})
            $CheckBoxSelectAll.Add_Click({CheckBoxSelectAllClick})

            #region Functions
            function Get-MissingAppxPackages
            {
           	[CmdletBinding()]
           	param
           	(
          		[switch]
          		$AllUsers
           	)

           	# Check if running as admin for AllUsers queries
           	$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

			$CommonPackages = @(
				@{ Name = "Microsoft.OutlookForWindows"; DisplayName = "Microsoft Outlook" }
				@{ Name = "Microsoft.WindowsCalculator"; DisplayName = "Calculator" }
				@{ Name = "Microsoft.WindowsCamera"; DisplayName = "Camera" }
				@{ Name = "Microsoft.Windows.Photos"; DisplayName = "Photos" }
				@{ Name = "Microsoft.GamingServices"; DisplayName = "Gaming Services" }
				@{ Name = "Microsoft.YourPhone"; DisplayName = "Phone Link" }
				@{ Name = "DolbyLaboratories.DolbyAccess"; DisplayName = "Dolby Access" }
			)

			# Add Voice Recorder only for Windows 10
			$os = Get-OSInfo
			if (-not $os.IsWindows11) {
				$CommonPackages += @{ Name = "Microsoft.WindowsSoundRecorder"; DisplayName = "Voice Recorder" }
			}

           	$MissingPackages = @()
           	$InstalledCount = 0
           	$ExcludedCount = 0

           	foreach ($Package in $CommonPackages)
           	{
          		if ($Package.Name -in $ExcludedAppxPackages)
          		{
         			$ExcludedCount++
         			continue
          		}

          		# Check if package is installed
          		$Installed = $null

          		if ($AllUsers)
          		{
         			if ($IsAdmin)
         			{
            				# Admin: Check all users
            				$Installed = Get-AppxPackage -Name $Package.Name -AllUsers -ErrorAction SilentlyContinue
         			}
         			else
         			{
            				# Non-admin: Can only check current user
            				$Installed = Get-AppxPackage -Name $Package.Name -ErrorAction SilentlyContinue
            				if (-not $script:AllUsersWarningShown)
            				{
           					LogWarning "Running without admin rights - 'All Users' mode will only check current user"
           					$script:AllUsersWarningShown = $true
            				}
         			}
          		}
          		else
          		{
         			# Current user only
         			$Installed = Get-AppxPackage -Name $Package.Name -ErrorAction SilentlyContinue
          		}

          		if ($null -eq $Installed)
          		{
         			$MissingPackages += [PSCustomObject]@{
            				Name = $Package.Name
            				PackageFullName = $Package.Name
            				DisplayName = $Package.DisplayName
         			}
          		}
          		else
          		{
         			$InstalledCount++
         			#LogInfo "Already installed: $($Package.DisplayName)"
          		}
           	}

           	#LogInfo "Package scan complete: $($MissingPackages.Count) missing, $InstalledCount installed, $ExcludedCount excluded"
           	return $MissingPackages | Sort-Object -Property DisplayName
            }

            function CheckBoxForAllUsersClick
            {
                $PanelContainer.Children.Clear()
                $PackagesToInstall.Clear()
                $MissingPackages = Get-MissingAppxPackages -AllUsers:$CheckBoxForAllUsers.IsChecked
                Add-Control -Packages $MissingPackages -Panel $PanelContainer
                ButtonInstallSetIsEnabled
            }

            function ButtonInstallClick
            {
           	$Window.Close()

           	$SuccessfulPackages = [System.Collections.Generic.List[string]]::new()
           	#$FailedPackages = [System.Collections.Generic.List[string]]::new()
           	$ManualPackages = [System.Collections.Generic.List[string]]::new()

           	# Store URLs for apps that need Store installation
           	$StoreUrls = @{
          		"Microsoft.WindowsCalculator" = "ms-windows-store://pdp/?productid=9WZDNCRFHVN5"
          		"Microsoft.WindowsCamera" = "ms-windows-store://pdp/?productid=9WZDNCRFJBBG"
          		"Microsoft.Windows.Photos" = "ms-windows-store://pdp/?productid=9WZDNCRFJBH4"
          		"DolbyLaboratories.DolbyAccess" = "ms-windows-store://pdp/?productid=9N0866FS04W8"
          		"Microsoft.GamingServices" = "ms-windows-store://pdp/?productid=9MWPM2CQNLHN"
          		"Microsoft.OutlookForWindows" = "ms-windows-store://pdp/?productid=9NRX63209R7B"
          		"MSTeams" = "ms-windows-store://pdp/?productid=XP8BT8DW290MPM"
          		"Microsoft.YourPhone" = "ms-windows-store://pdp/?productid=9NMPJ99VJBWV"
           	}

           	# Winget package mappings
           	$WingetMap = @{
          		"Microsoft.WindowsCalculator" = "Microsoft.WindowsCalculator"
          		"Microsoft.WindowsCamera" = "Microsoft.WindowsCamera"
          		"Microsoft.Windows.Photos" = "Microsoft.Windows.Photos"
          		"Microsoft.OutlookForWindows" = "Microsoft.OutlookForWindows"
          		"MSTeams" = "Microsoft.Teams"
          		"Microsoft.GamingServices" = "Microsoft.GamingServices"
          		"Microsoft.YourPhone" = "Microsoft.YourPhone"
          		"DolbyLaboratories.DolbyAccess" = "DolbyLaboratories.DolbyAccess"
           	}

           	foreach ($PackageName in $PackagesToInstall)
           	{
          		try {
         			# METHOD 1: Check if package files exist and register them
         			$WindowsAppsPath = "$env:ProgramFiles\WindowsApps"
         			$PackageFolders = Get-ChildItem -Path $WindowsAppsPath -Directory -ErrorAction SilentlyContinue |
            				Where-Object {$_.Name -like "*$PackageName*"} |
            				Sort-Object LastWriteTime -Descending

         			$Installed = $false
         			foreach ($Folder in $PackageFolders)
         			{
            				$ManifestPath = Join-Path $Folder.FullName "AppXManifest.xml"
            				if (Test-Path $ManifestPath)
            				{
           					#LogInfo "Found existing package files for $PackageName. Registering..."
           					try {
          						Add-AppxPackage -DisableDevelopmentMode -Register $ManifestPath -ErrorAction Stop
          						Start-Sleep -Seconds 2

          						$VerifyInstall = Get-AppxPackage -Name $PackageName -AllUsers:$CheckBoxForAllUsers.IsChecked -ErrorAction SilentlyContinue
          						if ($VerifyInstall)
          						{
         							$SuccessfulPackages.Add($PackageName)
         							#LogInfo "Successfully registered $PackageName for $scope"
         							$Installed = $true
         							break
          						}
           					}
           					catch {
          						if ($_.Exception.Message -like "*0x80073D02*")
          						{
         							#LogInfo "$PackageName registration failed - system components in use"
         							$ManualPackages.Add($PackageName)
         							$Installed = $true
         							break
          						}
           					}
                    	}
         			}

         			if ($Installed) { continue }

         			# METHOD 2: Try provisioned packages
         			#LogInfo "Checking provisioned packages for $PackageName..."
         			$Provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            				Where-Object {$_.DisplayName -eq $PackageName -or $_.PackageName -like "*$PackageName*"}

         			if ($Provisioned)
         			{
            				try {
           					Add-AppxProvisionedPackage -Online -PackageName $Provisioned.PackageName -SkipLicense -ErrorAction Stop | Out-Null
           					Start-Sleep -Seconds 3

           					$VerifyInstall = Get-AppxPackage -Name $PackageName -AllUsers:$CheckBoxForAllUsers.IsChecked -ErrorAction SilentlyContinue
           					if ($VerifyInstall)
           					    {
              						$SuccessfulPackages.Add($PackageName)
              						#LogInfo "Successfully installed $PackageName for $scope"
              						continue
           					    }
                            }
            				catch {
           					LogError "Provisioned package installation failed for $PackageName"
            				}
         			}

         			# METHOD 3: Try winget
         			#LogInfo "Trying winget for $PackageName..."
         			$WingetPath = Get-Command winget -ErrorAction SilentlyContinue
         			if ($WingetPath)
         			{
            				$WingetID = $WingetMap[$PackageName]
           				if ($WingetID)
            				{
           					if ($CheckBoxForAllUsers.IsChecked)
           					{
          						$WingetProcess = Start-Process -FilePath "winget" -ArgumentList "install --exact --id $WingetID --scope machine --silent --accept-package-agreements --accept-source-agreements" -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
           					}
           					else
           					{
          						$WingetProcess = Start-Process -FilePath "winget" -ArgumentList "install --exact --id $WingetID --scope user --silent --accept-package-agreements --accept-source-agreements" -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
           					}

								if ($WingetProcess.ExitCode -ne 0)
								{
									LogError "winget failed to install $PackageName with exit code $($WingetProcess.ExitCode)"
								}

           					Start-Sleep -Seconds 5
           					$AfterWinget = Get-AppxPackage -Name $PackageName -AllUsers:$CheckBoxForAllUsers.IsChecked -ErrorAction SilentlyContinue

           					if ($AfterWinget)
           					{
          						$SuccessfulPackages.Add($PackageName)
          						#LogInfo "Successfully installed $PackageName for $scope"
          						continue
           					}
                        }
         			}

         			# METHOD 4: Try Microsoft Store as last resort
         			$StoreUrl = $StoreUrls[$PackageName]
         			if ($StoreUrl)
         			{
            				#LogInfo "Opening Microsoft Store for $PackageName. Please install manually..."
            				Start-Process $StoreUrl

            				Add-Type -AssemblyName System.Windows.Forms
            				[System.Windows.Forms.MessageBox]::Show("Microsoft Store has been opened for $PackageName.`n`nPlease install the app manually, then click OK to continue with the next app.", "Manual Installation Required", "OK", "Information")

            				Start-Sleep -Seconds 2
            				$AfterStore = Get-AppxPackage -Name $PackageName -AllUsers:$CheckBoxForAllUsers.IsChecked -ErrorAction SilentlyContinue
            				if ($AfterStore)
            				{
               					$SuccessfulPackages.Add($PackageName)
               					#LogInfo "Successfully installed $PackageName for $scope"
            				}
            				else
            				{
               					$ManualPackages.Add($PackageName)
               					LogError "User will install $PackageName manually later"
            				}
         			}
         			else
         			{
                        LogError "$PackageName - Could not install automatically"
            			$ManualPackages.Add($PackageName)
         			}
          		}
          		catch {
         			LogError "$PackageName - Installation failed: $($_.Exception.Message)"
         			$ManualPackages.Add($PackageName)
          		}
           	}

           	if ($ManualPackages.Count -gt 0)
           	{
          		#LogInfo "The following apps need manual installation: $($ManualPackages -join ', ')"
           	}

           	#LogInfo "Installation complete: $($SuccessfulPackages.Count) installed, $($ManualPackages.Count) need manual attention"

            # Log results
            if ($SuccessfulPackages.Count -gt 0)
            {
                $scope = if ($CheckBoxForAllUsers.IsChecked) { "all users" } else { "current user" }
                foreach ($Package in $SuccessfulPackages)
                {
                    LogInfo "Successfully installed $Package for $scope"
                }
            }

            if ($ManualPackages.Count -gt 0)
            {
                #LogInfo "The following apps need manual installation: $($ManualPackages -join ', ')"
            }

            #LogInfo "Installation complete: $($SuccessfulPackages.Count) installed, $($ManualPackages.Count) need manual attention"
        }

            function Add-Control
            {
           	param($Packages, $Panel)

           	foreach ($Package in $Packages)
           	{
          		$CheckBox = New-Object System.Windows.Controls.CheckBox
          		$CheckBox.Tag = $Package.PackageFullName
          		$CheckBox.IsChecked = $true
          		$CheckBox.Margin = "5,5,5,5"
          		$CheckBox.VerticalAlignment = "Center"

          		$TextBlock = New-Object System.Windows.Controls.TextBlock
          		$TextBlock.Text = $Package.DisplayName
          		$TextBlock.Margin = "5,5,5,5"
          		$TextBlock.VerticalAlignment = "Center"

          		$StackPanel = New-Object System.Windows.Controls.StackPanel
          		$StackPanel.Orientation = "Horizontal"
          		$StackPanel.Margin = "2,2,2,2"
          		$StackPanel.Children.Add($CheckBox) | Out-Null
          		$StackPanel.Children.Add($TextBlock) | Out-Null

          		$Panel.Children.Add($StackPanel) | Out-Null
          		$PackagesToInstall.Add($Package.PackageFullName) | Out-Null

          		$CheckBox.Add_Click({CheckBoxClick})
           	}
        }

            function CheckBoxClick
            {
           	$CheckBox = $_.Source
           	if ($CheckBox.IsChecked)
           	{
          		$PackagesToInstall.Add($CheckBox.Tag) | Out-Null
           	}
           	else
           	{
          		$PackagesToInstall.Remove($CheckBox.Tag)
           	}
           	ButtonInstallSetIsEnabled
            }

            function CheckBoxSelectAllClick
            {
           	$CheckBox = $_.Source

           	if ($CheckBox.IsChecked)
           	{
          		$PackagesToInstall.Clear()
          		foreach ($Item in $PanelContainer.Children)
          		{
         			$ChildCheckBox = $Item.Children[0]
         			$ChildCheckBox.IsChecked = $true
         			$PackagesToInstall.Add($ChildCheckBox.Tag) | Out-Null
          		}
           	}
           	else
           	{
          		$PackagesToInstall.Clear()
          		foreach ($Item in $PanelContainer.Children)
          		{
         			$Item.Children[0].IsChecked = $false
          		}
           	}
           	ButtonInstallSetIsEnabled
            }

            function ButtonInstallSetIsEnabled
            {
           	$ButtonInstall.IsEnabled = ($PackagesToInstall.Count -gt 0)
            }
            #endregion Functions

            # Check "For all users" checkbox if specified
            if ($ForAllUsers)
            {
           	$CheckBoxForAllUsers.IsChecked = $true
            }

            $PackagesToInstall = [System.Collections.Generic.List[string]]::new()
            $MissingPackages = Get-MissingAppxPackages -AllUsers:$ForAllUsers

            if ($MissingPackages.Count -eq 0)
            {
           	LogInfo "No apps found to install"
            }
            else
            {
           	Add-Control -Packages $MissingPackages -Panel $PanelContainer

           	if ($PackagesToInstall.Count -gt 0)
	{
		$ButtonInstall.IsEnabled = $true
	}

	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
    }
    Write-ConsoleStatus -Status success
}
		"Uninstall"
		{
			# Show the app picker and remove the packages the user selects.
			Add-Type -AssemblyName PresentationCore, PresentationFramework
			Write-ConsoleStatus -Action "Uninstalling UWP apps"
			LogInfo "Uninstalling UWP apps:"
			#region Variables
			# The following UWP apps will have their checkboxes unchecked
			$UncheckedAppxPackages = @(
				# Dolby Access
				"DolbyLaboratories.DolbyAccess",

				# Windows Media Player
				"Microsoft.ZuneMusic",

				# Screen Sketch
				"Microsoft.ScreenSketch",

				# Photos (and Video Editor)
				"Microsoft.Windows.Photos",
				"Microsoft.Photos.MediaEngineDLC",

				# Calculator
				"Microsoft.WindowsCalculator",

				# Windows Camera
				"Microsoft.WindowsCamera",

				# Xbox Identity Provider
				"Microsoft.XboxIdentityProvider",

				# Xbox Console Companion
				"Microsoft.XboxApp",

				# Xbox
				"Microsoft.GamingApp",
				"Microsoft.GamingServices",

				# Paint
				"Microsoft.Paint",

				# Xbox TCUI
				"Microsoft.Xbox.TCUI",

				# Xbox Speech To Text Overlay
				"Microsoft.XboxSpeechToTextOverlay",

				# Game Bar
				"Microsoft.XboxGamingOverlay",

				# Game Bar Plugin
				"Microsoft.XboxGameOverlay"
			)

			# The following UWP apps will be excluded from the display
			$ExcludedAppxPackages = @(
				# AMD Radeon Software
				"AdvancedMicroDevicesInc-2.AMDRadeonSoftware",

				# Intel Graphics Control Center
				"AppUp.IntelGraphicsControlPanel",
				"AppUp.IntelGraphicsExperience",

				# ELAN Touchpad
				"ELANMicroelectronicsCorpo.ELANTouchpadforThinkpad",
				"ELANMicroelectronicsCorpo.ELANTrackPointforThinkpa",

				# Microsoft Application Compatibility Enhancements
				"Microsoft.ApplicationCompatibilityEnhancements",

				# AVC Encoder Video Extension
				"Microsoft.AVCEncoderVideoExtension",

				# Microsoft Desktop App Installer
				"Microsoft.DesktopAppInstaller",

				# Store Experience Host
				"Microsoft.StorePurchaseApp",

				# Cross Device Experience Host
				"MicrosoftWindows.CrossDevice",

				# Notepad
				"Microsoft.WindowsNotepad",

				# Microsoft Store
				"Microsoft.WindowsStore",

				# Windows Terminal
				"Microsoft.WindowsTerminal",
				"Microsoft.WindowsTerminalPreview",

				# Web Media Extensions
				"Microsoft.WebMediaExtensions",

				# AV1 Video Extension
				"Microsoft.AV1VideoExtension",

				# Windows Subsystem for Linux
				"MicrosoftCorporationII.WindowsSubsystemForLinux",

				# HEVC Video Extensions from Device Manufacturer
				"Microsoft.HEVCVideoExtension",
				"Microsoft.HEVCVideoExtensions",

				# Raw Image Extension
				"Microsoft.RawImageExtension",

				# HEIF Image Extensions
				"Microsoft.HEIFImageExtension",

				# MPEG-2 Video Extension
				"Microsoft.MPEG2VideoExtension",

				# VP9 Video Extensions
				"Microsoft.VP9VideoExtensions",

				# Webp Image Extensions
				"Microsoft.WebpImageExtension",

				# PowerShell
				"Microsoft.PowerShell",

				# NVIDIA Control Panel
				"NVIDIACorp.NVIDIAControlPanel",

				# Realtek Audio Console
				"RealtekSemiconductorCorp.RealtekAudioControl",

				# Synaptics
				"SynapticsIncorporated.SynapticsControlPanel",
				"SynapticsIncorporated.24916F58D6E7"
			)

			#region XAML Markup
			# The section defines the design of the upcoming dialog box
			[xml]$XAML = @"
			<Window
				xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
				xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
				Name="Window"
				MinHeight="400" MinWidth="415"
				SizeToContent="Width" WindowStartupLocation="CenterScreen"
				TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
				FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
				Background="#F1F1F1" Foreground="#262626">
				<Window.Resources>
					<Style TargetType="StackPanel">
						<Setter Property="Orientation" Value="Horizontal"/>
						<Setter Property="VerticalAlignment" Value="Top"/>
					</Style>
					<Style TargetType="CheckBox">
						<Setter Property="Margin" Value="10, 13, 10, 10"/>
						<Setter Property="IsChecked" Value="True"/>
					</Style>
					<Style TargetType="TextBlock">
						<Setter Property="Margin" Value="0, 10, 10, 10"/>
					</Style>
					<Style TargetType="Button">
						<Setter Property="Margin" Value="20"/>
						<Setter Property="Padding" Value="10"/>
						<Setter Property="IsEnabled" Value="False"/>
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
					<Grid Grid.Row="0">
						<Grid.ColumnDefinitions>
							<ColumnDefinition Width="*"/>
							<ColumnDefinition Width="*"/>
						</Grid.ColumnDefinitions>
						<StackPanel Name="PanelSelectAll" Grid.Column="0" HorizontalAlignment="Left">
							<CheckBox Name="CheckBoxSelectAll" IsChecked="False"/>
							<TextBlock Name="TextBlockSelectAll" Margin="10,10, 0, 10"/>
						</StackPanel>
						<StackPanel Name="PanelRemoveForAll" Grid.Column="1" HorizontalAlignment="Right">
							<TextBlock Name="TextBlockRemoveForAll" Margin="10,10, 0, 10"/>
							<CheckBox Name="CheckBoxForAllUsers" IsChecked="False"/>
						</StackPanel>
					</Grid>
					<Border>
						<ScrollViewer>
							<StackPanel Name="PanelContainer" Orientation="Vertical"/>
						</ScrollViewer>
					</Border>
					<Button Name="ButtonUninstall" Grid.Row="2"/>
				</Grid>
			</Window>
"@
			#endregion XAML Markup

			$Form = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML))
			$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
				Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
			}

			$Window.Title               = "Uninstall UWP Apps"
			$ButtonUninstall.Content    = "Uninstall"
			$TextBlockRemoveForAll.Text = "Uninstall for all users"
			# Extract the localized "Select all" string from shell32.dll
			$TextBlockSelectAll.Text    = [WinAPI.GetStrings]::GetString(31276)

			$ButtonUninstall.Add_Click({ButtonUninstallClick})
			$CheckBoxForAllUsers.Add_Click({CheckBoxForAllUsersClick})
			$CheckBoxSelectAll.Add_Click({CheckBoxSelectAllClick})
			#endregion Variables

			#region Functions
			function Get-AppxBundle
			{
				[CmdletBinding()]
				param
				(
					[string[]]
					$Exclude,

					[switch]
					$AllUsers
				)

				$AppxPackages = @(Get-AppxPackage -PackageTypeFilter Bundle -AllUsers:$AllUsers | Where-Object -FilterScript {$_.Name -notin $ExcludedAppxPackages})

				# The -PackageTypeFilter Bundle doesn't contain these packages, and we need to add manually
				$Packages = @(
					# Outlook
					"Microsoft.OutlookForWindows",

					# Microsoft Teams
					"MSTeams"
				)
				foreach ($Package in $Packages)
				{
					if (Get-AppxPackage -Name $Package -AllUsers:$AllUsers)
					{
						$AppxPackages += Get-AppxPackage -Name $Package -AllUsers:$AllUsers
					}
				}

				$PackagesIds = [Windows.Management.Deployment.PackageManager, Windows.Web, ContentType = WindowsRuntime]::new().FindPackages() | Select-Object -Property DisplayName -ExpandProperty Id | Select-Object -Property Name, DisplayName
				foreach ($AppxPackage in $AppxPackages)
				{
					$PackageId = $PackagesIds | Where-Object -FilterScript {$_.Name -eq $AppxPackage.Name}
					if (-not $PackageId)
					{
						continue
					}

					[PSCustomObject]@{
						Name            = $AppxPackage.Name
						PackageFullName = $AppxPackage.PackageFullName
						# Sometimes there's more than one package presented in Windows with the same package name like {Microsoft Teams, Microsoft Teams} and we need to display the first one
						DisplayName     = $PackageId.DisplayName | Select-Object -First 1
					}
				}
			}

			function Add-Control
			{
				[CmdletBinding()]
				param
				(
					[Parameter(
						Mandatory = $true,
						ValueFromPipeline = $true
					)]
					[ValidateNotNull()]
					[PSCustomObject[]]
					$Packages
				)

				process
				{
					foreach ($Package in $Packages)
					{
						$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
						$CheckBox.Tag = $Package.PackageFullName

						$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock

						if ($Package.DisplayName)
						{
							$TextBlock.Text = $Package.DisplayName
						}
						else
						{
							$TextBlock.Text = $Package.Name
						}

						$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
						$StackPanel.Children.Add($CheckBox) | Out-Null
						$StackPanel.Children.Add($TextBlock) | Out-Null

						$PanelContainer.Children.Add($StackPanel) | Out-Null

						if ($UncheckedAppxPackages.Contains($Package.Name))
						{
							$CheckBox.IsChecked = $false
						}
						else
						{
							$CheckBox.IsChecked = $true
							$PackagesToRemove.Add($Package.PackageFullName)
						}

						$CheckBox.Add_Click({CheckBoxClick})
					}
				}
			}

			function CheckBoxForAllUsersClick
			{
				$PanelContainer.Children.RemoveRange(0, $PanelContainer.Children.Count)
				$PackagesToRemove.Clear()
				$AppXPackages = Get-AppxBundle -Exclude $ExcludedAppxPackages -AllUsers:$CheckBoxForAllUsers.IsChecked
				$AppXPackages | Add-Control

				ButtonUninstallSetIsEnabled
			}

			function ButtonUninstallClick
			{
				$Window.Close() | Out-Null

				# If MSTeams is selected to uninstall, delete quietly "Microsoft Teams Meeting Add-in for Microsoft Office" too
				# & "$env:SystemRoot\System32\msiexec.exe" --% /x {A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91} /qn
				if ($PackagesToRemove -match "MSTeams")
				{
					$MSIProcess = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList "/x {A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91} /qn" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
					if ($MSIProcess.ExitCode -ne 0)
					{
						LogError "msiexec failed to remove the Teams Meeting Add-in with exit code $($MSIProcess.ExitCode)"
					}
				}

				$PackagesToRemove | Remove-AppxPackage -AllUsers:$CheckBoxForAllUsers.IsChecked

				if ($CheckBoxForAllUsers.IsChecked)
				{
					foreach ($Package in $PackagesToRemove)
					{
						LogInfo "Successfully removed $Package for all users"
					}
				}
				else
				{
					foreach ($Package in $PackagesToRemove)
					{
						LogInfo "Successfully removed $Package for current user"
					}
				}
			}

			function CheckBoxClick
			{
				$CheckBox = $_.Source

				if ($CheckBox.IsChecked)
				{
					$PackagesToRemove.Add($CheckBox.Tag) | Out-Null
				}
				else
				{
					$PackagesToRemove.Remove($CheckBox.Tag)
				}

				ButtonUninstallSetIsEnabled
			}

			function CheckBoxSelectAllClick
			{
				$CheckBox = $_.Source

				if ($CheckBox.IsChecked)
				{
					$PackagesToRemove.Clear()

					foreach ($Item in $PanelContainer.Children)
					{
						foreach ($Child in $Item.Children)
						{
							if ($Child -is [System.Windows.Controls.CheckBox])
							{
								$Child.IsChecked = $true
								$PackagesToRemove.Add($Child.Tag)
							}
						}
					}
				}
				else
				{
					$PackagesToRemove.Clear()

					foreach ($Item in $PanelContainer.Children)
					{
						foreach ($Child in $Item.Children)
						{
							if ($Child -is [System.Windows.Controls.CheckBox])
							{
								$Child.IsChecked = $false
							}
						}
					}
				}

				ButtonUninstallSetIsEnabled
			}

			function ButtonUninstallSetIsEnabled
			{
				if ($PackagesToRemove.Count -gt 0)
				{
					$ButtonUninstall.IsEnabled = $true
				}
				else
				{
					$ButtonUninstall.IsEnabled = $false
				}
			}
			#endregion Functions

			# Check "For all users" checkbox to uninstall packages from all accounts
			if ($ForAllUsers)
			{
				$CheckBoxForAllUsers.IsChecked = $true
			}

			$PackagesToRemove = [Collections.Generic.List[string]]::new()
			$AppXPackages = Get-AppxBundle -Exclude $ExcludedAppxPackages -AllUsers:$ForAllUsers
			$AppXPackages | Add-Control

			if ($AppXPackages.Count -eq 0)
			{
				LogInfo "No apps available to uninstall"
			}
			else
			{
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

					# Emulate the Backspace key sending to prevent the console window to freeze
					[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
				}
				#endregion Sendkey function

				if ($PackagesToRemove.Count -gt 0)
				{
					$ButtonUninstall.IsEnabled = $true
				}

				# Force move the WPF form to the foreground
				$Window.Add_Loaded({$Window.Activate()})
				$Form.ShowDialog() | Out-Null
			}
			Write-ConsoleStatus -Status success
		}
	}
}

<#
	.SYNOPSIS
	Cortana autostarting

	.PARAMETER Disable
	Disable Cortana autostarting

	.PARAMETER Enable
	Enable Cortana autostarting

	.EXAMPLE
	CortanaAutostart -Disable

	.EXAMPLE
	CortanaAutostart -Enable

	.NOTES
	Current user
#>
function CortanaAutostart
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

	if (-not (Get-AppxPackage -Name Microsoft.549981C3F5F10))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())
		return
	}

	if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId"))
	{
		New-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Force | Out-Null
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Cortana autostarting"
			LogInfo "Disabling Cortana autostarting"
			New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 1 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Cortana autostarting"
			LogInfo "Enabling Cortana autostarting"
			New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 2 -Force | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}


<#
.SYNOPSIS
Enable or disable New Outlook

.PARAMETER Enable
Enable New Outlook

.PARAMETER Disable
Disable New Outlook

.EXAMPLE
NewOutlook -Enable

.EXAMPLE
NewOutlook -Disable

.NOTES
Current user
#>
function NewOutlook
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
			Write-ConsoleStatus -Action "Enabling New Outlook"
			LogInfo "Enabling New Outlook"
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Preferences" -Name "UseNewOutlook" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\General" -Name "HideNewOutlookToggle" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General" -Name "DoNewOutlookAutoMigration" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Preferences" -Name "NewOutlookMigrationUserSetting" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling New Outlook"
			LogInfo "Disabling New Outlook"
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Preferences" -Name "UseNewOutlook" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\General" -Name "HideNewOutlookToggle" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General" -Name "DoNewOutlookAutoMigration" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Preferences" -Name "NewOutlookMigrationUserSetting" -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
.SYNOPSIS
Enable or disable Background Apps

.PARAMETER Enable
Enable Background Apps (default value)

.PARAMETER Disable
Disable Background Apps

.EXAMPLE
BackgroundApps -Enable

.EXAMPLE
BackgroundApps -Disable

.NOTES
Current user
#>
function BackgroundApps
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Background Apps"
			LogInfo "Enabling Background Apps"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Background Apps"
			LogInfo "Disabling Background Apps"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
.SYNOPSIS
Enable or disable Notification Tray/Calendar

.PARAMETER Enable
Enable Notification Tray/Calendar (default value)

.PARAMETER Disable
Disable Notification Tray/Calendar

.EXAMPLE
Notifications -Enable

.EXAMPLE
Notifications -Disable

.NOTES
Current user

.CAUTION
This will completely disable Windows notifications.
You will not receive app alerts, system warnings, reminders, or calendar events.
The notification tray and calendar flyout will not function.
#>
function Notifications
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Notification Tray/Calendar"
			LogInfo "Enabling Notification Tray/Calendar"
			Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Notification Tray/Calendar"
			LogInfo "Disabling Notification Tray/Calendar"
			if (-not (Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer"))
			{
				New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force -ErrorAction SilentlyContinue | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Write-ConsoleStatus -Status success
		}
	}
}

<#
.SYNOPSIS
Enable or disable Edge Debloat

.PARAMETER Enable
Enable Edge Debloat

.PARAMETER Disable
Disable Edge Debloat (default value)

.EXAMPLE
EdgeDebloat -Enable

.EXAMPLE
EdgeDebloat -Disable

.NOTES
Current user

.CAUTION
This will enforce multiple Group Policy settings on Microsoft Edge.
Telemetry, personalization reporting, and diagnostic data will be disabled.
Shopping assistant, collections, rewards, and feedback features will be removed.
The Copilot sidebar extension will be blocked via extension blocklist.
First run experience and insider promotions will be hidden.
These changes apply system-wide and may affect all Edge user profiles.
#>
function EdgeDebloat
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	$EdgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
	$EdgeUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
	$EdgeBlocklistPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Edge Debloat"
			LogInfo "Enabling Edge Debloat"
			
			# Create paths if they don't exist
			if (-not (Test-Path $EdgeUpdatePath))
			{
				New-Item -Path $EdgeUpdatePath -Force -ErrorAction SilentlyContinue | Out-Null
			}
			if (-not (Test-Path $EdgePath))
			{
				New-Item -Path $EdgePath -Force -ErrorAction SilentlyContinue | Out-Null
			}
			if (-not (Test-Path $EdgeBlocklistPath))
			{
				New-Item -Path $EdgeBlocklistPath -Force -ErrorAction SilentlyContinue | Out-Null
			}
			
			Set-ItemProperty -Path $EdgeUpdatePath -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "PersonalizationReportingEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgeBlocklistPath -Name "1" -Type String -Value "ofefcgjbeghpigppfmkologfjadafddi" -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "ShowRecommendationsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "HideFirstRunExperience" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "UserFeedbackAllowed" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "ConfigureDoNotTrack" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "AlternateErrorPagesEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "EdgeCollectionsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "EdgeShoppingAssistantEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "MicrosoftEdgeInsiderPromotionEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "ShowMicrosoftRewards" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "WebWidgetAllowed" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "DiagnosticData" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "EdgeAssetDeliveryServiceEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path $EdgePath -Name "WalletDonationEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
			
			LogInfo "Edge debloat policies applied"
			Write-ConsoleStatus -Status success
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Edge Debloat"
			LogInfo "Disabling Edge Debloat"
			
			Remove-ItemProperty -Path $EdgeUpdatePath -Name "CreateDesktopShortcutDefault" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "PersonalizationReportingEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgeBlocklistPath -Name "1" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "ShowRecommendationsEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "HideFirstRunExperience" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "UserFeedbackAllowed" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "ConfigureDoNotTrack" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "AlternateErrorPagesEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "EdgeCollectionsEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "EdgeShoppingAssistantEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "MicrosoftEdgeInsiderPromotionEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "ShowMicrosoftRewards" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "WebWidgetAllowed" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "DiagnosticData" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "EdgeAssetDeliveryServiceEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path $EdgePath -Name "WalletDonationEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
			
			LogInfo "Edge debloat policies removed"
			Write-ConsoleStatus -Status success
		}
	}
}

<#
.SYNOPSIS
Enable or disable Revert Start Menu

.PARAMETER Enable
Revert to the original Start Menu from 24H2

.PARAMETER Disable
Restore the new Start Menu (default value)

.EXAMPLE
RevertStartMenu -Enable

.EXAMPLE
RevertStartMenu -Disable

.NOTES
Current user

.CAUTION
Reverting the Start Menu may break future Windows updates that depend on the new layout.
#>
function RevertStartMenu
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[switch]$Disable
	)

	$viveToolUrl = "https://github.com/thebookisclosed/ViVe/releases/download/v0.3.4/ViVeTool-v0.3.4-IntelAmd.zip"
	$featureId = "47205210"
	$tempDir = "$env:TEMP\ViVeTool"
	$SupportedMessage = "Revert Start Menu is only supported on Windows 11 24H2 build 26100.7019+ or 26H1 build 28000.1575+ and newer. Skipping."
	$DownloadFailedMessage = "Unable to download ViVeTool from GitHub. Skipping Revert Start Menu."
	$IsRevertStartMenuSupported = Test-Windows11FeatureBranchSupport -Thresholds @(
		@{ DisplayVersion = "24H2"; Build = 26100; UBR = 7019 },
		@{ DisplayVersion = "26H1"; Build = 28000; UBR = 1575 }
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Write-ConsoleStatus -Action "Enabling Revert Start Menu"
			LogInfo "Enabling Revert Start Menu"

			if (-not $IsRevertStartMenuSupported)
			{
				Write-ConsoleStatus -Status success
				LogWarning $SupportedMessage
				return
			}

			try
			{
				# Create temp directory
				if (Test-Path $tempDir)
				{
					Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
				}
				New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
				
				# Download ViVeTool
				$zipPath = "$tempDir\ViVeTool.zip"
				Invoke-WebRequest $viveToolUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop | Out-Null
				LogInfo "Downloaded ViVeTool"
				
				# Extract
				Expand-Archive $zipPath -DestinationPath $tempDir -Force -ErrorAction Stop | Out-Null
				LogInfo "Extracted ViVeTool"
				
				# Run ViVeTool
				$viveExe = "$tempDir\ViVeTool.exe"
				if (-not (Test-Path $viveExe))
				{
					throw "ViVeTool.exe was not found after extraction"
				}
				$ViVeProcess = Start-Process $viveExe -ArgumentList "/disable /id:$featureId" -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
				if ($ViVeProcess.ExitCode -ne 0)
				{
					throw "ViVeTool returned exit code $($ViVeProcess.ExitCode)"
				}
				LogInfo "Applied ViVeTool setting to disable feature $featureId"
				
				# Cleanup
				Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Cleaned up temporary files"
				LogInfo "Please restart your computer to apply the changes."
				Write-ConsoleStatus -Status success
			}
			catch
			{
				if ($_.Exception.Message -match 'github\.com|remote name could not be resolved|The remote server returned an error|Unable to connect|connection could not be established')
				{
					LogWarning "$DownloadFailedMessage Error: $($_.Exception.Message)"
					Write-Host "skipped!" -ForegroundColor Yellow
				}
				else
				{
					LogError "Failed to enable Revert Start Menu: $($_.Exception.Message)"
					Write-ConsoleStatus -Status failed
				}
			}
		}
		"Disable"
		{
			Write-ConsoleStatus -Action "Disabling Revert Start Menu"
			LogInfo "Disabling Revert Start Menu"

			if (-not $IsRevertStartMenuSupported)
			{
				Write-ConsoleStatus -Status success
				LogWarning $SupportedMessage
				return
			}

			try
			{
				# Create temp directory
				if (Test-Path $tempDir)
				{
					Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
				}
				New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
				
				# Download ViVeTool
				$zipPath = "$tempDir\ViVeTool.zip"
				Invoke-WebRequest $viveToolUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop | Out-Null
				LogInfo "Downloaded ViVeTool"
				
				# Extract
				Expand-Archive $zipPath -DestinationPath $tempDir -Force -ErrorAction Stop | Out-Null
				LogInfo "Extracted ViVeTool"
				
				# Run ViVeTool
				$viveExe = "$tempDir\ViVeTool.exe"
				if (-not (Test-Path $viveExe))
				{
					throw "ViVeTool.exe was not found after extraction"
				}
				$ViVeProcess = Start-Process $viveExe -ArgumentList "/enable /id:$featureId" -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
				if ($ViVeProcess.ExitCode -ne 0)
				{
					throw "ViVeTool returned exit code $($ViVeProcess.ExitCode)"
				}
				LogInfo "Applied ViVeTool setting to enable feature $featureId"
				
				# Cleanup
				Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
				LogInfo "Cleaned up temporary files"
				LogInfo "Please restart your computer to apply the changes."
				Write-ConsoleStatus -Status success
			}
			catch
			{
				if ($_.Exception.Message -match 'github\.com|remote name could not be resolved|The remote server returned an error|Unable to connect|connection could not be established')
				{
					LogWarning "$DownloadFailedMessage Error: $($_.Exception.Message)"
					Write-Host "skipped!" -ForegroundColor Yellow
				}
				else
				{
					LogError "Failed to disable Revert Start Menu: $($_.Exception.Message)"
					Write-ConsoleStatus -Status failed
				}
			}
		}
	}
}
#endregion UWP apps
