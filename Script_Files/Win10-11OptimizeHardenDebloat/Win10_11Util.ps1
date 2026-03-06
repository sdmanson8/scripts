<#
	.SYNOPSIS
	This Script is a PowerShell module for Windows 10 & Windows 11 fine-tuning and automating the routine tasks

	.VERSION
	2.0.1

	.DATE
	03.10.2021 - initial version
	24.02.2026 - updated to v2.0.0 with new functions and improvements
	04.03.2026 - updated to v2.0.1 with bug fixes and optimizations
	
	.AUTHOR
	sdmanson8

	.DESCRIPTION
	Place the "#" char before function if you don't want to run it
	Remove the "#" char before function if you want to run it
	Every tweak in the preset file has its corresponding function to restore the default settings

	.EXAMPLE Run the whole script
	.\Win10_11Util.ps1

	.EXAMPLE Run the script by specifying the module functions as an argument
	.\Win10_11Util.ps1 -Functions "DiagTrackService -Disable", "DiagnosticDataLevel -Minimal", UninstallUWPApps

	.NOTES
	Supported Windows 10 versions
	Version: 1607+
	Editions: Home/Pro/Enterprise

	Supported Windows 11 versions
	Version: 23H2+
	Editions: Home/Pro/Enterprise

	.NOTES
	To use the TAB completion for functions and their arguments dot source the Functions.ps1 script first:
		. .\Function.ps1 (with a dot at the beginning)

	.NOTES
	The below sources were used, and edited for my purposes:
	https://github.com/Disassembler0/Win10-Initial-Setup-Script
	https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
	https://github.com/farag2/Sophia-Script-for-Windows
	https://github.com/zoicware/RemoveWindowsAI/tree/main
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)

Clear-Host

#region InitialActions

# Get the OS version
#$osVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
$currentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

# Determine if it's Windows 10 or 11 based on build number (Windows 11 builds start at 22000)
if ([int]$currentBuild -ge 22000) {
	$osName = "Windows 11"
} else {
	$osName = "Windows 10"
}

$Host.UI.RawUI.WindowTitle = "WinUtil Script for $osName"

$RequiredFiles = @(
    "$PSScriptRoot\Localizations\Win10_11Util.psd1",
    "$PSScriptRoot\Module\Win10_11Util.psm1",
    "$PSScriptRoot\Manifest\Win10_11Util.psd1"
)

$MissingRequired = $RequiredFiles | Where-Object { -not (Test-Path -LiteralPath $_) }
$RegionFiles = Get-ChildItem -Path "$PSScriptRoot\Module\Regions" -Filter '*.psm1' -File -ErrorAction SilentlyContinue

if ($MissingRequired -or -not $RegionFiles) {
    Write-Host ""
    Write-Warning "There are missing files in the script folder. Please re-download the archive."
    Write-Host ""

    if ($MissingRequired) {
        Write-Warning "Missing required files:"
        $MissingRequired | ForEach-Object { Write-Warning "  $_" }
    }

    if (-not $RegionFiles) {
        Write-Warning "No region files found in: $PSScriptRoot\Module\Regions"
    }

    exit
}

Remove-Module -Name Win10_11Util -Force -ErrorAction Ignore
try
{
	Import-LocalizedData -BindingVariable Global:Localization -UICulture $PSUICulture -BaseDirectory $PSScriptRoot\Localizations -FileName Win10_11Util -ErrorAction Stop
}
catch
{
	Import-LocalizedData -BindingVariable Global:Localization -UICulture en-US -BaseDirectory $PSScriptRoot\Localizations -FileName Win10_11Util
}

# Checking whether script is the correct PowerShell version
try
{
	Import-Module -Name $PSScriptRoot\Manifest\Win10_11Util.psd1 -Force -ErrorAction Stop
}
catch [System.InvalidOperationException]
{
	Write-Warning -Message $Localization.UnsupportedPowerShell
	exit
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Preset configuration starts here
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

<#
	.SYNOPSIS
	Run the script by specifying functions as an argument
	 ,

	.EXAMPLE
	.\Win10_11Util.ps1 -Functions "DiagTrackService -Disable", "DiagnosticDataLevel -Minimal", UninstallUWPApps

	.NOTES
	Use commas to separate funtions

#>
if ($Functions)
{
	Invoke-Command -ScriptBlock {InitialActions}

	foreach ($Function in $Functions)
	{
		Invoke-Expression -Command $Function
	}

	# The "PostActions" and "Errors" functions will be executed at the end
	Invoke-Command -ScriptBlock {PostActions; Errors}

	exit
}

# Restart Script in Powershell 5.1 if running Powershell 7
Restart-Script -ScriptPath $MyInvocation.MyCommand.Path

# The mandatory checks. If you want to disable a warning message about whether the preset file was customized, remove the "-Warning" argument
InitialActions -Warning
#endregion InitialActions

#region Protection
# Create a restore point
# CreateRestorePoint
#endregion Protection

#region Initial Setup
# Check and Install WinGet
CheckWinGet

#Install Powershell 7
Update-Powershell

# Hide "About this Picture" on Desktop
Update-DesktopRegistry

#kill foreground applications
Stop-Foreground
#endregion Initial Setup

#region OS Hardening
#block remote commands
Disable-RemoteCommands

#prevent local Windows wireless exploitation
Suspend-AirstrikeAttack

#disable SMBv3 compression
Disable-SMBv3Compression

#harden MS Office security
Protect-MSOffice

#perform general OS hardening
Protect-OS

#Prevent Remote DLL Hijacking
Set-DLLHijackingPrevention

#Disable IPv6
Disable-IPv6

#Disable TCP Timestamps
Disable-TCPTimestamps

#Enable Biometrics Anti-Spoofing
Enable-BiometricsAntiSpoofing

#ensure registry path exists before setting properties
Update-RegistryPaths

#Disable AutoRun function
Disable-AutoRun

#disable AES ciphers
Disable-AESCiphers

#disable RC2 and RC4 ciphers
Disable-RC2RC4Ciphers

#disable Triple DES cipher
Disable-TripleDESCipher

#disable specified hash algorithms
Disable-HashAlgorithms

#configure Key Exchange Algorithms
Update-KeyExchanges

#configure SSL/TLS protocols
Update-Protocols

#configure cipher suites
Update-CipherSuites

#configure strong .NET authentication
Update-DotNetStrongAuth

#configure Event Log sizes
Update-EventLogSize

#configure Adobe Reader security
Update-AdobereaderDCSTIG

#kill foreground applications
Stop-Foreground
#endregion OS Hardening

#region Privacy & Telemetry
<#
	Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic
	Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore and affects Feedback Hub
#>
DiagTrackService -Disable

# Enable the "Connected User Experiences and Telemetry" service (DiagTrack), and allow the connection for the Unified Telemetry Client Outbound Traffic (default value)
# DiagTrackService -Enable

# Set the diagnostic data collection to minimum
DiagnosticDataLevel -Minimal

# Set the diagnostic data collection to default (default value)
# DiagnosticDataLevel -Default

# Turn off the Windows Error Reporting
ErrorReporting -Disable

# Turn on the Windows Error Reporting (default value)
# ErrorReporting -Enable

# Change the feedback frequency to "Never"
FeedbackFrequency -Never

# Change the feedback frequency to "Automatically" (default value)
# FeedbackFrequency -Automatically

# Turn off the diagnostics tracking scheduled tasks
ScheduledTasks -Disable

# Turn on the diagnostics tracking scheduled tasks (default value)
# ScheduledTasks -Enable

# Enable Offering of Malicious Software Removal Tool through Windows Update
# UpdateMSRT -Enable
# Disable Offering of Malicious Software Removal Tool through Windows Update
UpdateMSRT -Disable

# Enable Offering of drivers through Windows Update
# Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
UpdateDriver -Enable
# Disable Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
# Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
# UpdateDriver -Disable

# Enable Receiving updates for other Microsoft products via Windows Update
# UpdateMSProducts -Enable
# Disable Receiving updates for other Microsoft products via Windows Update
UpdateMSProducts -Disable

# Enable Windows Update automatic downloads
# UpdateAutoDownload -Enable
# Disable Windows Update automatic downloads
UpdateAutoDownload -Disable

# Enable Automatic restart after Windows Update installation
# UpdateRestart -Enable
# Disable Automatic restart after Windows Update installation
UpdateRestart -Disable

# Enable Nightly wake-up for Automatic Maintenance and Windows Updates
# MaintenanceWakeUp -Enable
# Disable Nightly wake-up for Automatic Maintenance and Windows Updates
MaintenanceWakeUp -Disable

# Enable Shared Experiences - Applicable since 1703. Not applicable to Server
# This setting can be set also via GPO, however doing so causes reset of Start Menu cache. See https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/145 for details
# SharedExperiences -Enable
# Disable Shared Experiences - Applicable since 1703. Not applicable to Server
# This setting can be set also via GPO, however doing so causes reset of Start Menu cache. See https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/145 for details
SharedExperiences -Disable

# Enable Clipboard History - Applicable since 1809. Not applicable to Server
ClipboardHistory -Enable
# Disable Clipboard History - Applicable since 1809. Not applicable to Server
# ClipboardHistory -Disable

# Enable Superfetch service
# Superfetch -Enable
# Disable Superfetch service
Superfetch -Disable

# Enable NTFS paths with length over 260 characters
NTFSLongPaths -Enable
# Disable NTFS paths with length over 260 characters
# NTFSLongPaths -Disable

# Enable Updating of NTFS last access timestamps
NTFSLastAccess -Enable
# Disable Updating of NTFS last access timestamps
# NTFSLastAccess -Disable

# Enable Sleep start menu and keyboard button
# SleepButton -Enable
# Disable Sleep start menu and keyboard button
SleepButton -Disable

# Enable Display and sleep mode timeouts
#SleepTimeout -Enable
# Disable Display and sleep mode timeouts
SleepTimeout -Disable

# Enable Fast Startup
# FastStartup -Enable
# Disable Fast Startup
FastStartup -Disable

# Enable Automatic reboot on crash (BSOD)
# AutoRebootOnCrash -Enable
# Disable Automatic reboot on crash (BSOD)
AutoRebootOnCrash -Disable

# Do not use sign-in info to automatically finish setting up device after an update
SigninInfo -Disable
# Use sign-in info to automatically finish setting up device after an update (default value)
# SigninInfo -Enable

# Do not let websites provide locally relevant content by accessing language list
LanguageListAccess -Disable
# Let websites provide locally relevant content by accessing language list (default value)
# LanguageListAccess -Enable

# Do not let apps show me personalized ads by using my advertising ID
AdvertisingID -Disable
# Let apps show me personalized ads by using my advertising ID (default value)
# AdvertisingID -Enable

# Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
WindowsWelcomeExperience -Hide
# Show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (default value)
# WindowsWelcomeExperience -Show

#Enable the Windows Web Experience Pack (used for widgets and lock screen features)
#LockWidgets -Enable
#disable the Windows Web Experience Pack (used for widgets and lock screen features)
LockWidgets -Disable

# Get tips and suggestions when I use Windows (default value)
WindowsTips -Enable
# Do not get tips and suggestions when I use Windows
# WindowsTips -Disable

# Hide from me suggested content in the Settings app
SettingsSuggestedContent -Hide
# Show me suggested content in the Settings app (default value)
# SettingsSuggestedContent -Show

# Turn off automatic installing suggested apps
AppsSilentInstalling -Disable
# Turn on automatic installing suggested apps (default value)
# AppsSilentInstalling -Enable

# Do not suggest ways to get the most out of Windows and finish setting up this device
WhatsNewInWindows -Disable
# Suggest ways to get the most out of Windows and finish setting up this device (default value)
# WhatsNewInWindows -Enable

# Don't let Microsoft use your diagnostic data for personalized tips, ads, and recommendations
TailoredExperiences -Disable
# Let Microsoft use your diagnostic data for personalized tips, ads, and recommendations (default value)
# TailoredExperiences -Enable

# Disable Bing search in Start Menu
BingSearch -Disable
# Enable Bing search in Start Menu (default value)
# BingSearch -Enable

# Do not show recommendations for tips, shortcuts, new apps, and more in Start menu
StartRecommendationsTips -Hide
# Show recommendations for tips, shortcuts, new apps, and more in Start menu (default value)
# StartRecommendationsTips -Show

# Do not show Microsoft account-related notifications on Start Menu in Start menu
StartAccountNotifications -Hide
# Show Microsoft account-related notifications on Start Menu in Start menu (default value)
# StartAccountNotifications -Show


# Enable WiFi Sense to share WiFi networks with contacts and connect to suggested open hotspots.
# WiFiSense -Enable
# Disable WiFi Sense to prevent automatic connections to open hotspots and sharing of WiFi networks with contacts.
WiFiSense -Disable
# Enable web search integration in system search (e.g., Cortana or Windows Search).
# WebSearch -Enable
# Disable web search to limit searches to local files, apps, and settings only.
WebSearch -Disable

# Enable activity history tracking across devices and timelines.
# ActivityHistory -Enable
# Disable activity history to prevent tracking and syncing of activities across devices.
# Note: The checkbox "Store my activity history on this device" ("Let Windows collect my activities from this PC" on older versions) remains checked even when the function is disabled.
ActivityHistory -Disable

# Enable device sensors such as accelerometer, gyroscope, and ambient light sensor.
Sensors -Enable
# Disable device sensors to restrict apps and system components from accessing sensor data.
# Sensors -Disable

# Enable location services to allow apps and system services to access device location.
# LocationService -Enable
# Disable location services to prevent apps and system services from accessing device location.
LocationService -Disable

# Enable automatic updates for offline maps to ensure maps are kept up to date.
# MapUpdates -Enable
# Disable automatic map updates to save bandwidth and storage.
MapUpdates -Disable

# Enable synchronization of preferred web languages across devices for a consistent browsing experience.
# WebLangList -Enable
# Disable synchronization of web languages to keep preferences local to the device.
WebLangList -Disable

# Enable access to the camera for apps and system services that use the Windows camera API.
Camera -Enable
# Disable camera access to prevent apps and services from using the device camera via standard Windows API.
# Note: Disabling this will not prevent direct hardware-level access by certain apps.
# Camera -Disable

# Enable microphone access for voice input and recording via the Windows audio API.
Microphone -Enable
# Disable microphone access to prevent apps and services from using the device microphone via standard Windows API.
# Note: Disabling this will not prevent direct hardware-level access by certain apps.
# Microphone -Disable

# Enable WAP Push messaging to receive service messages from mobile carriers.
WAPPush -Enable
# Disable WAP Push messaging to prevent receiving service messages from carriers.
# Note: This service is required for Microsoft Intune and other enterprise mobile management services.
# WAPPush -Disable

# Enable automatic clearing of recent files list upon system logout.
ClearRecentFiles -Enable
# Disable automatic clearing to retain recent files after logout.
# Note: Empties most recently used (MRU) lists such as the 'Recent Items' menu on the Start menu, jump lists, and file shortcuts in applications upon logout.
# ClearRecentFiles -Disable

# Enable tracking of recently accessed files to maintain a list of most recently used (MRU) items.
# RecentFiles -Enable
# Disable tracking to stop the creation of most recently used (MRU) items lists.
# Note: Prevents the creation of MRU lists such as the 'Recent Items' menu on the Start menu, jump lists, and file shortcuts in applications.
RecentFiles -Disable

# Enable access to voice activation from UWP apps
UWPVoiceActivation -Enable
# Disable access to voice activation from UWP apps
# UWPVoiceActivation -Disable

# Enable access to notifications from UWP apps
UWPNotifications -Enable
# Disable access to notifications from UWP apps
# UWPNotifications -Disable

# Enable access to account info from UWP apps
UWPAccountInfo -Enable
# Disable access to account info from UWP apps
# UWPAccountInfo -Disable

# Enable access to contacts from UWP apps
UWPContacts -Enable
# Disable access to contacts from UWP apps
# UWPContacts -Disable

# Enable access to calendar from UWP apps
UWPCalendar -Enable
# Disable access to calendar from UWP apps
# UWPCalendar -Disable

# Enable access to phone calls from UWP apps
UWPPhoneCalls -Enable
# Disable access to phone calls from UWP apps
# UWPPhoneCalls -Disable

# Enable access to call history from UWP apps
UWPCallHistory -Enable
# Disable access to call history from UWP apps
# UWPCallHistory -Disable

# Enable access to email from UWP apps
UWPEmail -Enable
# Disable access to email from UWP apps
# UWPEmail -Disable

# Enable access to tasks from UWP apps
UWPTasks -Enable
# Disable access to tasks from UWP apps
# UWPTasks -Disable

# Enable access to messaging (SMS, MMS) from UWP apps
UWPMessaging -Enable
# Disable access to messaging (SMS, MMS) from UWP apps
# UWPMessaging -Disable

# Enable access to radios (e.g. Bluetooth) from UWP apps
UWPRadios -Enable
# Disable access to radios (e.g. Bluetooth) from UWP apps
# UWPRadios -Disable

# Enable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
UWPOtherDevices -Enable
# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
# UWPOtherDevices -Disable

# Enable access to diagnostic information from UWP apps
UWPDiagInfo -Enable
# Disable access to diagnostic information from UWP apps
# UWPDiagInfo -Disable

# Enable access to libraries and file system from UWP apps
UWPFileSystem -Enable
# Disable access to libraries and file system from UWP apps
# UWPFileSystem -Disable

# Enable UWP apps swap file
UWPSwapFile -Enable
# Disable UWP apps swap file
# This disables creation and use of swapfile.sys and frees 256 MB of disk space.
# Swapfile.sys is used only by UWP apps. The tweak has no effect on the real swap in pagefile.sys.
UWPSwapFile -Disable

# Enable PowerShell 7 Telemetry (default value)
# Powershell7Telemetry -Enable
# Disable PowerShell 7 Telemetry 
Powershell7Telemetry -Disable

#endregion Privacy & Telemetry

#region System Tweaks
# Enable Cross-Device Resume (default value)
# CrossDeviceResume -Enable
# Disable Cross-Device Resume 
CrossDeviceResume -Disable

# Enable Multiplane Overlay (default value)
# MultiplaneOverlay -Enable
# Disable Multiplane Overlay 
MultiplaneOverlay -Disable

# Enable Modern Standby fix (default value)
# StandbyFix -Enable
# Disable Modern Standby fix 
StandbyFix -Disable

# Enable S3 Sleep
S3Sleep -Enable
# Disable S3 Sleep (default value)
# S3Sleep -Disable

# Enable Explorer Automatic Folder Discovery
ExplorerAutoDiscovery -Enable
# Disable Explorer Automatic Folder Discovery (default value)
# ExplorerAutoDiscovery -Disable

# Enable Windows Platform Binary Table (WPBT) (default value)
# WPBT -Enable
# Disable Windows Platform Binary Table (WPBT) 
WPBT -Disable

# Run Disk Cleanup
DiskCleanup

# Apply recommended startup types to Windows services
ServicesManual -Enable
# Restore Windows services to their original startup types (default value)
# ServicesManual -Disable

# CAUTION: Blocking Adobe network access may prevent license validation, disable Creative Cloud syncing, break cloud-based features, trigger subscription errors, and may violate Adobe license terms
# Enable Adobe Network Block (default value)
AdobeNetworkBlock -Enable
# Disable Adobe Network Block 
# AdobeNetworkBlock -Disable

# CAUTION: Blocking Razer software installation may prevent Razer Synapse from updating, disable RGB/macro functionality, stop firmware updates, and cause limited device features
# Enable Razer Software Block (default value)
RazerBlock -Enable
# Disable Razer Software Block 
# RazerBlock -Disable

# CAUTION: Brave Debloat disables rewards, wallet, VPN, and AI chat features - only use if you want to remove these features completely
# Enable Brave Debloat (default value)
BraveDebloat -Enable
# Disable Brave Debloat 
# BraveDebloat -Disable

# CAUTION: Disabling Fullscreen Optimizations may reduce gaming performance in some applications - use only for troubleshooting
# Enable Fullscreen Optimizations (default value)
FullscreenOptimizations -Enable
# Disable Fullscreen Optimizations 
# FullscreenOptimizations -Disable

# CAUTION: Teredo is an IPv6 tunneling protocol needed for NAT traversal - disabling may break Xbox Live and certain peer-to-peer applications
# Enable Teredo (default value)
# Teredo -Enable 
# Disable Teredo 
Teredo -Disable
#endregion System Tweaks

#region UI & Personalization

# Enable Full directory path in Explorer title bar
ExplorerTitleFullPath -Enable
# Disable Full directory path in Explorer title bar
# ExplorerTitleFullPath -Disable

# Enable Folder merge conflicts
FolderMergeConflicts -Enable
# Disable Folder merge conflicts
# FolderMergeConflicts -Disable

# Enable All folders in Explorer navigation pane
NavPaneAllFolders -Enable
# Disable All folders in Explorer navigation pane
# NavPaneAllFolders -Disable

# Enable Libraries in Explorer navigation pane
NavPaneLibraries -Enable
# Disable Libraries in Explorer navigation pane
# NavPaneLibraries -Disable

# Enable Launch folder windows in a separate process
# FldrSeparateProcess -Enable
# Disable Launch folder windows in a separate process
FldrSeparateProcess -Disable

# Enable Restore previous folder windows at logon
# RestoreFldrWindows -Enable
# Disable Restore previous folder windows at logon
RestoreFldrWindows -Disable

# Enable Coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
EncCompFilesColor -Enable
# Disable Coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
# EncCompFilesColor -Disable

# Enable Sharing Wizard
# SharingWizard -Enable
# Disable Sharing Wizard
SharingWizard -Disable

# Enable Item selection checkboxes
# SelectCheckboxes -Enable
# Disable Item selection checkboxes
SelectCheckboxes -Disable

# Enable Sync provider notifications
# SyncNotifications -Enable
# Disable Sync provider notifications
SyncNotifications -Disable

# Enable recently and frequently used item shortcuts in Explorer
# RecentShortcuts -Enable
# Disable recently and frequently used item shortcuts in Explorer
# Note: This is only UI tweak to hide the shortcuts. In order to stop creating most recently used (MRU) items lists everywhere, use privacy tweak 'DisableRecentFiles' instead.
RecentShortcuts -Disable

# Enable Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
# BuildNumberOnDesktop -Enable
# Disable Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
BuildNumberOnDesktop -Disable

# Enable 'Share' context menu item. Applicable since 1709
ShareMenu -Enable
# Disable 'Share' context menu item. Applicable since 1709
# ShareMenu -Disable

# Enable thumbnails, show only file extension icons
# Thumbnails -Enable
# Disable thumbnails, show only file extension icons
Thumbnails -Disable

# Enable creation of thumbnail cache files
# ThumbnailCache -Enable
# Disable creation of thumbnail cache files
ThumbnailCache -Disable

# Enable creation of Thumbs.db thumbnail cache files on network folders
# ThumbsDBOnNetwork -Enable
# Disable creation of Thumbs.db thumbnail cache files on network folders
ThumbsDBOnNetwork -Disable

# Show the "This PC" icon on Desktop
# ThisPC -Show
# Hide the "This PC" icon on Desktop (default value)
ThisPC -Hide

# Do not use item check boxes
CheckBoxes -Disable
# Use check item check boxes (default value)
# CheckBoxes -Enable

# Show hidden files, folders, and drives
# HiddenItems -Enable
# Do not show hidden files, folders, and drives (default value)
HiddenItems -Disable

# Enable Protected operating system files
# SuperHiddenFiles -Enable
# Disable Protected operating system files
SuperHiddenFiles -Disable

# Show file name extensions
# FileExtensions -Show
# Hide file name extensions (default value)
FileExtensions -Hide

# Show folder merge conflicts
MergeConflicts -Show
# Hide folder merge conflicts (default value)
# MergeConflicts -Hide

# Open File Explorer to "This PC"
OpenFileExplorerTo -ThisPC
# Open File Explorer to Quick access (default value)
# OpenFileExplorerTo -QuickAccess
# Open File Explorer to Downloads
# OpenFileExplorerTo -Downloads

# Disable File Explorer compact mode (default value)
FileExplorerCompactMode -Disable
# Enable File Explorer compact mode
# FileExplorerCompactMode -Enable

# Do not show sync provider notification within File Explorer
OneDriveFileExplorerAd -Hide
# Show sync provider notification within File Explorer (default value)
# OneDriveFileExplorerAd -Show

# When I snap a window, do not show what I can snap next to it
SnapAssist -Disable
# When I snap a window, show what I can snap next to it (default value)
# SnapAssist -Enable

# Show the file transfer dialog box in the detailed mode
FileTransferDialog -Detailed
# Show the file transfer dialog box in the compact mode (default value)
# FileTransferDialog -Compact

# Display the recycle bin files delete confirmation dialog
RecycleBinDeleteConfirmation -Enable
# Do not display the recycle bin files delete confirmation dialog (default value)
# RecycleBinDeleteConfirmation -Disable

# Hide recently used files in Quick access
QuickAccessRecentFiles -Hide
# Show recently used files in Quick access (default value)
# QuickAccessRecentFiles -Show
# Hide frequently used folders in Quick access
QuickAccessFrequentFolders -Hide
# Show frequently used folders in Quick access (default value)
# QuickAccessFrequentFolders -Show

# Hide the Meet Now icon in the notification area
MeetNow -Hide
# Show the Meet Now icon in the notification area (default value)
# MeetNow -Show

# Disable "News and Interests" on the taskbar
NewsInterests -Disable
# Enable "News and Interests" on the taskbar (default value)
# NewsInterests -Enable

# Set the taskbar alignment to the center (default value)
# TaskbarAlignment -Center
# Set the taskbar alignment to the left
TaskbarAlignment -Left

# Hide the widgets icon on the taskbar
TaskbarWidgets -Hide
# Show the widgets icon on the taskbar (default value)
# TaskbarWidgets -Show

# Hide the search on the taskbar
TaskbarSearch -Hide
# Show the search icon on the taskbar
# TaskbarSearch -SearchIcon
# Show the search box on the taskbar (default value)
# TaskbarSearch -SearchBox

# Hide search highlights
SearchHighlights -Hide
# Show search highlights (default value)
# SearchHighlights -Show

# Hide the Task view button from the taskbar
TaskViewButton -Hide
# Show the Task view button on the taskbar (default value)
# TaskViewButton -Show

# Combine taskbar buttons and always hide labels (default value)
TaskbarCombine -Always
# Combine taskbar buttons and hide labels when taskbar is full
# TaskbarCombine -Full
# Combine taskbar buttons and never hide labels
# TaskbarCombine -Never

# Unpin Microsoft Edge, Microsoft Store, Mail, and Outlook shortcuts from the taskbar
# Microsoft Edge, Microsoft Store Outlook
UnpinTaskbarShortcuts -Shortcuts Edge, Store, Outlook, Mail

# Enable end task in taskbar by right click
TaskbarEndTask -Enable
# Disable end task in taskbar by right click (default value)
# TaskbarEndTask -Disable

# View the Control Panel icons by large icons
# ControlPanelView -LargeIcons
# View the Control Panel icons by small icons
# ControlPanelView -SmallIcons
# View the Control Panel icons by category (default value)
ControlPanelView -Category

# Set the default Windows mode to dark
WindowsColorMode -Dark
# Set the default Windows mode to light (default value)
# WindowsColorMode -Light

# Set the default app mode to dark
AppColorMode -Dark
# Set the default app mode to light (default value)
# AppColorMode -Light

# Hide first sign-in animation after the upgrade
FirstLogonAnimation -Disable
# Show first sign-in animation after the upgrade (default value)
# FirstLogonAnimation -Enable

# Set the quality factor of the JPEG desktop wallpapers to maximum
JPEGWallpapersQuality -Max
# Set the quality factor of the JPEG desktop wallpapers to default
# JPEGWallpapersQuality -Default

# Do not add the "- Shortcut" suffix to the file name of created shortcuts
ShortcutsSuffix -Disable
# Add the "- Shortcut" suffix to the file name of created shortcuts (default value)
# ShortcutsSuffix -Enable

# Enable Shortcut icon arrow
ShortcutArrow -Enable
# Disable Shortcut icon arrow
# ShortcutArrow -Disable

# Use the Print screen button to open screen snipping
PrtScnSnippingTool -Enable
# Do not use the Print screen button to open screen snipping (default value)
# PrtScnSnippingTool -Disable

# Let me use a different input method for each app window
# AppsLanguageSwitch -Enable
# Do not use a different input method for each app window (default value)
AppsLanguageSwitch -Disable

# When I grab a windows's title bar and shake it, minimize all other windows
AeroShaking -Enable
# When I grab a windows's title bar and shake it, don't minimize all other windows (default value)
# AeroShaking -Disable

# Do not group files and folder in the Downloads folder
FolderGroupBy -None
# Group files and folder by date modified in the Downloads folder (default value)
# FolderGroupBy -Default

# Do not expand to open folder on navigation pane (default value)
NavigationPaneExpand -Disable
# Expand to open folder on navigation pane
# NavigationPaneExpand -Enable

# Remove Recommended section in Start Menu. Applicable only to Enterprise and Education editions, but not to IoT Enterprise
StartRecommendedSection -Hide
# Show Recommended section in Start Menu (default value). Applicable only to Enterprise and Education editions, but not to IoT Enterprise
# StartRecommendedSection -Show
#endregion UI & Personalization

#region OneDrive
# Uninstall OneDrive. The OneDrive user folder won't be removed
OneDrive -Uninstall
# Install OneDrive 64-bit (default value)
# OneDrive -Install

# Install OneDrive 64-bit all users to %ProgramFiles% depending which installer is triggered
# OneDrive -Install -AllUsers
#endregion OneDrive

#region System
# Enable Lock screen
LockScreen -Enable
# Disable Lock screen
# LockScreen -Disable

# Enable Lock screen - Applicable since 1903
LockScreenRS1 -Enable
# Disable Lock screen - Applicable since 1903
# LockScreenRS1 -Disable

# Enable Network options from Lock Screen
NetworkFromLockScreen -Enable
# Disable Network options from Lock Screen
# NetworkFromLockScreen -Disable

# Enable Shutdown options from Lock Screen
ShutdownFromLockScreen -Enable
# Disable Shutdown options from Lock Screen
# ShutdownFromLockScreen -Disable

# Enable Lock screen Blur - Applicable since 1903
LockScreenBlur -Enable
# Disable Lock screen Blur - Applicable since 1903
# LockScreenBlur -Disable

# Enable Task Manager details - Applicable since 1607
TaskManagerDetails -Enable
# Disable Task Manager details - Applicable since 1607
# TaskManagerDetails -Disable

# Enable File operations details
FileOperationsDetails -Enable
# Disable File operations details
# FileOperationsDetails -Disable

# Enable File delete confirmation dialog
FileDeleteConfirm -Enable
# Disable File delete confirmation dialog
# FileDeleteConfirm -Disable

# Enable All tray icons
# TrayIcons -Enable
# Disable All tray icons
TrayIcons -Disable

# Enable 'Search for app in store for unknown extensions'
# SearchAppInStore -Enable
# Disable 'Search for app in store for unknown extensions'
SearchAppInStore -Disable

# Enable 'How do you want to open this file?' prompt
# NewAppPrompt -Enable
# Disable 'How do you want to open this file?' prompt
NewAppPrompt -Disable

# Enable 'Recently added' list from the Start Menu
# RecentlyAddedApps -Enable
# Disable 'Recently added' list from the Start Menu
RecentlyAddedApps -Disable

# Enable 'Most used' apps list from the Start Menu - Applicable until 1703 (hidden by default since then)
# MostUsedApps -Enable
# Disable 'Most used' apps list from the Start Menu - Applicable until 1703 (hidden by default since then)
MostUsedApps -Disable

# Adjusts visual effects to Performance
VisualFX -Performance
# Adjusts visual effects to Appearance
# VisualFX -Appearance

# Enable Window title bar color according to prevalent background color
TitleBarColor -Enable
# Disable Window title bar color according to prevalent background color
# TitleBarColor -Disable

# Enable Enhanced pointer precision
EnhPointerPrecision -Enable
# Disable Enhanced pointer precision
# EnhPointerPrecision -Disable

# Enable Play Windows Startup sound
StartupSound -Enable
# Disable Play Windows Startup sound
# StartupSound -Disable

# Enable Change sound scheme
# ChangingSoundScheme -Enable
# Disable Change sound scheme
ChangingSoundScheme -Disable

# Enable Verbose startup/shutdown status messages
VerboseStatus -Enable
# Disable Verbose startup/shutdown status messages
# VerboseStatus -Disable

# Turn on Storage Sense
StorageSense -Enable
# Turn off Storage Sense (default value)
# StorageSense -Disable

# Disable hibernation. It isn't recommended to turn off for laptops
Hibernation -Disable
# Enable hibernate (default value)
# Hibernation -Enable

# Disable the Windows 260 characters path limit
Win32LongPathLimit -Disable
# Enable the Windows 260 character path limit (default value)
# Win32LongPathLimit -Enable

# Display Stop error code when BSoD occurs
BSoDStopError -Enable
# Do not display stop error code when BSoD occurs (default value)
# BSoDStopError -Disable

# Choose when to be notified about changes to your computer: never notify
AdminApprovalMode -Never
# Choose when to be notified about changes to your computer: notify me only when apps try to make changes to my computer (default value)
# AdminApprovalMode -Default

# Turn off Delivery Optimization
DeliveryOptimization -Disable
# Turn on Delivery Optimization (default value)
# DeliveryOptimization -Enable

# Do not let Windows manage my default printer
WindowsManageDefaultPrinter -Disable
# Let Windows manage my default printer (default value)
# WindowsManageDefaultPrinter -Enable

<#
	Disable the Windows features using the pop-up dialog box
	If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not disable the "Media Features" feature
#>
WindowsFeatures -Disable
# Enable the Windows features using the pop-up dialog box
# WindowsFeatures -Enable

<#
	Uninstall optional features using the pop-up dialog box
	If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not uninstall the "Media Features" feature
#>
WindowsCapabilities -Uninstall
# Install optional features using the pop-up dialog box
# WindowsCapabilities -Install

# Set current network profile to Private
CurrentNetwork -Private
# Set current network profile to Public
# CurrentNetwork -Public

# Set Unknown network profile to Private
UnknownNetworks -Private
# Set unknown networks profile to Public
# UnknownNetworks -Public

# Enable Automatic installation of network devices
NetDevicesAutoInst -Enable
# Disable Automatic installation of network devices
# NetDevicesAutoInst -Disable

# Enable Home Groups services - Not applicable since 1803. Not applicable to Server
# HomeGroups -Enable
# Disable Home Groups services - Not applicable since 1803. Not applicable to Server
HomeGroups -Disable

# Enable Obsolete SMB 1.0 protocol - Disabled by default since 1709
# SMB1 -Enable
# Disable Obsolete SMB 1.0 protocol - Disabled by default since 1709
SMB1 -Disable

# Enable file and printer sharing
SMBServer -Enable
# Completely disable file and printer sharing, if disabled it leaves the system able to connect to another SMB server as a client
# Note: Do not Disable if you plan to use Docker and Shared Drives (as it uses SMB internally), see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/216
# SMBServer -Disable

# Enable NetBIOS over TCP/IP on all currently installed network interfaces
# NetBIOS -Enable
# Disable NetBIOS over TCP/IP on all currently installed network interfaces
NetBIOS -Disable

# Enable Link-Local Multicast Name Resolution (LLMNR) protocol
LLMNR -Enable
# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
# LLMNR -Disable

# Enable Client for Microsoft Networks for all installed network interfaces
MSNetClient -Enable
# Disable Client for Microsoft Networks for all installed network interfaces
# MSNetClient -Disable

# Enable Quality of Service (QoS) packet scheduler for all installed network interfaces
QoS -Enable
# Disable Quality of Service (QoS) packet scheduler for all installed network interfaces
# QoS -Disable

# Enable Network Connectivity Status Indicator active test
NCSIProbe -Enable
# Disable Network Connectivity Status Indicator active test
# Note: This may reduce the ability of OS and other components to determine internet access, however protects against a specific type of zero-click attack.
# See https://github.com/Disassembler0/Win10-Initial-Setup-Script/pull/111 for details
# NCSIProbe -Disable

# Enable Internet Connection Sharing (e.g. mobile hotspot)
ConnectionSharing -Enable
# Disable Internet Connection Sharing (e.g. mobile hotspot)
# ConnectionSharing -Disable

# Receive updates for other Microsoft products
UpdateMicrosoftProducts -Enable
# Do not receive updates for other Microsoft products (default value)
# UpdateMicrosoftProducts -Disable

# Notify me when a restart is required to finish updating
RestartNotification -Show
# Do not notify me when a restart is required to finish updating (default value)
# RestartNotification -Hide

# Restart as soon as possible to finish updating
# RestartDeviceAfterUpdate -Enable
# Don't restart as soon as possible to finish updating (default value)
RestartDeviceAfterUpdate -Disable

# Automatically adjust active hours for me based on daily usage
ActiveHours -Automatically
# Manually adjust active hours for me based on daily usage (default value)
# ActiveHours -Manually

# Do not get the latest updates as soon as they're available (default value)
WindowsLatestUpdate -Disable
# Get the latest updates as soon as they're available
# WindowsLatestUpdate -Enable

# Set power plan on "High performance". It isn't recommended to turn on for laptops
PowerPlan -High
# Set power plan on "Balanced" (default value)
# PowerPlan -Balanced

# Do not allow the computer to turn off the network adapters to save power. It isn't recommended to turn off for laptops
NetworkAdaptersSavePower -Disable
# Allow the computer to turn off the network adapters to save power (default value)
# NetworkAdaptersSavePower -Enable

# Override for default input method: English
InputMethod -English
# Override for default input method: use language list (default value)
# InputMethod -Default

<#
	Change user folders location to the root of any drive using the interactive menu
	User files or folders won't be moved to a new location. Move them manually
	They're located in the %USERPROFILE% folder by default
#>
# Set-UserShellFolderLocation -Root
<#
	Select folders for user folders location manually using a folder browser dialog
	User files or folders won't be moved to a new location. Move them manually
	They're located in the %USERPROFILE% folder by default
#>
# Set-UserShellFolderLocation -Custom
<#
	Change user folders location to the default values
	User files or folders won't be moved to the new location. Move them manually
	They're located in the %USERPROFILE% folder by default
#>
# Set-UserShellFolderLocation -Default

# Use the latest installed .NET runtime for all apps
LatestInstalled.NET -Enable
# Do not use the latest installed .NET runtime for all apps (default value)
# LatestInstalled.NET -Disable

<#
	Save screenshots by pressing Win+PrtScr on the Desktop
	The function will be applied only if the preset is configured to remove the OneDrive application, or the app was already uninstalled
	Otherwise the backup functionality for the "Desktop" and "Pictures" folders in OneDrive breaks
#>
# WinPrtScrFolder -Desktop
# Save screenshots by pressing Win+PrtScr in the Pictures folder (default value)
# WinPrtScrFolder -Default

<#
	Run troubleshooter automatically, then notify me
	In order this feature to work Windows level of diagnostic data gathering will be set to "Optional diagnostic data", and the error reporting feature will be turned on
#>
RecommendedTroubleshooting -Automatically
<#
	Ask me before running troubleshooter (default value)
	In order this feature to work Windows level of diagnostic data gathering will be set to "Optional diagnostic data"
#>
# RecommendedTroubleshooting -Default

# Disable and delete reserved storage after the next update installation
ReservedStorage -Disable
# Enable reserved storage (default value)
# ReservedStorage -Enable

# Disable help lookup via F1
F1HelpPage -Disable
# Enable help lookup via F1 (default value)
# F1HelpPage -Enable

# Enable Num Lock at startup
NumLock -Enable
# Disable Num Lock at startup (default value)
# NumLock -Disable

# Disable Caps Lock
# CapsLock -Disable
# Enable Caps Lock (default value)
# CapsLock -Enable

# Turn off pressing the Shift key 5 times to turn Sticky keys
StickyShift -Disable
# Turn on pressing the Shift key 5 times to turn Sticky keys (default value)
# StickyShift -Enable

# Don't use AutoPlay for all media and devices
#Autoplay -Disable
# Use AutoPlay for all media and devices (default value)
Autoplay -Enable

# Automatically saving my restartable apps and restart them when I sign back in
#SaveRestartableApps -Enable
# Turn off automatically saving my restartable apps and restart them when I sign back in (default value)
SaveRestartableApps -Disable

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
NetworkDiscovery -Enable
# Disable "Network Discovery" and "File and Printers Sharing" for workgroup networks (default value)
# NetworkDiscovery -Disable

<#
	Register app, calculate hash, and associate with an extension with the "How do you want to open this" pop-up hidden

	Set-Association -ProgramPath "C:\SumatraPDF.exe" -Extension .pdf -Icon "shell32.dll,100"
	Set-Association -ProgramPath "%ProgramFiles%\Notepad++\notepad++.exe" -Extension .txt -Icon "%ProgramFiles%\Notepad++\notepad++.exe,0"
	Set-Association -ProgramPath MSEdgeMHT -Extension .html
#>
# Set-Association -ProgramPath "%ProgramFiles%\Notepad++\notepad++.exe" -Extension .txt -Icon "%ProgramFiles%\Notepad++\notepad++.exe,0"

# Windows Application_Associations.json
# Export all Windows associations into Application_Associations.json file to script root folder
# Export-Associations

<#
	 Windows Application_Associations.json
	 Application_Associations.json,

	Import all Windows associations from an Application_Associations.json file
	You need to install all apps according to an exported Application_Associations.json file to restore all associations
#>
# Import-Associations

# Set Windows Terminal as default terminal app to host the user interface for command-line applications
DefaultTerminalApp -WindowsTerminal
# Set Windows Console Host as default terminal app to host the user interface for command-line applications (default value)
# DefaultTerminalApp -ConsoleHost

# Install the latest Microsoft Visual C++ Redistributable Packages 2015–2022 (x86/x64)
# Install-VCRedist -Redistributables 2015_2022_x86, 2015_2022_x64

# Install the latest .NET Desktop Runtime 8, 9 x64
# Install-DotNetRuntimes -Runtimes NET8x64, NET9x64

# List Microsoft Edge channels to prevent desktop shortcut creation upon its update
PreventEdgeShortcutCreation -Channels Stable, Beta, Dev, Canary
# Do not prevent desktop shortcut creation upon Microsoft Edge update (default value)
# PreventEdgeShortcutCreation -Disable

# Back up the system registry to %SystemRoot%\System32\config\RegBack folder when PC restarts and create a RegIdleBackup in the Task Scheduler task to manage subsequent backups
# RegistryBackup -Enable
# Do not back up the system registry to %SystemRoot%\System32\config\RegBack folder (default value)
# RegistryBackup -Disable
#endregion System

#region WSL
<#
	Enable Windows Subsystem for Linux (WSL), install the latest WSL Linux kernel version, and a Linux distribution using a pop-up form
	The "Receive updates for other Microsoft products" setting will enabled automatically to receive kernel updates
#>
# Install-WSL
#endregion WSL

#region Start menu
# Show default Start layout (default value)
# StartLayout -Default
# Show more pins on Start
StartLayout -ShowMorePins
# Show more recommendations on Start
# StartLayout -ShowMoreRecommendations
#endregion Start menu

#region UWP apps
# Install Copilot App
#Copilot -Install
# Uninstall Copilot App
Copilot -Uninstall

# Install UWP apps using the pop-up dialog box
# UWPApps -Install
# Uninstall UWP apps using the pop-up dialog box
UWPApps -Uninstall
<#
	Uninstall UWP apps for all users using the pop-up dialog box
	If the "For All Users" is checked apps packages will not be installed for new users
#>
# UWPApps -ForAllUsers

# Disable Cortana autostarting
CortanaAutostart -Disable
# Enable Cortana autostarting (default value)
# CortanaAutostart -Enable

# Enable New Outlook (default value)
# NewOutlook -Enable
# Disable New Outlook 
NewOutlook -Disable

# CAUTION: Disabling Background Apps prevents apps from running in the background - may affect notifications, updates, and sync functionality
# Enable Background Apps (default value)
BackgroundApps -Enable
# Disable Background Apps 
# BackgroundApps -Disable

# CAUTION: Disabling Notifications will completely turn off Windows notifications - you won't receive app alerts, system warnings, reminders, or calendar events
# Enable Notification Tray/Calendar (default value)
Notifications -Enable
# Disable Notification Tray/Calendar 
# Notifications -Disable

# CAUTION: Edge Debloat enforces multiple Group Policy settings that may affect Edge functionality including telemetry, personalization, shopping assistant, collections, rewards, and Copilot
# Enable Edge Debloat (default value)
# EdgeDebloat -Enable
# Disable Edge Debloat 
EdgeDebloat -Disable

# CAUTION: Reverting the Start Menu may break future Windows updates that depend on the new layout and requires additional tooling
# Enable Revert Start Menu (revert to original Start Menu from 24H2)
# RevertStartMenu -Enable
# Disable Revert Start Menu (restore new Start Menu) (default value)
RevertStartMenu -Disable
#endregion UWP apps

#region Gaming
<#
	Disable Xbox Game Bar
	To prevent popping up the "You'll need a new app to open this ms-gamingoverlay" warning, you need to disable the Xbox Game Bar app, even if you uninstalled it before
#>
XboxGameBar -Disable
# Enable Xbox Game Bar (default value)
# XboxGameBar -Enable

# Disable Xbox Game Bar tips
# Xbox Game Bar
XboxGameTips -Disable
# Enable Xbox Game Bar tips (default value)
# XboxGameTips -Enable

# Choose an app and set the "High performance" graphics performance for it. Only if you have a dedicated GPU
#Set-AppGraphicsPerformance

<#
	Turn on hardware-accelerated GPU scheduling. Restart needed
	Only if you have a dedicated GPU and WDDM verion is 2.7 or higher
#>
GPUScheduling -Enable
# Turn off hardware-accelerated GPU scheduling (default value). Restart needed
# GPUScheduling -Disable
#endregion Gaming

#region Scheduled tasks
<#
	Create the "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates.
	A native interactive toast notification pops up every 30 days. You have to enable Windows Script Host in order to make the function work
#>
#CleanupTask -Register
# Delete the "Windows Cleanup" and "Windows Cleanup Notification" scheduled tasks for cleaning up Windows unused files and updates
# CleanupTask -Delete

<#
	Create the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder
	The task will wait until the Windows Updates service finishes running. The task runs every 90 days. You have to enable Windows Script Host in order to make the function work
#>
#SoftwareDistributionTask -Register
# Delete the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder
# SoftwareDistributionTask -Delete

<#
	Create the "Temp" scheduled task for cleaning up the %TEMP% folder
	Only files older than one day will be deleted. The task runs every 60 days. You have to enable Windows Script Host in order to make the function work
#>
#TempTask -Register
# Delete the "Temp" scheduled task for cleaning up the %TEMP% folder
#endregion Scheduled tasks

#region Microsoft Defender & Security
# Enable Microsoft Defender Exploit Guard network protection
NetworkProtection -Enable
# Disable Microsoft Defender Exploit Guard network protection (default value)
# NetworkProtection -Disable

# Enable detection for potentially unwanted applications and block them
PUAppsDetection -Enable
# Disable detection for potentially unwanted applications and block them (default value)
# PUAppsDetection -Disable

# Enable sandboxing for Microsoft Defender
DefenderSandbox -Enable
# Disable sandboxing for Microsoft Defender (default value)
# DefenderSandbox -Disable

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
DismissSmartScreenFilter

# Create the "Process Creation" ustom view in the Event Viewer to log executed processes and their arguments
EventViewerCustomView -Enable
# Remove the "Process Creation" custom view in the Event Viewer to log executed processes and their arguments (default value)
# EventViewerCustomView -Disable

# Enable logging for all Windows PowerShell modules
PowerShellModulesLogging -Enable
# Disable logging for all Windows PowerShell modules (default value)
# PowerShellModulesLogging -Disable

# Enable logging for all PowerShell scripts input to the Windows PowerShell event log
PowerShellScriptsLogging -Enable
# Disable logging for all PowerShell scripts input to the Windows PowerShell event log (default value)
# PowerShellScriptsLogging -Disable

# Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe
AppsSmartScreen -Disable
# Microsoft Defender SmartScreen marks downloaded files from the Internet as unsafe (default value)
# AppsSmartScreen -Enable

# Disable the Attachment Manager marking files that have been downloaded from the Internet as unsafe
SaveZoneInformation -Disable
# Enable the Attachment Manager marking files that have been downloaded from the Internet as unsafe (default value)
# SaveZoneInformation -Enable

# Disable Windows Script Host. Blocks WSH from executing .js and .vbs files
# WindowsScriptHost -Disable
# Enable Windows Script Host (default value)
# WindowsScriptHost -Enable

# Enable Windows Sandbox. Applicable only to Professional, Enterprise and Education editions
# WindowsSandbox -Enable
# Disable Windows Sandbox (default value). Applicable only to Professional, Enterprise and Education editions
# WindowsSandbox -Disable

<#
	Enable DNS-over-HTTPS for IPv4
	The valid IPv4 addresses: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9
#>
# DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1
# Disable DNS-over-HTTPS for IPv4 (default value)
DNSoverHTTPS -Disable

# Enable Local Security Authority protection to prevent code injection
# LocalSecurityAuthority -Enable
# Disable Local Security Authority protection (default value)
LocalSecurityAuthority -Disable

# Enable sharing mapped drives between users
SharingMappedDrives -Enable
# Disable sharing mapped drives between users
SharingMappedDrives -Disable

# Enable Firewall
Firewall -Enable
# Disable Firewall
# Firewall -Disable

# Show Windows Defender SysTray icon
# DefenderTrayIcon -Enable
# Hide Windows Defender SysTray icon
DefenderTrayIcon -Disable

# Enable Windows Defender Cloud
DefenderCloud -Enable
# Disable Windows Defender Cloud
# DefenderCloud -Disable

# Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Applicable since 1803
# Warning: This may cause old applications and drivers to crash or even cause BSOD
# Problems were confirmed with old video drivers (Intel HD Graphics for 2nd gen., Radeon HD 6850), and old antivirus software (Kaspersky Endpoint Security 10.2, 11.2)
# CIMemoryIntegrity -Enable
# Disable Core Isolation Memory Integrity
CIMemoryIntegrity -Disable

# Enable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
# Not supported on VMs and VDI environment. Check requirements on https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard
DefenderAppGuard -Enable
# Disable Windows Defender Application Guard
# DefenderAppGuard -Disable

# Show Account Protection warning in Defender
# AccountProtectionWarn -Enable
# Hide Account Protection warning in Defender about not using a Microsoft account
AccountProtectionWarn -Disable

# Enable blocking of downloaded files (i.e. storing zone information)
# DownloadBlocking -Enable
# Disable blocking of downloaded files
DownloadBlocking -Disable

# Enable F8 boot menu options
F8BootMenu -Enable
# Disable F8 boot menu options
# F8BootMenu -Disable

# Enable automatic recovery mode during boot
# BootRecovery -Enable

# Disable automatic recovery mode during boot
# This causes boot process to always ignore startup errors and attempt to boot normally
# It is still possible to interrupt the boot and enter recovery mode manually. In order to disable even that, apply also DisableRecoveryAndReset tweak
BootRecovery -Disable

# Set Data Execution Prevention (DEP) policy to OptIn
# DEPOptOut -Enable
# Set Data Execution Prevention (DEP) policy to OptOut
DEPOptOut -Disable

#endregion Microsoft Defender & Security

#region Context menu
# Show the "Extract all" item in the Windows Installer (.msi) context menu
MSIExtractContext -Show
# Hide the "Extract all" item from the Windows Installer (.msi) context menu (default value)
# MSIExtractContext -Hide

# Show the "Install" item in the Cabinet (.cab) filenames extensions context menu
CABInstallContext -Show
# Hide the "Install" item from the Cabinet (.cab) filenames extensions context menu (default value)
# CABInstallContext -Hide

# Hide the "Edit with Clipchamp" item from the media files context menu
EditWithClipchampContext -Hide
# Show the "Edit with Clipchamp" item in the media files context menu (default value)
# EditWithClipchampContext -Show

# Hide the "Edit with Photos" item from the media files context menu
EditWithPhotosContext -Hide
# Show the "Edit with Photos" item in the media files context menu (default value)
# EditWithPhotosContext -Show

# Hide the "Edit with Paint" item from the media files context menu
EditWithPaintContext -Hide
# Show the "Edit with Paint" item in the media files context menu (default value)
# EditWithPaintContext -Show

# Hide the "Print" item from the .bat and .cmd context menu
PrintCMDContext -Hide
# Show the "Print" item in the .bat and .cmd context menu (default value)
# PrintCMDContext -Show

# Hide the "Compressed (zipped) Folder" item from the "New" context menu
CompressedFolderNewContext -Hide
# Show the "Compressed (zipped) Folder" item to the "New" context menu (default value)
# CompressedFolderNewContext -Show

# Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
MultipleInvokeContext -Enable
# Disable the "Open", "Print", and "Edit" context menu items for more than 15 items selected (default value)
# MultipleInvokeContext -Disable

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
UseStoreOpenWith -Hide
# Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog (default value)
# UseStoreOpenWith -Show

# Show the "Open in Windows Terminal" item in the folders context menu (default value)
OpenWindowsTerminalContext -Show
# Hide the "Open in Windows Terminal" item in the folders context menu
# OpenWindowsTerminalContext -Hide

# Open Windows Terminal in context menu as administrator by default
OpenWindowsTerminalAdminContext -Enable
# Do not open Windows Terminal in context menu as administrator by default (default value)
# OpenWindowsTerminalAdminContext -Disable
#endregion Context menu

#region Taskbar Clock
# Show seconds on the taskbar clock
# SecondsInSystemClock -Show
# Hide seconds on the taskbar clock (default value)
SecondsInSystemClock -Hide

# Show time in Notification Center
ClockInNotificationCenter -Show
# Hide time in Notification Center (default value)
# ClockInNotificationCenter -Hide
#endregion Taskbar Clock

#region Cursors
# Download and install free dark "Windows 11 Cursors Concept" cursors from Jepri Creations. Internet connection required
# https://www.deviantart.com/jepricreations/art/Windows-11-Cursors-Concept-886489356
# Install-Cursors -Dark
# Download and install free light "Windows 11 Cursors Concept" cursors from Jepri Creations. Internet connection required
# https://www.deviantart.com/jepricreations/art/Windows-11-Cursors-Concept-886489356
# Install-Cursors -Light
# Set default cursors
Install-Cursors -Default
#endregion Cursors

#region Start Menu Apps
# Hide recently added apps in Start
RecentlyAddedStartApps -Hide
# Show recently added apps in Start (default value)
# RecentlyAddedStartApps -Show

# Hide most used apps in Start (default value)
MostUsedStartApps -Hide
# Show most used Apps in Start
# MostUsedStartApps -Show
#endregion Start Menu Apps

#region Explorer
# Do not restore previous folder windows at logon (default value)
RestorePreviousFolders -Disable
# Restore previous folder windows at logon
# RestorePreviousFolders -Enable
#endregion Explorer

#region Update Policies
<#
	Display all policy registry keys (even manually created ones) in the Local Group Policy Editor snap-in (gpedit.msc)
	This can take up to 30 minutes, depending on the number of policies created in the registry and your system resources
#>
# UpdateLGPEPolicies

# Scan the Windows registry and display applied registry policies in the Local Group Policy Editor snap-in (gpedit.msc)
# ScanRegistryPolicies
#endregion Update Policies

#region Post Actions
# Environment refresh and other neccessary post actions
PostActions
#endregion Post Actions

#region Errors
# Errors output
#endregion Errors