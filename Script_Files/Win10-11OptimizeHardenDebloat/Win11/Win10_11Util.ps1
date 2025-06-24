<#
	.SYNOPSIS
	This Script is a PowerShell module for Windows 10 & Windows 11 fine-tuning and automating the routine tasks

	.VERSION
	1.0.2

	.DATE
	13.01.2025

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
	Supported Windows 11 versions
	Version: 23H2+
	Editions: Home/Pro/Enterprise

	.NOTES
	To use the TAB completion for functions and their arguments dot source the Functions.ps1 script first:
		. .\Function.ps1 (with a dot at the beginning)
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)

Clear-Host

$Host.UI.RawUI.WindowTitle = "WinUtil Script for Windows 10/11"

# Checking whether all files were expanded before running
$ScriptFiles = @(
    "$PSScriptRoot\Localizations\Win10_11Util.psd1",  # Localization file
    "$PSScriptRoot\Module\Win10_11Util.psm1",        # Module definition
    "$PSScriptRoot\Manifest\Win10_11Util.psd1"       # Manifest file
)

if (($ScriptFiles | Test-Path) -contains $false)
{
	Write-Information -MessageData "" -InformationAction Continue
	Write-Warning -Message "There are no files in the script folder. Please, re-download the archive."
	Write-Information -MessageData "" -InformationAction Continue
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
	Import-Module -Name $PSScriptRoot\Manifest\Win10_11Util.psd1 -PassThru -Force -ErrorAction Stop
}
catch [System.InvalidOperationException]
{
	Write-Warning -Message $Localization.UnsupportedPowerShell
	exit
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Preset configuration starts here
# Отсюда начинается настройка пресета
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

<#
	.SYNOPSIS
	Run the script by specifying functions as an argument
	Запустить скрипт, указав в качестве аргумента функции

	.EXAMPLE
	.\Win10_11Util.ps1 -Functions "DiagTrackService -Disable", "DiagnosticDataLevel -Minimal", UninstallUWPApps

	.NOTES
	Use commas to separate funtions
	Разделяйте функции запятыми
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

# Restart script in v5.1 if required
Restart-Script -scriptPath $MyInvocation.MyCommand.Path

#region Protection
# The mandatory checks. If you want to disable a warning message about whether the preset file was customized, remove the "-Warning" argument
# Обязательные проверки. Чтобы выключить предупреждение о необходимости настройки пресет-файла, удалите аргумент "-Warning"
InitialActions -Warning

# Create a restore point
# Создать точку восстановления
CreateRestorePoint
#endregion Protection

# Check and Install WinGet
CheckWinGet

#Install Powershell 7
Update-Powershell

# Hide "About this Picture" on Desktop
Update-DesktopRegistry

#kill foreground applications
Stop-Foreground

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

#region Privacy & Telemetry
<#
	Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic
	Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore and affects Feedback Hub

	Отключить службу "Функциональные возможности для подключенных пользователей и телеметрия" (DiagTrack) и блокировать соединение для исходящего трафик клиента единой телеметрии
	Отключение службы "Функциональные возможности для подключенных пользователей и телеметрия" (DiagTrack) может привести к тому, что вы больше не сможете получать достижения Xbox, а также влияет на работу Feedback Hub
#>
DiagTrackService -Disable

# Enable the "Connected User Experiences and Telemetry" service (DiagTrack), and allow the connection for the Unified Telemetry Client Outbound Traffic (default value)
# Включить службу "Функциональные возможности для подключенных пользователей и телеметрия" (DiagTrack) и разрешить подключение для исходящего трафик клиента единой телеметрии (значение по умолчанию)
# DiagTrackService -Enable

# Set the diagnostic data collection to minimum
# Установить уровень сбора диагностических данных ОС на минимальный
DiagnosticDataLevel -Minimal

# Set the diagnostic data collection to default (default value)
# Установить уровень сбора диагностических данных ОС по умолчанию (значение по умолчанию)
# DiagnosticDataLevel -Default

# Turn off the Windows Error Reporting
# Отключить запись отчетов об ошибках Windows
ErrorReporting -Disable

# Turn on the Windows Error Reporting (default value)
# Включить отчеты об ошибках Windows (значение по умолчанию)
# ErrorReporting -Enable

# Change the feedback frequency to "Never"
# Изменить частоту формирования отзывов на "Никогда"
FeedbackFrequency -Never

# Change the feedback frequency to "Automatically" (default value)
# Изменить частоту формирования отзывов на "Автоматически" (значение по умолчанию)
# FeedbackFrequency -Automatically

# Turn off the diagnostics tracking scheduled tasks
# Отключить задания диагностического отслеживания
ScheduledTasks -Disable

# Turn on the diagnostics tracking scheduled tasks (default value)
# Включить задания диагностического отслеживания (значение по умолчанию)
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
# Не использовать данные для входа для автоматического завершения настройки устройства после перезапуска
SigninInfo -Disable

# Use sign-in info to automatically finish setting up device after an update (default value)
# Использовать данные для входа, чтобы автоматически завершить настройку после обновления (значение по умолчанию)
# SigninInfo -Enable

# Do not let websites provide locally relevant content by accessing language list
# Не позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков
LanguageListAccess -Disable

# Let websites provide locally relevant content by accessing language list (default value)
# Позволить веб-сайтам предоставлять местную информацию за счет доступа к списку языков (значение по умолчанию)
# LanguageListAccess -Enable

# Do not let apps show me personalized ads by using my advertising ID
# Не разрешать приложениям показывать персонализированную рекламу с помощью моего идентификатора рекламы
AdvertisingID -Disable

# Let apps show me personalized ads by using my advertising ID (default value)
# Разрешить приложениям показывать персонализированную рекламу с помощью моего идентификатора рекламы (значение по умолчанию)
# AdvertisingID -Enable

# Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
# Скрывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях
WindowsWelcomeExperience -Hide

# Show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (default value)
# Показывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях (значение по умолчанию)
# WindowsWelcomeExperience -Show

#Enable the Windows Web Experience Pack (used for widgets and lock screen features)
#LockWidgets -Enable
#disable the Windows Web Experience Pack (used for widgets and lock screen features)
LockWidgets -Disable

# Get tips and suggestions when I use Windows (default value)
# Получать советы и предложения при использованию Windows (значение по умолчанию)
WindowsTips -Enable

# Do not get tips and suggestions when I use Windows
# Не получать советы и предложения при использованию Windows
# WindowsTips -Disable

# Hide from me suggested content in the Settings app
# Скрывать рекомендуемое содержимое в приложении "Параметры"
SettingsSuggestedContent -Hide

# Show me suggested content in the Settings app (default value)
# Показывать рекомендуемое содержимое в приложении "Параметры" (значение по умолчанию)
# SettingsSuggestedContent -Show

# Turn off automatic installing suggested apps
# Отключить автоматическую установку рекомендованных приложений
AppsSilentInstalling -Disable

# Turn on automatic installing suggested apps (default value)
# Включить автоматическую установку рекомендованных приложений (значение по умолчанию)
# AppsSilentInstalling -Enable

# Do not suggest ways to get the most out of Windows and finish setting up this device
# Не предлагать способы завершения настройки этого устройства для наиболее эффективного использования Windows
WhatsNewInWindows -Disable

# Suggest ways to get the most out of Windows and finish setting up this device (default value)
# Предложить способы завершения настройки этого устройства для наиболее эффективного использования Windows (значение по умолчанию)
# WhatsNewInWindows -Enable

# Don't let Microsoft use your diagnostic data for personalized tips, ads, and recommendations
# Не разрешать корпорации Майкрософт использовать диагностические данные персонализированных советов, рекламы и рекомендаций
TailoredExperiences -Disable

# Let Microsoft use your diagnostic data for personalized tips, ads, and recommendations (default value)
# Разрешить корпорации Майкрософт использовать диагностические данные для персонализированных советов, рекламы и рекомендаций (значение по умолчанию)
# TailoredExperiences -Enable

# Disable Bing search in Start Menu
# Отключить в меню "Пуск" поиск через Bing
BingSearch -Disable

# Enable Bing search in Start Menu (default value)
# Включить поиск через Bing в меню "Пуск" (значение по умолчанию)
# BingSearch -Enable

# Do not show recommendations for tips, shortcuts, new apps, and more in Start menu
# Не показать рекомендации с советами, сочетаниями клавиш, новыми приложениями и т. д. в меню "Пуск"
StartRecommendationsTips -Hide

# Show recommendations for tips, shortcuts, new apps, and more in Start menu (default value)
# Показать рекомендации с советами, сочетаниями клавиш, новыми приложениями и т. д. в меню "Пуск" (значение по умолчанию)
# StartRecommendationsTips -Show

# Do not show Microsoft account-related notifications on Start Menu in Start menu
# Не показывать в меню "Пуск" уведомления, связанные с учетной записью Microsoft
StartAccountNotifications -Hide

# Show Microsoft account-related notifications on Start Menu in Start menu (default value)
# Переодически показывать в меню "Пуск" уведомления, связанные с учетной записью Microsoft (значение по умолчанию)
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

#endregion Privacy & Telemetry

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
# Отобразить значок "Этот компьютер" на рабочем столе
# ThisPC -Show

# Hide the "This PC" icon on Desktop (default value)
# Скрыть "Этот компьютер" на рабочем столе (значение по умолчанию)
ThisPC -Hide

# Do not use item check boxes
# Не использовать флажки для выбора элементов
CheckBoxes -Disable

# Use check item check boxes (default value)
# Использовать флажки для выбора элементов (значение по умолчанию)
# CheckBoxes -Enable

# Show hidden files, folders, and drives
# Отобразить скрытые файлы, папки и диски
# HiddenItems -Enable

# Do not show hidden files, folders, and drives (default value)
# Не показывать скрытые файлы, папки и диски (значение по умолчанию)
HiddenItems -Disable

# Enable Protected operating system files
# SuperHiddenFiles -Enable
# Disable Protected operating system files
SuperHiddenFiles -Disable

# Show file name extensions
# Отобразить расширения имён файлов
# FileExtensions -Show

# Hide file name extensions (default value)
# Скрывать расширения имён файлов файлов (значение по умолчанию)
FileExtensions -Hide

# Show folder merge conflicts
# Не скрывать конфликт слияния папок
MergeConflicts -Show

# Hide folder merge conflicts (default value)
# Скрывать конфликт слияния папок (значение по умолчанию)
# MergeConflicts -Hide

# Open File Explorer to "This PC"
# Открывать проводник для "Этот компьютер"
OpenFileExplorerTo -ThisPC

# Open File Explorer to Quick access (default value)
# Открывать проводник для "Быстрый доступ" (значение по умолчанию)
# OpenFileExplorerTo -QuickAccess

# Open File Explorer to Downloads
# OpenFileExplorerTo -Downloads

# Disable File Explorer compact mode (default value)
# Отключить компактный вид проводника (значение по умолчанию)
FileExplorerCompactMode -Disable

# Enable File Explorer compact mode
# Включить компактный вид проводника
# FileExplorerCompactMode -Enable

# Do not show sync provider notification within File Explorer
# Не показывать уведомления поставщика синхронизации в проводнике
OneDriveFileExplorerAd -Hide

# Show sync provider notification within File Explorer (default value)
# Показывать уведомления поставщика синхронизации в проводнике (значение по умолчанию)
# OneDriveFileExplorerAd -Show

# When I snap a window, do not show what I can snap next to it
# При прикреплении окна не показывать, что можно прикрепить рядом с ним
SnapAssist -Disable

# When I snap a window, show what I can snap next to it (default value)
# При прикреплении окна показывать, что можно прикрепить рядом с ним (значение по умолчанию)
# SnapAssist -Enable

# Show the file transfer dialog box in the detailed mode
# Отображать диалоговое окно передачи файлов в развернутом виде
FileTransferDialog -Detailed

# Show the file transfer dialog box in the compact mode (default value)
# Отображать диалоговое окно передачи файлов в свернутом виде (значение по умолчанию)
# FileTransferDialog -Compact

# Display the recycle bin files delete confirmation dialog
# Запрашивать подтверждение на удаление файлов в корзину
RecycleBinDeleteConfirmation -Enable

# Do not display the recycle bin files delete confirmation dialog (default value)
# Не запрашивать подтверждение на удаление файлов в корзину (значение по умолчанию)
# RecycleBinDeleteConfirmation -Disable

# Hide recently used files in Quick access
# Скрыть недавно использовавшиеся файлы на панели быстрого доступа
QuickAccessRecentFiles -Hide

# Show recently used files in Quick access (default value)
# Показать недавно использовавшиеся файлы на панели быстрого доступа (значение по умолчанию)
# QuickAccessRecentFiles -Show

# Hide frequently used folders in Quick access
# Скрыть недавно используемые папки на панели быстрого доступа
QuickAccessFrequentFolders -Hide

# Show frequently used folders in Quick access (default value)
# Показать часто используемые папки на панели быстрого доступа (значение по умолчанию)
# QuickAccessFrequentFolders -Show

# Hide the Meet Now icon in the notification area
# Скрыть иконку "Провести собрание" в области уведомлений
MeetNow -Hide

# Show the Meet Now icon in the notification area (default value)
# Отображать иконку "Провести собрание" в области уведомлений (значение по умолчанию)
# MeetNow -Show

# Disable "News and Interests" on the taskbar
# Отключить "Новости и интересы" на панели задач
NewsInterests -Disable

# Enable "News and Interests" on the taskbar (default value)
# Включить "Новости и интересы" на панели задач (значение по умолчанию)
# NewsInterests -Enable

# Set the taskbar alignment to the center (default value)
# Установить выравнивание панели задач по центру (значение по умолчанию)
# TaskbarAlignment -Center

# Set the taskbar alignment to the left
# Установить выравнивание панели задач по левому краю
TaskbarAlignment -Left

# Hide the widgets icon on the taskbar
# Скрыть кнопку "Мини-приложения" с панели задач
TaskbarWidgets -Hide

# Show the widgets icon on the taskbar (default value)
# Отобразить кнопку "Мини-приложения" на панели задач (значение по умолчанию)
# TaskbarWidgets -Show

# Hide the search on the taskbar
# Скрыть поле или значок поиска на панели задач
TaskbarSearch -Hide

# Show the search icon on the taskbar
# Показать значок поиска на панели задач
# TaskbarSearch -SearchIcon

# Show the search icon and label on the taskbar
# Показать значок и метку поиска на панели задач
# TaskbarSearch -SearchIconLabel

# Show the search box on the taskbar (default value)
# Показать поле поиска на панели задач (значение по умолчанию)
# TaskbarSearch -SearchBox

# Hide search highlights
# Скрыть главное в поиске
SearchHighlights -Hide

# Show search highlights (default value)
# Показать главное в поиске (значение по умолчанию)
# SearchHighlights -Show

# Hide the Task view button from the taskbar
# Скрыть кнопку "Представление задач" с панели задач
TaskViewButton -Hide

# Show the Task view button on the taskbar (default value)
# Отобразить кнопку "Представление задач" на панели задач (значение по умолчанию)
# TaskViewButton -Show

# Combine taskbar buttons and always hide labels (default value)
# Объединить кнопки панели задач и всегда скрывать метки (значение по умолчанию)
TaskbarCombine -Always

# Combine taskbar buttons and hide labels when taskbar is full
# Объединить кнопки панели задач и скрывать метки при переполнении панели задач
# TaskbarCombine -Full

# Combine taskbar buttons and never hide labels
# Объединить кнопки панели задач и никогда не скрывать метки
# TaskbarCombine -Never

# Unpin Microsoft Edge, Microsoft Store, and Outlook shortcuts from the taskbar
# Открепить ярлыки Microsoft Edge, Microsoft Store и Outlook от панели задач
UnpinTaskbarShortcuts -Shortcuts Edge, Store, Outlook

# Enable end task in taskbar by right click
# Включить завершение задачи на панели задач правой кнопкой мыши
TaskbarEndTask -Enable

# Disable end task in taskbar by right click (default value)
# Выключить завершение задачи на панели задач правой кнопкой мыши (значение по умолчанию)
# TaskbarEndTask -Disable

# View the Control Panel icons by large icons
# Просмотр иконок Панели управления как: крупные значки
# ControlPanelView -LargeIcons

# View the Control Panel icons by small icons
# Просмотр иконок Панели управления как: маленькие значки
# ControlPanelView -SmallIcons

# View the Control Panel icons by category (default value)
# Просмотр иконок Панели управления как: категория (значение по умолчанию)
ControlPanelView -Category

# Set the default Windows mode to dark
# Установить режим Windows по умолчанию на темный
WindowsColorMode -Dark

# Set the default Windows mode to light (default value)
# Установить режим Windows по умолчанию на светлый (значение по умолчанию)
# WindowsColorMode -Light

# Set the default app mode to dark
# Установить цвет режима приложения на темный
AppColorMode -Dark

# Set the default app mode to light (default value)
# Установить цвет режима приложения на светлый (значение по умолчанию)
# AppColorMode -Light

# Hide first sign-in animation after the upgrade
# Скрывать анимацию при первом входе в систему после обновления
FirstLogonAnimation -Disable

# Show first sign-in animation after the upgrade (default value)
# Показывать анимацию при первом входе в систему после обновления (значение по умолчанию)
# FirstLogonAnimation -Enable

# Set the quality factor of the JPEG desktop wallpapers to maximum
# Установить коэффициент качества обоев рабочего стола в формате JPEG на максимальный
JPEGWallpapersQuality -Max

# Set the quality factor of the JPEG desktop wallpapers to default
# Установить коэффициент качества обоев рабочего стола в формате JPEG по умолчанию
# JPEGWallpapersQuality -Default

# Do not add the "- Shortcut" suffix to the file name of created shortcuts
# Нe дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков
ShortcutsSuffix -Disable

# Add the "- Shortcut" suffix to the file name of created shortcuts (default value)
# Дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков (значение по умолчанию)
# ShortcutsSuffix -Enable

# Enable Shortcut icon arrow
ShortcutArrow -Enable
# Disable Shortcut icon arrow
# ShortcutArrow -Disable

# Use the Print screen button to open screen snipping
# Использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана
PrtScnSnippingTool -Enable

# Do not use the Print screen button to open screen snipping (default value)
# Не использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана (значение по умолчанию)
# PrtScnSnippingTool -Disable

# Let me use a different input method for each app window
# Позволить выбирать метод ввода для каждого окна
# AppsLanguageSwitch -Enable

# Do not use a different input method for each app window (default value)
# Не использовать метод ввода для каждого окна (значение по умолчанию)
AppsLanguageSwitch -Disable

# When I grab a windows's title bar and shake it, minimize all other windows
# При захвате заголовка окна и встряхивании сворачиваются все остальные окна
AeroShaking -Enable

# When I grab a windows's title bar and shake it, don't minimize all other windows (default value)
# При захвате заголовка окна и встряхивании не сворачиваются все остальные окна (значение по умолчанию)
# AeroShaking -Disable

# Do not group files and folder in the Downloads folder
# Не группировать файлы и папки в папке Загрузки
FolderGroupBy -None

# Group files and folder by date modified in the Downloads folder (default value)
# Группировать файлы и папки по дате изменения (значение по умолчанию)
# FolderGroupBy -Default

# Do not expand to open folder on navigation pane (default value)
# Не разворачивать до открытой папки область навигации (значение по умолчанию)
NavigationPaneExpand -Disable

# Expand to open folder on navigation pane
# Развернуть до открытой папки область навигации
# NavigationPaneExpand -Enable

# Remove Recommended section in Start Menu. Applicable only to Enterprise and Education editions, but not to IoT Enterprise
# Удалить раздел "Рекомендуем" в меню "Пуск". Применимо только к редакциям Enterprise и Education, но не к IoT Enterprise
StartRecommendedSection -Hide

# Show Recommended section in Start Menu (default value). Applicable only to Enterprise and Education editions, but not to IoT Enterprise
# Показывать раздел "Рекомендуем" в меню "Пуск" (значение по умолчанию). Применимо только к редакциям Enterprise и Education, но не к IoT Enterprise
# StartRecommendedSection -Show
#endregion UI & Personalization

#region OneDrive
# Uninstall OneDrive. The OneDrive user folder won't be removed
# Удалить OneDrive. Папка пользователя OneDrive не будет удалена
OneDrive -Uninstall

# Install OneDrive 64-bit (default value)
# Установить OneDrive 64-бит (значение по умолчанию)
# OneDrive -Install

# Install OneDrive 64-bit all users to %ProgramFiles% depending which installer is triggered
# Установить OneDrive 64-бит для всех пользователей в %ProgramFiles% в зависимости от того, как запускается инсталлятор
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
# Включить Контроль памяти
StorageSense -Enable

# Turn off Storage Sense (default value)
# Выключить Контроль памяти (значение по умолчанию)
# StorageSense -Disable

# Disable hibernation. It isn't recommended to turn off for laptops
# Отключить режим гибернации. Не рекомендуется выключать на ноутбуках
Hibernation -Disable

# Enable hibernate (default value)
# Включить режим гибернации (значение по умолчанию)
# Hibernation -Enable

# Disable the Windows 260 characters path limit
# Отключить ограничение Windows на 260 символов в пути
Win32LongPathLimit -Disable

# Enable the Windows 260 character path limit (default value)
# Включить ограничение Windows на 260 символов в пути (значение по умолчанию)
# Win32LongPathLimit -Enable

# Display Stop error code when BSoD occurs
# Отображать код Stop-ошибки при появлении BSoD
BSoDStopError -Enable

# Do not display stop error code when BSoD occurs (default value)
# Не отображать код Stop-ошибки при появлении BSoD (значение по умолчанию)
# BSoDStopError -Disable

# Choose when to be notified about changes to your computer: never notify
# Настройка уведомления об изменении параметров компьютера: никогда не уведомлять
AdminApprovalMode -Never

# Choose when to be notified about changes to your computer: notify me only when apps try to make changes to my computer (default value)
# Настройка уведомления об изменении параметров компьютера: уведомлять меня только при попытках приложений внести изменения в компьютер (значение по умолчанию)
# AdminApprovalMode -Default

# Turn off Delivery Optimization
# Выключить оптимизацию доставки
DeliveryOptimization -Disable

# Turn on Delivery Optimization (default value)
# Включить оптимизацию доставки (значение по умолчанию)
# DeliveryOptimization -Enable

# Do not let Windows manage my default printer
# Не разрешать Windows управлять принтером, используемым по умолчанию
WindowsManageDefaultPrinter -Disable

# Let Windows manage my default printer (default value)
# Разрешать Windows управлять принтером, используемым по умолчанию (значение по умолчанию)
# WindowsManageDefaultPrinter -Enable

<#
	Disable the Windows features using the pop-up dialog box
	If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not disable the "Media Features" feature

	Если вы хотите оставить параметр "Параметры мультимедиа" в дополнительных параметрах схемы управления питанием, не отключайте "Компоненты для работы с медиа"
	Отключить компоненты Windows, используя всплывающее диалоговое окно
#>
WindowsFeatures -Disable

# Enable the Windows features using the pop-up dialog box
# Включить компоненты Windows, используя всплывающее диалоговое окно
# WindowsFeatures -Enable

<#
	Uninstall optional features using the pop-up dialog box
	If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not uninstall the "Media Features" feature

	Удалить дополнительные компоненты, используя всплывающее диалоговое окно
	Если вы хотите оставить параметр "Параметры мультимедиа" в дополнительных параметрах схемы управления питанием, не удаляйте компонент "Компоненты для работы с медиа"
#>
WindowsCapabilities -Uninstall

# Install optional features using the pop-up dialog box
# Установить дополнительные компоненты, используя всплывающее диалоговое окно
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
# Получать обновления для других продуктов Майкрософт
UpdateMicrosoftProducts -Enable

# Do not receive updates for other Microsoft products (default value)
# Не получать обновления для других продуктов Майкрософт (значение по умолчанию)
# UpdateMicrosoftProducts -Disable

# Notify me when a restart is required to finish updating
# Уведомлять меня о необходимости перезагрузки для завершения обновления
RestartNotification -Show

# Do not notify me when a restart is required to finish updating (default value)
# Не yведомлять меня о необходимости перезагрузки для завершения обновления (значение по умолчанию)
# RestartNotification -Hide

# Restart as soon as possible to finish updating
# Перезапустить устройство как можно быстрее, чтобы завершить обновление
# RestartDeviceAfterUpdate -Enable
 
# Don't restart as soon as possible to finish updating (default value)
# Не перезапускать устройство как можно быстрее, чтобы завершить обновление (значение по умолчанию)
RestartDeviceAfterUpdate -Disable

# Automatically adjust active hours for me based on daily usage
# Автоматически изменять период активности для этого устройства на основе действий
ActiveHours -Automatically

# Manually adjust active hours for me based on daily usage (default value)
# Вручную изменять период активности для этого устройства на основе действий (значение по умолчанию)
# ActiveHours -Manually

# Do not get the latest updates as soon as they're available (default value)
# Не получать последние обновления, как только они будут доступны (значение по умолчанию)
WindowsLatestUpdate -Disable

# Get the latest updates as soon as they're available
# Получайте последние обновления, как только они будут доступны
# WindowsLatestUpdate -Enable

# Set power plan on "High performance". It isn't recommended to turn on for laptops
# Установить схему управления питанием на "Высокая производительность". Не рекомендуется включать на ноутбуках
PowerPlan -High

# Set power plan on "Balanced" (default value)
# Установить схему управления питанием на "Сбалансированная" (значение по умолчанию)
# PowerPlan -Balanced

# Do not allow the computer to turn off the network adapters to save power. It isn't recommended to turn off for laptops
# Запретить отключение всех сетевых адаптеров для экономии энергии. Не рекомендуется выключать на ноутбуках
NetworkAdaptersSavePower -Disable

# Allow the computer to turn off the network adapters to save power (default value)
# Разрешить отключение всех сетевых адаптеров для экономии энергии (значение по умолчанию)
# NetworkAdaptersSavePower -Enable

# Override for default input method: English
# Переопределить метод ввода по умолчанию: английский
InputMethod -English

# Override for default input method: use language list (default value)
# Переопределить метод ввода по умолчанию: использовать список языков (значение по умолчанию)
# InputMethod -Default

<#
	Change user folders location to the root of any drive using the interactive menu
	User files or folders won't be moved to a new location. Move them manually
	They're located in the %USERPROFILE% folder by default

	Переместить пользовательские папки в корень любого диска на выбор с помощью интерактивного меню
	Пользовательские файлы и папки не будут перемещены в новое расположение. Переместите их вручную
	По умолчанию они располагаются в папке %USERPROFILE%
#>
# Set-UserShellFolderLocation -Root

<#
	Select folders for user folders location manually using a folder browser dialog
	User files or folders won't be moved to a new location. Move them manually
	They're located in the %USERPROFILE% folder by default

	Выбрать папки для расположения пользовательских папок вручную, используя диалог "Обзор папок"
	Пользовательские файлы и папки не будут перемещены в новое расположение. Переместите их вручную
	По умолчанию они располагаются в папке %USERPROFILE%
#>
# Set-UserShellFolderLocation -Custom

<#
	Change user folders location to the default values
	User files or folders won't be moved to the new location. Move them manually
	They're located in the %USERPROFILE% folder by default

	Изменить расположение пользовательских папок на значения по умолчанию
	Пользовательские файлы и папки не будут перемещены в новое расположение. Переместите их вручную
	По умолчанию они располагаются в папке %USERPROFILE%
#>
# Set-UserShellFolderLocation -Default

# Use the latest installed .NET runtime for all apps
# Использовать последнюю установленную среду выполнения .NET для всех приложений
LatestInstalled.NET -Enable

# Do not use the latest installed .NET runtime for all apps (default value)
# Не использовать последнюю установленную версию .NET для всех приложений (значение по умолчанию)
# LatestInstalled.NET -Disable

<#
	Save screenshots by pressing Win+PrtScr on the Desktop
	The function will be applied only if the preset is configured to remove the OneDrive application, or the app was already uninstalled
	Otherwise the backup functionality for the "Desktop" and "Pictures" folders in OneDrive breaks

	Сохранять скриншоты по нажатию Win+PrtScr на рабочий стол
	Функция будет применена только в случае, если в пресете настроено удаление приложения OneDrive или приложение уже удалено,
	иначе в OneDrive ломается функционал резервного копирования для папок "Рабочий стол" и "Изображения"
#>
WinPrtScrFolder -Desktop

# Save screenshots by pressing Win+PrtScr in the Pictures folder (default value)
# Cохранять скриншоты по нажатию Win+PrtScr в папку "Изображения" (значение по умолчанию)
# WinPrtScrFolder -Default

<#
	Run troubleshooter automatically, then notify me
	In order this feature to work Windows level of diagnostic data gathering will be set to "Optional diagnostic data", and the error reporting feature will be turned on

	Автоматически запускать средства устранения неполадок, а затем уведомлять
	Чтобы заработала данная функция, уровень сбора диагностических данных ОС будет установлен на "Необязательные диагностические данные" и включится создание отчетов об ошибках Windows
#>
RecommendedTroubleshooting -Automatically

<#
	Ask me before running troubleshooter (default value)
	In order this feature to work Windows level of diagnostic data gathering will be set to "Optional diagnostic data"

	Спрашивать перед запуском средств устранения неполадок (значение по умолчанию)
	Чтобы заработала данная функция, уровень сбора диагностических данных ОС будет установлен на "Необязательные диагностические данные" и включится создание отчетов об ошибках Windows
#>
# RecommendedTroubleshooting -Default

# Disable and delete reserved storage after the next update installation
# Отключить и удалить зарезервированное хранилище после следующей установки обновлений
ReservedStorage -Disable

# Enable reserved storage (default value)
# Включить зарезервированное хранилище (значение по умолчанию)
# ReservedStorage -Enable

# Disable help lookup via F1
# Отключить открытие справки по нажатию F1
F1HelpPage -Disable

# Enable help lookup via F1 (default value)
# Включить открытие справки по нажатию F1 (значение по умолчанию)
# F1HelpPage -Enable

# Enable Num Lock at startup
# Включить Num Lock при загрузке
NumLock -Enable

# Disable Num Lock at startup (default value)
# Выключить Num Lock при загрузке (значение по умолчанию)
# NumLock -Disable

# Disable Caps Lock
# Выключить Caps Lock
# CapsLock -Disable

# Enable Caps Lock (default value)
# Включить Caps Lock (значение по умолчанию)
# CapsLock -Enable

# Turn off pressing the Shift key 5 times to turn Sticky keys
# Выключить залипание клавиши Shift после 5 нажатий
StickyShift -Disable

# Turn on pressing the Shift key 5 times to turn Sticky keys (default value)
# Включить залипание клавиши Shift после 5 нажатий (значение по умолчанию)
# StickyShift -Enable

# Don't use AutoPlay for all media and devices
# Не использовать автозапуск для всех носителей и устройств
Autoplay -Disable

# Use AutoPlay for all media and devices (default value)
# Использовать автозапуск для всех носителей и устройств (значение по умолчанию)
# Autoplay -Enable

# Automatically saving my restartable apps and restart them when I sign back in
# Автоматически сохранять мои перезапускаемые приложения из системы и перезапускать их при повторном входе
SaveRestartableApps -Enable

# Turn off automatically saving my restartable apps and restart them when I sign back in (default value)
# Выключить автоматическое сохранение моих перезапускаемых приложений из системы и перезапускать их при повторном входе (значение по умолчанию)
# SaveRestartableApps -Disable

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
# Включить сетевое обнаружение и общий доступ к файлам и принтерам для рабочих групп
NetworkDiscovery -Enable

# Disable "Network Discovery" and "File and Printers Sharing" for workgroup networks (default value)
# Выключить сетевое обнаружение и общий доступ к файлам и принтерам для рабочих групп (значение по умолчанию)
# NetworkDiscovery -Disable

<#
	Register app, calculate hash, and associate with an extension with the "How do you want to open this" pop-up hidden
	Зарегистрировать приложение, вычислить хэш и ассоциировать его с расширением без всплывающего окна "Каким образом вы хотите открыть этот файл?"

	Set-Association -ProgramPath "C:\SumatraPDF.exe" -Extension .pdf -Icon "shell32.dll,100"
	Set-Association -ProgramPath "%ProgramFiles%\Notepad++\notepad++.exe" -Extension .txt -Icon "%ProgramFiles%\Notepad++\notepad++.exe,0"
	Set-Association -ProgramPath MSEdgeMHT -Extension .html
#>
# Set-Association -ProgramPath "%ProgramFiles%\Notepad++\notepad++.exe" -Extension .txt -Icon "%ProgramFiles%\Notepad++\notepad++.exe,0"

# Экспортировать все ассоциации в Windows в корень папки в виде файла Application_Associations.json
# Export all Windows associations into Application_Associations.json file to script root folder
# Export-Associations

<#
	Импортировать все ассоциации в Windows из файла Application_Associations.json
	Вам необходимо установить все приложения согласно экспортированному файлу Application_Associations.json, чтобы восстановить все ассоциации

	Import all Windows associations from an Application_Associations.json file
	You need to install all apps according to an exported Application_Associations.json file to restore all associations
#>
# Import-Associations

# Set Windows Terminal as default terminal app to host the user interface for command-line applications
# Установить Windows Terminal как приложение терминала по умолчанию для размещения пользовательского интерфейса для приложений командной строки
DefaultTerminalApp -WindowsTerminal

# Set Windows Console Host as default terminal app to host the user interface for command-line applications (default value)
# Установить Windows Console Host как приложение терминала по умолчанию для размещения пользовательского интерфейса для приложений командной строки (значение по умолчанию)
# DefaultTerminalApp -ConsoleHost

# Install the latest Microsoft Visual C++ Redistributable Packages 2015–2022 (x86/x64)
# Установить последнюю версию распространяемых пакетов Microsoft Visual C++ 2015–2022 (x86/x64)
# Install-VCRedist -Redistributables 2015_2022_x86, 2015_2022_x64

# Install the latest .NET Desktop Runtime 8, 9 x64
#Установить последнюю версию .NET Desktop Runtime 8, 9 x64
# Install-DotNetRuntimes -Runtimes NET8x64, NET9x64

# Enable proxying only blocked sites from the unified registry of Roskomnadzor. The function is applicable for Russia only
# Включить проксирование только заблокированных сайтов из единого реестра Роскомнадзора. Функция применима только для России
# https://antizapret.prostovpn.org
RKNBypass -Enable

# Disable proxying only blocked sites from the unified registry of Roskomnadzor (default value)
# Выключить проксирование только заблокированных сайтов из единого реестра Роскомнадзора (значение по умолчанию)
# https://antizapret.prostovpn.org
# RKNBypass -Disable

# List Microsoft Edge channels to prevent desktop shortcut creation upon its update
# Перечислите каналы Microsoft Edge для предотвращения создания ярлыков на рабочем столе после его обновления
PreventEdgeShortcutCreation -Channels Stable, Beta, Dev, Canary

# Do not prevent desktop shortcut creation upon Microsoft Edge update (default value)
# Не предотвращать создание ярлыков на рабочем столе при обновлении Microsoft Edge (значение по умолчанию)
# PreventEdgeShortcutCreation -Disable

# Back up the system registry to %SystemRoot%\System32\config\RegBack folder when PC restarts and create a RegIdleBackup in the Task Scheduler task to manage subsequent backups
# Создавать копии реестра при перезагрузки ПК и создавать задание RegIdleBackup в Планировщике задания для управления последующими резервными копиями
# RegistryBackup -Enable

# Do not back up the system registry to %SystemRoot%\System32\config\RegBack folder (default value)
# Не создавать копии реестра при перезагрузки ПК (значение по умолчанию)
# RegistryBackup -Disable
#endregion System

#region WSL
<#
	Enable Windows Subsystem for Linux (WSL), install the latest WSL Linux kernel version, and a Linux distribution using a pop-up form
	The "Receive updates for other Microsoft products" setting will enabled automatically to receive kernel updates

	Установить подсистему Windows для Linux (WSL), последний пакет обновления ядра Linux и дистрибутив Linux, используя всплывающую форму
	Параметр "При обновлении Windows получать обновления для других продуктов Майкрософт" будет включен автоматически в Центре обновлении Windows, чтобы получать обновления ядра
#>
# Install-WSL
#endregion WSL

#region Start menu
# Show default Start layout (default value)
# Отображать стандартный макет начального экрана (значение по умолчанию)
# StartLayout -Default

# Show more pins on Start
# Отображать больше закреплений на начальном экране
StartLayout -ShowMorePins

# Show more recommendations on Start
# Отображать больше рекомендаций на начальном экране
# StartLayout -ShowMoreRecommendations
#endregion Start menu

#region UWP apps

# Install Copilot App
#Copilot -Install

# Uninstall Copilot App
Copilot -Uninstall

# Uninstall UWP apps using the pop-up dialog box
# Удалить UWP-приложения, используя всплывающее диалоговое окно
UninstallUWPApps

<#
	Uninstall UWP apps for all users using the pop-up dialog box
	If the "For All Users" is checked apps packages will not be installed for new users

	Удалить UWP-приложения для всех пользователей, используя всплывающее диалоговое окно
	Пакеты приложений не будут установлены для новых пользователей, если отмечена галочка "Для всех пользователей"
#>
# UninstallUWPApps -ForAllUsers

# Disable Cortana autostarting
# Выключить автозагрузку Кортана
CortanaAutostart -Disable

# Enable Cortana autostarting (default value)
# Включить автозагрузку Кортана (значение по умолчанию)
# CortanaAutostart -Enable
#endregion UWP apps

#region Gaming
<#
	Disable Xbox Game Bar
	To prevent popping up the "You'll need a new app to open this ms-gamingoverlay" warning, you need to disable the Xbox Game Bar app, even if you uninstalled it before

	Отключить Xbox Game Bar
	Чтобы предотвратить появление предупреждения "Вам понадобится новое приложение, чтобы открыть этот ms-gamingoverlay", вам необходимо отключить приложение Xbox Game Bar, даже если вы удалили его раньше
#>
XboxGameBar -Disable

# Enable Xbox Game Bar (default value)
# Включить Xbox Game Bar (значение по умолчанию)
# XboxGameBar -Enable

# Disable Xbox Game Bar tips
# Отключить советы Xbox Game Bar
XboxGameTips -Disable

# Enable Xbox Game Bar tips (default value)
# Включить советы Xbox Game Bar (значение по умолчанию)
# XboxGameTips -Enable

# Choose an app and set the "High performance" graphics performance for it. Only if you have a dedicated GPU
# Выбрать приложение и установить для него параметры производительности графики на "Высокая производительность". Только при наличии внешней видеокарты
Set-AppGraphicsPerformance

<#
	Turn on hardware-accelerated GPU scheduling. Restart needed
	Only if you have a dedicated GPU and WDDM verion is 2.7 or higher

	Включить планирование графического процессора с аппаратным ускорением. Необходима перезагрузка
	Только при наличии внешней видеокарты и WDDM версии 2.7 и выше
#>
GPUScheduling -Enable

# Turn off hardware-accelerated GPU scheduling (default value). Restart needed
# Выключить планирование графического процессора с аппаратным ускорением (значение по умолчанию). Необходима перезагрузка
# GPUScheduling -Disable
#endregion Gaming

#region Scheduled tasks
<#
	Create the "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates.
	A native interactive toast notification pops up every 30 days. You have to enable Windows Script Host in order to make the function work

	Создать задание "Windows Cleanup" по очистке неиспользуемых файлов и обновлений Windows в Планировщике заданий.
	Задание выполняется каждые 30 дней. Необходимо включить Windows Script Host для того, чтобы работала функция
#>
#CleanupTask -Register

# Delete the "Windows Cleanup" and "Windows Cleanup Notification" scheduled tasks for cleaning up Windows unused files and updates
# Удалить задания "Windows Cleanup" и "Windows Cleanup Notification" по очистке неиспользуемых файлов и обновлений Windows из Планировщика заданий
# CleanupTask -Delete

<#
	Create the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder
	The task will wait until the Windows Updates service finishes running. The task runs every 90 days. You have to enable Windows Script Host in order to make the function work

	Создать задание "SoftwareDistribution" по очистке папки %SystemRoot%\SoftwareDistribution\Download в Планировщике заданий
	Задание будет ждать, пока служба обновлений Windows не закончит работу. Задание выполняется каждые 90 дней. Необходимо включить Windows Script Host для того, чтобы работала функция
#>
#SoftwareDistributionTask -Register

# Delete the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder
# Удалить задание "SoftwareDistribution" по очистке папки %SystemRoot%\SoftwareDistribution\Download из Планировщика заданий
# SoftwareDistributionTask -Delete

<#
	Create the "Temp" scheduled task for cleaning up the %TEMP% folder
	Only files older than one day will be deleted. The task runs every 60 days. You have to enable Windows Script Host in order to make the function work

	Создать задание "Temp" в Планировщике заданий по очистке папки %TEMP%
	Удаляться будут только файлы старше одного дня. Задание выполняется каждые 60 дней. Необходимо включить Windows Script Host для того, чтобы работала функция
#>
#TempTask -Register

# Delete the "Temp" scheduled task for cleaning up the %TEMP% folder
# Удалить задание "Temp" по очистке папки %TEMP% из Планировщика заданий
# TempTask -Delete
#endregion Scheduled tasks

#region Microsoft Defender & Security
# Enable Microsoft Defender Exploit Guard network protection
# Включить защиту сети в Microsoft Defender Exploit Guard
NetworkProtection -Enable

# Disable Microsoft Defender Exploit Guard network protection (default value)
# Выключить защиту сети в Microsoft Defender Exploit Guard (значение по умолчанию)
# NetworkProtection -Disable

# Enable detection for potentially unwanted applications and block them
# Включить обнаружение потенциально нежелательных приложений и блокировать их
PUAppsDetection -Enable

# Disable detection for potentially unwanted applications and block them (default value)
# Выключить обнаружение потенциально нежелательных приложений и блокировать их (значение по умолчанию)
# PUAppsDetection -Disable

# Enable sandboxing for Microsoft Defender
# Включить песочницу для Microsoft Defender
DefenderSandbox -Enable

# Disable sandboxing for Microsoft Defender (default value)
# Выключить песочницу для Microsoft Defender (значение по умолчанию)
# DefenderSandbox -Disable

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
# Отклонить предложение Microsoft Defender в "Безопасность Windows" о входе в аккаунт Microsoft
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
# Отклонить предложение Microsoft Defender в "Безопасность Windows" включить фильтр SmartScreen для Microsoft Edge
DismissSmartScreenFilter

# Create the "Process Creation" сustom view in the Event Viewer to log executed processes and their arguments
# Создать настраиваемое представление "Создание процесса" в Просмотре событий для журналирования запускаемых процессов и их аргументов
EventViewerCustomView -Enable

# Remove the "Process Creation" custom view in the Event Viewer to log executed processes and their arguments (default value)
# Удалить настраиваемое представление "Создание процесса" в Просмотре событий для журналирования запускаемых процессов и их аргументов (значение по умолчанию)
# EventViewerCustomView -Disable

# Enable logging for all Windows PowerShell modules
# Включить ведение журнала для всех модулей Windows PowerShell
PowerShellModulesLogging -Enable

# Disable logging for all Windows PowerShell modules (default value)
# Выключить ведение журнала для всех модулей Windows PowerShell (значение по умолчанию)
# PowerShellModulesLogging -Disable

# Enable logging for all PowerShell scripts input to the Windows PowerShell event log
# Включить ведение журнала для всех вводимых сценариев PowerShell в журнале событий Windows PowerShell
PowerShellScriptsLogging -Enable

# Disable logging for all PowerShell scripts input to the Windows PowerShell event log (default value)
# Выключить ведение журнала для всех вводимых сценариев PowerShell в журнале событий Windows PowerShell (значение по умолчанию)
# PowerShellScriptsLogging -Disable

# Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe
# Microsoft Defender SmartScreen не помечает скачанные файлы из интернета как небезопасные
AppsSmartScreen -Disable

# Microsoft Defender SmartScreen marks downloaded files from the Internet as unsafe (default value)
# Microsoft Defender SmartScreen помечает скачанные файлы из интернета как небезопасные (значение по умолчанию)
# AppsSmartScreen -Enable

# Disable the Attachment Manager marking files that have been downloaded from the Internet as unsafe
# Выключить проверку Диспетчером вложений файлов, скачанных из интернета, как небезопасные
SaveZoneInformation -Disable

# Enable the Attachment Manager marking files that have been downloaded from the Internet as unsafe (default value)
# Включить проверку Диспетчера вложений файлов, скачанных из интернета как небезопасные (значение по умолчанию)
# SaveZoneInformation -Enable

# Disable Windows Script Host. Blocks WSH from executing .js and .vbs files
# Отключить Windows Script Host. Блокирует запуск файлов .js и .vbs
# WindowsScriptHost -Disable

# Enable Windows Script Host (default value)
# Включить Windows Script Host (значение по умолчанию)
# WindowsScriptHost -Enable

# Enable Windows Sandbox. Applicable only to Professional, Enterprise and Education editions
# Включить Windows Sandbox. Применимо только к редакциям Professional, Enterprise и Education
# WindowsSandbox -Enable

# Disable Windows Sandbox (default value). Applicable only to Professional, Enterprise and Education editions
# Выключить Windows Sandbox (значение по умолчанию). Применимо только к редакциям Professional, Enterprise и Education
# WindowsSandbox -Disable

<#
	Enable DNS-over-HTTPS for IPv4
	The valid IPv4 addresses: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9

	Включить DNS-over-HTTPS для IPv4
	Действительные IPv4-адреса: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9
#>
# DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1

# Disable DNS-over-HTTPS for IPv4 (default value)
# Выключить DNS-over-HTTPS для IPv4 (значение по умолчанию)
# DNSoverHTTPS -Disable

# Enable DNS-over-HTTPS via Comss.one DNS server. Applicable for Russia only
# Включить DNS-over-HTTPS для IPv4 через DNS-сервер Comss.one. Применимо только для России
# DNSoverHTTPS -ComssOneDNS

# Enable Local Security Authority protection to prevent code injection
# Включить защиту локальной системы безопасности, чтобы предотвратить внедрение кода
# LocalSecurityAuthority -Enable

# Disable Local Security Authority protection (default value)
# Выключить защиту локальной системы безопасности (значение по умолчанию)
# LocalSecurityAuthority -Disable

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
# Отобразить пункт "Извлечь все" в контекстное меню Windows Installer (.msi)
MSIExtractContext -Show

# Hide the "Extract all" item from the Windows Installer (.msi) context menu (default value)
# Скрыть пункт "Извлечь все" из контекстного меню Windows Installer (.msi) (значение по умолчанию)
# MSIExtractContext -Hide

# Show the "Install" item in the Cabinet (.cab) filenames extensions context menu
# Отобразить пункт "Установить" в контекстное меню .cab архивов
CABInstallContext -Show

# Hide the "Install" item from the Cabinet (.cab) filenames extensions context menu (default value)
# Скрыть пункт "Установить" из контекстного меню .cab архивов (значение по умолчанию)
# CABInstallContext -Hide

# Hide the "Edit with Clipchamp" item from the media files context menu
# Скрыть пункт "Редактировать в Climpchamp" из контекстного меню
EditWithClipchampContext -Hide

# Show the "Edit with Clipchamp" item in the media files context menu (default value)
# Отобразить пункт "Редактировать в Climpchamp" в контекстном меню (значение по умолчанию)
# EditWithClipchampContext -Show

# Hide the "Edit with Photos" item from the media files context menu
# Скрыть пункт "Изменить с помощью приложения "Фотографии"" из контекстного меню
EditWithPhotosContext -Hide

# Show the "Edit with Photos" item in the media files context menu (default value)
# Отобразить пункт "Изменить с помощью приложения "Фотографии"" в контекстном меню (значение по умолчанию)
# EditWithPhotosContext -Show

# Hide the "Edit with Paint" item from the media files context menu
# Скрыть пункт "Изменить с помощью приложения "Paint"" из контекстного меню
EditWithPaintContext -Hide

# Show the "Edit with Paint" item in the media files context menu (default value)
# Отобразить пункт "Изменить с помощью приложения "Paint"" в контекстном меню (значение по умолчанию)
# EditWithPaintContext -Show

# Hide the "Print" item from the .bat and .cmd context menu
# Скрыть пункт "Печать" из контекстного меню .bat и .cmd файлов
PrintCMDContext -Hide

# Show the "Print" item in the .bat and .cmd context menu (default value)
# Отобразить пункт "Печать" в контекстном меню .bat и .cmd файлов (значение по умолчанию)
# PrintCMDContext -Show

# Hide the "Compressed (zipped) Folder" item from the "New" context menu
# Скрыть пункт "Сжатая ZIP-папка" из контекстного меню "Создать"
CompressedFolderNewContext -Hide

# Show the "Compressed (zipped) Folder" item to the "New" context menu (default value)
# Отобразить пункт "Сжатая ZIP-папка" в контекстном меню "Создать" (значение по умолчанию)
# CompressedFolderNewContext -Show

# Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
# Включить элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
MultipleInvokeContext -Enable

# Disable the "Open", "Print", and "Edit" context menu items for more than 15 items selected (default value)
# Отключить элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов (значение по умолчанию)
# MultipleInvokeContext -Disable

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
# Скрыть пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
UseStoreOpenWith -Hide

# Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog (default value)
# Отобразить пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью" (значение по умолчанию)
# UseStoreOpenWith -Show

# Show the "Open in Windows Terminal" item in the folders context menu (default value)
# Отобразить пункт "Открыть в Терминале Windows" в контекстном меню папок (значение по умолчанию)
OpenWindowsTerminalContext -Show

# Hide the "Open in Windows Terminal" item in the folders context menu
# Скрыть пункт "Открыть в Терминале Windows" в контекстном меню папок
# OpenWindowsTerminalContext -Hide

# Open Windows Terminal in context menu as administrator by default
# Открывать Windows Terminal из контекстного меню от имени администратора по умолчанию
OpenWindowsTerminalAdminContext -Enable

# Do not open Windows Terminal in context menu as administrator by default (default value)
# Не открывать Windows Terminal из контекстного меню от имени администратора по умолчанию (значение по умолчанию)
# OpenWindowsTerminalAdminContext -Disable
#endregion Context menu

#region Update Policies
<#
	Display all policy registry keys (even manually created ones) in the Local Group Policy Editor snap-in (gpedit.msc)
	This can take up to 30 minutes, depending on the number of policies created in the registry and your system resources

	Отобразить все политики реестра (даже созданные вручную) в оснастке Редактора локальной групповой политики (gpedit.msc)
	Это может занять до 30 минут в зависимости от количества политик, созданных в реестре, и мощности вашей системы
#>
# UpdateLGPEPolicies
#endregion Update Policies

# Environment refresh and other neccessary post actions
# Обновление окружения и прочие необходимые действия после выполнения основных функций
PostActions

# Errors output
# Вывод ошибок
Errors
