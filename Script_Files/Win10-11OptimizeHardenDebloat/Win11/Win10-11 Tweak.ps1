$Host.UI.RawUI.WindowTitle = "Windows 11 Tweaks"

# Tweaks
# Adds a # to disable functions
$tweaks = @(
    # We take admin privileges #
    "RequireAdmin",
 
    # Privacy - AntiTracking - Telemetry #
    # "DisableTelemetry",             
	# "EnableTelemetry",
	
    #"DisableWiFiSense",             
	# "EnableWiFiSense", # Please comment this line if you want to do connection sharing
	
    #"DisableSmartScreen",           
	# "EnableSmartScreen",
	
    #"DisableWebSearch",             
	# "EnableWebSearch",
	
    #"DisableAppSuggestions",        
	# "EnableAppSuggestions",
	
    "DisableBackgroundApps",        
	# "EnableBackgroundApps",
	
    "DisableLockScreenSpotlight",   
	# "EnableLockScreenSpotlight",
	
    "DisableLocationTracking",      
	# "EnableLocationTracking",
	
    #"DisableMapUpdates",            
	# "EnableMapUpdates",
	
    #"DisableFeedback",              
	# "EnableFeedback",
	
    #"DisableAdvertisingID",         
	# "EnableAdvertisingID",
	
    #"DisableCortana",               
	# "EnableCortana",
	
    "DisableErrorReporting",        
	# "EnableErrorReporting",
	
    #"SetP2PUpdateLocal",            
	 "SetP2PUpdateInternet",
	
    # "DisableAutoLogger",          
	# "EnableAutoLogger", # May cause instability.
	
    #"DisableDiagTrack",             
	# "EnableDiagTrack",
	
    #"DisableWAPPush",               
	# "EnableWAPPush",
 
    # Permissions / Firewall / Autorun et cie #
    #"SetUACLow",                    
	# "SetUACHigh", # This option disables user action confirmations. Disabling it is fine, but may cause some problems with some apps.
    
	 "EnableSharingMappedDrives",   
	# "DisableSharingMappedDrives",
    
	# "DisableAdminShares",          
	"EnableAdminShares",

    # "DisableSMB1",                 
	# "EnableSMB1",
    
	#"SetCurrentNetworkPrivate",      
	# "SetCurrentNetworkPublic",
    
	# "SetUnknownNetworksPrivate",   
	"SetUnknownNetworksPublic",
    
	"EnableCtrldFolderAccess",       
	# "DisableCtrldFolderAccess",
    
	# "DisableFirewall",               
	"EnableFirewall",
    
	# "DisableDefender",               
	"EnableDefender",
    
	# "DisableDefenderCloud",          
	"EnableDefenderCloud",
    
	# "DisableUpdateMSRT",          
	"EnableUpdateMSRT",
    
	# "DisableUpdateDriver",           
	"EnableUpdateDriver",  # This line disables the Drivers part of WinUpdate (used to reinstall its drivers properly). This service can still be find in services.msc.
    
	"DisableUpdateRestart",          
	# "EnableUpdateRestart",
    
	# "DisableHomeGroups",             
	"EnableHomeGroups",
    
	# "DisableSharedExperiences",      
	"EnableSharedExperiences",
    
	#"DisableRemoteAssistance",       
	# "EnableRemoteAssistance",
    
	"DisableRemoteDesktop",          
	# "EnableRemoteDesktop",
    
	#"DisableAutoplay",               
	# "EnableAutoplay",
    
	"DisableAutorun",               
	# "EnableAutorun",
    
	"EnableStorageSense",           
	# "DisableStorageSense",
    
	"DisableDefragmentation",        
	# "EnableDefragmentation",
    
	"DisableSuperfetch",             
	# "EnableSuperfetch",
    
	"DisableIndexing",               
	# "EnableIndexing",
    
	# "SetBIOSTimeUTC",              
    "SetBIOSTimeLocal",
    
	"DisableHibernation",            
	# "EnableHibernation",
   
    "DisableFastStartup",            
	# "EnableFastStartup",
 
    # Sleep Deactivation / Windows Visuals /  #
    # "DisableActionCenter",        
	# "EnableActionCenter",
    
	# "DisableLockScreen",            
	# "EnableLockScreen",
    
	# "DisableLockScreenRS1",         
	# "EnableLockScreenRS1",
    
	# "HideNetworkFromLockScreen",    
	# "ShowNetworkOnLockScreen",
    
	# "HideShutdownFromLockScreen",   
	# "ShowShutdownOnLockScreen",
    
	"DisableStickyKeys",            
	# "EnableStickyKeys",
    
	#"ShowTaskManagerDetails"        
	# "HideTaskManagerDetails",
    
	#"ShowFileOperationsDetails",    
	# "HideFileOperationsDetails",
    
	"DisableFileDeleteConfirm",     
	# "EnableFileDeleteConfirm", ## This line will delete without confirmation the files you delete without going through the trashcan.
    
	#"ShowTaskbarSearchBox",         
    #"HideTaskbarSearchBox",
    
	#"HideTaskView",                 
	# "ShowTaskView",
   
    # "ShowSmallTaskbarIcons",        
	# "ShowLargeTaskbarIcons",
    
	# "HideTaskbarTitles",            
	# "ShowTaskbarTitles",
	
    #"HideTaskbarPeopleIcon",        
	# "ShowTaskbarPeopleIcon",

    #"ShowTrayIcons",                
	# "HideTrayIcons",

    # "ShowKnownExtensions",          
	 "HideKnownExtensions",

    "HideHiddenFiles",              
	# "ShowHiddenFiles",

    # "HideSyncNotifications"         
	# "ShowSyncNotifications",
    
	# "HideRecentShortcuts",          
	"ShowRecentShortcuts",
    
	"SetExplorerThisPC",            
	# "SetExplorerQuickAccess",
    
	"HideThisPCFromDesktop",       
	# "ShowThisPCOnDesktop",
    
	# "ShowUserFolderOnDesktop",    
	# "HideUserFolderFromDesktop",
    
	# "HideDesktopFromThisPC",      
	# "ShowDesktopInThisPC",
    
	# "HideDocumentsFromThisPC",     
	# "ShowDocumentsInThisPC",
    
	# "HideDownloadsFromThisPC",     
	# "ShowDownloadsInThisPC",
    
	# "HideMusicFromThisPC",         
	# "ShowMusicInThisPC",
    
	# "HidePicturesFromThisPC",      
	# "ShowPicturesInThisPC",
    
	# "HideVideosFromThisPC",        
	# "ShowVideosInThisPC",
    
	"Hide3DObjectsFromThisPC",     
	# "Show3DObjectsInThisPC",
	
 	## This line is used to change the whole visual of the Windows desktop (Reduce the taskbar).
	############ I disable it for you to avoid having all those who read not come and take my head on their little taskbar but if you read this, 
	############ remove the # in front of the line 
	"SetVisualFXPerformance",     
	# "SetVisualFXAppearance",
	
    "DisableThumbnails",          
	# "EnableThumbnails",
    
	"DisableThumbsDB",              
	# "EnableThumbsDB",

	
	## This line will remove the English keyboard from your PC. Replace the "EN" with the abbreviation of the language you are
	## concerned with.
	# "RemoveENKeyboard",
	# "AddENKeyboard",
	
    "EnableNumlock",                
	# "DisableNumlock",
 
    # OneDrive - Boot Menu - #
    # "DisableOneDrive",              
	# "EnableOneDrive",
    
	# "UninstallOneDrive",            
	# "InstallOneDrive",
    
	# "UninstallMsftBloat",           
	# "InstallMsftBloat",
    
	"UninstallThirdPartyBloat",     
	# "InstallThirdPartyBloat",
    
	# "UninstallWindowsStore",        
    # "InstallWindowsStore", # This line deletes the Windows Store. To be reinstalled if you play Xbox Games.
    
	"DisableXboxFeatures",          
	# "EnableXboxFeatures", # Here we disable ALL Xbox, if you play games that need it, add a #, if you have deleted it, change the order.
    
	#"DisableAdobeFlash",            
    "EnableAdobeFlash",
   
    "UninstallMediaPlayer",         
	# "InstallMediaPlayer", 

    "UninstallWorkFolders",         
	# "InstallWorkFolders",

    # "InstallLinuxSubsystem",      
	# "UninstallLinuxSubsystem",

    # "InstallHyperV",              
	# "UninstallHyperV",

    "SetPhotoViewerAssociation",  
	# "UnsetPhotoViewerAssociation",

    "AddPhotoViewerOpenWith",       
	# "RemovePhotoViewerOpenWith",
    
	#"DisableSearchAppInStore",      
    "EnableSearchAppInStore",
   
    "DisableNewAppPrompt",          
	# "EnableNewAppPrompt",
 
    "EnableF8BootMenu",           
	# "DisableF8BootMenu",
    
	"SetDEPOptOut",                 
	# "SetDEPOptIn",
   
   # Services - WindowsSearch #
    "DeleteTempFiles",
    "CleanWinSXS", 
    #"EnableWindowsSearch",         
    "DisableWindowsSearch",
    #"DisableCompatibilityAppraiser",
   
    ### Connexion / Windows / GPDW ###
    "DisableConnectedStandby",
    # "EnableBigDesktopIcons"
    # "DisableUpdateDriver" # Disable automatic driver updates
    "DisableHibernation"
)
 
 ##############################################################
## DON'T TOUCH THIS BELOW IF YOU DON'T KNOW WHAT YOU ARE DOING ##
 ############################################################## 
 
##########
# Privacy
##########
 
# Disable Telemetry
Function DisableTelemetry {
    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
}
 
# Enable Telemetry
Function EnableTelemetry {
    Write-Host "Enabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
}
 
# Disable Wi-Fi Sense
Function DisableWiFiSense {
    Write-Host "Disabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
}
 
# Enable Wi-Fi Sense
Function EnableWiFiSense {
    Write-Host "Enabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
}
 
# Disable SmartScreen Filter
Function DisableSmartScreen {
    Write-Host "Disabling SmartScreen Filter..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
    $edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
    If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -Type DWord -Value 0
}
  
# Disable Web Search in Start Menu
Function DisableWebSearch {
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
    Write-Host "Disabling Application suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}
  
# Disable Background application access - ie. if apps can download or update even when they aren't used
Function DisableBackgroundApps {
    Write-Host "Disabling Background application access..."
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
}
 
# Enable Background application access
Function EnableBackgroundApps {
    Write-Host "Enabling Background application access..."
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
    }
}
 
# Disable Lock screen Spotlight - New backgrounds, tips, advertisements etc.
Function DisableLockScreenSpotlight {
    Write-Host "Disabling Lock screen spotlight..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
}
 
# Enable Lock screen Spotlight
Function EnableLockScreenSpotlight {
    Write-Host "Disabling Lock screen spotlight..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 1
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue
}
 
# Disable Location Tracking
Function DisableLocationTracking {
    Write-Host "Disabling Location Tracking..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}
 
# Enable Location Tracking
Function EnableLocationTracking {
    Write-Host "Enabling Location Tracking..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
}
 
# Disable automatic Maps updates
Function DisableMapUpdates {
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}
 
# Enable automatic Maps updates
Function EnableMapUpdates {
    Write-Host "Enable automatic Maps updates..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue
}
 
# Disable Feedback
Function DisableFeedback {
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
}
 
# Enable Feedback
Function EnableFeedback {
    Write-Host "Enabling Feedback..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
}
 
# Disable Advertising ID
Function DisableAdvertisingID {
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0
}
 
# Enable Advertising ID
Function EnableAdvertisingID {
    Write-Host "Enabling Advertising ID..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 2
}
 
# Disable Cortana
Function DisableCortana {
    Write-Host "Disabling Cortana..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}
 
# Enable Cortana
Function EnableCortana {
    Write-Host "Enabling Cortana..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
}
 
# Disable Error reporting
Function DisableErrorReporting {
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
}
 
# Enable Error reporting
Function EnableErrorReporting {
    Write-Host "Enabling Error reporting..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
}
 
# Restrict Windows Update P2P only to local network
Function SetP2PUpdateLocal {
    Write-Host "Restricting Windows Update P2P only to local network..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3
}
 
# Unrestrict Windows Update P2P
Function SetP2PUpdateInternet {
    Write-Host "Unrestricting Windows Update P2P to internet..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -ErrorAction SilentlyContinue
}
 
# Remove AutoLogger file and restrict directory
Function DisableAutoLogger {
    Write-Host "Removing AutoLogger file and restricting directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}
 
# Unrestrict AutoLogger directory
Function EnableAutoLogger {
    Write-Host "Unrestricting AutoLogger directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
}
 
# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
}
 
# Enable and start Diagnostics Tracking Service
Function EnableDiagTrack {
    Write-Host "Enabling and starting Diagnostics Tracking Service..."
    Set-Service "DiagTrack" -StartupType Automatic
    Start-Service "DiagTrack" -WarningAction SilentlyContinue
}
 
# Stop and disable WAP Push Service
Function DisableWAPPush {
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
}
 
# Enable and start WAP Push Service
Function EnableWAPPush {
    Write-Host "Enabling and starting WAP Push Service..."
    Set-Service "dmwappushservice" -StartupType Automatic
    Start-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
}
 
 
 
##########
# Service Tweaks
##########
 
# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
    Write-Host "Lowering UAC level..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}
 
# Raise UAC level
Function SetUACHigh {
    Write-Host "Raising UAC level..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}
 
# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
    Write-Host "Enabling sharing mapped drives between users..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}
 
# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
    Write-Host "Disabling sharing mapped drives between users..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}
 
# Disable implicit administrative shares
Function DisableAdminShares {
    Write-Host "Disabling implicit administrative shares..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}
 
# Enable implicit administrative shares
Function EnableAdminShares {
    Write-Host "Enabling implicit administrative shares..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}
 
# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
    Write-Host "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}
 
# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
    Write-Host "Enabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}
 
# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
    Write-Host "Setting current network profile to private..."
    Set-NetConnectionProfile -NetworkCategory Private
}
 
# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
    Write-Host "Setting current network profile to public..."
    Set-NetConnectionProfile -NetworkCategory Public
}
 
# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
    Write-Host "Setting unknown networks profile to private..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}
 
# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
    Write-Host "Setting unknown networks profile to public..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}
 
# Enable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function EnableCtrldFolderAccess {
    Write-Host "Enabling Controlled Folder Access..."
    Set-MpPreference -EnableControlledFolderAccess Enabled
}
 
# Disable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function DisableCtrldFolderAccess {
    Write-Host "Disabling Controlled Folder Access..."
    Set-MpPreference -EnableControlledFolderAccess Disabled
}
 
# Disable Firewall
Function DisableFirewall {
    Write-Host "Disabling Firewall..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}
 
# Enable Firewall
Function EnableFirewall {
    Write-Host "Enabling Firewall..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}
 
# Disable Windows Defender
Function DisableDefender {
    Write-Host "Disabling Windows Defender..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
}
 
# Enable Windows Defender
Function EnableDefender {
    Write-Host "Enabling Windows Defender..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
}
 
# Disable Windows Defender Cloud
Function DisableDefenderCloud {
    Write-Host "Disabling Windows Defender Cloud..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}
 
# Enable Windows Defender Cloud
Function EnableDefenderCloud {
    Write-Host "Enabling Windows Defender Cloud..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
}
 
# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
    Write-Host "Disabling Malicious Software Removal Tool offering..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}
 
# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
    Write-Host "Enabling Malicious Software Removal Tool offering..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}
 
# Disable offering of drivers through Windows Update
Function DisableUpdateDriver {
    Write-Host "Disabling driver offering through Windows Update..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
}
 
# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
    Write-Host "Enabling driver offering through Windows Update..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}
 
# Disable Windows Update automatic restart
Function DisableUpdateRestart {
    Write-Host "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
}
 
# Enable Windows Update automatic restart
Function EnableUpdateRestart {
    Write-Host "Enabling Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
}
 
# Stop and disable Home Groups services - Not applicable to Server
Function DisableHomeGroups {
    Write-Host "Stopping and disabling Home Groups services..."
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
}
 
# Enable and start Home Groups services - Not applicable to Server
Function EnableHomeGroups {
    Write-Host "Starting and enabling Home Groups services..."
    Set-Service "HomeGroupListener" -StartupType Manual
    Set-Service "HomeGroupProvider" -StartupType Manual
    Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
}
 
# Disable Shared Experiences - Not applicable to Server
Function DisableSharedExperiences {
    Write-Host "Disabling Shared Experiences..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0
}
 
# Enable Shared Experiences - Not applicable to Server
Function EnableSharedExperiences {
    Write-Host "Enabling Shared Experiences..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 1
}
 
# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}
 
# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
    Write-Host "Enabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
}
 
# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
    Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
}
 
# Disable Remote Desktop
Function DisableRemoteDesktop {
    Write-Host "Disabling Remote Desktop..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
}
 
# Disable Autoplay
Function DisableAutoplay {
    Write-Host "Disabling Autoplay..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}
 
# Enable Autoplay
Function EnableAutoplay {
    Write-Host "Enabling Autoplay..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}
 
# Disable Autorun for all drives
Function DisableAutorun {
    Write-Host "Disabling Autorun for all drives..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}
 
# Enable Autorun for removable drives
Function EnableAutorun {
    Write-Host "Enabling Autorun for all drives..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}
 
# Enable Storage Sense - automatic disk cleanup - Not applicable to Server
Function EnableStorageSense {
    Write-Host "Enabling Storage Sense..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1 -ErrorAction SilentlyContinue
}
 
# Disable Storage Sense - Not applicable to Server
Function DisableStorageSense {
    Write-Host "Disabling Storage Sense..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0 -ErrorAction SilentlyContinue
}
 
# Disable scheduled defragmentation task
Function DisableDefragmentation {
    Write-Host "Disabling scheduled defragmentation..."
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
 
# Enable scheduled defragmentation task
Function EnableDefragmentation {
    Write-Host "Enabling scheduled defragmentation..."
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
 
# Stop and disable Superfetch service - Not applicable to Server
Function DisableSuperfetch {
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
}
 
# Start and enable Superfetch service - Not applicable to Server
Function EnableSuperfetch {
    Write-Host "Starting and enabling Superfetch service..."
    Set-Service "SysMain" -StartupType Automatic
    Start-Service "SysMain" -WarningAction SilentlyContinue
}
 
# Stop and disable Windows Search indexing service
Function DisableIndexing {
    Write-Host "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}
 
# Start and enable Windows Search indexing service
Function EnableIndexing {
    Write-Host "Starting and enabling Windows Search indexing service..."
    Set-Service "WSearch" -StartupType Automatic
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
    Start-Service "WSearch" -WarningAction SilentlyContinue
}
 
# Set BIOS time to UTC
Function SetBIOSTimeUTC {
    Write-Host "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
}
 
# Set BIOS time to local time
Function SetBIOSTimeLocal {
    Write-Host "Setting BIOS time to Local time..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
}
 
# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernation {
    Write-Host "Enabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 1
}
 
# Disable Hibernation
Function DisableHibernation {
    Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
}
 
# Disable Fast Startup
Function DisableFastStartup {
    Write-Host "Disabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}
 
# Enable Fast Startup
Function EnableFastStartup {
    Write-Host "Enabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}
 
##########
# UI Tweaks
##########
 
# Disable Action Center
Function DisableActionCenter {
    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}
 
# Enable Action Center
Function EnableActionCenter {
    Write-Host "Enabling Action Center..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
}
 
# Disable Lock screen
Function DisableLockScreen {
    Write-Host "Disabling Lock screen..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
}
 
# Enable Lock screen
Function EnableLockScreen {
    Write-Host "Enabling Lock screen..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}
 
# Disable Lock screen (Anniversary Update workaround) - Applicable to 1607 or newer
Function DisableLockScreenRS1 {
    Write-Host "Disabling Lock screen using scheduler workaround..."
    $service = New-Object -com Schedule.Service
    $service.Connect()
    $task = $service.NewTask(0)
    $task.Settings.DisallowStartIfOnBatteries = $false
    $trigger = $task.Triggers.Create(9)
    $trigger = $task.Triggers.Create(11)
    $trigger.StateChange = 8
    $action = $task.Actions.Create(0)
    $action.Path = "reg.exe"
    $action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
    $service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}
 
# Enable Lock screen (Anniversary Update workaround) - Applicable to 1607 or newer
Function EnableLockScreenRS1 {
    Write-Host "Enabling Lock screen (removing scheduler workaround)..."
    Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
}
 
# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
    Write-Host "Hiding network options from Lock Screen..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
}
 
# Show network options on lock screen
Function ShowNetworkOnLockScreen {
    Write-Host "Showing network options on Lock Screen..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
}
 
# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
    Write-Host "Hiding shutdown options from Lock Screen..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
}
 
# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
    Write-Host "Showing shutdown options on Lock Screen..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1
}
 
# Disable Sticky keys prompt
Function DisableStickyKeys {
    Write-Host "Disabling Sticky keys prompt..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}
 
# Enable Sticky keys prompt
Function EnableStickyKeys {
    Write-Host "Enabling Sticky keys prompt..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
}
 
# Show Task Manager details
Function ShowTaskManagerDetails {
    Write-Host "Showing task manager details..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Force | Out-Null
    }
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    If (!($preferences)) {
        $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
        While (!($preferences)) {
            Start-Sleep -m 250
            $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
        }
        Stop-Process $taskmgr
    }
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
}
 
# Hide Task Manager details
Function HideTaskManagerDetails {
    Write-Host "Hiding task manager details..."
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    If ($preferences) {
        $preferences.Preferences[28] = 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    }
}
 
# Show file operations details
Function ShowFileOperationsDetails {
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}
 
# Hide file operations details
Function HideFileOperationsDetails {
    Write-Host "Hiding file operations details..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
}
 
# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
    Write-Host "Enabling file delete confirmation dialog..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}
 
# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm {
    Write-Host "Disabling file delete confirmation dialog..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}
 
# Hide Taskbar Search button / box
Function HideTaskbarSearchBox {
    Write-Host "Hiding Taskbar Search box / button..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}
 
# Show Taskbar Search button / box
Function ShowTaskbarSearchBox {
    Write-Host "Showing Taskbar Search box / button..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue
}
 
# Hide Task View button
Function HideTaskView {
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}
 
# Show Task View button
Function ShowTaskView {
    Write-Host "Showing Task View button..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}
 
# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
    Write-Host "Showing small icons in taskbar..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}
 
# Show large icons in taskbar
Function ShowLargeTaskbarIcons {
    Write-Host "Showing large icons in taskbar..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
}
 
# Show titles in taskbar
Function ShowTaskbarTitles {
    Write-Host "Showing titles in taskbar..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
}
 
# Hide titles in taskbar
Function HideTaskbarTitles {
    Write-Host "Hiding titles in taskbar..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
}
 
# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
    Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}
 
# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
    Write-Host "Showing People icon..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue
}
 
# Show all tray icons
Function ShowTrayIcons {
    Write-Host "Showing all tray icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
}
 
# Hide tray icons as needed
Function HideTrayIcons {
    Write-Host "Hiding tray icons..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -ErrorAction SilentlyContinue
}
 
# Show known file extensions
Function ShowKnownExtensions {
    Write-Host "Showing known file extensions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}
 
# Hide known file extensions
Function HideKnownExtensions {
    Write-Host "Hiding known file extensions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}
 
# Show hidden files
Function ShowHiddenFiles {
    Write-Host "Showing hidden files..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}
 
# Hide hidden files
Function HideHiddenFiles {
    Write-Host "Hiding hidden files..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}
 
# Hide sync provider notifications
Function HideSyncNotifications {
    Write-Host "Hiding sync provider notifications..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}
 
# Show sync provider notifications
Function ShowSyncNotifications {
    Write-Host "Showing sync provider notifications..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1
}
 
# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts {
    Write-Host "Hiding recent shortcuts..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}
 
# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
    Write-Host "Showing recent shortcuts..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue
}
 
# Change default Explorer view to This PC
Function SetExplorerThisPC {
    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}
 
# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess {
    Write-Host "Changing default Explorer view to Quick Access..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
}
 
# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
    Write-Host "Showing This PC shortcut on desktop..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}
 
# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
    Write-Host "Hiding This PC shortcut from desktop..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}
 
# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop {
    Write-Host "Showing User Folder shortcut on desktop..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}
 
# Hide User Folder shortcut from desktop
Function HideUserFolderFromDesktop {
    Write-Host "Hiding User Folder shortcut from desktop..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
}
 
# Hide Desktop icon from This PC
Function HideDesktopFromThisPC {
    Write-Host "Hiding Desktop icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Desktop icon in This PC
Function ShowDesktopInThisPC {
    Write-Host "Showing Desktop icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
    }
}
 
# Hide Documents icon from This PC
Function HideDocumentsFromThisPC {
    Write-Host "Hiding Documents icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Documents icon in This PC
Function ShowDocumentsInThisPC {
    Write-Host "Showing Documents icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
    }
}
 
# Hide Downloads icon from This PC
Function HideDownloadsFromThisPC {
    Write-Host "Hiding Downloads icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Downloads icon in This PC
Function ShowDownloadsInThisPC {
    Write-Host "Showing Downloads icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
    }
}
 
# Hide Music icon from This PC
Function HideMusicFromThisPC {
    Write-Host "Hiding Music icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Music icon in This PC
Function ShowMusicInThisPC {
    Write-Host "Showing Music icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
    }
}
 
# Hide Pictures icon from This PC
Function HidePicturesFromThisPC {
    Write-Host "Hiding Pictures icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Pictures icon in This PC
Function ShowPicturesInThisPC {
    Write-Host "Showing Pictures icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
    }
}
 
# Hide Videos icon from This PC
Function HideVideosFromThisPC {
    Write-Host "Hiding Videos icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Videos icon in This PC
Function ShowVideosInThisPC {
    Write-Host "Showing Videos icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
    }
}
 
# Hide 3D Objects icon from This PC
Function Hide3DObjectsFromThisPC {
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC {
    Write-Host "Showing 3D Objects icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
    }
}
 
# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
    Write-Host "Adjusting visual effects for performance..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}
 
# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
    Write-Host "Adjusting visual effects for appearance..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x9E,0x1E,0x07,0x80,0x12,0x00,0x00,0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}
 
# Disable thumbnails, show only file extension icons
Function DisableThumbnails {
    Write-Host "Disabling thumbnails..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
}
 
# Enable thumbnails
Function EnableThumbnails {
    Write-Host "Enabling thumbnails..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}
 
# Disable creation of Thumbs.db thumbnail cache files
Function DisableThumbsDB {
    Write-Host "Disabling creation of Thumbs.db..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}
 
# Enable creation of Thumbs.db thumbnail cache files
Function EnableThumbsDB {
    Write-Host "Enable creation of Thumbs.db..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue
}
 
# Add secondary en-US keyboard
Function AddENKeyboard {
    Write-Host "Adding secondary en-US keyboard..."
    $langs = Get-WinUserLanguageList
    $langs.Add("en-US")
    Set-WinUserLanguageList $langs -Force
}
 
# Remove secondary en-US keyboard
Function RemoveENKeyboard {
    Write-Host "Removing secondary en-US keyboard..."
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force
}
 
# Enable NumLock after startup
Function EnableNumlock {
    Write-Host "Enabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}
 
# Disable NumLock after startup
Function DisableNumlock {
    Write-Host "Disabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
    Add-Type -AssemblyName System.Windows.Forms
    If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}
 
 
 
##########
# Application Tweaks
##########
 
# Disable OneDrive
Function DisableOneDrive {
    Write-Host "Disabling OneDrive..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}
 
# Enable OneDrive
Function EnableOneDrive {
    Write-Host "Enabling OneDrive..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
}
 
# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
    Write-Host "Uninstalling OneDrive..."
    Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
    Start-Sleep -s 3
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 3
    Stop-Process -Name explorer -ErrorAction SilentlyContinue
    Start-Sleep -s 3
    Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}
 
# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
    Write-Host "Installing OneDrive..."
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive -NoNewWindow
}
 
# Uninstall default Microsoft applications
Function UninstallMsftBloat {
    Write-Host "Uninstalling Msft defaults..."
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage # Added removal of Dolby sound installed by default
    Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage # Warning, this line removes the default Windows photo viewer.
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage # Be careful with your StickyNotes, if the script is activated, your StickyNotes will be deleted and clearly unrecoverable.
    Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage 
    Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
}
 
# Install default Microsoft applications
Function InstallMsftBloat {
    Write-Host "Installation Msft defaults"
    Get-AppxPackage -AllUsers "Microsoft.3DBuilder" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingFinance" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingNews" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingSports" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingWeather" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Getstarted" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Office.OneNote" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.People" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.SkypeApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsAlarms" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.windowscommunicationsapps" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsMaps" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsPhone" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsSoundRecorder" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.ZuneMusic" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.ZuneVideo" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.AppConnector" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Office.Sway" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Messaging" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.CommsPhone" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.OneConnect" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MinecraftUWP" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MSPaint" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.RemoteDesktop" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Print3D" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
 
# Uninstall default third party applications
function UninstallThirdPartyBloat {
    Write-Host "Uninstallings applications commerciales ..."
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
    Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
    Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
    Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
    Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
    Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
    Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
    Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
    Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
    Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
    Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
    Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
    Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
    Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
    Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
    Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
}
 
# Install default third party applications
Function InstallThirdPartyBloat {
    Write-Host "Installing default third party applications..."
    Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Facebook.Facebook" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "CAF9E577.Plex" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
 
# Uninstall Windows Store
Function UninstallWindowsStore {
    Write-Host "Uninstalling Windows Store..."
    Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}
 
# Install Windows Store
Function InstallWindowsStore {
    Write-Host "Installing Windows Store..."
    Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
 
# Disable Xbox features
Function DisableXboxFeatures {
    Write-Host "Uninstalling Xbox..."
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}
 
# Enable Xbox features
Function EnableXboxFeatures {
    Write-Host "R�installation de Xbox..."
    Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
}
 
# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
    Write-Host "Disabling built-in Adobe Flash in IE and Edge..."
    If (!(Test-Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons")) {
        New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Name "Flags" -Type DWord -Value 1
}
 
# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash {
    Write-Host "Enabling built-in Adobe Flash in IE and Edge..."
    Remove-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Name "Flags" -ErrorAction SilentlyContinue
}
 
# Uninstall Windows Media Player
Function UninstallMediaPlayer {
    Write-Host "Uninstalling Windows Media Player..."
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Windows Media Player
Function InstallMediaPlayer {
    Write-Host "Installing Windows Media Player..."
    Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
    Write-Host "Uninstalling Work Folders Client..."
    Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
    Write-Host "Installing Work Folders Client..."
    Enable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Linux Subsystem - Applicable to 1607 or newer, not applicable to Server yet
Function InstallLinuxSubsystem {
    Write-Host "Installing Linux Subsystem..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Uninstall Linux Subsystem - Applicable to 1607 or newer, not applicable to Server yet
Function UninstallLinuxSubsystem {
    Write-Host "Uninstalling Linux Subsystem..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 0
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
    Write-Host "Installing Hyper-V..."
    If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
        Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
    } Else {
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
}
 
# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
    Write-Host "Uninstalling Hyper-V..."
    If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
        Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
    } Else {
        Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
}
 
# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
    Write-Host "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
        New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
        New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
        Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
        Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
    }
}
 
# Unset Photo Viewer association for bmp, gif, jpg, png and tif
Function UnsetPhotoViewerAssociation {
    Write-Host "Unsetting Photo Viewer association for bmp, gif, jpg, png and tif..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
    Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
    Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
    Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
}
 
# Add Photo Viewer to "Open with..."
Function AddPhotoViewerOpenWith {
    Write-Host "Adding Photo Viewer to `"Open with...`""
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}
 
# Remove Photo Viewer from "Open with..."
Function RemovePhotoViewerOpenWith {
    Write-Host "Removing Photo Viewer from `"Open with...`""
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}
 
# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
    Write-Host "Disabling search for app in store for unknown extensions..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}
 
# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
    Write-Host "Enabling search for app in store for unknown extensions..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}
 
# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt {
    Write-Host "Disabling 'How do you want to open this file?' prompt..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}
 
# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt {
    Write-Host "Enabling 'How do you want to open this file?' prompt..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
}
 
# Enable F8 boot menu options
Function EnableF8BootMenu {
    Write-Host "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}
 
# Disable F8 boot menu options
Function DisableF8BootMenu {
    Write-Host "Disabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
}
 
# Set Data Execution Prevention (DEP) policy to OptOut
Function SetDEPOptOut {
    Write-Host "Setting Data Execution Prevention (DEP) policy to OptOut..."
    bcdedit /set `{current`} nx OptOut | Out-Null
}
 
# Set Data Execution Prevention (DEP) policy to OptIn
Function SetDEPOptIn {
    Write-Host "Setting Data Execution Prevention (DEP) policy to OptIn..."
    bcdedit /set `{current`} nx OptIn | Out-Null
}
 
 
 
##########
# Server specific Tweaks
##########
 
# Hide Server Manager after login
Function HideServerManagerOnLogin {
    Write-Host "Hiding Server Manager after login..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -Type DWord -Value 1
}
 
# Hide Server Manager after login
Function ShowServerManagerOnLogin {
    Write-Host "Showing Server Manager after login..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -ErrorAction SilentlyContinue
}
 
# Disable Shutdown Event Tracker
Function DisableShutdownTracker {
    Write-Host "Disabling Shutdown Event Tracker..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0
}
 
# Enable Shutdown Event Tracker
Function EnableShutdownTracker {
    Write-Host "Enabling Shutdown Event Tracker..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -ErrorAction SilentlyContinue
}
 
# Disable password complexity and maximum age requirements
Function DisablePasswordPolicy {
    Write-Host "Disabling password complexity and maximum age requirements..."
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
    (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}
 
# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy {
    Write-Host "Enabling password complexity and maximum age requirements..."
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
    (Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}
 
# Disable Ctrl+Alt+Del requirement before login
Function DisableCtrlAltDelLogin {
    Write-Host "Disabling Ctrl+Alt+Del requirement before login..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1
}
 
# Enable Ctrl+Alt+Del requirement before login
Function EnableCtrlAltDelLogin {
    Write-Host "Enabling Ctrl+Alt+Del requirement before login..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0
}
 
# Disable Internet Explorer Enhanced Security Configuration (IE ESC)
Function DisableIEEnhancedSecurity {
    Write-Host "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}
 
# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity {
    Write-Host "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}
 
# Delete Temp Files
Function DeleteTempFiles {
    Write-Host "Cleaning up temporary files..."
    $tempfolders = @("$env:WINDIR\Temp\*", "$env:WINDIR\Prefetch\*", "$env:SystemDrive\Documents and Settings\*\Local Settings\temp\*", "$env:SystemDrive\Users\*\Appdata\Local\Temp\*")
    Remove-Item $tempfolders -force -recurse 2>&1 | Out-Null
}
 
# Clean WinSXS folder (WARNING: this takes a while!)
Function CleanWinSXS {
    Write-Host "Cleaning WinSXS folder, this may take a while, please wait..."
    Dism.exe /online /Cleanup-Image /StartComponentCleanup
}
 
# Remove startup delay (use with SSD)
Function DisableStartupDelay {
    Write-Host "Removing startup delay..."
    New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name Serialize -Force | Out-Null
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Name StartupDelayInMSec  -PropertyType DWORD -Value 0 -Force | Out-Null
}
 
# Stop and disable Windows Search Service
Function DisableWindowsSearch {
    Write-Host "Stopping and disabling Windows Search Service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}
 
# Enable and start Windows Search Service
Function EnableWindowsSearch {
    Write-Host "Enabling and starting Windows Search Service..."
    Set-Service "WSearch" -StartupType Automatic
    Start-Service "WSearch" -WarningAction SilentlyContinue
}
 
# Stop and disable Microsoft Compatibility Appraiser
Function DisableCompatibilityAppraiser {
    Write-Host "Stopping and disabling Microsoft Compatibility Appraiser..."
 
    # Disable compattelrunner.exe launched by scheduled tasks
    'Microsoft Compatibility Appraiser',
    'ProgramDataUpdater' | ForEach-Object {
        Get-ScheduledTask -TaskName $_ -TaskPath '\Microsoft\Windows\Application Experience\' |
        Disable-ScheduledTask | Out-Null
    }
 
    del $env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl -ErrorAction SilentlyContinue
 
    # Disable the Autologger session at the next computer restart
    Set-AutologgerConfig -Name 'AutoLogger-Diagtrack-Listener' -Start 0
}
 
##########
# GPD Win Specific Tweaks
##########
 
# Disable Connected Standby (CSEnabled)
Function DisableConnectedStandby {
    Write-Host "Disabling Connected Standby..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\\CurrentControlSet\Control\Power" -Name "CSEnabled" -Type DWord -Value 0
}
 
# Disable hibernation/sleep
Function DisableHibernation {
    Write-Host "Disabling hibernation..."
    Start-Process 'powercfg.exe' -Verb runAs -ArgumentList '/h off'
}
 
# Increase Desktop Icon Size
Function EnableBigDesktopIcons {
    Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -name IconSize -value 100
}
 
##########
# Auxiliary Functions
##########
 
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
 
 
# Test if registry path exists
function Test-RegistryValue {
    param (
 
     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,
 
    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )
 
    try {
 
    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
     return $true
     }
 
    catch {
 
    return $false
 
    }
}
 
 
##########
# Parse parameters and apply tweaks
##########
 
Clear-Host
Start-Sleep -Seconds 2
Write-Host "`nExecuting Script`n"
Write-Host ""
Start-Sleep -Seconds 1
# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
    $preset = Resolve-Path $($args | Select-Object -Skip 1)
    $PSCommandArgs = "-preset `"$preset`""
}
 
# Load function names from command line arguments or a preset file
If ($args) {
    $tweaks = $args
    If ($preset) {
        $tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
    }
}
 
Write-Warning "A reboot is required for all changes to take effect"

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
