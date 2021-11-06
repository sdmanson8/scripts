# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "New User Script for Windows 10 Optimizer"

#Create A Restore Point
	$SystemDriveUniqueID = (Get-Volume | Where-Object -FilterScript {$_.DriveLetter -eq "$($env:SystemDrive[0])"}).UniqueID#
	$SystemProtection = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients")."{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}") | Where-Object -FilterScript {$_ -match [regex]::Escape($SystemDriveUniqueID)}

    $ComputerRestorePoint = $false

	switch ($null -eq $SystemProtection)
	{
		$true
		{
			$ComputerRestorePoint = $true
			Enable-ComputerRestore -Drive $env:SystemDrive
		}
	}
	# Never skip creating a restore point
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 0 -Force

	Checkpoint-Computer -Description "New User Windows 10 Optimizer" -RestorePointType MODIFY_SETTINGS

	# Revert the System Restore checkpoint creation frequency to 1440 minutes
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force

	# Turn off System Protection for the system drive if it was turned off before without deleting the existing restore points
	if ($ComputerRestorePoint)
	{
		Disable-ComputerRestore -Drive $env:SystemDrive
	}   

########################### Script Starting ###################################
###############################################################################

Write-Host "`nPreparing to Configure your Computer.. Please Wait`n"
Start-Sleep -Seconds 1

    # Run PSWindowsUpdate

    Write-Host Installing PSWindowsUpdate module
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

    ECHO Y | powershell Install-Module -Name PSWindowsUpdate -Force
    ECHO Y | powershell Import-Module -Name PSWindowsUpdate
    ECHO Y | powershell Add-WUServiceManager -MicrosoftUpdate

    #Install all available Updates
    Write-Host Install Windows Updates
    Install-WindowsUpdate -AcceptAll

##################################################################################

    #Stop edge from taking over as the default .PDF viewer    
    Write-Host "Stopping Edge from taking over as the default .PDF viewer"
    # Identify the edge application class 
    $Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
    $edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
    
    # Specify the paths to the file and URL associations 
    $FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
    $URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
    
    # get the software classes for the file and URL types that Edge will associate 
    $FileTypes = Get-Item $FileAssocKey 
    $URLTypes = Get-Item $URLAssocKey 
    
    $FileAssoc = Get-ItemProperty $FileAssocKey 
    $URLAssoc = Get-ItemProperty $URLAssocKey 
    
    $Associations = @() 
    $Filetypes.Property | foreach { $Associations += $FileAssoc.$_ } 
    $URLTypes.Property | foreach { $Associations += $URLAssoc.$_ }


    # add registry values in each software class to stop edge from associating as the default 
    foreach ($Association in $Associations) { 
        $Class = Join-Path HKCU:SOFTWARE\Classes $Association 
        #if (Test-Path $class) 
        #   {write-host $Association} 
        # Get-Item $Class 
        Set-ItemProperty $Class -Name NoOpenWith -Value "" 
        Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
    } 

##################################################################################

    #Change Performance Options to Adjust for best performance
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type "DWORD" -Value 2 -Force

##################################################################################

    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\" -Name "Parameters" -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters" -Name "StoragePolicy" -Force
    
    #Storage Sense
    #Frequency Run Every 7 Days
    $7DFrequencyRun = Read-Host -Prompt "Do you want to run Storage Sense every 7 Days? [Y/N]"
    if ($7DFrequencyRun -eq 'y') {  
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 7 -Force
       } else {
    #Frequency Run Every 30 Days
    Write-Host "Setting Storage Sense to run every 30 days"
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 30 -Force
      }  
           
    #Clean-Up Recycle Bin Every 14 Days
    $7DRecycleBinCleanup = Read-Host -Prompt "Do you want to clean the Recycle Bin every 14 Days? [Y/N]"
    if ($7DRecycleBinCleanup -eq 'y') { 
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 256 -PropertyType DWord -Value 14 -Force
      } else {    
    #Clean-Up Recycle Bin Every 30 Days
    Write-Host "Setting Cleanup for the Recycle Bin every 30 days"
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 256 -PropertyType DWord -Value 30 -Force
      }

    #Clean-up Download Folder every 14 days
    $7DDownloadFolderCleanup = Read-Host -Prompt "Do you want to clean your Downloads Folder every 14 Days? [Y/N]"
    if ($7DDownloadFolderCleanup -eq 'y') { 
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 512 -PropertyType DWord -Value 14 -Force
      } else {    
    #Clean-up Download Folder every 30 days
    Write-Host "Setting Cleanup for your Downloads Folder every 30 days"
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 512 -PropertyType DWord -Value 30 -Force
      }

##################################################################################
$github = "Windows-Optimize-Harden-Debloat"
$Url = "https://github.com/sdmanson8/scripts/archive/refs/heads/main.zip"
$ZipFile = "$env:USERPROFILE\Downloads\" + $(Split-Path -Path $Url -Leaf)
$Destination= "$env:USERPROFILE\Downloads\"
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $ZipFile -UseBasicParsing
$ExtractShell = New-Object -ComObject Shell.Application
$Files = $ExtractShell.Namespace($ZipFile).Items()
Write-Output "Extracting ZIP..... This might take a little while"
$ExtractShell.NameSpace($Destination).CopyHere($Files)
Remove-Item $ZipFile -Force -ErrorAction SilentlyContinue -Confirm:$false
Set-Location "$Destination\scripts-main\Script Files"
Move-Item "Win10-11OptimizeHardenDebloat" "$Destination\Win10-11OptimizeHardenDebloat"
Set-Location $Destination
Remove-Item "$Destination\scripts-main" -ErrorAction SilentlyContinue -Confirm:$false -Force -Recurse
Remove-Item "$Destination\Win10-11OptimizeHardenDebloat\Win11" -ErrorAction SilentlyContinue -Confirm:$false -Force -Recurse

#Executing Scripts
Clear-Host
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win10"
& '.\RamOptimizer-Win10-11Debloat-TweakingScript.ps1'
Start-Sleep -Seconds 1
Clear-Host
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win10"
cmd.exe /k .\windows_hardening.cmd
Clear-Host
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win10"
& '.\Win10-11 Tweak.ps1'
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win10"
& '.\Sophia_NewUser.ps1'
Start-Sleep -Seconds 1
Write-Warning "A reboot is required for all changes to take effect"
Start-Sleep -Seconds 1

##################################################################################

#Configure Browsers
#Mozilla Firefox
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Mozilla.reg -OutFile $env:USERPROFILE\Downloads\firefox.reg -UseBasicParsing
regedit.exe /S $env:USERPROFILE\Downloads\firefox.reg
#Chrome
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.reg -OutFile $env:USERPROFILE\Downloads\chrome.reg -UseBasicParsing
regedit.exe /S $env:USERPROFILE\Downloads\chrome.reg
#Chromium
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chromium.reg -OutFile $env:USERPROFILE\Downloads\Chromium.reg -UseBasicParsing
regedit.exe /S $env:USERPROFILE\Downloads\Chromium.reg
#Edge
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Edge.reg -OutFile $env:USERPROFILE\Downloads\Edge.reg -UseBasicParsing
regedit.exe /S $env:USERPROFILE\Downloads\Edge.reg

#Remove Old Files
Set-Location "$env:USERPROFILE"
Remove-Item "$env:USERPROFILE\Downloads\Win10-11OptimizeHardenDebloat" -ErrorAction SilentlyContinue -Confirm:$false -Force -Recurse
Remove-Item "$env:USERPROFILE\Downloads\stop" -ErrorAction SilentlyContinue -Confirm:$false -Force
Remove-Item "$env:USERPROFILE\Downloads\firefox.reg" -ErrorAction SilentlyContinue -Confirm:$false -Force
Remove-Item "$env:USERPROFILE\Downloads\chrome.reg" -ErrorAction SilentlyContinue -Confirm:$false -Force
Remove-Item "$env:USERPROFILE\Downloads\Chromium.reg" -ErrorAction SilentlyContinue -Confirm:$false -Force
Remove-Item "$env:USERPROFILE\Downloads\Edge.reg" -ErrorAction SilentlyContinue -Confirm:$false -Force

##################################################################################

#Install .Net Framework 3.5
Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart

Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/ClickOnce.reg -OutFile $env:USERPROFILE\Downloads\ClickOnce.reg -UseBasicParsing
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\Security\TrustManager\PromptingLevel" -Name "LocalIntranet" -Force
regedit.exe /S $env:USERPROFILE\Downloads\ClickOnce.reg
Start-Sleep -Milliseconds 400
Remove-Item "$env:USERPROFILE\Downloads\ClickOnce.reg" -ErrorAction SilentlyContinue -Confirm:$false -Force
##################################################################################

#Repair SMB
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Force
wmic service where "Name LIKE '%%lanmanserver%%'" call StartService
wmic service where "Name LIKE '%%lanmanserver%%'" call ChangeStartMode Automatic
Start-Sleep -Seconds 1

##################################################################################

#Prevent Bloatware Reinstall
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PreventBloatwareReInstall.reg -OutFile $env:USERPROFILE\Downloads\PreventBloatwareReInstall.reg -UseBasicParsing
regedit.exe /S $env:USERPROFILE\Downloads\PreventBloatwareReInstall.reg
Remove-Item "$env:USERPROFILE\Downloads\PreventBloatwareReInstall.reg" -ErrorAction SilentlyContinue -Confirm:$false -Force

##################################################################################

#Change Clock and Date formats 24H, metric (Sign out required to see changes)

Set-ItemProperty "HKCU:\Control Panel\International" -Name "iMeasure" -Type "String" -Value 0 -Force
Set-ItemProperty "HKCU:\Control Panel\International" -Name "iNegCurr" -Type "String" -Value 1 -Force
Set-ItemProperty "HKCU:\Control Panel\International" -Name "iTime" -Type "String" -Value 1 -Force
Set-ItemProperty "HKCU:\Control Panel\International" -Name "sShortDate" -Type "String" -Value "dd.MM.yyyy" -Force
Set-ItemProperty "HKCU:\Control Panel\International" -Name "sShortTime" -Type "String" -Value "HH:mm" -Force
Set-ItemProperty "HKCU:\Control Panel\International" -Name "sTimeFormat" -Type "String" -Value "H:mm:ss" -Force

##################################################################################

#Disable Reboot after Windows Updates are installed

SCHTASKS /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable
Rename-Item "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" "Reboot.bak"
Move-Item "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
SCHTASKS /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable

##################################################################################

#Remove Windows.Old
if (Test-Path -Path $env:SystemDrive\Windows.old\)
	  {
         takeown /F $env:SystemDrive\Windows.old\* /R /A /D Y
         cacls $env:SystemDrive\Windows.old\*.* /T /grant administrators:F
         Remove-Item $env:SystemDrive\Windows.old\ -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
         Write-Host "Clearing Component Store (WinSxS)"
         Start-Sleep -Seconds 2
         dism /online /cleanup-image /StartComponentCleanup /ResetBase
      }
		else
    	{
          Write-Host "`nWindows.Old does not Exist... Ignoring`n" -ForegroundColor Red
        }


##################################################################################

<#
Purpose:  Deletes Temporary Internet Files for the Current Logged On User.
			  Deletes Temp Files from Windows Directory.
			  Deletes Various Internet cache files in Windows 7, 8 and 10.
			  Deletes User History.
			  Deletes Windows Memory Dump Files.
			  Deletes Google Chrome Temporary Internet Files.
			  Deletes Mozilla Firefox Temporary Internet Files.

#>
function CleanTempFiles
{
[cmdletbinding()]
param
(
	[Parameter(Mandatory=$False,Position=0)] [string]$ComputerName = $env:computername
)
# Tell Powershell to ignore any errors that may fill up the screen.
$ErrorActionPreference = 'silentlycontinue'

<#
 Deletes the files for the location passed to it.
 $Description is the short description for the Progress Bar.
 $FilePath is the path to the directory that contains the files to be deleted.
 $Color is the color of the text displayed on screen for the location cleaned.
#>

Function DeleteTempFiles($Description, $FilePath, $Color)
{
	$TempFiles = @() # Empty Array
	[int]$InitialCount = 0 # Initial Declaration.  Total Files/Folders.
	[int]$FinalCount = 0 # Initial Declaration.  Remaining Files/Folders.
	
	# Check current version of PowerShell and gather items accordingly.
	If($PSVersionTable.PSVersion -Like "*2*")
	{
		$TempFiles = Get-ChildItem $FilePath -Recurse -Force
	}
	Else
	{
		$TempFiles = Get-ChildItem $FilePath -File -Recurse -Force
		$TempFiles += Get-ChildItem $FilePath -Directory -Recurse -Force
	}
	
	# Get the count of all the files to be deleted for the current File Path.
	[int]$InitialCount = $TempFiles.count
	
	# Do the actual deletion and report it on screen.
	For($i = 1; $i -le $InitialCount; $i++)
	{
		$FileName = Select-Object -InputObject $TempFiles[($i - 1)]
		Write-Progress -Activity "$Description Clean-up" -Status "Attempting to Delete File [$i / $InitialCount]: $FileName" `
			-PercentComplete (($i / $InitialCount) * 100) -Id 1
		Remove-Item -Path $TempFiles[($i - 1)].FullName -Force -Recurse
	}
	Write-Progress -Activity "$Description Clean-up" -Status "Complete" -Completed -Id 1
	
	[int]$FinalCount = (Get-ChildItem $FilePath -Recurse -Force).count
	[int]$DeletedCount = ($InitialCount - $FinalCount) # Total Files/Folders Deleted.
	
	Write-Host "$Description - Complete" -ForeGround $Color -Background Black
	Write-Host "Cleaned: $DeletedCount Files/Folders" -Foreground Yellow -Background Black
	Write-Host "Remaining:  $FinalCount Files/Folders" -Foreground Yellow -Background Black
	Write-Host ""
}

# Get the Currently Logged in User. Format: <DOMAIN>\<USERNAME>
$Profile = (Get-WMIObject -Class Win32_ComputerSystem -ComputerName $ComputerName).UserName

# Get the Operating System.
$OSVersion = (Get-WMIObject -ComputerName $ComputerName -Class Win32_OperatingSystem).caption

# Get just the User Name for the Current Profile.
$UserName = ([regex]::matches($Profile, '[^\\]+$') | %{$_.value})

 # Get Disk Size
 $Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
    @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
    @{ Name = "Size (GB)" ; Expression = { "{0:N1}" -f ( $_.Size / 1gb) } },
    @{ Name = "FreeSpace (GB)" ; Expression = { "{0:N1}" -f ( $_.Freespace / 1gb ) } },
    @{ Name = "PercentFree" ; Expression = { "{0:P1}" -f ( $_.FreeSpace / $_.Size ) } } |
        Format-Table -AutoSize | Out-String
Write-Host -ForegroundColor Green "Before: $Before"       

Write-Host "*****Starting User Junk File Clean-up*****" -Foreground Green -Background Black

# Internet Explorer Temp Files, Cookies, History, etc. to be located and deleted.
$UserTempFiles = "\\{0}\C$\Users\{1}\AppData\Local\Temp" -f $ComputerName, $UserName
$UserTempIntFiles = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\Temporary Internet Files" -f $ComputerName, $UserName
$UserHistory = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\History\" -f $ComputerName, $UserName
$UserThumbsDB = "\\{0}\C$\Users\{1}\Appdata\Local\Microsoft\Windows\Explorer\" -f $ComputerName, $UserName
$7UserCookies = "\\{0}\C$\Users\{1}\AppData\Roaming\Microsoft\Windows\Cookies\" -f $ComputerName, $UserName
$8UserCookies = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\INetCookies\" -f $ComputerName, $UserName
$8INetCache = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\INetCache\" -f $ComputerName, $UserName

Write-Host $env:USERDNSDOMAIN\$UserName -Foreground white -Background Black

# Clean-Up User Temp Files
DeleteTempFiles "Temp Files" $UserTempFiles "Cyan"

# Clean-Up User Temporary Internet Files
    # Check if Microsoft Edge is Running, Stop Microsoft Edge if Running
    Write-Host "Is Microsoft Edge Running?"
    if((get-process "msedge" -ea SilentlyContinue) -eq $Null){ 
        echo "Not Running" 
    }
    else{ 
    echo "Running, Stopping Process"
    Stop-Process -processname "msedge"
        }
DeleteTempFiles "Temporary Internet Files" $UserTempIntFiles "Cyan"

# Clean-Up User History
DeleteTempFiles "User History" $UserHistory "Cyan"

If($OSVersion -Like "*7*")
{
	# Clean-Up User Cookies on Windows 7
	DeleteTempFiles "Internet Browser Cookies" $7UserCookies "Cyan"
}
Else
{
	# Clean-Up User Cookies on Windows 8 or 10
	DeleteTempFiles "Internet Browser Cookies" $8UserCookies "Cyan"
	
	# Clean-Up User Internet Cache on Windows 8 or 10
	DeleteTempFiles "Internet Browser Cache" $8INetCache "Cyan"
}


# Mozilla Firefox Profile where the Temp Files are stored.
# Check if Firefox is Running, Stop Firefox if Running
    Write-Host "Is Firefox Running?"
    if((get-process "firefox" -ea SilentlyContinue) -eq $Null){ 
        echo "Not Running" 
    }
    else{ 
    echo "Running, Stopping Process"
    Stop-Process -processname "firefox"
        }
$FireFoxProfilesFolder = "\\{0}\C$\Users\{1}\AppData\Local\Mozilla\Firefox\Profiles\" -f $ComputerName, $UserName
$FireFoxProfiles = Get-ChildItem $FireFoxProfilesFolder -Directory

# Clean-Up User Mozilla Firefox Cache.
Foreach($FFProfile in $FireFoxProfiles)
{
	$FireFoxTempFiles = $FFProfile.FullName + "\cache2\entries\"
	
	DeleteTempFiles "Mozilla FireFox Cache" $FireFoxTempFiles "Cyan"
}

# Google Chrome Temp Files to be deleted.
    # Check if Chrome is Running, Stop Chrome if Running
    Write-Host "Is Chrome Running?"
    if((get-process "chrome" -ea SilentlyContinue) -eq $Null){ 
        echo "Not Running" 
    }
    else{ 
    echo "Running, Stopping Process"
    Stop-Process -processname "chrome"
        }
$ChromeTempFiles = "\\{0}\C$\Users\{1}\Appdata\Local\Google\Chrome\User Data\Default\Cache\" -f $Computername, $UserName

# Clean-Up User Google Chrome Cache.
DeleteTempFiles "Google Chrome Cache" $ChromeTempFiles "Cyan"


$WindowsTempFiles = "\\{0}\C$\Windows\Temp" -f $ComputerName
$WindowsFiles = "\\{0}\C$\Windows" -f $ComputerName

# Clean-Up Windows Temp Files
DeleteTempFiles "Windows Temp Files" $WindowsTempFiles "Red"

$WinTempFiles = "C:\Windows\Temp\*" -f $ComputerName, $UserName
$PrefetchTempFiles = "C:\Windows\Prefetch\*" -f $ComputerName, $UserName
$OtherTempFiles = "C:\Documents and Settings\*\Local Settings\temp\*" -f $ComputerName, $UserName

# Clean-Up Windows Temp Files
DeleteTempFiles "Windows Temp Files" $WinTempFiles "Cyan"

# Clean-Up Prefetch Temp Files
DeleteTempFiles "Prefetch Temp Files" $PrefetchTempFiles "Cyan"

# Clean-Up Other Temp Files
DeleteTempFiles "Other Temp Files" $OtherTempFiles "Cyan"

# Clear HP Support Assistant Installation Folder
$HPSetup ="C:\swsetup" -f $ComputerName, $UserName
    if (Test-Path $HPSetup) {
        DeleteTempFiles "Clearing HP Support Assistant Installation Folder" $HPSetup "Cyan"
    }

# Ask for confirmation to delete users Downloaded files - Anything older than 90 days
    $DeleteOldDownloads = Read-Host "Would you like to delete files older than 90 days in the Downloads folder for All Users? (Y/N)"
# Delete files older than 90 days from Downloads folder
    if ($DeleteOldDownloads -eq 'Y') { 
        Write-Host -ForegroundColor Yellow "Deleting files older than 90 days from User Downloads folder`n"
        Foreach ($user in $Users) {
            $UserDownloads = "C:\Users\$user\Downloads" -f $ComputerName, $UserName
            $OldFiles = Get-ChildItem -Path "$UserDownloads\" -Recurse -File $ErrorActionPreference | Where-Object LastWriteTime -LT $DelDownloadsDate
            foreach ($file in $OldFiles) {
                DeleteTempFiles "Deleting files older than 90 days from Downloads folder" "$UserDownloads\$file" "Cyan"
            }
        }
    }

  # Empty Recycle Bin
        Write-Host -ForegroundColor Green "Cleaning Recycle Bin`n"
        $ErrorActionPreference = 'SilentlyContinue'
        $RecycleBin = "C:\`$Recycle.Bin"  -f $ComputerName, $UserName
        $BinFolders = Get-ChildItem $RecycleBin -Directory -Force

        Foreach ($Folder in $BinFolders) {
            # Translate the SID to a User Account
            $objSID = New-Object System.Security.Principal.SecurityIdentifier ($folder)
            try {
                $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
                Write-Host -Foreground Yellow -Background Black "Cleaning $objUser Recycle Bin"
            }
            # If SID cannot be Translated, Throw out the SID instead of error
            catch {
                $objUser = $objSID.Value
                Write-Host -Foreground Yellow -Background Black "$objUser"
            }
            $Files = @()

            if ($PSVersionTable.PSVersion -Like "*2*") {
                $Files = Get-ChildItem $Folder.FullName -Recurse -Force
            }
            else {
                $Files = Get-ChildItem $Folder.FullName -File -Recurse -Force
                $Files += Get-ChildItem $Folder.FullName -Directory -Recurse -Force
            }

            $FileTotal = $Files.Count

            for ($i = 1; $i -le $Files.Count; $i++) {
                $FileName = Select-Object -InputObject $Files[($i - 1)]
                Write-Progress -Activity "Recycle Bin Clean-up" -Status "Attempting to Delete File [$i / $FileTotal]: $FileName" -PercentComplete (($i / $Files.count) * 100) -Id 1
                Remove-Item -Path $Files[($i - 1)].FullName -Recurse -Force
            }
            Write-Progress -Activity "Recycle Bin Clean-up" -Status "Complete" -Completed -Id 1
        }
        Write-Host -ForegroundColor Green "Done`n `n"

        Write-Host "*****User Junk File Clean-up Complete*****" -Foreground Magenta -Background Black
# Get Drive size after clean
    $After = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
    @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
    @{ Name = "Size (GB)" ; Expression = { "{0:N1}" -f ( $_.Size / 1gb) } },
    @{ Name = "FreeSpace (GB)" ; Expression = { "{0:N1}" -f ( $_.Freespace / 1gb ) } },
    @{ Name = "PercentFree" ; Expression = { "{0:P1}" -f ( $_.FreeSpace / $_.Size ) } } |
        Format-Table -AutoSize | Out-String

        Start-Sleep -Seconds 2
        Write-Host -ForegroundColor Green "After: $After"
}
CleanTempFiles

##################################################################################

#Install OneDrive
    # Ask for confirmation to Install Onedrive
    $InstallOneDrive = Read-Host "Would you like to Install Onedrive? (Y/N)"
    if ($InstallOneDrive -eq 'Y') { 
	    	$OneDrive = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -Force -ErrorAction Ignore
			if (-not $OneDrive)
			{
				if (Test-Path -Path $env:SystemRoot\SysWOW64\OneDriveSetup.exe)
				{
					Write-Information -MessageData "" -InformationAction Continue
					Write-Verbose -Message $Localization.OneDriveInstalling -Verbose
					Start-Process -FilePath $env:SystemRoot\SysWOW64\OneDriveSetup.exe
				}
				else
				{
					try
					{
						# Downloading the latest OneDrive installer x64
						if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
						{
							Write-Information -MessageData "" -InformationAction Continue
							Write-Verbose -Message $Localization.OneDriveDownloading -Verbose

							# Parse XML to get the URL
							# https://go.microsoft.com/fwlink/p/?LinkID=844652
							$Parameters = @{
								Uri             = "https://g.live.com/1rewlive5skydrive/OneDriveProduction"
								UseBasicParsing = $true
								Verbose         = $true
							}
							$Content = Invoke-RestMethod @Parameters

							# Remove invalid chars
							[xml]$OneDriveXML = $Content -replace "﻿", ""

							$OneDriveURL = ($OneDriveXML).root.update.amd64binary.url[-1]
							$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
							$Parameters = @{
								Uri         = $OneDriveURL
								OutFile     = "$DownloadsFolder\OneDriveSetup.exe"
								SslProtocol = "Tls12"
								Verbose     = $true
							}
							Invoke-WebRequest @Parameters

							Start-Process -FilePath "$DownloadsFolder\OneDriveSetup.exe"
						}
					}
					catch [System.Net.WebException]
					{
						Write-Warning -Message $Localization.NoInternetConnection
						Write-Error -Message $Localization.NoInternetConnection -ErrorAction SilentlyContinue

						Write-Error -Message ($Localization.RestartFunction -f $MyInvocation.Line) -ErrorAction SilentlyContinue

						return
					}
				}

				Get-ScheduledTask -TaskName "Onedrive* Update*" | Enable-ScheduledTask
			}
}

##################################################################################
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value dd/MM/yyyy
#Force Reboot Computer
Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/reboot_forced.bat" -OutFile "$env:SystemDrive\reboot_forced.bat" -UseBasicParsing
cmd.exe /k "%SystemDrive%\reboot_forced.bat & del %SystemDrive%\reboot_forced.bat"

