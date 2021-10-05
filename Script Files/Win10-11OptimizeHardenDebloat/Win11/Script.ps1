# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Main Script for Windows 11 Optimizer"

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

	Checkpoint-Computer -Description "Windows 11 Optimizer" -RestorePointType MODIFY_SETTINGS

	# Revert the System Restore checkpoint creation frequency to 1440 minutes
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force

	# Turn off System Protection for the system drive if it was turned off before without deleting the existing restore points
	if ($ComputerRestorePoint)
	{
		Disable-ComputerRestore -Drive $env:SystemDrive
	}   

########################### Script Starting ###################################
###############################################################################

Write-Host "`nLet's Start with the Basics...`n"
Start-Sleep -Seconds 1

#Set TimeZone
cmd.exe --% /c sc triggerinfo w32time start/networkon stop/networkoff
Write-Host "`nSet your TimeZone..`n"

$key = Read-Host "Enter the City for your Time Zone WITHOUT "" "" ..."
Get-TimeZone -ListAvailable | Where-Object {$_.displayname -match "$key"}
$key2 = Read-Host "Enter the 'Id' for your Time Zone WITHOUT "" "" ..."
Set-TimeZone -Id "$key2"

Write-Host "`nForce Re-Sync Windows Time Server`n"
net stop w32time
w32tm /unregister
w32tm /register
net start w32time
w32tm /resync /force

##################################################################################

Write-Host "Checking if Windows is Activated"
function Get-ActivationStatus {
[CmdletBinding()]
 param(
 [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
 [string]$DNSHostName = $Env:COMPUTERNAME
 )
 process {
 try {
 $wpa = Get-WmiObject SoftwareLicensingProduct -ComputerName $DNSHostName `
 -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
 -Property LicenseStatus -ErrorAction Stop
 } catch {
 $status = New-Object ComponentModel.Win32Exception ($_.Exception.ErrorCode)
 $wpa = $null 
 }
 $out = New-Object psobject -Property @{
 ComputerName = $DNSHostName;
 Status = [string]::Empty;
 }
 if ($wpa) {
 :outer foreach($item in $wpa) {
 switch ($item.LicenseStatus) {
 0 {$out.Status = "Unlicensed"}
 1 {$out.Status = "Licensed"; break outer}
 2 {$out.Status = "Out-Of-Box Grace Period"; break outer}
 3 {$out.Status = "Out-Of-Tolerance Grace Period"; break outer}
 4 {$out.Status = "Non-Genuine Grace Period"; break outer}
 5 {$out.Status = "Notification"; break outer}
 6 {$out.Status = "Extended Grace"; break outer}
 default {$out.Status = "Unknown value"}
 }
 }
 } else { $out.Status = $status.Message }
 $out
 }
}

Write-Host "`nChecking to see if Windows is Activated`n"
Start-Sleep -Seconds 1

$status = (Get-ActivationStatus)

If ($status.Status -eq "licensed") {
Write-Host "Windows is activated" -ForegroundColor Yellow
}
else { ($status.Status -eq "Unlicensed") 
Write-Host "Windows is not activated" -ForegroundColor Red -BackgroundColor Black

#Activate Windows
Write-Host "`nPreparing to Activate Windows..`n"
Start-Sleep -Seconds 1
$ActivateWindows = Read-Host "Do you want to Activate Windows using OEM Key? [Y = OEM | N = Own Key / Skip License Activation]"
if ($ActivateWindows -eq 'y') {
$ProductKey = (Get-CimInstance -ClassName SoftwareLicensingService).OA3xOriginalProductKey
  if ($null -ne $ProductKey)
    {
        start-process $env:WINDIR\System32\changePK.exe -ArgumentList "/ProductKey $ProductKey"
        Start-Sleep -Seconds 10
        $status = (Get-ActivationStatus)
        If ($status.Status -eq "licensed") {
        Write-Host "Windows is activated" -ForegroundColor Yellow
    }
        else { ($status.Status -eq "Unlicensed") 
        Write-Host "Windows is not activated" -ForegroundColor Red -BackgroundColor Black
        }
    }

}
else {
Write-Host @writecolor "Do you want to use your own Windows Product key? (Y = Yes | N = Skip License Activation)"
$confirmation = Read-Host 
if ($confirmation -eq 'y') {
    Write-Host @writecolor "Please Enter your Genuine 25 Digit Product key"
    $key = Read-Host 
    changepk.exe /ProductKey $key
    Start-Sleep -Seconds 2
    slmgr.vbs /ato
    Start-Sleep -Seconds 10
    $status = (Get-ActivationStatus)
    If ($status.Status -eq "licensed") {
    Write-Host "Windows is activated" -ForegroundColor Yellow
    }
      else { ($status.Status -eq "Unlicensed") 
      Write-Host "Windows is not activated" -ForegroundColor Red -BackgroundColor Black
           }
       }
   }
}

##################################################################################

Write-Host "`nPreparing to Configure your Computer.. Please Wait`n"
Start-Sleep -Seconds 1

    # Run PSWindowsUpdate

    Write-Host Installing PSWindowsUpdate module
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

    ECHO Y | powershell Install-Module -Name PSWindowsUpdate -Force
    ECHO Y | powershell Import-Module -Name PSWindowsUpdate
    ECHO Y | powershell Add-WUServiceManager -MicrosoftUpdate

    #Install all available Updates & Reboot if Required
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
Invoke-WebRequest -Uri $Url -OutFile $ZipFile
$ExtractShell = New-Object -ComObject Shell.Application
$Files = $ExtractShell.Namespace($ZipFile).Items()
Write-Output "Extracting ZIP..... This might take a little while"
$ExtractShell.NameSpace($Destination).CopyHere($Files)
Remove-Item $ZipFile -Force -ErrorAction SilentlyContinue -Confirm:$false
Set-Location "$Destination\scripts-main\Script Files"
Move-Item "Win10-11OptimizeHardenDebloat" "$Destination\Win10-11OptimizeHardenDebloat"
Set-Location $Destination
Remove-Item "$Destination\scripts-main" -ErrorAction SilentlyContinue -Confirm:$false -Force -Recurse
Remove-Item "$Destination\Win10-11OptimizeHardenDebloat\Win10" -ErrorAction SilentlyContinue -Confirm:$false -Force -Recurse

#Executing Scripts
Clear-Host
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win11"
& '.\RamOptimizer-Win10-11Debloat-TweakingScript.ps1'
Start-Sleep -Seconds 1
Clear-Host
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win11"
cmd.exe /k .\windows_hardening.cmd
Clear-Host
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win11"
& '.\Win10-11 Tweak.ps1'
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win11"
& '.\Sophia.ps1'
Start-Sleep -Seconds 1
Write-Warning "A reboot is required for all changes to take effect"
Start-Sleep -Seconds 1

Clear-Host

#Removing Get-ActivationStatus Function
Get-Item -Path Function:\Get-ActivationStatus | Remove-Item

##################################################################################

#Configure Browsers
#Mozilla Firefox
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Mozilla.reg -OutFile $env:USERPROFILE\Downloads\firefox.reg
regedit.exe /S $env:USERPROFILE\Downloads\firefox.reg
#Chrome
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.reg -OutFile $env:USERPROFILE\Downloads\chrome.reg
regedit.exe /S $env:USERPROFILE\Downloads\chrome.reg
#Chromium
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chromium.reg -OutFile $env:USERPROFILE\Downloads\Chromium.reg
regedit.exe /S $env:USERPROFILE\Downloads\Chromium.reg
#Edge
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Edge.reg -OutFile $env:USERPROFILE\Downloads\Edge.reg
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
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PreventBloatwareReInstall.reg -OutFile $env:USERPROFILE\Downloads\PreventBloatwareReInstall.reg
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
Rename-Item "%WinDir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" "Reboot.bak"
Move-Item "%WinDir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
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

#Force Reboot Computer
Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/reboot_forced.bat" -OutFile "$env:SystemDrive\reboot_forced.bat"
cmd.exe /k "%SystemDrive%\reboot_forced.bat & del %SystemDrive%\reboot_forced.bat"

