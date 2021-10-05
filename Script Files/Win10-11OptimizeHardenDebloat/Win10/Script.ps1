$Host.UI.RawUI.WindowTitle = "Main Script for Windows 10 Optimizer"

Write-Host "`nLet's Start with the Basics...`n"
Start-Sleep -Seconds 1

#Set TimeZone
Write-Host "`nSet your TimeZone..`n"

$key = Read-Host "Enter the City for your Time Zone WITHOUT "" "" ..."
Get-TimeZone -ListAvailable | Where-Object {$_.displayname -match "$key"}
$key2 = Read-Host "Enter the 'Id' for your Time Zone WITHOUT "" "" ..."
Set-TimeZone -Id "$key2"

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
        #start-process c:\Windows\System32\changePK.exe -ArgumentList "/ProductKey $ProductKey"
        Start-Sleep -Seconds 1
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
    #changepk.exe /ProductKey $key
    #Start-Sleep -Seconds 2
    #slmgr.vbs /ato
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

Write-Host "`nPreparing to Configure your Computer.. Please Wait`n"
Start-Sleep -Seconds 1

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

    #Stops edge from taking over as the default .PDF viewer    
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

#Change Performance Options to Adjust for best performance
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type "DWORD" -Value 2 -Force

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
Set-Location "$Destination\Win10-11OptimizeHardenDebloat\Win10"

Powershell.exe "$env:USERPROFILE\Downloads\Win10-11OptimizeHardenDebloat\Win10\Win10-11OptimizeHarden.ps1"
Start-Sleep -Seconds 1
Powershell.exe "$env:USERPROFILE\Downloads\Win10-11OptimizeHardenDebloat\Win10\Sophia.ps1"
Start-Sleep -Seconds 1
Powershell.exe "$env:USERPROFILE\Downloads\Win10-11OptimizeHardenDebloat\Win10\RamOptimizer-Win10-11Debloat-TweakingScript.ps1"
Start-Sleep -Seconds 1
Write-Warning "Please Restart your Computer !!"

Set-Location "$env:USERPROFILE"
Start-Sleep -Seconds 1
Remove-Item "$env:USERPROFILE\Downloads\Win10-11OptimizeHardenDebloat" -ErrorAction SilentlyContinue -Confirm:$false -Force -Recurse

#Removing Get-ActivationStatus Function
Get-Item -Path Function:\Get-ActivationStatus | Remove-Item

#Reboot Computer
    # Ask for confirmation to Reboot Computer
    $Reboot = Read-Host "Would you like to Restart your Computer? (Y/N)"
    if ($Reboot -eq 'Y') { 
    Restart-Computer
}

