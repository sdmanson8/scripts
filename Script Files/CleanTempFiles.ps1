
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

#Force Reboot Computer
Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/reboot_forced.bat" -OutFile "$env:SystemDrive\reboot_forced.bat"
cmd.exe /k "%SystemDrive%\reboot_forced.bat & del %SystemDrive%\reboot_forced.bat"
