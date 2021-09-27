#Create Restore Point
Checkpoint-Computer -Description "Delete Temporary Files for $env:UserName" -RestorePointType MODIFY_SETTINGS

Clear-Host
Start-Sleep -Seconds 2
Write-Host "Deleting Temporary Files for $env:UserName `r"
<#

Purpose:  Deletes Temporary Internet Files for the Current Logged On User.
			  Deletes Temp Files from Windows Directory.
			  Deletes Various Internet cache files in Windows 7, 8 and 10.
			  Deletes User History.
			  Deletes Windows Memory Dump Files.
			  Deletes Google Chrome Temporary Internet Files.
			  Deletes Mozilla Firefox Temporary Internet Files.
#>
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
		Remove-Item -Path $TempFiles[($i - 1)].FullName -Force -Recurse -ErrorAction SilentlyContinue
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

Write-Host "*****Starting User Junk File Clean-up*****" -Foreground Green -Background Black

#######################################################################
# INTERNET EXPLORER CLEAN-UP
#######################################################################

# Internet Explorer Temp Files, Cookies, History, etc. to be located and deleted.
$UserTempFiles = "\\{0}\C$\Users\{1}\AppData\Local\Temp" -f $ComputerName, $UserName
$UserTempIntFiles = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\Temporary Internet Files" -f $ComputerName, $UserName
$UserHistory = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\History\" -f $ComputerName, $UserName
$UserThumbsDB = "\\{0}\C$\Users\{1}\Appdata\Local\Microsoft\Windows\Explorer\" -f $ComputerName, $UserName
$7UserCookies = "\\{0}\C$\Users\{1}\AppData\Roaming\Microsoft\Windows\Cookies\" -f $ComputerName, $UserName
$8UserCookies = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\INetCookies\" -f $ComputerName, $UserName
$8INetCache = "\\{0}\C$\Users\{1}\AppData\Local\Microsoft\Windows\INetCache\" -f $ComputerName, $UserName

Write-Host $UserName -Foreground white -Background Black
# Clean-Up User Temp Files
DeleteTempFiles "Temp Files" $UserTempFiles "Cyan"

# Clean-Up User Temporary Internet Files
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

#######################################################################
# MOZILLA FIREFOX CLEAN-UP
#######################################################################

# Mozilla Firefox Profile where the Temp Files are stored.
$FireFoxProfilesFolder = "\\{0}\C$\Users\{1}\AppData\Local\Mozilla\Firefox\Profiles\" -f $ComputerName, $UserName
$FireFoxProfiles = Get-ChildItem $FireFoxProfilesFolder -Directory

# Clean-Up User Mozilla Firefox Cache.
Foreach($FFProfile in $FireFoxProfiles)
{
	$FireFoxTempFiles = $FFProfile.FullName + "\cache2\entries\"
	
	DeleteTempFiles "Mozilla FireFox Cache" $FireFoxTempFiles "Cyan"
}

#######################################################################
# GOOGLE CHROME CLEAN-UP
#######################################################################

# Google Chrome Temp Files to be deleted.
$ChromeTempFiles = "\\{0}\C$\Users\{1}\Appdata\Local\Google\Chrome\User Data\Default\Cache\" -f $Computername, $UserName

# Clean-Up User Google Chrome Cache.
DeleteTempFiles "Google Chrome Cache" $ChromeTempFiles "Cyan"

###############################################################################
# WINDOWS FILES CLEAN-UP
###############################################################################

$WindowsTempFiles = "\\{0}\C$\Windows\Temp" -f $ComputerName
$WindowsFiles = "\\{0}\C$\Windows" -f $ComputerName

# Clean-Up Windows Temp Files
DeleteTempFiles "Windows Temp Files" $WindowsTempFiles "Red"

Write-Host "*****User Junk File Clean-up Complete*****" -Foreground Magenta -Background Black
