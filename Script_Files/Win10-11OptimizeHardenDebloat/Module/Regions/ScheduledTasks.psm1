using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Scheduled tasks
<#
	.SYNOPSIS
	The "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates

	.PARAMETER Register
	Create the "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates

	.PARAMETER Delete
	Delete the "Windows Cleanup" and "Windows Cleanup Notification" scheduled tasks for cleaning up Windows unused files and updates

	.EXAMPLE
	CleanupTask -Register

	.EXAMPLE
	CleanupTask -Delete

	.NOTES
	A native interactive toast notification pops up every 30 days

	.NOTES
	Windows Script Host has to be enabled

	.NOTES
	Current user
#>
function CleanupTask
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Register"
		)]
		[switch]
		$Register,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Delete"
		)]
		[switch]
		$Delete
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Register"
		{
			Write-Host "Registering the 'Windows Cleanup' scheduled task for cleaning up Windows unused files and updates - " -NoNewline
			LogInfo "Registering the 'Windows Cleanup' scheduled task for cleaning up Windows unused files and updates"
			# Enable notifications in Action Center
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Force -ErrorAction Ignore | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null
			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null

			# Remove registry keys if Windows Script Host is disabled
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings", "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction Ignore | Out-Null

			# Enable notifications
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications -Name ToastEnabled -Force -ErrorAction Ignore | Out-Null
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications -Name NoToastApplicationNotification -Force -ErrorAction Ignore | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null

			# Checking whether VBS engine is enabled
			if ((Get-WindowsCapability -Online -Name VBSCRIPT*).State -ne "Installed")
			{
				try
				{
					Get-WindowsCapability -Online -Name VBSCRIPT* | Add-WindowsCapability -Online | Out-Null
				}
				catch
				{
					return
				}
			}

			# Checking if we're trying to create the task when it was already created as another user
			if (Get-ScheduledTask -TaskPath "\Win10_11Util\" -TaskName "Windows Cleanup" -ErrorAction SilentlyContinue | Out-Null)
			{
				# Also we can parse "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows Cleanup" to сheck whether the task was created
				$ScheduleService = New-Object -ComObject Schedule.Service
				$ScheduleService.Connect()
				$ScheduleService.GetFolder("\Win10_11Util").GetTasks(0) | Where-Object -FilterScript {$_.Name -eq "Windows Cleanup"} | Foreach-Object {
					# Get user's SID the task was created as
					$Script:SID = ([xml]$_.xml).Task.Principals.Principal.UserID
				}

				# Convert SID to username
				$TaskUserAccount = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value -split "\\" | Select-Object -Last 1

				if ($TaskUserAccount -ne $env:USERNAME)
				{
					LogError ($Localization.ScheduledTaskPresented -f $MyInvocation.Line.Trim(), $TaskUserAccount)
					return
				}
			}

			# Remove all old tasks
			# We have to use -ErrorAction Ignore in both cases, unless we get an error
			Get-ScheduledTask -TaskPath "\Win10_11Util Script\" -ErrorAction Ignore | ForEach-Object -Process {
				Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Ignore | Out-Null
			}

			# Remove folders in Task Scheduler. We cannot remove all old folders explicitly and not get errors if any of folders do not exist
			$ScheduleService = New-Object -ComObject Schedule.Service
			$ScheduleService.Connect()
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util Script")
			{
				$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util Script", $null)
			}

			Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
				Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore | Out-Null
			}

			$VolumeCaches = @(
				"BranchCache",
				"Delivery Optimization Files",
				"Device Driver Packages",
				"Language Pack",
				"Previous Installations",
				"Setup Log Files",
				"System error memory dump files",
				"System error minidump files",
				"Temporary Files",
				"Temporary Setup Files",
				"Update Cleanup",
				"Upgrade Discarded Files",
				"Windows Defender",
				"Windows ESD installation files",
				"Windows Upgrade Log Files"
			)
			foreach ($VolumeCache in $VolumeCaches)
			{
				if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache"))
				{
					New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Force | Out-Null
				}
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force | Out-Null
			}

			# Persist Win10_11Util notifications to prevent to immediately disappear from Action Center
			if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util))
			{
				New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Force | Out-Null
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force | Out-Null

			if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util))
			{
				New-Item -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Force | Out-Null
			}
			# Register app
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Name DisplayName -Value Win10_11Util -PropertyType String -Force | Out-Null
			# Determines whether the app can be seen in Settings where the user can turn notifications on or off
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Name ShowInSettings -Value 0 -PropertyType DWord -Force | Out-Null

			# Register the "WindowsCleanup" protocol to be able to run the scheduled task by clicking the "Run" button in a toast
			if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command))
			{
				New-Item -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command -Force | Out-Null
			}
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name "(default)" -PropertyType String -Value "URL:WindowsCleanup" -Force | Out-Null
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name "URL Protocol" -PropertyType String -Value "" -Force | Out-Null
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name EditFlags -PropertyType DWord -Value 2162688 -Force | Out-Null

			# Start the "Windows Cleanup" task if the "Run" button clicked
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command -Name "(default)" -PropertyType String -Value 'powershell.exe -Command "& {Start-ScheduledTask -TaskPath ''\Win10_11Util\'' -TaskName ''Windows Cleanup''}"' -Force | Out-Null

			$CleanupTaskPS = @"

Get-Process -Name cleanmgr, Dism, DismHost | Stop-Process -Force

`$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
`$ProcessInfo.FileName = "`$env:SystemRoot\System32\cleanmgr.exe"
`$ProcessInfo.Arguments = "/sagerun:1337"
`$ProcessInfo.UseShellExecute = `$true
`$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

`$Process = New-Object -TypeName System.Diagnostics.Process
`$Process.StartInfo = `$ProcessInfo
`$Process.Start() | Out-Null

Start-Sleep -Seconds 3

`$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
`$ProcessInfo.FileName = "`$env:SystemRoot\System32\Dism.exe"
`$ProcessInfo.Arguments = "/Online /English /Cleanup-Image /StartComponentCleanup /NoRestart"
`$ProcessInfo.UseShellExecute = `$true
`$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

`$Process = New-Object -TypeName System.Diagnostics.Process
`$Process.StartInfo = `$ProcessInfo
`$Process.Start() | Out-Null
"@

			# Save script to be able to call them from VBS file
			if (-not (Test-Path -Path $env:SystemRoot\System32\Tasks\Win10_11Util))
			{
				New-Item -Path $env:SystemRoot\System32\Tasks\Win10_11Util -ItemType Directory -Force | Out-Null
			}
			# Save in UTF8 with BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup.ps1" -Value $CleanupTaskPS -Encoding UTF8 -Force | Out-Null

			# Create vbs script that will help us calling Windows_Cleanup.ps1 script silently, without interrupting system from Focus Assist mode turned on, when a powershell.exe console pops up
			$CleanupTaskVBS = @"

CreateObject("Wscript.Shell").Run "powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File %SystemRoot%\System32\Tasks\Win10_11Util\Windows_Cleanup.ps1", 0
"@
			# Save in UTF8 without BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup.vbs" -Value $CleanupTaskVBS -Encoding Default -Force | Out-Null

			# Create "Windows Cleanup" task
			# We cannot create a schedule task if %COMPUTERNAME% is equal to %USERNAME%, so we have to use a "$env:COMPUTERNAME\$env:USERNAME" method
			# https://github.com/PowerShell/PowerShell/issues/21377
			$Action     = New-ScheduledTaskAction -Execute wscript.exe -Argument "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup.vbs"
			$Settings   = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
			$Principal  = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -RunLevel Highest
			$Parameters = @{
				TaskName    = "Windows Cleanup"
				TaskPath    = "Win10_11Util"
				Principal   = $Principal
				Action      = $Action
				Description = $Localization.CleanupTaskDescription -f $env:USERNAME
				Settings    = $Settings
			}
			Register-ScheduledTask @Parameters -Force | Out-Null

			# Set author for scheduled task
			$Task = Get-ScheduledTask -TaskName "Windows Cleanup"
			$Task.Author = "sdmanson8"
			$Task | Set-ScheduledTask | Out-Null

			# We have to call PowerShell script via another VBS script silently because VBS has appropriate feature to suppress console appearing (none of other workarounds work)
			# powershell.exe process wakes up system anyway even from turned on Focus Assist mode (not a notification toast)
			# https://github.com/DCourtel/Windows_10_Focus_Assist/blob/master/FocusAssistLibrary/FocusAssistLib.cs
			# https://redplait.blogspot.com/2018/07/wnf-ids-from-perfntcdll-adk-version.html
			$ToastNotificationPS = @"

# Get Focus Assist status
# https://github.com/DCourtel/Windows_10_Focus_Assist/blob/master/FocusAssistLibrary/FocusAssistLib.cs
# https://redplait.blogspot.com/2018/07/wnf-ids-from-perfntcdll-adk-version.html

`$CompilerParameters = [System.CodeDom.Compiler.CompilerParameters]::new("System.dll")
`$CompilerParameters.TempFiles = [System.CodeDom.Compiler.TempFileCollection]::new(`$env:TEMP, `$false)
`$CompilerParameters.GenerateInMemory = `$true
`$Signature = @{
	Namespace          = "WinAPI"
	Name               = "Focus"
	Language           = "CSharp"
	CompilerParameters = `$CompilerParameters
	MemberDefinition   = @""
[DllImport("NtDll.dll", SetLastError = true)]
private static extern uint NtQueryWnfStateData(IntPtr pStateName, IntPtr pTypeId, IntPtr pExplicitScope, out uint nChangeStamp, out IntPtr pBuffer, ref uint nBufferSize);

[StructLayout(LayoutKind.Sequential)]
public struct WNF_TYPE_ID
{
	public Guid TypeId;
}

[StructLayout(LayoutKind.Sequential)]
public struct WNF_STATE_NAME
{
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
	public uint[] Data;

	public WNF_STATE_NAME(uint Data1, uint Data2) : this()
	{
		uint[] newData = new uint[2];
		newData[0] = Data1;
		newData[1] = Data2;
		Data = newData;
	}
}

public enum FocusAssistState
{
	NOT_SUPPORTED = -2,
	FAILED = -1,
	OFF = 0,
	PRIORITY_ONLY = 1,
	ALARMS_ONLY = 2
};

// Returns the state of Focus Assist if available on this computer
public static FocusAssistState GetFocusAssistState()
{
	try
	{
		WNF_STATE_NAME WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED = new WNF_STATE_NAME(0xA3BF1C75, 0xD83063E);
		uint nBufferSize = (uint)Marshal.SizeOf(typeof(IntPtr));
		IntPtr pStateName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WNF_STATE_NAME)));
		Marshal.StructureToPtr(WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED, pStateName, false);

		uint nChangeStamp = 0;
		IntPtr pBuffer = IntPtr.Zero;
		bool success = NtQueryWnfStateData(pStateName, IntPtr.Zero, IntPtr.Zero, out nChangeStamp, out pBuffer, ref nBufferSize) == 0;
		Marshal.FreeHGlobal(pStateName);

		if (success)
		{
			return (FocusAssistState)pBuffer;
		}
	}
	catch {}

	return FocusAssistState.FAILED;
}
""@
}

if (-not ("WinAPI.Focus" -as [type]))
{
	Add-Type @Signature
}

while ([WinAPI.Focus]::GetFocusAssistState() -ne "OFF")
{
	Start-Sleep -Seconds 600
}

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

[xml]`$ToastTemplate = @""
<toast duration="Long">
	<visual>
		<binding template="ToastGeneric">
			<text>$($Localization.CleanupTaskNotificationTitle)</text>
			<group>
				<subgroup>
					<text hint-style="body" hint-wrap="true">$($Localization.CleanupTaskNotificationEvent)</text>
				</subgroup>
			</group>
		</binding>
	</visual>
	<audio src="ms-winsoundevent:notification.default" />
	<actions>
		<action content="$($Localization.Run)" arguments="WindowsCleanup:" activationType="protocol"/>
		<action content="" arguments="dismiss" activationType="system"/>
	</actions>
</toast>
""@

`$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
`$ToastXml.LoadXml(`$ToastTemplate.OuterXml)

`$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New(`$ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Win10_11Util").Show(`$ToastMessage)
"@

			# Save in UTF8 with BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.ps1" -Value $ToastNotificationPS -Encoding UTF8 -Force | Out-Null
			# Replace here-string double quotes with single ones
			(Get-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.ps1" -Encoding UTF8).Replace('@""', '@"').Replace('""@', '"@') | Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.ps1" -Encoding UTF8 -Force | Out-Null

			# Create vbs script that will help us calling Windows_Cleanup_Notification.ps1 script silently, without interrupting system from Focus Assist mode turned on, when a powershell.exe console pops up
			$ToastNotificationVBS = @"

CreateObject("Wscript.Shell").Run "powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File %SystemRoot%\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.ps1", 0
"@
			# Save in UTF8 without BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.vbs" -Value $ToastNotificationVBS -Encoding Default -Force | Out-Null

			# Create the "Windows Cleanup Notification" task
			# We cannot create a schedule task if %COMPUTERNAME% is equal to %USERNAME%, so we have to use a "$env:COMPUTERNAME\$env:USERNAME" method
			# https://github.com/PowerShell/PowerShell/issues/21377
			$Action    = New-ScheduledTaskAction -Execute wscript.exe -Argument "$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.vbs"
			$Settings  = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
			$Principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -RunLevel Highest
			$Trigger   = New-ScheduledTaskTrigger -Daily -DaysInterval 30 -At 9pm
			$Parameters = @{
				TaskName    = "Windows Cleanup Notification"
				TaskPath    = "Win10_11Util"
				Action      = $Action
				Settings    = $Settings
				Principal   = $Principal
				Trigger     = $Trigger
				Description = $Localization.CleanupNotificationTaskDescription -f $env:USERNAME
			}
			Register-ScheduledTask @Parameters -Force | Out-Null

			# Set author for scheduled task
			$Task = Get-ScheduledTask -TaskName "Windows Cleanup Notification"
			$Task.Author = "sdmanson8"
			$Task | Set-ScheduledTask | Out-Null

			# Start Task Scheduler in the end if any scheduled task was created
			$Script:ScheduledTasks = $true | Out-Null
			Write-Host "success!" -ForegroundColor Green
		}
		"Delete"
		{
			Write-Host "Deleting the 'Windows Cleanup' and 'Windows Cleanup Notification' scheduled tasks for cleanup - " -NoNewline
			LogInfo "Deleting the 'Windows Cleanup' and 'Windows Cleanup Notification' scheduled tasks for cleanup"
			# Remove files first unless we cannot remove folder if there's no more tasks there
			$Paths = @(
				"$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.vbs",
				"$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup_Notification.ps1",
				"$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup.ps1",
				"$env:SystemRoot\System32\Tasks\Win10_11Util\Windows_Cleanup.vbs"
			)
			Remove-Item -Path $Paths -Force -ErrorAction Ignore | Out-Null

			# Remove all old tasks
			# We have to use -ErrorAction Ignore in both cases, unless we get an error
			Get-ScheduledTask -TaskPath "\Win10_11Util Script\" -ErrorAction Ignore | ForEach-Object -Process {
				Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Ignore | Out-Null
			}

			# Remove folder in Task Scheduler if there is no tasks left there. We cannot remove all old folders explicitly and not get errors if any of folders do not exist
			$ScheduleService = New-Object -ComObject Schedule.Service
			$ScheduleService.Connect()
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util Script")
			{
				$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util Script", $null)
			}

			# Removing current task
			Unregister-ScheduledTask -TaskPath "\Win10_11Util\" -TaskName "Windows Cleanup", "Windows Cleanup Notification" -Confirm:$false -ErrorAction Ignore | Out-Null

			Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
				Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore | Out-Null
			}
			Remove-Item -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Recurse -Force -ErrorAction Ignore | Out-Null

			# Remove folder in Task Scheduler if there is no tasks left there
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util")
			{
				if (($ScheduleService.GetFolder("Win10_11Util").GetTasks(0) | Select-Object -Property Name).Name.Count -eq 0)
				{
					$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util", $null)
				}
			}
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder

	.PARAMETER Register
	Create the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder

	.PARAMETER Delete
	Delete the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder

	.EXAMPLE
	SoftwareDistributionTask -Register

	.EXAMPLE
	SoftwareDistributionTask -Delete

	.NOTES
	The task will wait until the Windows Updates service finishes running. The task runs every 90 days

	.NOTES
	Windows Script Host has to be enabled

	.NOTES
	Current user
#>
function SoftwareDistributionTask
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Register"
		)]
		[switch]
		$Register,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Delete"
		)]
		[switch]
		$Delete
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Register"
		{
			Write-Host "Registering the 'SoftwareDistribution' scheduled task for cleanup - " -NoNewline
			LogInfo "Registering the 'SoftwareDistribution' scheduled task for cleanup"
			# Enable notifications in Action Center
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null
			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null

			# Remove registry keys if Windows Script Host is disabled
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings", "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction SilentlyContinue | Out-Null

			# Enable notifications
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications -Name ToastEnabled -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications -Name NoToastApplicationNotification -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null

			# Checking whether VBS engine is enabled
			if ((Get-WindowsCapability -Online -Name VBSCRIPT*).State -ne "Installed")
			{
				try
				{
					Get-WindowsCapability -Online -Name VBSCRIPT* | Add-WindowsCapability -Online | Out-Null
				}
				catch
				{
					return
				}
			}

			# Checking if we're trying to create the task when it was already created as another user
			if (Get-ScheduledTask -TaskPath "\Win10_11Util\" -TaskName SoftwareDistribution -ErrorAction Ignore | Out-Null)
			{
				# Also we can parse $env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistribution to сheck whether the task was created
				$ScheduleService = New-Object -ComObject Schedule.Service
				$ScheduleService.Connect()
				$ScheduleService.GetFolder("\Win10_11Util").GetTasks(0) | Where-Object -FilterScript {$_.Name -eq "SoftwareDistribution"} | Foreach-Object {
					# Get user's SID the task was created as
					$Script:SID = ([xml]$_.xml).Task.Principals.Principal.UserID
				}

				# Convert SID to username
				$TaskUserAccount = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value -split "\\" | Select-Object -Last 1

				if ($TaskUserAccount -ne $env:USERNAME)
				{
					LogError ($Localization.ScheduledTaskPresented -f $MyInvocation.Line.Trim(), $TaskUserAccount)

					return
				}
			}

			# Remove all old tasks
			# We have to use -ErrorAction Ignore in both cases, unless we get an error
			Get-ScheduledTask -TaskPath "\Win10_11Util Script\" -ErrorAction Ignore | ForEach-Object -Process {
				Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Ignore | Out-Null
			}

			# Remove folders in Task Scheduler. We cannot remove all old folders explicitly and not get errors if any of folders do not exist
			$ScheduleService = New-Object -ComObject Schedule.Service
			$ScheduleService.Connect()
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util Script")
			{
				$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util Script", $null)
			}

			# Persist Win10_11Util notifications to prevent to immediately disappear from Action Center
			if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util))
			{
				New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Force | Out-Null
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force | Out-Null

			if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util))
			{
				New-Item -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Force | Out-Null
			}
			# Register app
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Name DisplayName -Value Win10_11Util -PropertyType String -Force | Out-Null
			# Determines whether the app can be seen in Settings where the user can turn notifications on or off
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Name ShowInSettings -Value 0 -PropertyType DWord -Force | Out-Null

			# We have to call PowerShell script via another VBS script silently because VBS has appropriate feature to suppress console appearing (none of other workarounds work)
			# powershell.exe process wakes up system anyway even from turned on Focus Assist mode (not a notification toast)
			# https://github.com/DCourtel/Windows_10_Focus_Assist/blob/master/FocusAssistLibrary/FocusAssistLib.cs
			# https://redplait.blogspot.com/2018/07/wnf-ids-from-perfntcdll-adk-version.html
			$SoftwareDistributionTaskPS = @"

# Get Focus Assist status
# https://github.com/DCourtel/Windows_10_Focus_Assist/blob/master/FocusAssistLibrary/FocusAssistLib.cs
# https://redplait.blogspot.com/2018/07/wnf-ids-from-perfntcdll-adk-version.html

`$CompilerParameters = [System.CodeDom.Compiler.CompilerParameters]::new("System.dll")
`$CompilerParameters.TempFiles = [System.CodeDom.Compiler.TempFileCollection]::new(`$env:TEMP, `$false)
`$CompilerParameters.GenerateInMemory = `$true
`$Signature = @{
	Namespace          = "WinAPI"
	Name               = "Focus"
	Language           = "CSharp"
	CompilerParameters = `$CompilerParameters
	MemberDefinition   = @""
[DllImport("NtDll.dll", SetLastError = true)]
private static extern uint NtQueryWnfStateData(IntPtr pStateName, IntPtr pTypeId, IntPtr pExplicitScope, out uint nChangeStamp, out IntPtr pBuffer, ref uint nBufferSize);

[StructLayout(LayoutKind.Sequential)]
public struct WNF_TYPE_ID
{
	public Guid TypeId;
}

[StructLayout(LayoutKind.Sequential)]
public struct WNF_STATE_NAME
{
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
	public uint[] Data;

	public WNF_STATE_NAME(uint Data1, uint Data2) : this()
	{
		uint[] newData = new uint[2];
		newData[0] = Data1;
		newData[1] = Data2;
		Data = newData;
	}
}

public enum FocusAssistState
{
	NOT_SUPPORTED = -2,
	FAILED = -1,
	OFF = 0,
	PRIORITY_ONLY = 1,
	ALARMS_ONLY = 2
};

// Returns the state of Focus Assist if available on this computer
public static FocusAssistState GetFocusAssistState()
{
	try
	{
		WNF_STATE_NAME WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED = new WNF_STATE_NAME(0xA3BF1C75, 0xD83063E);
		uint nBufferSize = (uint)Marshal.SizeOf(typeof(IntPtr));
		IntPtr pStateName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WNF_STATE_NAME)));
		Marshal.StructureToPtr(WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED, pStateName, false);

		uint nChangeStamp = 0;
		IntPtr pBuffer = IntPtr.Zero;
		bool success = NtQueryWnfStateData(pStateName, IntPtr.Zero, IntPtr.Zero, out nChangeStamp, out pBuffer, ref nBufferSize) == 0;
		Marshal.FreeHGlobal(pStateName);

		if (success)
		{
			return (FocusAssistState)pBuffer;
		}
	}
	catch {}

	return FocusAssistState.FAILED;
}
""@
}

if (-not ("WinAPI.Focus" -as [type]))
{
	Add-Type @Signature
}

# Wait until it will be "OFF" (0)
while ([WinAPI.Focus]::GetFocusAssistState() -ne "OFF")
{
	Start-Sleep -Seconds 600
}

# Run the task
(Get-Service -Name wuauserv).WaitForStatus("Stopped", "01:00:00")
Get-ChildItem -Path `$env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

[xml]`$ToastTemplate = @""
<toast duration="Long">
	<visual>
		<binding template="ToastGeneric">
			<text>$($Localization.SoftwareDistributionTaskNotificationEvent)</text>
		</binding>
	</visual>
	<audio src="ms-winsoundevent:notification.default" />
</toast>
""@

`$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
`$ToastXml.LoadXml(`$ToastTemplate.OuterXml)

`$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New(`$ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Win10_11Util").Show(`$ToastMessage)
"@
			# Save script to be able to call them from VBS file
			if (-not (Test-Path -Path $env:SystemRoot\System32\Tasks\Win10_11Util))
			{
				New-Item -Path $env:SystemRoot\System32\Tasks\Win10_11Util -ItemType Directory -Force | Out-Null
			}
			# Save in UTF8 with BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.ps1" -Value $SoftwareDistributionTaskPS -Encoding UTF8 -Force | Out-Null
			# Replace here-string double quotes with single ones
			(Get-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.ps1" -Encoding UTF8).Replace('@""', '@"').Replace('""@', '"@') | Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.ps1" -Encoding UTF8 -Force | Out-Null

			# Create vbs script that will help us calling PS1 script silently, without interrupting system from Focus Assist mode turned on, when a powershell.exe console pops up
			$SoftwareDistributionTaskVBS = @"

CreateObject("Wscript.Shell").Run "powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File %SystemRoot%\System32\Tasks\Win10_11Util\SoftwareDistributionTask.ps1", 0
"@
			# Save in UTF8 without BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.vbs" -Value $SoftwareDistributionTaskVBS -Encoding Default -Force | Out-Null

			# Create the "SoftwareDistribution" task
			# We cannot create a schedule task if %COMPUTERNAME% is equal to %USERNAME%, so we have to use a "$env:COMPUTERNAME\$env:USERNAME" method
			# https://github.com/PowerShell/PowerShell/issues/21377
			$Action    = New-ScheduledTaskAction -Execute wscript.exe -Argument "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.vbs"
			$Settings  = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
			$Principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -RunLevel Highest
			$Trigger   = New-ScheduledTaskTrigger -Daily -DaysInterval 90 -At 9pm
			$Parameters = @{
				TaskName    = "SoftwareDistribution"
				TaskPath    = "Win10_11Util"
				Action      = $Action
				Settings    = $Settings
				Principal   = $Principal
				Trigger     = $Trigger
				Description = $Localization.FolderTaskDescription -f "%SystemRoot%\SoftwareDistribution\Download", $env:USERNAME
			}
			Register-ScheduledTask @Parameters -Force | Out-Null

			# Set author for scheduled task
			$Task = Get-ScheduledTask -TaskName "SoftwareDistribution"
			$Task.Author = "sdmanson8"
			$Task | Set-ScheduledTask | Out-Null

			$Script:ScheduledTasks = $true
			Write-Host "success!" -ForegroundColor Green
		}
		"Delete"
		{
			Write-Host "Deleting the 'SoftwareDistribution' scheduled task for cleanup - " -NoNewline
			LogInfo "Deleting the 'SoftwareDistribution' scheduled task for cleanup"
			# Remove files first unless we cannot remove folder if there's no more tasks there
			Remove-Item -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.vbs", "$env:SystemRoot\System32\Tasks\Win10_11Util\SoftwareDistributionTask.ps1" -Force -ErrorAction SilentlyContinue | Out-Null

			# Remove all old tasks
			# We have to use -ErrorAction Ignore in both cases, unless we get an error
			Get-ScheduledTask -TaskPath "\Win10_11Util Script\" -ErrorAction Ignore | ForEach-Object -Process {
				Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Ignore | Out-Null
			}

			# Remove folder in Task Scheduler if there is no tasks left there. We cannot remove all old folders explicitly and not get errors if any of folders do not exist
			$ScheduleService = New-Object -ComObject Schedule.Service
			$ScheduleService.Connect()
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util Script")
			{
				$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util Script", $null)
			}

			# Removing current task
			Unregister-ScheduledTask -TaskPath "\Win10_11Util\" -TaskName SoftwareDistribution -Confirm:$false -ErrorAction Ignore | Out-Null

			# Remove folder in Task Scheduler if there is no tasks left there
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util")
			{
				if (($ScheduleService.GetFolder("Win10_11Util").GetTasks(0) | Select-Object -Property Name).Name.Count -eq 0)
				{
					$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util", $null)
				}
			}
			Write-Host "success!" -ForegroundColor Green
		}
	}
}

<#
	.SYNOPSIS
	The "Temp" scheduled task for cleaning up the %TEMP% folder

	.PARAMETER Register
	Create the "Temp" scheduled task for cleaning up the %TEMP% folder

	.PARAMETER Delete
	Delete the "Temp" scheduled task for cleaning up the %TEMP% folder

	.EXAMPLE
	TempTask -Register

	.EXAMPLE
	TempTask -Delete

	.NOTES
	Only files older than one day will be deleted. The task runs every 60 days

	.NOTES
	Windows Script Host has to be enabled

	.NOTES
	Current user
#>
function TempTask
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Register"
		)]
		[switch]
		$Register,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Delete"
		)]
		[switch]
		$Delete
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Register"
		{
			Write-Host "Registering the 'Temp' scheduled task for cleaning up the %TEMP% folder - " -NoNewline
			LogInfo "Registering the 'Temp' scheduled task for cleaning up the %TEMP% folder"
			# Enable notifications in Action Center
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null
			Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null

			# Remove registry keys if Windows Script Host is disabled
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings", "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction SilentlyContinue | Out-Null

			# Enable notifications
			Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications -Name ToastEnabled -Force -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications -Name NoToastApplicationNotification -Force -ErrorAction SilentlyContinue | Out-Null
			Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR | Out-Null

			# Checking whether VBS engine is enabled
			if ((Get-WindowsCapability -Online -Name VBSCRIPT*).State -ne "Installed")
			{
				try
				{
					Get-WindowsCapability -Online -Name VBSCRIPT* | Add-WindowsCapability -Online | Out-Null
				}
				catch
				{
					return
				}
			}

			# Checking if we're trying to create the task when it was already created as another user
			if (Get-ScheduledTask -TaskPath "\Win10_11Util\" -TaskName Temp -ErrorAction Ignore | Out-Null)
			{
				# Also we can parse $env:SystemRoot\System32\Tasks\Win10_11Util\Temp to сheck whether the task was created
				$ScheduleService = New-Object -ComObject Schedule.Service
				$ScheduleService.Connect()
				$ScheduleService.GetFolder("\Win10_11Util").GetTasks(0) | Where-Object -FilterScript {$_.Name -eq "Temp"} | Foreach-Object {
					# Get user's SID the task was created as
					$Script:SID = ([xml]$_.xml).Task.Principals.Principal.UserID
				}

				# Convert SID to username
				$TaskUserAccount = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value -split "\\" | Select-Object -Last 1

				if ($TaskUserAccount -ne $env:USERNAME)
				{
					#Write-Information -MessageData "" -InformationAction Continue
					#LogWarning ($Localization.ScheduledTaskPresented -f $MyInvocation.Line.Trim(), $TaskUserAccount)
					LogError ($Localization.ScheduledTaskPresented -f $MyInvocation.Line.Trim(), $TaskUserAccount)

					return
				}
			}

			# Remove all old tasks
			# We have to use -ErrorAction Ignore in both cases, unless we get an error
			Get-ScheduledTask -TaskPath "\Win10_11Util Script\" -ErrorAction Ignore | ForEach-Object -Process {
				Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Ignore | Out-Null
			}

			# Remove folders in Task Scheduler. We cannot remove all old folders explicitly and not get errors if any of folders do not exist
			$ScheduleService = New-Object -ComObject Schedule.Service
			$ScheduleService.Connect()
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util Script")
			{
				$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util Script", $null)
			}

			# Persist Win10_11Util notifications to prevent to immediately disappear from Action Center
			if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util))
			{
				New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Force | Out-Null
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force | Out-Null

			if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util))
			{
				New-Item -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Force | Out-Null
			}
			# Register app
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Name DisplayName -Value Win10_11Util -PropertyType String -Force | Out-Null
			# Determines whether the app can be seen in Settings where the user can turn notifications on or off
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Name ShowInSettings -Value 0 -PropertyType DWord -Force | Out-Null

			# We have to call PowerShell script via another VBS script silently because VBS has appropriate feature to suppress console appearing (none of other workarounds work)
			# powershell.exe process wakes up system anyway even from turned on Focus Assist mode (not a notification toast)
			$TempTaskPS = @"

# Get Focus Assist status
# https://github.com/DCourtel/Windows_10_Focus_Assist/blob/master/FocusAssistLibrary/FocusAssistLib.cs
# https://redplait.blogspot.com/2018/07/wnf-ids-from-perfntcdll-adk-version.html

`$CompilerParameters = [System.CodeDom.Compiler.CompilerParameters]::new("System.dll")
`$CompilerParameters.TempFiles = [System.CodeDom.Compiler.TempFileCollection]::new(`$env:TEMP, `$false)
`$CompilerParameters.GenerateInMemory = `$true
`$Signature = @{
	Namespace          = "WinAPI"
	Name               = "Focus"
	Language           = "CSharp"
	CompilerParameters = `$CompilerParameters
	MemberDefinition   = @""
[DllImport("NtDll.dll", SetLastError = true)]
private static extern uint NtQueryWnfStateData(IntPtr pStateName, IntPtr pTypeId, IntPtr pExplicitScope, out uint nChangeStamp, out IntPtr pBuffer, ref uint nBufferSize);

[StructLayout(LayoutKind.Sequential)]
public struct WNF_TYPE_ID
{
	public Guid TypeId;
}

[StructLayout(LayoutKind.Sequential)]
public struct WNF_STATE_NAME
{
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
	public uint[] Data;

	public WNF_STATE_NAME(uint Data1, uint Data2) : this()
	{
		uint[] newData = new uint[2];
		newData[0] = Data1;
		newData[1] = Data2;
		Data = newData;
	}
}

public enum FocusAssistState
{
	NOT_SUPPORTED = -2,
	FAILED = -1,
	OFF = 0,
	PRIORITY_ONLY = 1,
	ALARMS_ONLY = 2
};

// Returns the state of Focus Assist if available on this computer
public static FocusAssistState GetFocusAssistState()
{
	try
	{
		WNF_STATE_NAME WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED = new WNF_STATE_NAME(0xA3BF1C75, 0xD83063E);
		uint nBufferSize = (uint)Marshal.SizeOf(typeof(IntPtr));
		IntPtr pStateName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WNF_STATE_NAME)));
		Marshal.StructureToPtr(WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED, pStateName, false);

		uint nChangeStamp = 0;
		IntPtr pBuffer = IntPtr.Zero;
		bool success = NtQueryWnfStateData(pStateName, IntPtr.Zero, IntPtr.Zero, out nChangeStamp, out pBuffer, ref nBufferSize) == 0;
		Marshal.FreeHGlobal(pStateName);

		if (success)
		{
			return (FocusAssistState)pBuffer;
		}
	}
	catch {}

	return FocusAssistState.FAILED;
}
""@
}

if (-not ("WinAPI.Focus" -as [type]))
{
	Add-Type @Signature
}

# Wait until it will be "OFF" (0)
while ([WinAPI.Focus]::GetFocusAssistState() -ne "OFF")
{
	Start-Sleep -Seconds 600
}

# Run the task
Get-ChildItem -Path `$env:TEMP -Recurse -Force | Where-Object -FilterScript {`$_.CreationTime -lt (Get-Date).AddDays(-1)} | Remove-Item -Recurse -Force

# Unnecessary folders to remove
`$Paths = @(
	# Get "C:\$WinREAgent" path because we need to open brackets for $env:SystemDrive but not for $WinREAgent
	(-join ("`$env:SystemDrive\", '`$WinREAgent')),
	(-join ("`$env:SystemDrive\", '`$SysReset')),
	(-join ("`$env:SystemDrive\", '`$Windows.~WS')),
	"`$env:SystemDrive\ESD",
	"`$env:SystemDrive\Intel",
	"`$env:SystemDrive\PerfLogs"
)

if ((Get-ChildItem -Path `$env:SystemDrive\Recovery -Force | Where-Object -FilterScript {`$_.Name -eq "ReAgentOld.xml"}).FullName)
{
	`$Paths += "$env:SystemDrive\Recovery"
}
Remove-Item -Path `$Paths -Recurse -Force

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

[xml]`$ToastTemplate = @""
<toast duration="Long">
	<visual>
		<binding template="ToastGeneric">
			<text>$($Localization.TempTaskNotificationEvent)</text>
		</binding>
	</visual>
	<audio src="ms-winsoundevent:notification.default" />
</toast>
""@

`$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
`$ToastXml.LoadXml(`$ToastTemplate.OuterXml)

`$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New(`$ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Win10_11Util").Show(`$ToastMessage)
"@
			# Save script to be able to call them from VBS file
			if (-not (Test-Path -Path $env:SystemRoot\System32\Tasks\Win10_11Util))
			{
				New-Item -Path $env:SystemRoot\System32\Tasks\Win10_11Util -ItemType Directory -Force | Out-Null
			}
			# Save in UTF8 with BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.ps1" -Value $TempTaskPS -Encoding UTF8 -Force | Out-Null
			# Replace here-string double quotes with single ones
			(Get-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.ps1" -Encoding UTF8).Replace('@""', '@"').Replace('""@', '"@') | Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.ps1" -Encoding UTF8 -Force | Out-Null

			# Create vbs script that will help us calling PS1 script silently, without interrupting system from Focus Assist mode turned on, when a powershell.exe console pops up
			$TempTaskVBS = @"

CreateObject("Wscript.Shell").Run "powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File %SystemRoot%\System32\Tasks\Win10_11Util\TempTask.ps1", 0
"@
			# Save in UTF8 without BOM
			Set-Content -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.vbs" -Value $TempTaskVBS -Encoding Default -Force | Out-Null

			# Create the "Temp" task
			# We cannot create a schedule task if %COMPUTERNAME% is equal to %USERNAME%, so we have to use a "$env:COMPUTERNAME\$env:USERNAME" method
			# https://github.com/PowerShell/PowerShell/issues/21377
			$Action    = New-ScheduledTaskAction -Execute wscript.exe -Argument "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.vbs"
			$Settings  = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
			$Principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -RunLevel Highest
			$Trigger   = New-ScheduledTaskTrigger -Daily -DaysInterval 60 -At 9pm
			$Parameters = @{
				TaskName    = "Temp"
				TaskPath    = "Win10_11Util"
				Action      = $Action
				Settings    = $Settings
				Principal   = $Principal
				Trigger     = $Trigger
				Description = $Localization.FolderTaskDescription -f "%TEMP%", $env:USERNAME
			}
			Register-ScheduledTask @Parameters -Force | Out-Null

			# Set author for scheduled task
			$Task = Get-ScheduledTask -TaskName "Temp"
			$Task.Author = "sdmanson8"
			$Task | Set-ScheduledTask | Out-Null

			$Script:ScheduledTasks = $true
			Write-Host "success!" -ForegroundColor Green
		}
		"Delete"
		{
			Write-Host "Deleting the 'Temp' scheduled task for cleaning up the %TEMP% folder - " -NoNewline
			LogInfo "Deleting the 'Temp' scheduled task for cleaning up the %TEMP% folder"
			# Remove files first unless we cannot remove folder if there's no more tasks there
			Remove-Item -Path "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.vbs", "$env:SystemRoot\System32\Tasks\Win10_11Util\TempTask.ps1" -Force -ErrorAction SilentlyContinue | Out-Null

			# Remove all old tasks
			# We have to use -ErrorAction Ignore in both cases, unless we get an error
			Get-ScheduledTask -TaskPath "\Win10_11Util Script\" -ErrorAction Ignore | ForEach-Object -Process {
				Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Ignore | Out-Null
			}

			# Remove folder in Task Scheduler if there is no tasks left there. We cannot remove all old folders explicitly and not get errors if any of folders do not exist
			$ScheduleService = New-Object -ComObject Schedule.Service
			$ScheduleService.Connect()
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util Script")
			{
				$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util Script", $null)
			}

			# Removing current task
			Unregister-ScheduledTask -TaskPath "\Win10_11Util\" -TaskName Temp -Confirm:$false -ErrorAction Ignore | Out-Null

			# Remove folder in Task Scheduler if there is no tasks left there
			if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Win10_11Util")
			{
				if (($ScheduleService.GetFolder("Win10_11Util").GetTasks(0) | Select-Object -Property Name).Name.Count -eq 0)
				{
					$ScheduleService.GetFolder("\").DeleteFolder("Win10_11Util", $null)
				}
			}
			Write-Host "success!" -ForegroundColor Green
		}
	}
}
#endregion Scheduled tasks
