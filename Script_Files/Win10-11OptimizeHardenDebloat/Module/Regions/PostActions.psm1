using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Post Actions
<#
	.SYNOPSIS
	Run the post-change refresh and cleanup actions after tweaks finish.

	.DESCRIPTION
	Refreshes shell state, applies any generated Local Group Policy text files,
	cleans up temporary policy files, restores previously opened folders where
	possible, and performs the extra post-run fixes expected by this preset.

	.EXAMPLE
	PostActions
#>
function PostActions
{
	Write-ConsoleStatus -Action "Performing post actions"
	LogInfo "Performing post actions"
	try
	{
	#region Refresh Environment
	# Refresh the shell so desktop, taskbar, and environment changes are visible immediately.
	$Signature = @{
		Namespace          = "WinAPI"
		Name               = "UpdateEnvironment"
		Language           = "CSharp"
		CompilerParameters = $CompilerParameters
		MemberDefinition   = @"
private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
private const int WM_SETTINGCHANGE = 0x1a;
private const int SMTO_ABORTIFHUNG = 0x0002;

[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int fuFlags, int uTimeout, IntPtr lpdwResult);

[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);

public static void Refresh()
{
	// Update desktop icons
	SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);

	// Update environment variables
	SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);

	// Update taskbar
	SendNotifyMessage(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
}

private static readonly IntPtr hWnd = new IntPtr(65535);
private const int Msg = 273;
// Virtual key ID of the F5 in File Explorer
private static readonly UIntPtr UIntPtr = new UIntPtr(41504);

[DllImport("user32.dll", SetLastError=true)]
public static extern int PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);

public static void PostMessage()
{
	// Simulate pressing F5 to refresh the desktop
	PostMessageW(hWnd, Msg, UIntPtr, IntPtr.Zero);
}
"@
	}
	if (-not ("WinAPI.UpdateEnvironment" -as [type]))
	{
		Add-Type @Signature -ErrorAction Stop
	}

	# Simulate pressing F5 to refresh the desktop
	[WinAPI.UpdateEnvironment]::PostMessage()

	# Refresh desktop icons, environment variables, taskbar
	[WinAPI.UpdateEnvironment]::Refresh()

	# Restart Start menu
	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction SilentlyContinue | Out-Null
	#endregion Refresh Environment

	#region Other actions
	# Rebuild Local Group Policy data if this run generated LGPO input files.
	# Apply policies found in registry to re-build database database because gpedit.msc relies in its own database
	if ((Test-Path -Path "$env:TEMP\Computer.txt") -or (Test-Path -Path "$env:TEMP\User.txt"))
	{
		if (Test-Path -Path "$env:TEMP\Computer.txt") {
    		$ComputerLgpoProcess = Start-Process -FilePath "$PSScriptRoot\..\Binaries\LGPO.exe" `
                  -ArgumentList "/t `"$env:TEMP\Computer.txt`"" `
                  -WindowStyle Hidden `
                  -Wait `
                  -PassThru `
                  -ErrorAction Stop `
                  -RedirectStandardOutput "$env:TEMP\LGPOOutput.txt" `
                  -RedirectStandardError "$env:TEMP\LGPOError.txt"
			if ($ComputerLgpoProcess.ExitCode -ne 0)
			{
				throw "LGPO.exe returned exit code $($ComputerLgpoProcess.ExitCode) while importing Computer.txt"
			}
		}

		if (Test-Path -Path "$env:TEMP\User.txt") {
    		$UserLgpoProcess = Start-Process -FilePath "$PSScriptRoot\..\Binaries\LGPO.exe" `
                  -ArgumentList "/t `"$env:TEMP\User.txt`"" `
                  -WindowStyle Hidden `
                  -Wait `
                  -PassThru `
                  -ErrorAction Stop `
                  -RedirectStandardOutput "$env:TEMP\LGPOOutput.txt" `
                  -RedirectStandardError "$env:TEMP\LGPOError.txt"
			if ($UserLgpoProcess.ExitCode -ne 0)
			{
				throw "LGPO.exe returned exit code $($UserLgpoProcess.ExitCode) while importing User.txt"
			}
		}

	# Run gpupdate silently
	cmd /c "gpupdate /force > NUL 2>&1" 2>$null | Out-Null
		if ($LASTEXITCODE -ne 0)
		{
			throw "gpupdate returned exit code $LASTEXITCODE"
		}
	}

	# PowerShell 5.1 (7.5 too) interprets 8.3 file name literally, if an environment variable contains a non-Latin word
	# https://github.com/PowerShell/PowerShell/issues/21070
	Get-ChildItem -Path "$env:TEMP\Computer.txt", "$env:TEMP\User.txt" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue | Out-Null

	# Kill all explorer instances in case "launch folder windows in a separate process" enabled
	Get-Process -Name explorer | Stop-Process -Force -ErrorAction SilentlyContinue | Out-Null
	Start-Sleep -Seconds 3

	# Restoring closed folders
	if (Get-Variable -Name OpenedFolder -ErrorAction Ignore)
	{
		foreach ($Script:OpenedFolder in $Script:OpenedFolders)
		{
			if (Test-Path -Path $Script:OpenedFolder)
			{
				Start-Process -FilePath explorer -ArgumentList $Script:OpenedFolder | Out-Null
			}
		}
	}

	# Open Startup page
	[System.Diagnostics.Process]::Start("ms-settings:startupapps")

<#
	# Checking whether any of scheduled tasks were created. Unless open Task Scheduler
	if ($Script:ScheduledTasks)
	{
		# Find and close taskschd.msc by its argument
		$taskschd_Process_ID = (Get-CimInstance -ClassName CIM_Process | Where-Object -FilterScript {$_.Name -eq "mmc.exe"} | Where-Object -FilterScript {
			$_.CommandLine -match "taskschd.msc"
		}).Handle
		# We have to check before executing due to "Set-StrictMode -Version Latest"
		if ($taskschd_Process_ID)
		{
			Get-Process -Id $taskschd_Process_ID | Stop-Process -Force
		}

		# Open Task Scheduler
		Start-Process -FilePath taskschd.msc
	}
	#endregion Other actions

	#region Toast notifications
	# Persist Win10_11Util notifications to prevent to immediately disappear from Action Center
	# Enable notifications in Action Center
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer, HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Force -ErrorAction Ignore
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR
	Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR

	# Enable notifications
	Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications -Name ToastEnabled -Force -ErrorAction Ignore
	Remove-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications -Name NoToastApplicationNotification -Force -ErrorAction Ignore
	Set-Policy -Scope User -Path Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type CLEAR

	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Force
	}
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Win10_11Util -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force

	if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util))
	{
		New-Item -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Win10_11Util -Force
	}
	Pause
#>

	# Restore guest SMB access and the Print Management console expected by this preset.
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                 -Name "AllowInsecureGuestAuth" `
                 -PropertyType DWord `
                 -Value 1 `
                 -Force `
                 -ErrorAction SilentlyContinue | Out-Null

	#Reinstall Print Management Console
	$PrintManagementProcess = Start-Process -FilePath "DISM.exe" `
                      -ArgumentList "/online /add-capability /CapabilityName:Print.Management.Console~~~~0.0.1.0 /quiet /norestart" `
                      -Wait `
                      -NoNewWindow `
                      -PassThru `
                      -ErrorAction Stop
	if ($PrintManagementProcess.ExitCode -ne 0)
	{
		throw "DISM.exe returned exit code $($PrintManagementProcess.ExitCode) while reinstalling Print Management Console"
	}
	Write-ConsoleStatus -Status success
	}
	catch
	{
		LogError "Post actions failed: $($_.Exception.Message)"
		Write-ConsoleStatus -Status failed
	}
}
#endregion Post Actions
