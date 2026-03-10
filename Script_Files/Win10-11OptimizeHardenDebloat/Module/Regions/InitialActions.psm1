using module ..\Logging.psm1
using module ..\Helpers.psm1

#region InitialActions
<#
	.SYNOPSIS
	Run the shared startup checks and runtime setup used before applying tweaks.

	.DESCRIPTION
	Prepares the Win10_11Util session by clearing previous errors, unblocking
	script files, setting network and compiler prerequisites, and initializing
	the runtime helpers used by other region modules.

	.PARAMETER Warning
	Show the warning prompt during startup checks.

	.EXAMPLE
	InitialActions
#>
function InitialActions
{
	param
	(
		[Parameter(Mandatory = $false)]
		[switch]
		$Warning
	)

	$osName = (Get-OSInfo).OSName

	LogInfo "Starting WinUtil Script for $osName" -addGap

	LogInfo "Beginning Initial Checks:"
	Clear-Host
	Write-Host "Please Wait...."

	# Clear the $Error variable
	$Global:Error.Clear()

	# Unblock all files in the script folder by removing the Zone.Identifier alternate data stream with a value of "3"
	Get-ChildItem -Path $PSScriptRoot\..\ -File -Recurse -Force | Unblock-File

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# Progress bar can significantly impact cmdlet performance
	# https://github.com/PowerShell/PowerShell/issues/2138
	$Script:ProgressPreference = "SilentlyContinue"

	# https://github.com/PowerShell/PowerShell/issues/21070
	$Script:CompilerParameters = [System.CodeDom.Compiler.CompilerParameters]::new("System.dll")
	$Script:CompilerParameters.TempFiles = [System.CodeDom.Compiler.TempFileCollection]::new($env:TEMP, $false)
	$Script:CompilerParameters.GenerateInMemory = $true
	$Signature = @{
		Namespace          = "WinAPI"
		Name               = "GetStrings"
		Language           = "CSharp"
		UsingNamespace     = "System.Text"
		CompilerParameters = $CompilerParameters
		MemberDefinition   = @"
[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr GetModuleHandle(string lpModuleName);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
internal static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);

public static string GetString(uint strId)
{
	IntPtr intPtr = GetModuleHandle("shell32.dll");
	StringBuilder sb = new StringBuilder(255);
	LoadString(intPtr, strId, sb, sb.Capacity);
	return sb.ToString();
}

// Get string from other DLLs
[DllImport("shlwapi.dll", CharSet=CharSet.Unicode)]
private static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf, int cchOutBuf, string ppvReserved);

public static string GetIndirectString(string indirectString)
{
	try
	{
		int returnValue;
		StringBuilder lptStr = new StringBuilder(1024);
		returnValue = SHLoadIndirectString(indirectString, lptStr, 1024, null);

		if (returnValue == 0)
		{
			return lptStr.ToString();
		}
		else
		{
			return null;
			// return "SHLoadIndirectString Failure: " + returnValue;
		}
	}
	catch // (Exception ex)
	{
		return null;
		// return "Exception Message: " + ex.Message;
	}
}
"@
	}
	if (-not ("WinAPI.GetStrings" -as [type]))
	{
		Add-Type @Signature
	}

	$Signature = @{
		Namespace          = "WinAPI"
		Name               = "ForegroundWindow"
		Language           = "CSharp"
		CompilerParameters = $CompilerParameters
		MemberDefinition   = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
"@
	}

	if (-not ("WinAPI.ForegroundWindow" -as [type]))
	{
		Add-Type @Signature | Out-Null
	}

	# Checking whether the logged-in user is an admin
	LogInfo "Checking whether the logged-in user is an admin"
	$CurrentUserName = (Get-Process -Id $PID -IncludeUserName).UserName | Split-Path -Leaf
	$LoginUserName = (Get-CimInstance -ClassName Win32_Process -Filter "name='explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | Select-Object -First 1).User

	if ($CurrentUserName -ne $LoginUserName)
	{
		LogWarning $Localization.LoggedInUserNotAdmin
	}

	# Checking whether the script was run in PowerShell ISE or VS Code
	LogInfo "Checking whether the script was run in PowerShell ISE or VS Code"
	if (($Host.Name -match "ISE") -or ($env:TERM_PROGRAM -eq "vscode"))
	{
		LogWarning ($Localization.UnsupportedHost -f $Host.Name.Replace("Host", ""))
	}

	# Checking whether Windows was broken by 3rd party harmful tweakers, trojans, or custom Windows images
	LogInfo "Checking whether Windows was broken by 3rd party harmful tweakers, trojans, or custom Windows images"
	$Tweakers = @{
		# https://github.com/Sycnex/Windows10Debloater
		Windows10Debloater  = "$env:SystemDrive\Temp\Windows10Debloater"
		# https://github.com/Fs00/Win10BloatRemover
		Win10BloatRemover   = "$env:TEMP\.net\Win10BloatRemover"
		# https://github.com/arcadesdude/BRU
		"Bloatware Removal" = "$env:SystemDrive\BRU\Bloatware-Removal*.log"
		# https://www.youtube.com/GHOSTSPECTRE
		"Ghost Toolbox"     = "$env:SystemRoot\System32\migwiz\dlmanifests\run.ghost.cmd"
		# https://win10tweaker.ru
		"Win 10 Tweaker"    = "HKCU:\Software\Win 10 Tweaker"
		# https://boosterx.ru
		BoosterX            = "$env:ProgramFiles\GameModeX\GameModeX.exe"
		# https://forum.ru-board.com/topic.cgi?forum=5&topic=14285&start=400#11
		"Defender Control"  = "$env:APPDATA\Defender Control"
		# https://forum.ru-board.com/topic.cgi?forum=5&topic=14285&start=260#12
		"Defender Switch"   = "$env:ProgramData\DSW"
		# https://revi.cc/revios/download
		"Revision Tool"     = "${env:ProgramFiles(x86)}\Revision Tool"
		# https://www.youtube.com/watch?v=L0cj_I6OF2o
		"WinterOS Tweaker"  = "$env:SystemRoot\WinterOS*"
		# https://github.com/ThePCDuke/WinCry
		WinCry              = "$env:SystemRoot\TempCleaner.exe"
		# https://www.youtube.com/watch?v=5NBqbUUB1Pk
		WinClean             = "$env:ProgramFiles\WinClean Plus Apps"
		# https://github.com/Atlas-OS/Atlas
		AtlasOS              = "$env:SystemRoot\AtlasModules"
		# https://x.com/NPKirbyy
		KirbyOS              = "$env:ProgramData\KirbyOS"
		# https://pc-np.com
		PCNP                 = "HKCU:\Software\PCNP"
	}
	foreach ($Tweaker in $Tweakers.Keys)
	{
		if (Test-Path -Path $Tweakers[$Tweaker])
		{
			if ($Tweakers[$Tweaker] -eq "HKCU:\Software\Win 10 Tweaker")
			{
				LogWarning $Localization.Win10TweakerWarning

			}
			LogWarning ($Localization.TweakerWarning -f $Tweaker)
		}
	}

	# Checking whether Windows was broken by 3rd party harmful tweakers, trojans, or custom Windows images
	$Tweakers = @{
		# https://forum.ru-board.com/topic.cgi?forum=62&topic=30617&start=1600#14
		AutoSettingsPS   = "$(Get-Item -Path `"HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`" | Where-Object -FilterScript {$_.Property -match `"AutoSettingsPS`"})"
		# Flibustier custom Windows image
		Flibustier       = "$(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\.NETFramework\Performance -Name *flibustier)"
		# https://github.com/builtbybel/Winpilot
		Winpilot         = "$((Get-ItemProperty -Path `"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`").PSObject.Properties | Where-Object -FilterScript {$_.Value -eq `"Winpilot`"})"
		# https://github.com/builtbybel/Winpilot
		Bloatynosy       = "$((Get-ItemProperty -Path `"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`").PSObject.Properties | Where-Object -FilterScript {$_.Value -eq `"BloatynosyNue`"})"
		# https://github.com/builtbybel/xd-AntiSpy
		"xd-AntiSpy"     = "$((Get-ItemProperty -Path `"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`").PSObject.Properties | Where-Object -FilterScript {$_.Value -eq `"xd-AntiSpy`"})"
		# https://forum.ru-board.com/topic.cgi?forum=5&topic=50519
		"Modern Tweaker" = "$((Get-ItemProperty -Path `"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`").PSObject.Properties | Where-Object -FilterScript {$_.Value -eq `"Modern Tweaker`"})"
		# https://discord.com/invite/kernelos
		KernelOS         = "$(Get-CimInstance -Namespace root/CIMV2/power -ClassName Win32_PowerPlan | Where-Object -FilterScript {$_.ElementName -match `"KernelOS`"})"
		# https://discord.com/invite/9ZCgxhaYV6
		ChlorideOS       = "$(Get-Volume | Where-Object -FilterScript {$_.FileSystemLabel -eq `"ChlorideOS`"})"
	}
	foreach ($Tweaker in $Tweakers.Keys)
	{
		if ($Tweakers[$Tweaker])
		{
			LogWarning ($Localization.TweakerWarning -f $Tweaker)
		}
	}

	# Remove harmful blocked DNS domains list from https://github.com/schrebra/Windows.10.DNS.Block.List
	LogInfo "Remove harmful blocked DNS domains list from https://github.com/schrebra/Windows.10.DNS.Block.List"
	Get-NetFirewallRule -DisplayName Block.MSFT* -ErrorAction Ignore | Remove-NetFirewallRule | Out-Null

	# Remove firewalled IP addresses that block Microsoft recourses added by harmful tweakers
	# https://wpd.app
	LogInfo "Remove firewalled IP addresses that block Microsoft recourses added by harmful tweakers"
	Get-NetFirewallRule -DisplayName "Blocker MicrosoftTelemetry*", "Blocker MicrosoftExtra*", "windowsSpyBlocker*" -ErrorAction Ignore | Remove-NetFirewallRule | Out-Null

	#LogInfo -MessageData "" -InformationAction Continue
	# Extract the localized "Please wait..." string from shell32.dll
	#Write-Verbose -Message ([WinAPI.GetStrings]::GetString(12612)) -Verbose
	#LogInfo -MessageData "" -InformationAction Continue

	# Remove IP addresses from hosts file that block Microsoft resources added by WindowsSpyBlocker
	# https://github.com/crazy-max/WindowsSpyBlocker
	LogInfo "Remove IP addresses from hosts file that block Microsoft resources added by WindowsSpyBlocker"
	try
	{
		# Checking whether https://github.com is alive
		$Parameters = @{
			Uri              = "https://github.com"
			Method           = "Head"
			DisableKeepAlive = $true
			UseBasicParsing  = $true
		}
		(Invoke-WebRequest @Parameters).StatusDescription | Out-Null

		Clear-Variable -Name IPArray -ErrorAction Ignore

		# https://github.com/crazy-max/WindowsSpyBlocker/tree/master/data/hosts
		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt"
			UseBasicParsing = $true
		}
		$extra = (Invoke-WebRequest @Parameters).Content

		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra_v6.txt"
			UseBasicParsing = $true
		}
		$extra_v6 = (Invoke-WebRequest @Parameters).Content

		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"
			UseBasicParsing = $true
		}
		$spy = (Invoke-WebRequest @Parameters).Content

		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy_v6.txt"
			UseBasicParsing = $true
		}
		$spy_v6 = (Invoke-WebRequest @Parameters).Content

		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/update.txt"
			UseBasicParsing = $true
		}
		$update = (Invoke-WebRequest @Parameters).Content

		$Parameters = @{
			Uri             = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/update_v6.txt"
			UseBasicParsing = $true
		}
		$update_v6 = (Invoke-WebRequest @Parameters).Content

		$IPArray = @($extra, $extra_v6, $spy, $spy_v6, $update, $update_v6) -split "`r?`n" |
			Where-Object { $_ -and ($_ -notmatch "^\s*#") }

		$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
		$HostsContent = Get-Content -Path $HostsPath -Encoding Default -Force

		$MatchedHostsEntries = $HostsContent | Where-Object {
			$Line = $_.Trim()
			$Line -and
			(-not $Line.StartsWith("#")) -and
			($IPArray | Select-String -SimpleMatch -Pattern $Line -Quiet)
		}

		if ($MatchedHostsEntries)
		{
			LogInfo "WindowsSpyBlocker entries detected in hosts file"

			$FilteredHosts = $HostsContent | Where-Object {
				$Line = $_.Trim()

				if (-not $Line -or $Line.StartsWith("#"))
				{
					return $true
				}

				-not ($IPArray | Select-String -SimpleMatch -Pattern $Line -Quiet)
			}

			LogInfo "Cleaning hosts file"
			$FilteredHosts | Set-Content -Path $HostsPath -Encoding Default -Force

			Start-Process -FilePath notepad.exe -ArgumentList $HostsPath | Out-Null
		}
	}
	catch [System.Net.WebException]
	{
		LogWarning "$( $Localization.NoResponse -f 'https://github.com' ) Skipping WindowsSpyBlocker hosts cleanup."
	}

	# Checking whether Windows Feature Experience Pack was removed by harmful tweakers
	LogInfo "Checking whether Windows Feature Experience Pack was removed by harmful tweakers"
	if (-not (Get-AppxPackage -Name MicrosoftWindows.Client.CBS))
	{
		LogWarning ($Localization.WindowsComponentBroken -f "Windows Feature Experience Pack")
	}

	# Checking whether EventLog service is running
	LogInfo "Checking whether EventLog service is running"
	if ((Get-Service -Name EventLog).Status -eq "Stopped")
	{
		LogWarning ($Localization.WindowsComponentBroken -f $([WinAPI.GetStrings]::GetString(22029)))
	}

	# Checking whether the Microsoft Store being an important system component was removed
	LogInfo "Checking whether the Microsoft Store being an important system component was removed"
	if (-not (Get-AppxPackage -Name Microsoft.WindowsStore))
	{
		LogWarning ($Localization.WindowsComponentBroken -f "Microsoft Store")
	}

	#region Defender checks
	# Checking whether necessary Microsoft Defender components exists
	LogInfo "Checking whether necessary Microsoft Defender components exists"
	$Files = @(
		"$env:SystemRoot\System32\smartscreen.exe",
		"$env:SystemRoot\System32\SecurityHealthSystray.exe",
		"$env:SystemRoot\System32\CompatTelRunner.exe"
	)
	foreach ($File in $Files)
	{
		if (-not (Test-Path -Path $File))
		{
			LogWarning ($Localization.WindowsComponentBroken -f $File)
		}
	}

	# Checking whether Windows Security Settings page was hidden from UI
	LogInfo "Checking whether Windows Security Settings page was hidden from UI"
	if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "SettingsPageVisibility", $null) -match "hide:windowsdefender")
	{
		LogWarning ($Localization.WindowsComponentBroken -f "Microsoft Defender")
	}

	# Checking whether WMI is corrupted
	LogInfo "Checking whether WMI is corrupted"
	try
	{
		Get-CimInstance -ClassName MSFT_MpComputerStatus -Namespace root/Microsoft/Windows/Defender -ErrorAction Stop | Out-Null
	}
	catch [Microsoft.Management.Infrastructure.CimException]
	{
		LogWarning ($Global:Error.Exception.Message | Select-Object -First 1)
		LogWarning ($Localization.WindowsComponentBroken -f "Microsoft Defender")
	}

	# Check Microsoft Defender state
	if ($null -eq (Get-CimInstance -ClassName AntiVirusProduct -Namespace root/SecurityCenter2 -ErrorAction Ignore))
	{
		LogWarning ($Localization.WindowsComponentBroken -f "Microsoft Defender")
	}

	# Checking services
	LogInfo "Checking services"
	try
	{
		$Services = Get-Service -Name Windefend, SecurityHealthService, wscsvc -ErrorAction Stop
		Get-Service -Name SecurityHealthService -ErrorAction Stop | Start-Service | Out-Null
	}
	catch [Microsoft.PowerShell.Commands.ServiceCommandException]
	{
		$Services = @()
		LogWarning ($Localization.WindowsComponentBroken -f "Microsoft Defender")
	}

	$Script:DefenderServices = (($Services | Where-Object { $_.Status -ne "Running" } | Measure-Object).Count -lt $Services.Count)

	# Checking Get-MpPreference cmdlet
	LogInfo "Checking Get-MpPreference cmdlet"
	try
	{
		(Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess | Out-Null
	}
	catch [Microsoft.Management.Infrastructure.CimException]
	{
		LogWarning ($Localization.WindowsComponentBroken -f "Microsoft Defender")
	}

	# Check Microsoft Defender state
	LogInfo "Checking Microsoft Defender state"
	$productState = (Get-CimInstance -ClassName AntiVirusProduct -Namespace root/SecurityCenter2 |
		Where-Object { $_.instanceGuid -eq "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}" }).productState

	$DefenderState = ('0x{0:x}' -f $productState).Substring(3, 2)

	if ($DefenderState -notmatch "00|01")
	{
		# Defender is a currently used AV. Continue...
		$Script:DefenderProductState = $true

		# Checking whether Microsoft Defender was turned off via GPO
		if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", $null) -eq 1)
		{
			$Script:AntiSpywareEnabled = $false
		}
		else
		{
			$Script:AntiSpywareEnabled = $true
		}

		# Checking whether Microsoft Defender was turned off via GPO
		if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", $null) -eq 1)
		{
			$Script:RealtimeMonitoringEnabled = $false
		}
		else
		{
			$Script:RealtimeMonitoringEnabled = $true
		}

		# Checking whether Microsoft Defender was turned off via GPO
		if ([Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", $null) -eq 1)
		{
			$Script:BehaviorMonitoringEnabled = $false
		}
		else
		{
			$Script:BehaviorMonitoringEnabled = $true
		}
	}
	else
	{
		$Script:DefenderProductState = $false
		$Script:AntiSpywareEnabled = $false
		$Script:RealtimeMonitoringEnabled = $false
		$Script:BehaviorMonitoringEnabled = $false
	}

	if ($Script:DefenderServices -and $Script:DefenderProductState -and $Script:AntiSpywareEnabled -and $Script:RealtimeMonitoringEnabled -and $Script:BehaviorMonitoringEnabled)
	{
		# Defender is enabled
		$Script:DefenderEnabled = $true

		switch ((Get-MpPreference).EnableControlledFolderAccess)
		{
			"1"
			{
				LogInfo "Disabling Controlled folder access"
				$Script:ControlledFolderAccess = $true
				Set-MpPreference -EnableControlledFolderAccess Disabled | Out-Null

				Start-Process -FilePath "windowsdefender://RansomwareProtection" | Out-Null
			}
			"0"
			{
				LogInfo "Controlled folder access has already been disabled"
				$Script:ControlledFolderAccess = $false
			}
			default
			{
				$Script:ControlledFolderAccess = $false
			}
		}
	}
	else
	{
		$Script:DefenderEnabled = $false
		$Script:ControlledFolderAccess = $false
	}
	#endregion Defender checks

	# Checking whether LGPO.exe exists in the files folder
	LogInfo "Checking whether LGPO.exe exists in the files folder"
	if (-not (Test-Path -Path "$PSScriptRoot\..\..\files\LGPO.exe"))
	{
		LogWarning ($Localization.Bin -f [IO.Path]::GetFullPath("$PSScriptRoot\..\..\files"))
	}

	# Enable back the SysMain service if it was disabled by harmful tweakers
	LogInfo "Enable back the SysMain service if it was disabled by harmful tweakers"
	if ((Get-Service -Name SysMain).Status -eq "Stopped")
	{
		Get-Service -Name SysMain | Set-Service -StartupType Automatic | Out-Null
		Get-Service -Name SysMain | Start-Service | Out-Null
	}

	# Automatically manage paging file size for all drives
	LogInfo "Automatically manage paging file size for all drives"
	if (-not (Get-CimInstance -ClassName CIM_ComputerSystem).AutomaticManagedPageFile)
	{
		Get-CimInstance -ClassName CIM_ComputerSystem | Set-CimInstance -Property @{AutomaticManagedPageFile = $true} | Out-Null
	}

	# PowerShell 5.1 (7.5 too) interprets 8.3 file name literally, if an environment variable contains a non-Latin word
	# https://github.com/PowerShell/PowerShell/issues/21070
	Get-ChildItem -Path "$env:TEMP\Computer.txt", "$env:TEMP\User.txt" -Force -ErrorAction Ignore |
		Remove-Item -Force -ErrorAction Ignore | Out-Null

	# Save all opened folders in order to restore them after File Explorer restart
	try
	{
		$Script:OpenedFolders = {
			(New-Object -ComObject Shell.Application).Windows() |
				ForEach-Object { $_.Document.Folder.Self.Path }
		}.Invoke()
	}
	catch [System.Management.Automation.PropertyNotFoundException]
	{
		$Script:OpenedFolders = @()
	}
	<#
		.SYNOPSIS
		The "Show menu" function with the up/down arrow keys and enter key to make a selection

		.PARAMETER Menu
		Array of items to choose from

		.PARAMETER Default
		Default selected item in array

		.PARAMETER AddSkip
		Add localized extracted "Skip" string from shell32.dll

		.EXAMPLE
		Show-Menu -Menu $Items -Default 1

		.LINK
		https://qna.habr.com/answer?answer_id=1522379
	#>
	Clear-Host
	function Show-Menu
	{
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true)]
			[array]
			$Menu,

			[Parameter(Mandatory = $true)]
			[int]
			$Default,

			[Parameter(Mandatory = $false)]
			[switch]
			$AddSkip
		)

		# Keep menu as array
		$Menu = @($Menu)

		# Add "Please use the arrow keys ↑ and ↓ on your keyboard to select your answer" to menu
		if ($Localization -and $Localization.KeyboardArrows)
		{
			$Menu += ($Localization.KeyboardArrows -f [System.Char]::ConvertFromUtf32(0x2191), [System.Char]::ConvertFromUtf32(0x2193))
		}
		else
		{
			$Menu += ("Please use the arrow keys {0} and {1} on your keyboard to select your answer" -f [System.Char]::ConvertFromUtf32(0x2191), [System.Char]::ConvertFromUtf32(0x2193))
		}

		if ($AddSkip)
		{
			# Extract the localized "Skip" string from shell32.dll
			$Menu += [WinAPI.GetStrings]::GetString(16956)
		}

		# Checking whether current terminal is Windows Terminal
		if ($env:WT_SESSION)
		{
			# https://github.com/microsoft/terminal/issues/14992
			[System.Console]::BufferHeight += $Menu.Count
		}

		$minY = [Console]::CursorTop

		# Default is passed in as 1-based selection
		$y = [Math]::Max([Math]::Min(($Default - 1), ($Menu.Count - 1)), 0)

		do
		{
			[Console]::CursorTop = $minY
			[Console]::CursorLeft = 0
			$i = 0

			foreach ($item in $Menu)
			{
				if ($i -ne $y)
				{
					Write-Host ('  {0}  ' -f $item)
				}
				else
				{
					Write-Host ('[ {0} ]' -f $item)
				}

				$i++
			}

			$k = [Console]::ReadKey($true)
			switch ($k.Key)
			{
				"UpArrow"
				{
					if ($y -gt 0)
					{
						$y--
					}
				}
				"DownArrow"
				{
					if ($y -lt ($Menu.Count - 1))
					{
						$y++
					}
				}
				"Enter"
				{
					return $Menu[$y]
				}
			}
		}
		while ($k.Key -notin ([ConsoleKey]::Escape, [ConsoleKey]::Enter))
	}

	# Extract the localized "Browse" string from shell32.dll
	$Script:Browse = [WinAPI.GetStrings]::GetString(9015)
	# Extract the localized "&No" string from shell32.dll
	$Script:No = [WinAPI.GetStrings]::GetString(33232).Replace("&", "")
	# Extract the localized "&Yes" string from shell32.dll
	$Script:Yes = [WinAPI.GetStrings]::GetString(33224).Replace("&", "")
	$Script:KeyboardArrows = if ($Localization -and $Localization.KeyboardArrows)
	{
		$Localization.KeyboardArrows -f [System.Char]::ConvertFromUtf32(0x2191), [System.Char]::ConvertFromUtf32(0x2193)
	}
	else
	{
		"Please use the arrow keys {0} and {1} on your keyboard to select your answer" -f [System.Char]::ConvertFromUtf32(0x2191), [System.Char]::ConvertFromUtf32(0x2193)
	}
	# Extract the localized "Skip" string from shell32.dll
	$Script:Skip = [WinAPI.GetStrings]::GetString(16956)

	Write-Information -MessageData "┏┓   •     ┏      ┓ ┏•   ┓ 		" -InformationAction Continue
	Write-Information -MessageData "┗┓┏┏┓┓┏┓╋  ╋┏┓┏┓  ┃┃┃┓┏┓┏┫┏┓┓┏┏┏" -InformationAction Continue
	Write-Information -MessageData "┗┛┗┛ ┗┣┛┗  ┛┗┛┛   ┗┻┛┗┛┗┗┻┗┛┗┻┛┛" -InformationAction Continue
	Write-Information -MessageData "      ┛                   		" -InformationAction Continue

	# Display a warning message about whether a user has customized the preset file
	if ($Warning)
	{
		# Get the name of a preset (e.g Win10_11Util.ps1) regardless if it was named
		# $_.File has no EndsWith() method
		[string]$PresetName = ((Get-PSCallStack).Position | Where-Object -FilterScript {$_.File}).File | Where-Object -FilterScript {$_.EndsWith(".ps1")}
		LogWarning ($Localization.CustomizationWarning -f "`"$PresetName`"")
		LogInfo "Showing Main Menu, waiting for input"

		do
		{
			$Choice = Show-Menu -Menu @($Script:Yes, $Script:No) -Default 2

			switch ($Choice)
			{
				$Script:Yes
				{
					continue
				}
				$Script:No
				{
					Invoke-Item -Path $PresetName
					Start-Sleep -Seconds 5
				}
				$Script:KeyboardArrows {}
			}
		}
		until ($Choice -ne $Script:KeyboardArrows)
	}

	LogInfo "Initial Checks finished, continuing with Main Script" -addGap
	Clear-Host
}
#endregion InitialActions
