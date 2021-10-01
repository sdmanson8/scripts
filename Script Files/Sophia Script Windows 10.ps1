#requires -version 5.1
#Calling Powershell as Admin and setting Execution Policy to Bypass to avoid Cannot run Scripts error
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
#Is Powershell 7 Installed
  $w64=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
  $w32=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object { try { $_.DisplayName -match "PowerShell 7-x64" } catch { $false } }
if ($w64 -or $w32)
{
    Start-Process pwsh.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file -elevated' -f ($myinvocation.MyCommand.Definition))
<#
# Check if Windows Terminal is Running, Stop Windows Terminal if Running
    if((get-process "WindowsTerminal" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else { 
    Stop-Process -processname "WindowsTerminal"
        }
# Check if CMD is Running, Stop CMD if Running
    if((get-process "cmd" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else { 
    Stop-Process -processname "cmd"
        }
# Check if Powershell is Running, Stop Powershell if Running
    if((get-process "powershell" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else { 
    Stop-Process -processname "powershell"
        }
# Check if Powershell ISE is Running, Stop Powershell ISE if Running
    if((get-process "powershell_ise" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else { 
    Stop-Process -processname "powershell_ise"
        }

# Check if Powershell 7 is Running, Stop Powershell 7 if Running
    if((get-process "pwsh" -ea SilentlyContinue) -eq $Null){ 
        echo "" 
    }
    else { 
    Stop-Process -processname "pwsh"
        }
#>
}
else {
    Write-Output "Powershell 7 is not installed on your machine."
    Write-Host "Preparing to Install Powershell 7 ... Please wait..."
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
    Write-Host Powershell 7 Installed
    Start-Sleep -Seconds 1
    Start-Process pwsh.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file -elevated' -f ($myinvocation.MyCommand.Definition)) 
   }
}

function ScriptFunct
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[string[]]
		$Functions
	)

	foreach ($Function in $Functions)
	{
		Invoke-Expression -Command $Function
	}

	# The "RefreshEnvironment" and "Errors" functions will be executed at the end
	Invoke-Command -ScriptBlock {RefreshEnvironment; Errors}
}


$Host.UI.RawUI.WindowTitle = "Windows 10 Bloatware and Security Hardening Script"

$Parameters = @{
	CommandName   = "ScriptFunct"
	ParameterName = "Functions"
	ScriptBlock   = {
		param
		(
			$commandName,
			$parameterName,
			$wordToComplete,
			$commandAst,
			$fakeBoundParameters
		)

		# Get functions list with arguments to complete
		$Commands = (Get-Module -Name ScriptFunct).ExportedCommands.Keys
		foreach ($Command in $Commands)
		{
			$ParameterSets = (Get-Command -Name $Command).Parametersets.Parameters | Where-Object -FilterScript {$null -eq $_.Attributes.AliasNames}

			# If a module command is PinToStart
			if ($Command -eq "PinToStart")
			{
				# Get all command arguments, excluding defaults
				foreach ($ParameterSet in $ParameterSets.Name)
				{
					# If an argument is Tiles
					if ($ParameterSet -eq "Tiles")
					{
						$ValidValues = ((Get-Command -Name PinToStart).Parametersets.Parameters | Where-Object -FilterScript {$null -eq $_.Attributes.AliasNames}).Attributes.ValidValues
						foreach ($ValidValue in $ValidValues)
						{
							# The "PinToStart -Tiles <function>" construction
							"PinToStart" + " " + "-" + $ParameterSet + " " + $ValidValue | Where-Object -FilterScript {$_ -like "*$wordToComplete*"} | ForEach-Object -Process {"`"$_`""}
						}

						# The "PinToStart -Tiles <functions>" construction
						"PinToStart" + " " + "-" + $ParameterSet + " " + ($ValidValues -join ", ") | Where-Object -FilterScript {$_ -like "*$wordToComplete*"} | ForEach-Object -Process {"`"$_`""}
					}

					continue
				}
			}

			# If a module command is UnpinTaskbarShortcuts
			if ($Command -eq "UnpinTaskbarShortcuts")
			{
				# Get all command arguments, excluding defaults
				foreach ($ParameterSet in $ParameterSets.Name)
				{
					# If an argument is Shortcuts
					if ($ParameterSet -eq "Shortcuts")
					{
						$ValidValues = ((Get-Command -Name UnpinTaskbarShortcuts).Parametersets.Parameters | Where-Object -FilterScript {$null -eq $_.Attributes.AliasNames}).Attributes.ValidValues
						foreach ($ValidValue in $ValidValues)
						{
							# The "UnpinTaskbarShortcuts -Shortcuts <function>" construction
							"UnpinTaskbarShortcuts" + " " + "-" + $ParameterSet + " " + $ValidValue | Where-Object -FilterScript {$_ -like "*$wordToComplete*"} | ForEach-Object -Process {"`"$_`""}
						}

						# The "UnpinTaskbarShortcuts -Shortcuts <functions>" construction
						"UnpinTaskbarShortcuts" + " " + "-" + $ParameterSet + " " + ($ValidValues -join ", ") | Where-Object -FilterScript {$_ -like "*$wordToComplete*"} | ForEach-Object -Process {"`"$_`""}
					}

					continue
				}
			}

			# If a module command is UninstallUWPApps
			if ($Command -eq "UninstallUWPApps")
			{
				(Get-Command -Name $Command).Name | Where-Object -FilterScript {$_ -like "*$wordToComplete*"}

				# Get all command arguments, excluding defaults
				foreach ($ParameterSet in $ParameterSets.Name)
				{
					# If an argument is ForAllUsers
					if ($ParameterSet -eq "ForAllUsers")
					{
						# The "UninstallUWPApps -ForAllUsers" construction
						"UninstallUWPApps" + " " + "-" + $ParameterSet | Where-Object -FilterScript {$_ -like "*$wordToComplete*"} | ForEach-Object -Process {"`"$_`""}
					}

					continue
				}
			}

			foreach ($ParameterSet in $ParameterSets.Name)
			{
				# The "Function -Argument" construction
				$Command + " " + "-" + $ParameterSet | Where-Object -FilterScript {$_ -like "*$wordToComplete*"} | ForEach-Object -Process {"`"$_`""}

				continue
			}

			# Get functions list without arguments to complete
			Get-Command -Name $Command | Where-Object -FilterScript {$null -eq $_.Parametersets.Parameters} | Where-Object -FilterScript {$_.Name -like "*$wordToComplete*"}

			continue
		}
	}
}

	# Detect the OS bitness
	switch ([System.Environment]::Is64BitOperatingSystem)
	{
		$false
		{
			Write-Warning -Message "The script supports Windows 10 x64 only"
			exit
		}
	}


	# Detect the OS build version
	switch (((Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber -ge 19041) -and ((Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber -le 19044))
	{
		$false
		{
			Write-Warning -Message "The script supports Windows 10 2004/20H2/21H1/21H2 versions"
			exit
		}
	}

	# Check whether the OS minor build version is 928 minimum
	switch ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion" -Name UBR) -ge 928)
	{
		$false
		{
			$Version = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion" -Name UBR
			Write-Warning -Message ("Windows 10 cumulative update installed: {0}. Supported cumulative update: 928 and higher" -f $Version)

			# Receive updates for other Microsoft products when you update Windows
			(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")

			Start-Sleep -Seconds 1

			# Open the "Windows Update" page
			Start-Process -FilePath "ms-settings:windowsupdate-action"

			Start-Sleep -Seconds 1

			# Trigger Windows Update for detecting new updates
			(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()

			exit
		}
	}

if ($Functions)
{
	Invoke-Command -ScriptBlock {Checkings}

	foreach ($Function in $Functions)
	{
		Invoke-Expression -Command $Function
	}

	# The "RefreshEnvironment" and "Errors" functions will be executed at the end
	Invoke-Command -ScriptBlock {RefreshEnvironment; Errors}

	exit
}

	# Check whether the script was opened via PowerShell ISE
	if ($Host.Name -match "ISE")
	{
		Write-Warning -Message "The script doesn't support running via Windows PowerShell ISE"
		exit
	}

	# Check whether the OS was infected by Win 10 Tweaker
	if (Test-Path -Path "HKCU:\Software\Win 10 Tweaker")
	{
		Write-Warning -Message "Probably your OS was infected via the Win 10 Tweaker backdoor"

		Start-Process -FilePath "https://youtu.be/na93MS-1EkM"
		Start-Process -FilePath "https://pikabu.ru/story/byekdor_v_win_10_tweaker_ili_sovremennyie_metodyi_borbyi_s_piratstvom_8227558"

		exit
	}

	# Import PowerShell 5.1 modules
	#Import-Module -Name Microsoft.PowerShell.Management, PackageManagement, Appx -UseWindowsPowerShell

	# Turn off Controlled folder access to let the script proceed
	switch ((Get-MpPreference).EnableControlledFolderAccess)
	{
		"1"
		{
			Write-Warning -Message "Controlled folder access disabled"

			$Script:ControlledFolderAccess = $true
			Set-MpPreference -EnableControlledFolderAccess Disabled

			# Open "Ransomware protection" page
			Start-Process -FilePath windowsdefender://RansomwareProtection
		}
		"0"
		{
			$Script:ControlledFolderAccess = $false
		}
	}

# Create a restore point for the system drive
function CreateRestorePoint
{
        $SystemDriveUniqueID = (Get-Volume | Where-Object -FilterScript {$_.DriveLetter -eq "$($env:SystemDrive[0])"}).UniqueID
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

	Checkpoint-Computer -Description "Windows 10 Bloatware and Security Hardening Script" -RestorePointType MODIFY_SETTINGS

	# Revert the System Restore checkpoint creation frequency to 1440 minutes
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force

	# Turn off System Protection for the system drive if it was turned off before without deleting the existing restore points
	if ($ComputerRestorePoint)
	{
		Disable-ComputerRestore -Drive $env:SystemDrive
	}
CreateRestorePoint

#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Set Directory to PSScriptRoot
#if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

#Install PowerShell Modules
Copy-Item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
#Unblock New PowerShell Modules
Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
#Install PSWindowsUpdate
Import-Module -Name PSWindowsUpdate -Force -Global

#Remove and Refresh Local Policies
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
gpupdate /force | Out-Null

#Install Latest Windows Updates
Start-Job -Name "Windows Updates" -ScriptBlock {
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot
}

Start-Job -Name "Mitigations" -ScriptBlock {
    #####SPECTURE MELTDOWN#####
    #https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type "DWORD" -Value 72 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type "DWORD" -Value 3 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type "String" -Value "1.0" -Force

    #Disable LLMNR
    #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
    New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
    Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force

    #Disable TCP Timestamps
    netsh int tcp set global timestamps=disabled

    #Enable DEP
    BCDEDIT /set "{current}" nx OptOut
    Set-Processmitigation -System -Enable DEP
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Type "DWORD" -Value 0 -Force

    #Enable SEHOP
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type "DWORD" -Value 0 -Force

    #Disable NetBIOS by updating Registry
    #http://blog.dbsnet.fr/disable-netbios-with-powershell#:~:text=Disabling%20NetBIOS%20over%20TCP%2FIP,connection%2C%20then%20set%20NetbiosOptions%20%3D%202
    $key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    Get-ChildItem $key | ForEach-Object { 
        Write-Host("Modify $key\$($_.pschildname)")
        $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
        Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
    }
    
    #Disable WPAD
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name "Wpad" -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "Wpad" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force

    #Enable LSA Protection/Auditing
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "LSASS.exe" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Type "DWORD" -Value 8 -Force

    #Disable Windows Script Host
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\" -Name "Settings" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    
    #Disable WDigest
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -Type "DWORD" -Value 0 -Force

    #Block Untrusted Fonts
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "QWORD" -Value "1000000000000" -Force
    
    #Disable Office OLE
    #https://adsecurity.org/?p=3299
    $officeversions = '16.0', '15.0', '14.0', '12.0'
    ForEach ($officeversion in $officeversions) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
    }
}

Start-Job -Name "PowerShell Hardening" -ScriptBlock {
   
    #Enable PowerShell Logging
    #https://www.digitalshadows.com/blog-and-research/powershell-security-best-practices/
    #https://www.cyber.gov.au/acsc/view-all-content/publications/securing-powershell-enterprise
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" -Name "Transcription" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Type "STRING" -Value "C:\PowershellLogs" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockLogging" -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableTranscripting" -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableInvocationHeader" -Type "DWORD" -Value "1" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Type "STRING" -Value "C:\PowershellLogs" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockLogging" -Type "DWORD" -Value "1" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableTranscripting" -Type "DWORD" -Value "1" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableInvocationHeader" -Type "DWORD" -Value "1" -Force

    #Prevent WinRM from using Basic Authentication
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Type "DWORD" -Value 0 -Force

    #WinRM Hardening
    #https://4sysops.com/archives/powershell-remoting-over-https-with-a-self-signed-ssl-certificate/
    #$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName (cmd /c hostname) 
    #Export-Certificate -Cert $Cert -FilePath C:\temp\cert
    #Remove Previous WinRM Listeners
    #Get-ChildItem WSMan:\Localhost\listener | Where-Object -Property Keys -eq "Transport=HTTP" | Remove-Item -Recurse
    #Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
    #Add New HTTPS (ONLY) Listener
    #New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Cert.Thumbprint –Force
    #Start the service at boot
    #Set-Service -Name "WinRM" -StartupType Automatic -Status Running
    #Enable Firewall rule
    #New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Private, Domain -LocalPort 5986 -Protocol TCP
    #Enable PSRemoting
    #Enable-PSRemoting -SkipNetworkProfileCheck -Force
}

#Windows Defender Configuration Files
New-Item -Path "C:\" -Name "Temp" -ItemType "directory" -Force | Out-Null; New-Item -Path "C:\temp\" -Name "Windows Defender" -ItemType "directory" -Force | Out-Null; Copy-Item -Path .\Files\"Windows Defender Configuration Files"\* -Destination "C:\temp\Windows Defender\" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null

Start-Job -Name "Windows Defender Hardening" -ScriptBlock {
    #Enable Windows Defender Exploit Protection
    Set-ProcessMitigation -PolicyFilePath "C:\temp\Windows Defender\DOD_EP_V3.xml"

    #Enable Windows Defender Application Control
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create
    Set-RuleOption -FilePath "C:\temp\Windows Defender\WDAC_V1_Recommended_Audit.xml" -Option 0

    #Windows Defender Hardening
    #https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
    #Enable real-time monitoring
    Write-Host "Enable real-time monitoring"
    Set-MpPreference -DisableRealtimeMonitoring 0
    #Enable sample submission
    Write-Host "Enable sample submission"
    Set-MpPreference -SubmitSamplesConsent 2
    #Enable checking signatures before scanning
    Write-Host "Enable checking signatures before scanning"
    Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
    #Enable behavior monitoring
    Write-Host "Enable behavior monitoring"
    Set-MpPreference -DisableBehaviorMonitoring 0
    #Enable IOAV protection
    Write-Host "Enable IOAV protection"
    Set-MpPreference -DisableIOAVProtection 0
    #Enable script scanning
    Write-Host "Enable script scanning"
    Set-MpPreference -DisableScriptScanning 0
    #Include command line in process creation events
    # Enable events auditing generated when a process is created (starts)
	auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force
    #Create the "Process Creation" Event Viewer сustom view to log the executed processes and their arguments
    # Enable events auditing generated when a process is created (starts)
	auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
	# Include command line in process creation events
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force

			$XML = @"
<ViewerConfig>
	<QueryConfig>
		<QueryParams>
			<UserQuery />
		</QueryParams>
		<QueryNode>
			<Name>$("Process Creation")</Name>
			<Description>$("Process creation and command-line auditing events")</Description>
			<QueryList>
				<Query Id="0" Path="Security">
					<Select Path="Security">*[System[(EventID=4688)]]</Select>
				</Query>
			</QueryList>
		</QueryNode>
	</QueryConfig>
</ViewerConfig>
"@

			if (-not (Test-Path -Path "$env:ProgramData\Microsoft\Event Viewer\Views"))
			{
				New-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views" -ItemType Directory -Force
			}

			# Save ProcessCreation.xml in the UTF-8 with BOM encoding
			Set-Content -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Value $XML -Encoding UTF8 -Force
    #Disable apps and files checking within Microsoft Defender SmartScreen
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
    #Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe
 	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments))
			{
				New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
			}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
    #Disable Windows Script Host - Blocks WSH from executing .js and .vbs files
   	if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"))
			{
				New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force
			}
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force
    #Disable Windows Sandbox
    			if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -like "Enterprise*"})
			{
				# Checking whether x86 virtualization is enabled in the firmware
				if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled -eq $true)
				{
					Disable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online -NoRestart
				}
				else
				{
					try
					{
						# Determining whether Hyper-V is enabled
						if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent -eq $true)
						{
							Disable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online -NoRestart
						}
					}
					catch [System.Exception]
					{
						Write-Error -Message "Enable Hardware VT" -ErrorAction SilentlyContinue
					}
				}
			}
    #Enable removable drive scanning
    Write-Host "Enable removable drive scanning"
    Set-MpPreference -DisableRemovableDriveScanning 0
    #Enable Block at first sight
    Write-Host "Enable Block at first sight"
    Set-MpPreference -DisableBlockAtFirstSeen 0
    #Enable potentially unwanted 
    Write-Host "Enable potentially unwanted apps"
    Set-MpPreference -PUAProtection Enabled
    #Schedule signature updates every 8 hours
    Write-Host "Schedule signature updates every 8 hours"
    Set-MpPreference -SignatureUpdateInterval 8
    #Enable archive scanning
    Write-Host "Enable archive scanning"
    Set-MpPreference -DisableArchiveScanning 0
    #Enable email scanning
    Write-Host "Enable email scanning"
    Set-MpPreference -DisableEmailScanning 0
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
         
    #Enable File Hash Computation
    Write-Host "Enable File Hash Computation"
    Set-MpPreference -EnableFileHashComputation 1
    #Enable Intrusion Prevention System
    Write-Host "Enable Intrusion Prevention System"
    Set-MpPreference -DisableIntrusionPreventionSystem $false
    #Enable Windows Defender Exploit Protection
    Write-Host "Enabling Exploit Protection"
    Set-ProcessMitigation -PolicyFilePath C:\temp\"Windows Defender"\DOD_EP_V3.xml
    #Set cloud block level to 'High'
    Write-Host "Set cloud block level to 'High'"
    Set-MpPreference -CloudBlockLevel High
    #Set cloud block timeout to 1 minute
    Write-Host "Set cloud block timeout to 1 minute"
    Set-MpPreference -CloudExtendedTimeout 50
    Write-Host "`nUpdating Windows Defender Exploit Guard settings`n" -ForegroundColor Green 
    #Enabling Controlled Folder Access and setting to block mode
    #Write-Host "Enabling Controlled Folder Access and setting to block mode"
    #Set-MpPreference -EnableControlledFolderAccess Enabled 
    #Enabling Network Protection and setting to block mode
    Write-Host "Enabling Network Protection and setting to block mode"
    Set-MpPreference -EnableNetworkProtection Enabled

    #Enable Cloud-delivered Protections
    #Set-MpPreference -MAPSReporting Advanced
    #Set-MpPreference -SubmitSamplesConsent SendAllSamples

    #Enable Windows Defender Attack Surface Reduction Rules
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
    #Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
    #Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
    #Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
    #Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
    #Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
    #Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
    #Block Win32 API calls from Office macros
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
    #Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode
    #Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
    #Block credential stealing from the Windows local security authority subsystem
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
    #Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode
    #Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
    #Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
    #Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
    #Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
}

#Debloating Scripts
#This Start-Job -Name "finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
#Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

#Creates a PSDrive to be able to access the 'HKCR' tree
$path = Test-Path HKCR:\
IF ($path -eq $False) {New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT} ELSE {Write-Host ""}
Start-Job -Name "Start-Debloat" -ScriptBlock {
    
    #Removes AppxPackages
    #Credit to Reddit user /u/GavinEke for a modified version of my whitelist code
    [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
    Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|`
    Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller'
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps } | Remove-AppxPackage -ErrorAction SilentlyContinue
    #Run this again to avoid error on 1803 or having to reboot.
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps } | Remove-AppxPackage -ErrorAction SilentlyContinue
    $AppxRemoval = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -NotMatch $WhitelistedApps } 
    ForEach ( $App in $AppxRemoval) {
    
        Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName 
        
    }
}

Start-Job -Name "Remove-Keys" -ScriptBlock {  
    #These are the registry keys that it will delete.  
    $Keys = @(
        
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
           
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
    
    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
    }
}
        
Start-Job -Name "Protect-Privacy" -ScriptBlock {
    
    Param([switch]$Debloat)    

    #Creates a PSDrive to be able to access the 'HKCR' tree
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        
    #Disables Windows Feedback Experience
    Write-Output "Disabling Windows Feedback Experience program"
    $Advertising = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising -Name Enabled -Value 0 -Verbose
    }
        
    #Stops Cortana from being used as part of your Windows Search Function
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
    If (Test-Path $Search) {
        Set-ItemProperty $Search -Name AllowCortana -Value 0 -Verbose
    }
        
    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Output "Stopping the Windows Feedback Experience program"
    $Period1 = 'HKCU:\Software\Microsoft\Siuf'
    $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
    $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
    If (!(Test-Path $Period3)) { 
        mkdir $Period1 -ErrorAction SilentlyContinue
        mkdir $Period2 -ErrorAction SilentlyContinue
        mkdir $Period3 -ErrorAction SilentlyContinue
        New-ItemProperty $Period3 -Name PeriodInNanoSeconds -Value 0 -Verbose -ErrorAction SilentlyContinue
    }
               
    Write-Output "Adding Registry key to prevent bloatware apps from returning"
    #Prevents bloatware applications from returning
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    If (!(Test-Path $registryPath)) {
        Mkdir $registryPath -ErrorAction SilentlyContinue
        New-ItemProperty $registryPath -Name DisableWindowsConsumerFeatures -Value 1 -Verbose -ErrorAction SilentlyContinue
    }          
    
    Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo -Name FirstRunSucceeded -Value 0 -Verbose
    }
        
    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Output "Turning off Data Collection"
    $DataCollection = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
    If (Test-Path $DataCollection) {
        Set-ItemProperty $DataCollection -Name AllowTelemetry -Value 0 -Verbose
    }
    
    #Disables People icon on Taskbar
    Write-Output "Disabling People icon on Taskbar"
    $People = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
    }
    
	#Kill Foreground
taskkill /F /IM "MicrosoftEdge.exe" 1>NUL 2>NUL
taskkill /F /IM "explorer.exe" 1>NUL 2>NUL

#Disable metro boot menu
bcdedit /set {default} bootmenupolicy legacy 1>NUL 2>NUL

#Add environmental variables
setx ProgramFiles "C:\Program Files" /m 1>NUL 2>NUL
setx ProgramFiles86 "C:\Program Files (x86)" /m 1>NUL 2>NUL
setx ProgramData "C:\ProgramData" /m 1>NUL 2>NUL

#Hide PerfLogs folder
attrib "C:\PerfLogs" +h 1>NUL 2>NUL

#Reveal Public Desktop folder
attrib "C:\Users\Public\Desktop" -h 1>NUL 2>NUL

#Delete "Your Phone" shortcut from Desktop
del /f /q "$user = $env:USERNAME
ls C:\Users\$user\Desktop\Your Phone.lnk" 1>NUL 2>NUL

#Disable Services
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushsvc" -Name Start -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PeerDistSvc" -Name "Start" -Type "DWORD" -Value 4 -Force

#Enable Developer mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type "DWORD" -Value 1 -Force

#Change Folder options
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "DWORD" -Value 0 -Force

#Disable Slideshow during Lock Screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen" -Name "SlideshowEnabled" -Type "DWORD" -Value 0 -Force

#Enable Peek at desktop
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisablePreviewDesktop" -Type "DWORD" -Value 0 -Force

#Disable all Content Delivery Manager features
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RemediationRequired" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 0 -Force

#Disable all suggested apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "22StokedOnIt.NotebookPro_ffs55s3hze5sr" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "2FE3CB00.PicsArt-PhotoStudio_crhqpqs3x1ygc" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "41038Axilesoft.ACGMediaPlayer_wxjjre7dryqb6" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "5CB722CC.SeekersNotesMysteriesofDarkwood_ypk0bew5psyra" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "7458BE2C.WorldofTanksBlitz_x4tje2y229k00" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "828B5831.HiddenCityMysteryofShadows_ytsefhwckbdv6" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "828B5831.TheSecretSociety-HiddenMystery_ytsefhwckbdv6" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "89006A2E.AutodeskSketchBook_tf1gferkr813w" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "9E2F88E3.Twitter_wgeqdkkx372wm" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.AsphaltStreetStormRacing_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.DisneyMagicKingdoms_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.DragonManiaLegends_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.MarchofEmpires_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "AdobeSystemsIncorporated.PhotoshopElements2018_ynb6jyjzte8ga" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "CAF9E577.Plex_aam28m9va5cke" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "DolbyLaboratories.DolbyAccess_rz1tebttyb220" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Drawboard.DrawboardPDF_gqbn7fs4pywxm" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Expedia.ExpediaHotelsFlightsCarsActivities_0wbx8rnn4qk5c" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Facebook.317180B0BB486_8xx8rvfyw5nnt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Facebook.Facebook_8xx8rvfyw5nnt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Facebook.InstagramBeta_8xx8rvfyw5nnt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Fitbit.FitbitCoach_6mqt6hf9g46tw" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "flaregamesGmbH.RoyalRevolt2_g0q0z3kw54rap" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "GAMELOFTSA.Asphalt8Airborne_0pp20fcewvvtj" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "king.com.BubbleWitch3Saga_kgqvnymyfvs32" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "king.com.CandyCrushSaga_kgqvnymyfvs32" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "king.com.CandyCrushSodaSaga_kgqvnymyfvs32" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.AgeCastles_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingNews_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingSports_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingWeather_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "microsoft.microsoftskydrive_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MinecraftUWP_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MSPaint_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "NAVER.LINEwin8_8ptj331gd3tyt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Nordcurrent.CookingFever_m9bz608c1b9ra" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "SiliconBendersLLC.Sketchable_r2kxzpx527qgj" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "SpotifyAB.SpotifyMusic_zpdnekdrzrea0" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "ThumbmunkeysLtd.PhototasticCollage_nfy108tqq3p12" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "USATODAY.USATODAY_wy7mw3214mat8" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "WinZipComputing.WinZipUniversal_3ykzqggjzj4z0" -Type "DWORD" -Value 0 -Force

#Disable mouse acceleration
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type "DWORD" -Value 0 -Force

#Disable Network Location Wizard prompts
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force

#Change Performance Options to Adjust for best performance
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type "DWORD" -Value 2 -Force

#Disable "Windows protected your PC" dialogue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type "DWORD" -Value 1 -Force

#Disable Malicious Software Removal Tool from installing
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type "DWORD" -Value 1 -Force

#Disable Error Reporting
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force

#Keep thumbnail cache upon Restart
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -Type "DWORD" -Value 0 -Force

#Increase System Restore point frequency
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type "DWORD" -Value 0 -Force

#Increase 15 file selection limit that hides context menu items
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "MultipleInvokePromptMinimum" -Type "DWORD" -Value 999 -Force

#Replace "Personalize" with "Appearance" in desktop context menu
Set-ACL "HKCR:\DesktopBackground\Shell\Personalize"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\DesktopBackground\Shell\Personalize"  reg  ace -ace "n:Administrators"
Set-ACL "HKCR:\DesktopBackground\Shell\Personalize\command"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\DesktopBackground\Shell\Personalize\command"  reg  ace -ace "n:Administrators"
Remove-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Personalize" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "Icon" -Type "String" -Value "display.dll,-1" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "MUIVerb" -Type "String" -Value "Appearance" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "Position" -Type "String" -Value "Bottom" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "Subcommands" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name "Icon" -Type "String" -Value "imageres.dll,-110" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name "MUIVerb" -Type "String" -Value "Background" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name "SettingsURI" -Type "String" -Value "ms-settings:personalization-background" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name "Icon" -Type "String" -Value "themecpl.dll" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name "MUIVerb" -Type "String" -Value "Colors" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name "SettingsURI" -Type "String" -Value "ms-settings:personalization-colors" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons" -Name "Icon" -Type "String" -Value "desk.cpl" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons" -Name "MUIVerb" -Type "String" -Value "Desktop Icons" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons\command" -Name "" -Type "String" -Value "rundll32 shell32.dll,Control_RunDLL desk.cpl,,0" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name "Icon" -Type "String" -Value "imageres.dll,285" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name "MUIVerb" -Type "String" -Value "Lock Screen" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name "SettingsURI" -Type "String" -Value "ms-settings:lockscreen" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers" -Name "Icon" -Type "String" -Value "main.cpl" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers" -Name "MUIVerb" -Type "String" -Value "Mouse Pointers" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers\command" -Name "" -Type "String" -Value "rundll32.exe shell32.dll,Control_RunDLL main.cpl,,1" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver" -Name "Icon" -Type "String" -Value "PhotoScreensaver.scr" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver" -Name "MUIVerb" -Type "String" -Value "Screen Saver" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver\command" -Name "" -Type "String" -Value "rundll32.exe shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds" -Name "Icon" -Type "String" -Value "mmsys.cpl" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds" -Name "MUIVerb" -Type "String" -Value "Sounds" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds\command" -Name "" -Type "String" -Value "rundll32.exe shell32.dll,Control_RunDLL mmsys.cpl ,2" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name "Icon" -Type "String" -Value "shell32.dll,-40" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name "MUIVerb" -Type "String" -Value "Taskbar" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name "SettingsURI" -Type "String" -Value "ms-settings:taskbar" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force

#Replace "Display Settings" with "Settings" in desktop context menu
Set-ACL "HKCR:\DesktopBackground\Shell\Display"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\DesktopBackground\Shell\Display"  reg  ace -ace "n:Administrators"
Set-ACL "HKCR:\DesktopBackground\Shell\Display\command"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\DesktopBackground\Shell\Display\command"  reg  ace -ace "n:Administrators"
Remove-ItemProperty -Path "HKCR\DesktopBackground\Shell\Display" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "MUIVerb" -Type "String" -Value "Settings" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "Position" -Type "String" -Value "Bottom" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "Subcommands" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name "MUIVerb" -Type "String" -Value "Accounts" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name "SettingsURI" -Type "String" -Value "ms-settings:yourinfo" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name "MUIVerb" -Type "String" -Value "Apps" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name "SettingsURI" -Type "String" -Value "ms-settings:appsfeatures" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name "MUIVerb" -Type "String" -Value "Devices" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name "SettingsURI" -Type "String" -Value "ms-settings:bluetooth" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name "MUIVerb" -Type "String" -Value "Display" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name "SettingsURI" -Type "String" -Value "ms-settings:display" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name "MUIVerb" -Type "String" -Value "Ease of Access" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name "SettingsURI" -Type "String" -Value "ms-settings:easeofaccess-narrator" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name "MUIVerb" -Type "String" -Value "Gaming" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name "SettingsURI" -Type "String" -Value "ms-settings:gaming-gamebar" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name "MUIVerb" -Type "String" -Value "Network && Internet" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name "SettingsURI" -Type "String" -Value "ms-settings:network" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name "MUIVerb" -Type "String" -Value "Personalization" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name "SettingsURI" -Type "String" -Value "ms-settings:themes" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone" -Name "MUIVerb" -Type "String" -Value "Phone" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone" -Name "SettingsURI" -Type "String" -Value "ms-settings:mobile-devices" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy" -Name "MUIVerb" -Type "String" -Value "Privacy" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy" -Name "SettingsURI" -Type "String" -Value "ms-settings:privacy" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search" -Name "MUIVerb" -Type "String" -Value "Search" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search" -Name "SettingsURI" -Type "String" -Value "ms-settings:cortana" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time" -Name "MUIVerb" -Type "String" -Value "Time && Language" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time" -Name "SettingsURI" -Type "String" -Value "ms-settings:dateandtime" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update" -Name "MUIVerb" -Type "String" -Value "Update && Security" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update" -Name "SettingsURI" -Type "String" -Value "ms-settings:windowsupdate" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force

#Add "Open Command Prompt here" to context menus
Set-ACL "HKCR:\Directory\shell\cmd"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\shell\cmd"  reg  ace -ace "n:Administrators"
Set-ACL "HKCR:\Directory\shell\cmd\command"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\shell\cmd\command"  reg  ace -ace "n:Administrators"
Remove-ItemProperty -Path "HKCR\Directory\shell\cmd" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "" -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas\command" -Name "" -Type "String" -Value "cmd.exe /s /k pushd \"%%V\"" -Force
Set-ACL "HKCR:\Directory\Background\shell\cmd"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\Background\shell\cmd"  reg  ace -ace "n:Administrators"
Set-ACL "HKCR:\Directory\Background\shell\cmd\command"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\Background\shell\cmd\command"  reg  ace -ace "n:Administrators"
Remove-ItemProperty -Path "HKCR\Directory\Background\shell\cmd" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "" -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas\command" -Name "" -Type "String" -Value "cmd.exe /s /k pushd \"%%V\"" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "" -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas\command" -Name "" -Type "String" -Value "cmd.exe /s /k pushd \"%%V\"" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "" -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas\command" -Name "" -Type "String" -Value "cmd.exe /s /k pushd \"%%V\"" -Force

# "Open PowerShell window here" from Shift+Right-click context menus
Set-ACL "HKCR:\Directory\shell\Powershell"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\shell\Powershell"  reg  ace -ace "n:Administrators"
Set-ACL "HKCR:\Directory\shell\Powershell\command"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\shell\Powershell\command"  reg  ace -ace "n:Administrators"
Remove-ItemProperty -Path "HKCR\Directory\shell\Powershell" -Force
Set-ACL "HKCR:\Directory\Background\shell\Powershell"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\Background\shell\Powershell"  reg  ace -ace "n:Administrators"
Set-ACL "HKCR:\Directory\Background\shell\Powershell\command"  reg  setowner -ownr "n:Administrators"
Set-ACL "HKCR:\Directory\Background\shell\Powershell\command"  reg  ace -ace "n:Administrators"
Remove-ItemProperty -Path "HKCR\Directory\Background\shell\Powershell" -Force

#Enable Windows Installer in Safe Mode
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSIServer" -Name "" -Type "String" -Value "Service" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer" -Name "" -Type "String" -Value "Service" -Force

#Increase 3 pinned contacts limit on taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "TaskbarCapacity" -Type "DWORD" -Value "999" -Force

#Disable online tips in Settings
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type "DWORD" -Value 0 -Force

#Set "Do this for all current items" checked by default
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "ConfirmationCheckBoxDoForAll" -Type "DWORD" -Value 1 -Force

#Add ".bat" to "New" submenu of Desktop context menu
Set-ItemProperty -Path "HKLM:\Software\Classes\.bat\ShellNew" -Name "NullFile" -Type "String" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\.bat\ShellNew" -Name "ItemName" -Type "ExpandString" -Value "@C:\Windows\System32\acppage.dll,-6002" -Force

#Add ".reg" to "New" submenu of Desktop context menu
Set-ItemProperty -Path "HKLM:\Software\Classes\.reg\ShellNew" -Name "NullFile" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\.reg\ShellNew" -Name "ItemName" -Type "ExpandString" -Value "@C:\WINDOWS\regedit.exe,-309" -Force

#Disable wide context menu
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\FlightedFeatures" -Name "ImmersiveContextMenu" -Type "DWORD" -Value 0 -Force

#Disable Sharing of handwriting data
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force

#Disable Sharing of handwriting error reports
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force

#Disable Inventory Collector
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type "DWORD" -Value 1 -Force

#Disable Camera in login screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\AccessPage\Camera" -Name "CameraEnabled" -Type "DWORD" -Value 0 -Force

#Disable transmission of typing information
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force

#Disable Microsoft conducting experiments with this machine
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Type "DWORD" -Value 0 -Force

#Disable advertisements via Bluetooth
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Type "DWORD" -Value 0 -Force

#Disable Windows Customer Experience Improvement Program
Set-ItemProperty -Path "HKLM:\Software\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value 0 -Force

#Disable syncing of text messages to Microsoft
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Type "DWORD" -Value 0 -Force

#Disable application access to user account information
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type "String" -Value "Deny" -Force

#Disable tracking of application startups
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type "DWORD" -Value 0 -Force

#Disable application access of diagnostic information
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Type "String" -Value "Deny" -Force

#Disable user steps recorder
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type "DWORD" -Value 1 -Force

#Disable telemetry
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value "4" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value "4" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value 0 -Force

#Disable synchronization of all settings to Microsoft
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Type "DWORD" -Value "5" -Force

#Disable Input Personalization
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicyy" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type "DWORD" -Value 0 -Force

#Disable updates for Speech Recognition and Speech Synthesis
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Type "DWORD" -Value 0 -Force

#Disable functionality to locate the system
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value 1 -Force

#Disable peer-to-peer functionality in Windows Update
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type "DWORD" -Value 0 -Force

#Disable ads in File Explorer and OneDrive
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type "DWORD" -Value 0 -Force

#Disable feedback reminders
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force

#Remove Task View button from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type "DWORD" -Value 0 -Force

#Enable clipboard history
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type "DWORD" -Value 1 -Force

#Set OEM logo
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "Logo" -Type "String" -Value "C:\Windows\Custom\logo.bmp" -Force

#Disable Open File security warning
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1806" -Type "DWORD" -Value "00000000" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1806" -Type "DWORD" -Value "00000000" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security" -Name "DisableSecuritySettingsCheck" -Type "DWORD" -Value "00000001" -Force

#Remove "Edit with photos" from context menus
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ActivatableClassId" -Type "String" -Value "App.AppX65n3t4j73ch7cremsjxn7q8bph1ma8jw.mca" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "PackageId" -Type "String" -Value "Microsoft.Windows.Photos_2017.18062.12990.0_x64__8wekyb3d8bbwe" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ContractId" -Type "String" -Value "Windows.File" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "DesiredInitialViewState" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "" -Type "String" -Value "@{Microsoft.Windows.Photos_2017.18062.12990.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.Windows.Photos/Resources/EditWithPhotos}" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ProgrammaticAccessOnly" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit\command" -Name "DelegateExecute" -Type "String" -Value "{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}" -Force

#Remove "Edit with Paint 3D" from context menus
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.png\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.gif\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.tif\Shell\3D Edit" -Force
Remove-ItemProperty -Path "HKLM\Software\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" -Force

#Remove "Include in library" from context menus
Remove-ItemProperty -Path "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" -Force

#Disable Microsoft Edge prelaunching
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowPrelaunch" -Type "DWORD" -Value 0 -Force

#Disable Microsoft Edge tab preloading
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type "DWORD" -Value 0 -Force

#Change active title bar color to black
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "AccentPalette" -Type "Binary" -Value "6B 6B 6B FF 59 59 59 FF 4C 4C 4C FF 3F 3F 3F FF 33 33 33 FF 26 26 26 FF 14 14 14 FF 88 17 98 00" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "StartColorMenu" -Type "DWORD" -Value "4281545523" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "AccentColorMenu" -Type "DWORD" -Value "4278190080" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "AccentColor" -Type "DWORD" -Value "4278190080" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationColor" -Type "DWORD" -Value "3288334336" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationAfterglow" -Type "DWORD" -Value "3288334336" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type "DWORD" -Value 1 -Force

#Change inactive title bar color to grey
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "AccentColorInactive" -Type "DWORD" -Value "4280953386" -Force

#Remove acrylic blur on sign-in screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type "DWORD" -Value 1 -Force

#Disable Some Service 
sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop WMPNetworkSvc
sc stop WSearch

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config remoteRegistry start= disabled
sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config WSearch start= disabled

#SCHEDULED TASKS tweaks 
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable  Not sure if should be disabled, maybe related to S.M.A.R.T.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
#The stubborn task Microsoft\Windows\SettingSync\BackgroundUploadTask can be Disabled using a simple bit change. I use a REG file for that (attached to this post).
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable

#Disable MRU lists (jump lists) of XAML apps in Start Menu 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value "DWORD" -Force

#remove Apps
"Get-AppxPackage *3DBuilder* | remove-AppxPackage"
"Get-AppxPackage *Getstarted* | remove-AppxPackage"
"Get-AppxPackage *WindowsAlarms* | remove-AppxPackage"
"Get-AppxPackage *WindowsCamera* | remove-AppxPackage"
"Get-AppxPackage *bing* | remove-AppxPackage"
"Get-AppxPackage *MicrosoftOfficeHub* | remove-AppxPackage"
"Get-AppxPackage *OneNote* | remove-AppxPackage"
"Get-AppxPackage *zunemusic* | remove-AppxPackage"
"Get-AppxPackage *SkypeApp* | remove-AppxPackage"
"Get-AppxPackage *zunevideo* | remove-AppxPackage"
"Get-AppxPackage *WindowsSoundRecorder* | remove-AppxPackage"
"Get-AppxPackage *windowscommunicationsapps* | remove-AppxPackage"
"Get-AppxPackage *bingnews* | remove-AppxPackage"
"Get-AppxPackage *WindowsCalculator* | remove-AppxPackage"
"Get-AppxPackage *WindowsMaps* | remove-AppxPackage"
"Get-AppxPackage *Sway* | remove-AppxPackage"
"Get-AppxPackage *CommsPhone* | remove-AppxPackage"
"Get-AppxPackage *ConnectivityStore* | remove-AppxPackage"
"Get-AppxPackage *Microsoft.Messaging* | remove-AppxPackage"
"Get-AppxPackage *Facebook* | remove-AppxPackage"
"Get-AppxPackage *Twitter* | remove-AppxPackage"
"Get-AppxPackage *sound recorder* | remove-AppxPackage"
"Get-AppxPackage *bingweather* | remove-AppxPackage"
"Get-AppxPackage *xboxapp* | remove-AppxPackage"
"Get-AppxPackage *Drawboard PDF* | remove-AppxPackage"
"Get-AppxPackage *solitairecollection* | remove-AppxPackage"

#NOW JUST SOME TWEAKS
#Show hidden files in Explorer 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

#Show super hidden system files in Explorer 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

#Show file extensions in Explorer 
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f

#Remove potential bloat
"Get-AppxPackage *Microsoft.3DBuilder* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Appconnector* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingFinance* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingSports* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingTranslator* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.FreshPaint* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.DesktopAppInstaller* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MicrosoftPowerBIForWindows* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MinecraftUWP* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.CommsPhone* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.ConnectivityStore* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingFoodAndDrink* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingTravel* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.BingHealthAndFitness* | Remove-AppxPackage"
"Get-AppxPackage *9E2F88E3.Twitter* | Remove-AppxPackage"
"Get-AppxPackage *PandoraMediaInc.29680B314EFC2* | Remove-AppxPackage"
"Get-AppxPackage *Flipboard.Flipboard* | Remove-AppxPackage"
"Get-AppxPackage *ShazamEntertainmentLtd.Shazam* | Remove-AppxPackage"
"Get-AppxPackage *king.com.CandyCrushSaga* | Remove-AppxPackage"
"Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage"
"Get-AppxPackage *king.com.* | Remove-AppxPackage"
"Get-AppxPackage *ClearChannelRadioDigital.iHeartRadio* | Remove-AppxPackage"
"Get-AppxPackage *4DF9E0F8.Netflix* | Remove-AppxPackage"
"Get-AppxPackage *6Wunderkinder.Wunderlist* | Remove-AppxPackage"
"Get-AppxPackage *Drawboard.DrawboardPDF* | Remove-AppxPackage"
"Get-AppxPackage *22StokedOnIt.NotebookPro* | Remove-AppxPackage"
"Get-AppxPackage *2FE3CB00.PicsArt-PhotoStudio* | Remove-AppxPackage"
"Get-AppxPackage *41038Axilesoft.ACGMediaPlayer* | Remove-AppxPackage"
"Get-AppxPackage *5CB722CC.SeekersNotesMysteriesofDarkwood* | Remove-AppxPackage"
"Get-AppxPackage *7458BE2C.WorldofTanksBlitz* | Remove-AppxPackage"
"Get-AppxPackage *D52A8D61.FarmVille2CountryEscape | Remove-AppxPackage"
"Get-AppxPackage *TuneIn.TuneInRadio* | Remove-AppxPackage"
"Get-AppxPackage *GAMELOFTSA.Asphalt8Airborne* | Remove-AppxPackage"
"Get-AppxPackage *TheNewYorkTimes.NYTCrossword* | Remove-AppxPackage"
"Get-AppxPackage *DB6EA5DB.CyberLinkMediaSuiteEssentials* | Remove-AppxPackage"
"Get-AppxPackage *Facebook.Facebook* | Remove-AppxPackage"
"Get-AppxPackage *flaregamesGmbH.RoyalRevolt2* | Remove-AppxPackage"
"Get-AppxPackage *Playtika.CaesarsSlotsFreeCasino* | Remove-AppxPackage"
"Get-AppxPackage *A278AB0D.MarchofEmpires* | Remove-AppxPackage"
"Get-AppxPackage *KeeperSecurityInc.Keeper* | Remove-AppxPackage"
"Get-AppxPackage *ThumbmunkeysLtd.PhototasticCollage* | Remove-AppxPackage"
"Get-AppxPackage *INGAG.XING* | Remove-AppxPackage"
"Get-AppxPackage *89006A2E.AutodeskSketchBook* | Remove-AppxPackage"
"Get-AppxPackage *D5EA27B7.Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
"Get-AppxPackage *46928bounde.EclipseManager* | Remove-AppxPackage"
"Get-AppxPackage *ActiproSoftwareLLC.562882FEEB49* | Remove-AppxPackage"
"Get-AppxPackage *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage"
"Get-AppxPackage *SpotifyAB.SpotifyMusic* | Remove-AppxPackage"
"Get-AppxPackage *A278AB0D.DisneyMagicKingdoms* | Remove-AppxPackage"
"Get-AppxPackage *WinZipComputing.WinZipUniversal* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.People* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Wallet* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Windows.Photos* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.windowscommunicationsapps* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"
"Get-AppxPackage *828B5831.HiddenCityMysteryofShadows* | Remove-AppxPackage"
"Get-AppxPackage *king.com.BubbleWitch3Saga* | Remove-AppxPackage"
"Get-AppxPackage *Fitbit.FitbitCoach* | Remove-AppxPackage"
"Get-AppxPackage *Facebook.InstagramBeta* | Remove-AppxPackage"
"Get-AppxPackage *Facebook.317180B0BB486* | Remove-AppxPackage"
"Get-AppxPackage *Expedia.ExpediaHotelsFlightsCarsActivities* | Remove-AppxPackage"
"Get-AppxPackage *CAF9E577.Plex* | Remove-AppxPackage"
"Get-AppxPackage *AdobeSystemsIncorporated.PhotoshopElements2018* | Remove-AppxPackage"
"Get-AppxPackage *A278AB0D.DragonManiaLegends* | Remove-AppxPackage"
"Get-AppxPackage *A278AB0D.AsphaltStreetStormRacing* | Remove-AppxPackage"
"Get-AppxPackage *828B5831.TheSecretSociety-HiddenMystery* | Remove-AppxPackage"
"Get-AppxPackage *USATODAY.USATODAY* | Remove-AppxPackage"
"Get-AppxPackage *SiliconBendersLLC.Sketchable* | Remove-AppxPackage"
"Get-AppxPackage *Nordcurrent.CookingFever* | Remove-AppxPackage"
"Get-AppxPackage *NAVER.LINEwin8* | Remove-AppxPackage"
"Get-AppxPackage *microsoft.microsoftskydrive* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.AgeCastles* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage"
"Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage"

#Remove potential bloat for new users
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.DesktopAppInstaller* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.3DBuilder* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Appconnector* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingFinance* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingNews* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingSports* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingTranslator* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingWeather* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.FreshPaint* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.DesktopAppInstaller* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Getstarted* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.GetHelp* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Messaging* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Microsoft3DViewer* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MicrosoftOfficeHub* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MicrosoftPowerBIForWindows* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MicrosoftStickyNotes* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MinecraftUWP* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.NetworkSpeedTest* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WindowsPhone* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.CommsPhone* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.ConnectivityStore* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Office.Sway* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingFoodAndDrink* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingTravel* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.BingHealthAndFitness* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *9E2F88E3.Twitter* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *PandoraMediaInc.29680B314EFC2* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Flipboard.Flipboard* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *ShazamEntertainmentLtd.Shazam* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *king.com.CandyCrushSaga* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *king.com.CandyCrushSodaSaga* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *king.com.* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *ClearChannelRadioDigital.iHeartRadio* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *4DF9E0F8.Netflix* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *6Wunderkinder.Wunderlist* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Drawboard.DrawboardPDF* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *22StokedOnIt.NotebookPro* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *2FE3CB00.PicsArt-PhotoStudio* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *41038Axilesoft.ACGMediaPlayer* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *5CB722CC.SeekersNotesMysteriesofDarkwood* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *7458BE2C.WorldofTanksBlitz* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *D52A8D61.FarmVille2CountryEscape | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *TuneIn.TuneInRadio* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *GAMELOFTSA.Asphalt8Airborne* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *TheNewYorkTimes.NYTCrossword* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *DB6EA5DB.CyberLinkMediaSuiteEssentials* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Facebook.Facebook* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *flaregamesGmbH.RoyalRevolt2* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Playtika.CaesarsSlotsFreeCasino* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *A278AB0D.MarchofEmpires* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *KeeperSecurityInc.Keeper* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *ThumbmunkeysLtd.PhototasticCollage* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *INGAG.XING* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *89006A2E.AutodeskSketchBook* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *D5EA27B7.Duolingo-LearnLanguagesforFree* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *46928bounde.EclipseManager* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *ActiproSoftwareLLC.562882FEEB49* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *DolbyLaboratories.DolbyAccess* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *SpotifyAB.SpotifyMusic* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *A278AB0D.DisneyMagicKingdoms* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *WinZipComputing.WinZipUniversal* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MSPaint* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Office.OneNote* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.OneConnect* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.People* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Print3D* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.SkypeApp* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Wallet* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Windows.Photos* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WindowsAlarms* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WindowsCamera* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.windowscommunicationsapps* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WindowsFeedbackHub* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WindowsMaps* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WindowsSoundRecorder* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.XboxApp* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.Xbox.TCUI* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.ZuneMusic* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.ZuneVideo* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *828B5831.HiddenCityMysteryofShadows* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *king.com.BubbleWitch3Saga* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Fitbit.FitbitCoach* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Facebook.InstagramBeta* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Facebook.317180B0BB486* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Expedia.ExpediaHotelsFlightsCarsActivities* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *CAF9E577.Plex* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *AdobeSystemsIncorporated.PhotoshopElements2018* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *A278AB0D.DragonManiaLegends* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *A278AB0D.AsphaltStreetStormRacing* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *828B5831.TheSecretSociety-HiddenMystery* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *USATODAY.USATODAY* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *SiliconBendersLLC.Sketchable* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Nordcurrent.CookingFever* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *NAVER.LINEwin8* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *microsoft.microsoftskydrive* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.AgeCastles* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.ScreenSketch* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.YourPhone* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.WebMediaExtensions* | Remove-AppxProvisionedPackage -Online"
"Get-AppxProvisionedPackage -Online | where Displayname -EQ *Microsoft.MixedReality.Portal* | Remove-AppxProvisionedPackage -Online"

#Apply Classic Shell settings
cd C:\Program Files\Classic Shell 1>NUL 2>NUL
ClassicStartMenu.exe -xml "C:\Windows\Custom\startmenu.xml" 1>NUL 2>NUL

$path = Test-Path HKCR:\
IF ($path -eq $true) {Remove-PSDrive HKCR} ELSE {Write-Host ""}

#Delete startup shortcut
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\startup.bat" -Force -Confirm:$false

explorer.exe
Write-Warning "A REBOOT IS REQUIRED"
Write-Warning "A REBOOT IS REQUIRED"
Start-Sleep -Seconds 1
    
    Write-Output "Removing CloudStore from registry if it exists"
    $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
    If (Test-Path $CloudStore) {
        Stop-Process -Force Explorer.exe -Force
        Remove-Item $CloudStore -Recurse -Force
        Start-Process Explorer.exe -Wait
    }

    #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
    reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
    Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
    reg unload HKU\Default_User
    
    #Disables scheduled tasks that are considered unnecessary 
    Write-Output "Disabling scheduled tasks"
    #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
    
}

#This includes fixes by xsisbest
Start-Job -Name "FixWhitelistedApps" -ScriptBlock {
    
    If (!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.MSPaint, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.MicrosoftStickyNotes, Microsoft.WindowsSoundRecorder, Microsoft.Windows.Photos)) {
    
        #Credit to abulgatz for the 4 lines of code
        Get-AppxPackage -allusers Microsoft.Paint3D | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        Get-AppxPackage -allusers Microsoft.MSPaint | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        Get-AppxPackage -allusers Microsoft.WindowsCalculator | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        Get-AppxPackage -allusers Microsoft.Windows.Photos | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } 
    }
}

Start-Job -Name "CheckDMWService" -ScriptBlock {
  
    If (Get-Service -Name dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
        Set-Service -Name dmwappushservice -StartupType Automatic
    }

    If (Get-Service -Name dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
        Start-Service -Name dmwappushservice
    } 
}

Start-Job -Name "CheckInstallService" -ScriptBlock {
    If (Get-Service -Name InstallService | Where-Object { $_.Status -eq "Stopped" }) {  
        Start-Service -Name InstallService
        Set-Service -Name InstallService -StartupType Automatic 
    }
}

Start-Job -Name "SSL Hardening" -ScriptBlock {

    #Increase Diffie-Hellman key (DHK) exchange to 4096-bit
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force -Name ServerMinKeyBitLength -Type "DWORD" -Value 0x00001000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force -Name ClientMinKeyBitLength -Type "DWORD" -Value 0x00001000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force -Name Enabled -Type "DWORD" -Value 0x00000001

    #Disable RC2 cipher
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Force 
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Force 
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Force 
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000

    #Disable RC4 cipher
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Force
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Force  
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Force
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Force  
    #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000

    #Disable DES cipher
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56" -Force
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Force  
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Force -Name Enabled -Type "DWORD" -Value 0x00000000

    #Disable 3DES (Triple DES) cipher
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" -Force  
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" -Force -Name Enabled -Type "DWORD" -Value 0x00000000       

    #Disable MD5 hash function
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Force
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Force -Name Enabled -Type "DWORD" -Value 0x00000000

    #Disable SHA1
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force -Name Enabled -Type "DWORD" -Value 0x00000000

    #Disable null cipher
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Force
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Force -Name Enabled -Type "DWORD" -Value 0x00000000

    #Force not to respond to renegotiation requests
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name AllowInsecureRenegoClients -Type "DWORD" -Value 0x00000000
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name AllowInsecureRenegoServers -Type "DWORD" -Value 0x00000000
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name DisableRenegoOnServer -Type "DWORD" -Value 0x00000001
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name UseScsvForTls -Type "DWORD" -Value 0x00000001

    #Disable SSL v2
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"-Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 1

    #Disable SSL v3
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"-Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 1

    #Enable TLS 1.0
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0x00000001

    #Enable DTLS 1.0
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable TLS 1.1
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable DTLS 1.1
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable TLS 1.2
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable TLS 1.3
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable DTLS 1.3
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable Strong Authentication for .NET applications (TLS 1.2)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
}

Start-Job -Name "SMB Optimizations and Hardening" -ScriptBlock {
    #https://docs.microsoft.com/en-us/windows/privacy/
    #https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
    #https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909
    #https://docs.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=win10-ps
    #SMB Optimizations
    Write-Output "SMB Optimizations"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileInfoCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DirectoryCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileNotFoundCacheEntriesMax" -Type "DWORD" -Value 2048 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type "DWORD" -Value 20 -Force
    Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
    Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
    Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force
    Set-SmbServerConfiguration -EnableLeasing $false -Force
    Set-SmbClientConfiguration -EnableLargeMtu $true -Force
    Set-SmbClientConfiguration -EnableMultiChannel $true -Force
    
    #SMB Hardening
    Write-Output "SMB Hardening"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "RestrictAnonymousSAM" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" -Value 256 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Type "DWORD" -Value 1 -Force
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
    Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
    Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
    Set-SmbServerConfiguration -EncryptData $True -Force 
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
}

Start-Job -Name "Remove Windows Bloatware" -ScriptBlock {
    #Removing Windows Bloatware
    Write-Host "Removing Bloatware"
    Write-Host "Removing Bloat Windows Apps"
    $WindowsApps = "*ACGMediaPlayer*", "*ActiproSoftwareLLC*", "*AdobePhotoshopExpress*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*BubbleWitch3Saga*", "*CandyCrush*", "*CommsPhone*", "*ConnectivityStore*", "*Dolby*", "*Duolingo-LearnLanguagesforFree*", "*EclipseManager*", "*Facebook*", "*FarmHeroesSaga*", "*Flipboard*", "*HiddenCity*", "*Hulu*", "*LinkedInforWindows*", "*Microsoft.3dbuilder*", "*Microsoft.549981C3F5F10*", "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*", "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*", "*Microsoft.Appconnector*", "*Microsoft.Asphalt8Airborne*", "*Microsoft.BingNews*", "*Microsoft.BingWeather*", "*Microsoft.DrawboardPDF*", "*Microsoft.GamingApp*", "*Microsoft.GetHelp*", "*Microsoft.Getstarted*", "*Microsoft.MSPaint*", "*Microsoft.Messaging*", "*Microsoft.Microsoft3DViewer*", "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.MicrosoftOfficeOneNote*", "*Microsoft.MicrosoftSolitaireCollection*", "*Microsoft.MicrosoftStickyNotes*", "*Microsoft.MixedReality.Portal*", "*Microsoft.OneConnect*", "*Microsoft.People*", "*Microsoft.Print3D*", "*Microsoft.SkypeApp*", "*Microsoft.Wallet*", "*Microsoft.Whiteboard*", "*Microsoft.WindowsAlarms*", "*Microsoft.WindowsCommunicationsApps*", "*Microsoft.WindowsFeedbackHub*", "*Microsoft.WindowsMaps*", "*Microsoft.WindowsSoundRecorder*", "*Microsoft.YourPhone*", "*Microsoft.ZuneMusic*", "*Microsoft.ZuneVideo*", "*Microsoft3DViewer*", "*MinecraftUWP*", "*Netflix*", "*Office.Sway*", "*OneCalendar*", "*OneNote*", "*PandoraMediaInc*", "*Royal Revolt*", "*Speed Test*", "*Sway*", "*Todos*", "*Twitter*", "*Viber*", "*WindowsScan*", "*Wunderlist*", "*bingsports*", "*empires*", "*spotify*", "*windowsphone*", "*xing*", "2FE3CB00.PicsArt-PhotoStudio", "46928bounde.EclipseManager", "4DF9E0F8.Netflix", "613EBCEA.PolarrPhotoEditorAcademicEdition", "6Wunderkinder.Wunderlist", "7EE7776C.LinkedInforWindows", "89006A2E.AutodeskSketchBook", "9E2F88E3.Twitter", "A278AB0D.DisneyMagicKingdoms", "A278AB0D.MarchofEmpires", "ActiproSoftwareLLC.562882FEEB491", "CAF9E577.Plex", "ClearChannelRadioDigital.iHeartRadio", "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "DolbyLaboratories.DolbyAccess", "Drawboard.DrawboardPDF", "Facebook.Facebook", "Fitbit.FitbitCoach", "Flipboard.Flipboard", "GAMELOFTSA.Asphalt8Airborne", "KeeperSecurityInc.Keeper", "Microsoft.3DBuilder", "Microsoft.549981C3F5F10", "Microsoft.Advertising.Xaml", "Microsoft.AppConnector", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness", "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.CommsPhone", "Microsoft.ConnectivityStore", "Microsoft.GamingServices", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MinecraftUWP", "Microsoft.MixedReality.Portal", "Microsoft.NetworkSpeedTest", "Microsoft.News", "Microsoft.Office.Lens", "Microsoft.Office.OneNote", "Microsoft.Office.Sway", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.Print3D", "Microsoft.ScreenSketch", "Microsoft.SkypeApp", "Microsoft.Wallet", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.WindowsReadingList", "Microsoft.WindowsSoundRecorder", "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft3DViewer", "NORDCURRENT.COOKINGFEVER", "PandoraMediaInc.29680B314EFC2", "Playtika.CaesarsSlotsFreeCasino", "ShazamEntertainmentLtd.Shazam", "SlingTVLLC.SlingTV", "SpotifyAB.SpotifyMusic", "TheNewYorkTimes.NYTCrossword", "ThumbmunkeysLtd.PhototasticCollage", "TuneIn.TuneInRadio", "WinZipComputing.WinZipUniversal", "XINGAG.XING", "flaregamesGmbH.RoyalRevolt2", "king.com.*", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga", "microsoft.windowscommunicationsapps"
    ForEach ($WindowsApp in $WindowsApps) {
        Get-AppxPackage -allusers $WindowsApp | Remove-AppxPackage -AllUsers
        Get-AppXProvisionedPackage -Online | Where-Object DisplayName -eq $WindowsApp | Remove-AppxProvisionedPackage -Online
    }

    #Prevents Apps from re-installing
    $cdm = @(
        "ContentDeliveryAllowed"
        "FeatureManagementEnabled"
        "OemPreInstalledAppsEnabled"
        "PreInstalledAppsEnabled"
        "PreInstalledAppsEverEnabled"
        "SilentInstalledAppsEnabled"
        "SubscribedContent-314559Enabled"
        "SubscribedContent-338387Enabled"
        "SubscribedContent-338388Enabled"
        "SubscribedContent-338389Enabled"
        "SubscribedContent-338393Enabled"
        "SubscribedContentEnabled"
        "SystemPaneSuggestionsEnabled"
    )

    New-Item -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    foreach ($key in $cdm) {
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
    }

    Mkdir -Force  "HKLM:\Software\Policies\Microsoft\WindowsStore"
    Set-ItemProperty "HKLM:\Software\Policies\Microsoft\WindowsStore" "AutoDownload" 2

    #Prevents "Suggested Applications" returning
    New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1


Start-Job -Name "Disable Telemetry and Services" -ScriptBlock {
    #Disabling Telemetry and Services
    Write-Host "Disabling Telemetry and Services"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "Search" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type "String" -Value  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -PropertyType DWord -Value 0 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name "AU" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallTime -Type "DWORD" -Value 3 -Force
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\" -Name "Update" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\" -Name "ExcludeWUDriversInQualityUpdates" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" -Name Value -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name DisableOnline -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name SyncDisabled -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowPrelaunch -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\" -Name "TabPreloader" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name AllowTabPreloading -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "MicrosoftEdge.exe" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft" -Name DoNotUpdateToEdgeWithChromium -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\System\" -Name "GameConfigStore" -Force
    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\CurrentControlSet\" -Name "Control" -Force
    Set-ItemProperty -Path "HKLM:\Software\CurrentControlSet\Control" -Name SvcHostSplitThresholdInKB -Type "DWORD" -Value 04000000 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLm:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
        #Show the "Extract all" item in the Windows Installer (.msi) context menu
    if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
			{
				New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
			}
	$Value = "{0}" -f "msiexec.exe /a `"%1`" /qb TARGETDIR=`"%1 extracted`""
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(default)" -PropertyType String -Value $Value -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-37514" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force
    #Show the "Run as different user" item in the .exe filename extensions context menu
    Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force -ErrorAction Ignore

    #Disable Razer Game Scanner Service
    Stop-Service "Razer Game Scanner Service"
    Set-Service  "Razer Game Scanner Service" -StartupType Disabled

    #Disable Windows Password Reveal Option
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Type "DWORD" -Value 1 -Force
    #Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Force -ErrorAction Ignore
    #Disable PowerShell 7+ Telemetry
    $POWERSHELL_Telemetry_OPTOUT = $true
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_Telemetry_OPTOUT', 1 , [System.EnvironmentVariableTarget]::Machine)
    Write-Host $POWERSHELL_Telemetry_OPTOUT

    #Disable NET Core CLI Telemetry
    $DOTNET_CLI_Telemetry_OPTOUT = $true
    [System.Environment]::SetEnvironmentVariable('DOTNET_CLI_Telemetry_OPTOUT', 1 , [System.EnvironmentVariableTarget]::Machine)
    Write-Host $DOTNET_CLI_Telemetry_OPTOUT

    # Uninstall One Drive
    		[xml]$Uninstall = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process {$_.SwidTagText}
			[xml]$Uninstall = $Uninstall.SoftwareIdentity.InnerXml
			[string]$UninstallString = $Uninstall.Meta.UninstallString
			if ($UninstallString)
			{
				Write-Information -MessageData "" -InformationAction Continue
				Write-Verbose -Message "Uninstalling OneDrive..." -Verbose

				Stop-Process -Name OneDrive -Force -ErrorAction Ignore
				Stop-Process -Name OneDriveSetup -Force -ErrorAction Ignore
				Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore

				# Getting link to the OneDriveSetup.exe and its' argument(s)
				[string[]]$OneDriveSetup = ($UninstallString -Replace("\s*/",",/")).Split(",").Trim()
				if ($OneDriveSetup.Count -eq 2)
				{
					Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..1] -Wait
				}
				else
				{
					Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..2] -Wait
				}

				# Get the OneDrive user folder path and remove it if it doesn't contain any user files
				if (Test-Path -Path $env:OneDrive)
				{
					if ((Get-ChildItem -Path $env:OneDrive -ErrorAction Ignore | Measure-Object).Count -eq 0)
					{
						Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction Ignore

						# https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa
						# The system does not move the file until the operating system is restarted
						# The system moves the file immediately after AUTOCHK is executed, but before creating any paging files
						$Signature = @{
							Namespace        = "WinAPI"
							Name             = "DeleteFiles"
							Language         = "CSharp"
							MemberDefinition = @"
public enum MoveFileFlags
{
	MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
}

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);

public static bool MarkFileDelete (string sourcefile)
{
	return MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
}
"@
						}

						# If there are some files or folders left in %LOCALAPPDATA\Temp%
						if ((Get-ChildItem -Path $env:OneDrive -ErrorAction Ignore | Measure-Object).Count -ne 0)
						{
							if (-not ("WinAPI.DeleteFiles" -as [type]))
							{
								Add-Type @Signature
							}

							try
							{
								Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction Stop
							}
							catch
							{
								# If files are in use remove them at the next boot
								Get-ChildItem -Path $env:OneDrive -Recurse -Force | ForEach-Object -Process {[WinAPI.DeleteFiles]::MarkFileDelete($_.FullName)}
							}
						}
					}
					else
					{
						# Invoke-Item doesn't work
						Start-Process -FilePath explorer -ArgumentList $env:OneDrive
					}
				}

				Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction Ignore
				Remove-Item -Path HKCU:\SOFTWARE\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path $env:SystemDrive\OneDriveTemp -Recurse -Force -ErrorAction Ignore
				Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false

				# Getting the OneDrive folder path
				$OneDriveFolder = Split-Path -Path (Split-Path -Path $OneDriveSetup[0] -Parent)

				# Save all opened folders in order to restore them after File Explorer restarting
				Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
				$OpenedFolders = {(New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process {$_.Document.Folder.Self.Path}}.Invoke()

				# Terminate the File Explorer process
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 0 -Force
				Stop-Process -Name explorer -Force
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 1 -Force

				# Attempt to unregister FileSyncShell64.dll and remove
				$FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\amd64\FileSyncShell64.dll" -Force
				foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName)
				{
					Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
					Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore

					if (Test-Path -Path $FileSyncShell64dll)
					{
						if (-not ("WinAPI.DeleteFiles" -as [type]))
						{
							Add-Type @Signature
						}

						# If files are in use remove them at the next boot
						Get-ChildItem -Path $FileSyncShell64dll -Recurse -Force | ForEach-Object -Process {[WinAPI.DeleteFiles]::MarkFileDelete($_.FullName)}
					}
				}

				Start-Sleep -Seconds 1

				# Start the File Explorer process
				Start-Process -FilePath explorer

				# Restoring closed folders
				foreach ($OpenedFolder in $OpenedFolders)
				{
					if (Test-Path -Path $OpenedFolder)
					{
						# Invoke-Item doesn't work
						Start-Process -FilePath explorer -ArgumentList $OpenedFolder
					}
				}

				Remove-Item -Path $OneDriveFolder -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path $env:LOCALAPPDATA\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Ignore
			}

    #Enable Storage Sense
   	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy))
		{
			New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -ItemType Directory -Force
		}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 1 -Force
 
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

    #Delete temporary files that apps aren't using
    if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1")
		{
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
		}
    
    #Disable hibernation
        Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    #Disable the Windows 260 character path limit
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force
    #Display the Stop error information on the BSoD
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force
    #UAC -Never notify
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force
    #Do not let Windows manage my default printer
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name LegacyDefaultPrinterMode -PropertyType DWord -Value 1 -Force

    #Disable Windows Features
    function WindowsFeatures
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	# Initialize an array list to store the selected Windows features
	$SelectedFeatures = New-Object -TypeName System.Collections.ArrayList($null)

	# The following Windows features will have their checkboxes checked
	[string[]]$CheckedFeatures = @(
		# Legacy Components
		"LegacyComponents",

		# PowerShell 2.0
		"MicrosoftWindowsPowerShellV2",
		"MicrosoftWindowsPowershellV2Root",

		# Microsoft XPS Document Writer
		"Printing-XPSServices-Features",

		# Work Folders Client
		"WorkFolders-Client"
	)

	# The following Windows features will have their checkboxes unchecked
	[string[]]$UncheckedFeatures = @(
		# Media Features
		# If you want to leave "Multimedia settings" in the advanced settings of Power Options do not disable this feature
		"MediaPlayback"
	)

	# The section defines the design of the upcoming dialog box
	[xml]$XAML = '
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
	'
	#endregion XAML Markup

	$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
	$Form = [Windows.Markup.XamlReader]::Load($Reader)
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions
	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Feature = $Features | Where-Object -FilterScript {$_.DisplayName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedFeatures.Add($Feature)
		}
		else
		{
			[void]$SelectedFeatures.Remove($Feature)
		}
		if ($SelectedFeatures.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function DisableButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		[void]$Window.Close()

		$SelectedFeatures | ForEach-Object -Process {Write-Verbose $_.DisplayName -Verbose}
		$SelectedFeatures | Disable-WindowsOptionalFeature -Online -NoRestart
	}

	function EnableButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		[void]$Window.Close()

		$SelectedFeatures | ForEach-Object -Process {Write-Verbose -Message $_.DisplayName -Verbose}
		$SelectedFeatures | Enable-WindowsOptionalFeature -Online -NoRestart
	}

	function Add-FeatureControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Feature
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})
			$CheckBox.ToolTip = $Feature.Description

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Feature.DisplayName
			$TextBlock.ToolTip = $Feature.Description

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			$CheckBox.IsChecked = $true

			# If feature checked add to the array list
			if ($UnCheckedFeatures | Where-Object -FilterScript {$Feature.FeatureName -like $_})
			{
				$CheckBox.IsChecked = $false
				# Exit function if item is not checked
				return
			}

			# If feature checked add to the array list
			[void]$SelectedFeatures.Add($Feature)
		}
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{

			$State = @("Disabled", "DisablePending")
			$ButtonContent = "Enable"
			$ButtonAdd_Click = {EnableButton}
		}
		"Disable"
		{
			$State = @("Enabled", "EnablePending")
			$ButtonContent = "Disable"
			$ButtonAdd_Click = {DisableButton}
		}
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Please wait..." -Verbose

	# Getting list of all optional features according to the conditions
	$OFS = "|"
	$Features = Get-WindowsOptionalFeature -Online | Where-Object -FilterScript {
		($_.State -in $State) -and (($_.FeatureName -match $UncheckedFeatures) -or ($_.FeatureName -match $CheckedFeatures))
	} | ForEach-Object -Process {Get-WindowsOptionalFeature -FeatureName $_.FeatureName -Online}
	$OFS = " "

	if (-not ($Features))
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Nothing to display" -Verbose

		return
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Displaying the dialog box..." -Verbose

	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	$SetForegroundWindow = @{
		Namespace        = "WinAPI"
		Name             = "ForegroundWindow"
		Language         = "CSharp"
		MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
"@
	}

	if (-not ("WinAPI.ForegroundWindow" -as [type]))
	{
		Add-Type @SetForegroundWindow
	}

	Get-Process | Where-Object -FilterScript {$_.MainWindowTitle -match "Windows 10 Bloatware and Security Hardening Script"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Milliseconds 100

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Milliseconds 100

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}

	$Window.Add_Loaded({$Features | Add-FeatureControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = "Windows features"

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
}
    WindowsFeatures -Disable
    # WindowsFeatures -Enable
    #Uninstall optional features

function WindowsCapabilities
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Uninstall"
		)]
		[switch]
		$Uninstall,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Install"
		)]
		[switch]
		$Install
	)

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# Initialize an array list to store the selected optional features
	$SelectedCapabilities = New-Object -TypeName System.Collections.ArrayList($null)

	# The following optional features will have their checkboxes checked
	[string[]]$CheckedCapabilities = @(
		# Steps Recorder
		"App.StepsRecorder*",

		# Microsoft Quick Assist
		"App.Support.QuickAssist*",

		# Microsoft Paint
		"Microsoft.Windows.MSPaint*",

		# WordPad
		"Microsoft.Windows.WordPad*"
	)

	# The following optional features will have their checkboxes unchecked
	[string[]]$UncheckedCapabilities = @(
		# Internet Explorer 11
		"Browser.InternetExplorer*",

		# Math Recognizer
		"MathRecognizer*",

		# Windows Media Player
		"Media.WindowsMediaPlayer*",

		# OpenSSH Client
		"OpenSSH.Client*"
	)

	# The following optional features will be excluded from the display
	[string[]]$ExcludedCapabilities = @(
		# The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
		"DirectX.Configuration.Database*",

		# Language components
		"Language.*",

		# Notepad
		"Microsoft.Windows.Notepad*",

		# Mail, contacts, and calendar sync component
		"OneCoreUAP.OneSync*",

		# Windows PowerShell Intergrated Scripting Enviroment
		"Microsoft.Windows.PowerShell.ISE*",

		# Management of printers, printer drivers, and printer servers
		"Print.Management.Console*",

		# Features critical to Windows functionality
		"Windows.Client.ShellComponents*"
	)
	#endregion Variables

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = '
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
	'
	#endregion XAML Markup

	$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
	$Form = [Windows.Markup.XamlReader]::Load($Reader)
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions
	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Capability = $Capabilities | Where-Object -FilterScript {$_.DisplayName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedCapabilities.Add($Capability)
		}
		else
		{
			[void]$SelectedCapabilities.Remove($Capability)
		}

		if ($SelectedCapabilities.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function UninstallButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		[void]$Window.Close()

		$SelectedCapabilities | ForEach-Object -Process {Write-Verbose -Message $_.DisplayName -Verbose}
		$SelectedCapabilities | Where-Object -FilterScript {$_.Name -in (Get-WindowsCapability -Online).Name} | Remove-WindowsCapability -Online

		if ([string]$SelectedCapabilities.Name -match "Browser.InternetExplorer")
		{
			Write-Information -MessageData "" -InformationAction Continue
			Write-Warning -Message "Make sure to restart your PC"
		}
	}

	function InstallButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		[void]$Window.Close()

		$SelectedCapabilities | ForEach-Object -Process {Write-Verbose -Message $_.DisplayName -Verbose}
		$SelectedCapabilities | Where-Object -FilterScript {$_.Name -in ((Get-WindowsCapability -Online).Name)} | Add-WindowsCapability -Online

		if ([string]$SelectedCapabilities.Name -match "Browser.InternetExplorer")
		{
			Write-Information -MessageData "" -InformationAction Continue
			Write-Warning -Message "Make sure to restart your PC"
		}
	}

	function Add-CapabilityControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Capability
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})
			$CheckBox.ToolTip = $Capability.Description

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Capability.DisplayName
			$TextBlock.ToolTip = $Capability.Description

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			# If capability checked add to the array list
			if ($UnCheckedCapabilities | Where-Object -FilterScript {$Capability.Name -like $_})
			{
				$CheckBox.IsChecked = $false
				# Exit function if item is not checked
				return
			}

			# If capability checked add to the array list
			[void]$SelectedCapabilities.Add($Capability)
		}
	}
	#endregion Functions

	switch ($PSCmdlet.ParameterSetName)
	{
		"Install"
		{
			# Check the internet connection
			try
			{
				(Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription
			}
			catch [System.Net.WebException]
			{
				Write-Warning -Message "No Internet connection"
				Write-Error -Message "No Internet connection" -ErrorAction SilentlyContinue

				Write-Error -Message ("Please re-run the function" -f $MyInvocation.Line) -ErrorAction SilentlyContinue

				return
			}

			$State = "NotPresent"
			$ButtonContent = "Install"
			$ButtonAdd_Click = {InstallButton}
		}
		"Uninstall"
		{
			$State = "Installed"
			$ButtonContent = "Uninstall"
			$ButtonAdd_Click = {UninstallButton}
		}
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Please wait..." -Verbose

	# Getting list of all capabilities according to the conditions
	$OFS = "|"
	$Capabilities = Get-WindowsCapability -Online | Where-Object -FilterScript {
		($_.State -eq $State) -and (($_.Name -match $UncheckedCapabilities) -or ($_.Name -match $CheckedCapabilities) -and ($_.Name -notmatch $ExcludedCapabilities))
	} | ForEach-Object -Process {Get-WindowsCapability -Name $_.Name -Online}
	$OFS = " "

	if (-not ($Capabilities))
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Nothing to display" -Verbose

		return
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Displaying the dialog box..." -Verbose

	#region Sendkey function
	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	$SetForegroundWindow = @{
		Namespace        = "WinAPI"
		Name             = "ForegroundWindow"
		Language         = "CSharp"
		MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
"@
	}

	if (-not ("WinAPI.ForegroundWindow" -as [type]))
	{
		Add-Type @SetForegroundWindow
	}

	Get-Process | Where-Object -FilterScript {$_.MainWindowTitle -match "Windows 10 Bloatware and Security Hardening Script"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Milliseconds 100

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Milliseconds 100

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}
	#endregion Sendkey function

	$Window.Add_Loaded({$Capabilities | Add-CapabilityControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = "Optional features"

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
   }
 }
else {

function WindowsCapabilities
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Uninstall"
		)]
		[switch]
		$Uninstall,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Install"
		)]
		[switch]
		$Install
	)

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# Initialize an array list to store the selected optional features
	$SelectedCapabilities = New-Object -TypeName System.Collections.ArrayList($null)

	# The following optional features will have their checkboxes checked
	[string[]]$CheckedCapabilities = @(
		# Steps Recorder
		"App.StepsRecorder*",

		# Microsoft Quick Assist
		"App.Support.QuickAssist*",

		# Microsoft Paint
		"Microsoft.Windows.MSPaint*",

		# WordPad
		"Microsoft.Windows.WordPad*"
	)

	# The following optional features will have their checkboxes unchecked
	[string[]]$UncheckedCapabilities = @(
		# Internet Explorer 11
		"Browser.InternetExplorer*",

		# Math Recognizer
		"MathRecognizer*",

		# Windows Media Player
		# If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not uninstall this feature
		"Media.WindowsMediaPlayer*",

		# OpenSSH Client
		"OpenSSH.Client*"
	)

	# The following optional features will be excluded from the display
	[string[]]$ExcludedCapabilities = @(
		# The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
		"DirectX.Configuration.Database*",

		# Language components
		"Language.*",

		# Notepad
		"Microsoft.Windows.Notepad*",

		# Mail, contacts, and calendar sync component
		"OneCoreUAP.OneSync*",

		# Windows PowerShell Intergrated Scripting Enviroment
		"Microsoft.Windows.PowerShell.ISE*",

		# Management of printers, printer drivers, and printer servers
		"Print.Management.Console*",

		# Features critical to Windows functionality
		"Windows.Client.ShellComponents*"
	)
	#endregion Variables

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = '
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
	'
	#endregion XAML Markup

	$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
	$Form = [Windows.Markup.XamlReader]::Load($Reader)
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions
	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Capability = $Capabilities | Where-Object -FilterScript {$_.DisplayName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedCapabilities.Add($Capability)
		}
		else
		{
			[void]$SelectedCapabilities.Remove($Capability)
		}

		if ($SelectedCapabilities.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function UninstallButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message $Localization.Patient -Verbose

		[void]$Window.Close()

		$SelectedCapabilities | ForEach-Object -Process {Write-Verbose -Message $_.DisplayName -Verbose}
		$SelectedCapabilities | Where-Object -FilterScript {$_.Name -in (Get-WindowsCapability -Online).Name} | Remove-WindowsCapability -Online

		if ([string]$SelectedCapabilities.Name -match "Browser.InternetExplorer")
		{
			Write-Information -MessageData "" -InformationAction Continue
			Write-Warning -Message $Localization.RestartWarning
		}
	}

	function InstallButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please Wait" -Verbose

		[void]$Window.Close()

		$SelectedCapabilities | ForEach-Object -Process {Write-Verbose -Message $_.DisplayName -Verbose}
		$SelectedCapabilities | Where-Object -FilterScript {$_.Name -in ((Get-WindowsCapability -Online).Name)} | Add-WindowsCapability -Online

		if ([string]$SelectedCapabilities.Name -match "Browser.InternetExplorer")
		{
			Write-Information -MessageData "" -InformationAction Continue
			Write-Warning -Message "Make sure to restart your PC"
		}
	}

	function Add-CapabilityControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Capability
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})
			$CheckBox.ToolTip = $Capability.Description

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Capability.DisplayName
			$TextBlock.ToolTip = $Capability.Description

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			# If capability checked add to the array list
			if ($UnCheckedCapabilities | Where-Object -FilterScript {$Capability.Name -like $_})
			{
				$CheckBox.IsChecked = $false
				# Exit function if item is not checked
				return
			}

			# If capability checked add to the array list
			[void]$SelectedCapabilities.Add($Capability)
		}
	}
	#endregion Functions

	switch ($PSCmdlet.ParameterSetName)
	{
		"Install"
		{
			# Check the internet connection
			try
			{
				(Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription
			}
			catch [System.Net.WebException]
			{
				Write-Warning -Message "No Internet connection"
				Write-Error -Message "No Internet connection" -ErrorAction SilentlyContinue

				Write-Error -Message ("Please re-run the function" -f $MyInvocation.Line) -ErrorAction SilentlyContinue

				return
			}

			$State = "NotPresent"
			$ButtonContent = "Install"
			$ButtonAdd_Click = {InstallButton}
		}
		"Uninstall"
		{
			$State = "Installed"
			$ButtonContent = "Uninstall"
			$ButtonAdd_Click = {UninstallButton}
		}
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Please Wait" -Verbose

	# Getting list of all capabilities according to the conditions
	$OFS = "|"
	$Capabilities = Get-WindowsCapability -Online | Where-Object -FilterScript {
		($_.State -eq $State) -and (($_.Name -match $UncheckedCapabilities) -or ($_.Name -match $CheckedCapabilities) -and ($_.Name -notmatch $ExcludedCapabilities))
	} | ForEach-Object -Process {Get-WindowsCapability -Name $_.Name -Online}
	$OFS = " "

	if (-not ($Capabilities))
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Nothing to display" -Verbose

		return
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Displaying the dialog box" -Verbose

	#region Sendkey function
	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	$SetForegroundWindow = @{
		Namespace        = "WinAPI"
		Name             = "ForegroundWindow"
		Language         = "CSharp"
		MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
"@
	}

	if (-not ("WinAPI.ForegroundWindow" -as [type]))
	{
		Add-Type @SetForegroundWindow
	}

	Get-Process | Where-Object -FilterScript {$_.MainWindowTitle -match "Windows 10 Bloatware and Security Hardening Script"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Milliseconds 100

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Milliseconds 100

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}
	#endregion Sendkey function

	$Window.Add_Loaded({$Capabilities | Add-CapabilityControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = "Optional features"

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
 }
}
    WindowsCapabilities -Uninstall
    # WindowsCapabilities -Install

     #Disable Powershell v2
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart

    #Receive updates for other Microsoft products when you update Windows
    (New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
    #Set power plan to 'High performance'
    POWERCFG /SETACTIVE SCHEME_MIN
    #Use the latest installed .NET runtime for all apps
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
    #Do not allow the computer to turn off the network adapters to save power
    foreach ($Adapter in $Adapters)
		{
			$Adapter.AllowComputerToTurnOffDevice = "Disabled"
			$Adapter | Set-NetAdapterPowerManagement
        }
    #Disable the Internet Protocol Version 6 (TCP/IPv6) component for all network connections
    # Check the internet connection
	try
	{
		if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
		{
			# Check whether the ISP supports IPv6 protocol using https://ipv6-test.com
			$IPv6Test = Invoke-RestMethod -Uri "https://v4v6.ipv6-test.com/api/myip.php?json" | Where-Object -FilterScript {$_.proto -eq "ipv6"}
		}
	}
	catch [System.Net.WebException]
	{
		Write-Warning -Message "No Internet connection"
		Write-Error -Message "No Internet connection" -ErrorAction SilentlyContinue

		Write-Error -Message ("Please re-run the function" -f $MyInvocation.Line) -ErrorAction SilentlyContinue

		return
	}
			if ($null -eq $IPv6Test)
			{
				Disable-NetAdapterBinding –Name * –ComponentID ms_tcpip6
			}
    
    #Save screenshots by pressing Win+PrtScr on the Desktop
 	$DesktopFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}" -Type ExpandString -Value $DesktopFolder -Force
    	# Save all opened folders in order to restore them after File Explorer restart
	Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
	$OpenedFolders = {(New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process {$_.Document.Folder.Self.Path}}.Invoke()

	# In order for the changes to take effect the File Explorer process has to be restarted
	Stop-Process -Name explorer -Force

	Start-Sleep -Seconds 3

	# Restoring closed folders
	foreach ($OpenedFolder in $OpenedFolders)
	{
		if (Test-Path -Path $OpenedFolder)
		{
			Invoke-Item -Path $OpenedFolder
		}
	}

    #RecommendedTroubleshooting -Automatically
    if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation))
			{
				New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 3 -Force
    #Disable and delete reserved storage after the next update installation
    try
			{
				Set-WindowsReservedStorageState -State Disabled
			}
			catch [System.Runtime.InteropServices.COMException]
			{
				Write-Error -Message ("This operation is not supported when reserved storage is in use\nPlease re-run the function again after PC restart" -f $MyInvocation.Line) -ErrorAction SilentlyContinue
			}
    #Disable help lookup via F1
    if (-not (Test-Path -Path "HKCU:\SOFTWARE\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
    	{
			New-Item -Path "HKCU:\SOFTWARE\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
		}
			New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force
    #Enable Num Lock at startup
    New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force
    #Turn off pressing the Shift key 5 times to turn Sticky keys
    New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force
    #Don't use AutoPlay for all media and devices
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force
    #Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
    if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain -eq $false)
		{
			Set-NetFirewallRule -Group $FirewallRules -Profile Private -Enabled True

			Set-NetFirewallRule -Profile Public, Private -Name FPS-SMB-In-TCP -Enabled True
			Set-NetConnectionProfile -NetworkCategory Private
		}
    #Automatically adjust active hours for me based on daily usage
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name SmartActiveHoursState -PropertyType DWord -Value 1 -Force
    #Don't restart this device as soon as possible when a restart is required to install an update
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 0 -Force
    
    #Set a path to a program to associate an extension with
    function Set-Association
{
	[CmdletBinding()]
	Param
	(
		[Parameter(
			Mandatory = $true,
			Position = 0
		)]
		[String]
		$ProgramPath,

		[Parameter(
			Mandatory = $true,
			Position = 1
		)]
		[String]
		$Extension,

		[Parameter(Mandatory = $false)]
		[String]
		$Icon
	)

	$ProgramPath = [System.Environment]::ExpandEnvironmentVariables($ProgramPath)
	$Icon = [System.Environment]::ExpandEnvironmentVariables($Icon)

	if (Test-Path -Path $ProgramPath)
	{
		# Generate ProgId
		$ProgId = (Get-Item -Path $ProgramPath).BaseName + $Extension.ToUpper()
	}
	else
	{
		$ProgId = $ProgramPath
	}

	#region functions
	$RegistryUtils = @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace RegistryUtils
{
	public static class Action
	{
		[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
		private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);

		[DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKey", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
		private static extern int RegQueryInfoKey(UIntPtr hkey, out StringBuilder lpClass, ref uint lpcbClass, IntPtr lpReserved,
			out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen, out uint lpcValues, out uint lpcbMaxValueNameLen,
			out uint lpcbMaxValueLen, out uint lpcbSecurityDescriptor, ref FILETIME lpftLastWriteTime);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern int RegCloseKey(UIntPtr hKey);

		[DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
		private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);

		public static void DeleteKey(RegistryHive registryHive, string subkey) {
			UIntPtr hKey = UIntPtr.Zero;
			var hive = new UIntPtr(unchecked((uint)registryHive));
			RegOpenKeyEx(hive, subkey, 0, 0x20019, out hKey);
			RegDeleteKey(hive, subkey);
		}

		private static DateTime ToDateTime(FILETIME ft)
		{
			IntPtr buf = IntPtr.Zero;
			try
			{
				long[] longArray = new long[1];
				int cb = Marshal.SizeOf(ft);
				buf = Marshal.AllocHGlobal(cb);
				Marshal.StructureToPtr(ft, buf, false);
				Marshal.Copy(buf, longArray, 0, 1);
				return DateTime.FromFileTime(longArray[0]);
			}
			finally
			{
				if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
			}
		}

		public static DateTime? GetLastModified(RegistryHive registryHive, string subKey)
		{
			var lastModified = new FILETIME();
			var lpcbClass = new uint();
			var lpReserved = new IntPtr();
			UIntPtr key = UIntPtr.Zero;

			try
			{
				try
				{
					var hive = new UIntPtr(unchecked((uint)registryHive));
					if (RegOpenKeyEx(hive, subKey, 0, (int)RegistryRights.ReadKey, out key) != 0)
					{
						return null;
					}

					uint lpcbSubKeys;
					uint lpcbMaxKeyLen;
					uint lpcbMaxClassLen;
					uint lpcValues;
					uint maxValueName;
					uint maxValueLen;
					uint securityDescriptor;
					StringBuilder sb;

					if (RegQueryInfoKey(key, out sb, ref lpcbClass, lpReserved, out lpcbSubKeys, out lpcbMaxKeyLen, out lpcbMaxClassLen, out lpcValues, out maxValueName, out maxValueLen, out securityDescriptor, ref lastModified) != 0)
					{
						return null;
					}

					var result = ToDateTime(lastModified);
					return result;
				}
				finally
				{
					if (key != UIntPtr.Zero)
					{
						RegCloseKey(key);
					}
				}
			}
			catch (Exception)
			{
				return null;
			}
		}
	}
}
'@

	if (-not('RegistryUtils.Action' -as [type]))
	{
		Add-Type -TypeDefinition $RegistryUtils
	}

	function Set-Icon
	{
		Param
		(
			[Parameter(
				Mandatory = $true,
				Position = 0

			)]
			[String]
			$ProgId,

			[Parameter(
				Mandatory = $true,
				Position = 1
			)]
			[String]
			$Icon
		)

		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Classes\$ProgId\DefaultIcon"))
		{
			New-Item -Path "HKCU:\SOFTWARE\Classes\$ProgId\DefaultIcon" -Force
		}
		New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$ProgId\DefaultIcon" -Name "(default)" -PropertyType String -Value $Icon -Force
	}

	function Remove-UserChoiceKey
	{
		Param
		(
			[Parameter(
				Mandatory = $true,
				Position = 0
			)]
			[string]
			$SubKey
		)

		[RegistryUtils.Action]::DeleteKey([Microsoft.Win32.RegistryHive]::CurrentUser,$SubKey)
	}

	function Set-UserAccessKey
	{
		Param
		(
			[Parameter(
				Mandatory = $true,
				Position = 0
			)]
			[string]
			$SubKey
		)

		$OpenSubKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKey,'ReadWriteSubTree','TakeOwnership')
		if ($OpenSubKey)
		{
			$Acl = [System.Security.AccessControl.RegistrySecurity]::new()
			# Get current user SID
			$UserSID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
			$Acl.SetSecurityDescriptorSddlForm("O:$UserSID`G:$UserSID`D:AI(D;;DC;;;$UserSID)")
			$OpenSubKey.SetAccessControl($Acl)
			$OpenSubKey.Close()
		}
	}

	function Write-ExtensionKeys
	{
		Param
		(
			[Parameter(
				Mandatory = $true,
				Position = 0
			)]
			[string]
			$ProgId,

			[Parameter(
				Mandatory = $true,
				Position = 1
			)]
			[String]
			$Extension
		)

		$OrigProgID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$Extension" -Name "(default)" -ErrorAction Ignore)."(default)"
		if ($OrigProgID)
		{
			# Save possible ProgIds history with extension
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name "$ProgID_$Extension" -PropertyType DWord -Value 0 -Force
		}

		$Name = "{0}_$Extension" -f (Split-Path -Path $ProgId -Leaf)
		New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name $Name -PropertyType DWord -Value 0 -Force

		if ("$ProgId_$Extension" -ne $Name)
		{
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name "$ProgId_$Extension" -PropertyType DWord -Value 0 -Force
		}

		# If ProgId doesn't exist set the specified ProgId for the extensions
		if (-not $OrigProgID)
		{
			if (-not (Test-Path -Path "HKCU:\SOFTWARE\Classes\$Extension"))
			{
				New-Item -Path "HKCU:\SOFTWARE\Classes\$Extension" -Force
			}
			New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$Extension" -Name "(default)" -PropertyType String -Value $ProgId -Force
		}

		# Set the specified ProgId in the possible options for the assignment
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Classes\$Extension\OpenWithProgids"))
		{
			New-Item -Path "HKCU:\SOFTWARE\Classes\$Extension\OpenWithProgids" -Force
		}
		New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$Extension\OpenWithProgids" -Name $ProgId -PropertyType None -Value ([byte[]]@()) -Force

		# Set the system ProgId to the extension parameters for the File Explorer to the possible options for the assignment, and if absent set the specified ProgId
		if ($OrigProgID)
		{
			if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids"))
			{
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids" -Force
			}
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids" -Name $OrigProgID -PropertyType None -Value ([byte[]]@()) -Force
		}

		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids"))
		{
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids" -Force
		}
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids" -Name $ProgID -PropertyType None -Value ([byte[]]@()) -Force

		# Removing the UserChoice key
		Remove-UserChoiceKey -SubKey "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"

		# Setting parameters in UserChoice. The key is being autocreated
		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"))
		{
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Force
		}
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Name ProgId -PropertyType String -Value $ProgID -Force

		# Getting a hash based on the time of the section's last modification. After creating and setting the first parameter
		$ProgHash = Get-Hash -ProgId $ProgId -Extension $Extension -SubKey "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"

		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"))
		{
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Force
		}
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -Name Hash -PropertyType String -Value $ProgHash -Force

		# Setting a ban on changing the UserChoice section
		Set-UserAccessKey -SubKey "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
	}

	function Write-AdditionalKeys
	{
		Param
		(
			[Parameter(
				Mandatory = $true,
				Position = 0
			)]
			[string]
			$ProgId,

			[Parameter(
				Mandatory = $true,
				Position = 1
			)]
			[string]
			$Extension
		)

		# If there is the system extension ProgId, write it to the already configured by default
		if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$Extension" -Name "(default)" -ErrorAction Ignore)."(default)")
		{
			if (-not (Test-Path -Path Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\FileAssociations\ProgIds))
			{
				New-Item -Path Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\FileAssociations\ProgIds -Force
			}
			New-ItemProperty -Path Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\FileAssociations\ProgIds -Name "_$Extension" -PropertyType DWord -Value 1 -Force
		}

		# Setting 'NoOpenWith' for all registered the extension ProgIDs
		[psobject]$OpenSubkey = Get-Item -Path "Registry::HKEY_CLASSES_ROOT\$Extension\OpenWithProgids" -ErrorAction Ignore | Select-Object -ExpandProperty Property

		if ($OpenSubkey)
		{
			foreach ($AppxProgID in ($OpenSubkey | Where-Object -FilterScript {$_ -match "AppX"}))
			{
				# If an app is installed
				if (Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Classes\$AppxProgID\Shell\open" -Name PackageId)
				{
					# If the specified ProgId is equal to UWP installed ProgId
					if ($ProgId -eq $AppxProgID)
					{
						# Remove association limitations for this UWP apps
						Remove-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$AppxProgID" -Name NoOpenWith -Force -ErrorAction Ignore
						Remove-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$AppxProgID" -Name NoStaticDefaultVerb -Force -ErrorAction Ignore
					}
					else
					{
						New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$AppxProgID" -Name NoOpenWith -PropertyType String -Value "" -Force
					}
				}
			}
		}

		$picture = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\KindMap" -Name $Extension -ErrorAction Ignore).$Extension
		$PBrush = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\PBrush\CLSID" -Name "(default)" -ErrorAction Ignore)."(default)"

		if (($picture -eq "picture") -and $PBrush)
		{
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name "PBrush_$Extension" -PropertyType DWord -Value 0 -Force
		}
	}

	function Get-Hash
	{
		[CmdletBinding()]
		[OutputType([string])]
		Param
		(
			[Parameter(
				Mandatory = $true,
				Position = 0
			)]
			[string]
			$ProgId,

			[Parameter(
				Mandatory = $true,
				Position = 1
			)]
			[string] $Extension,

			[Parameter(
				Mandatory = $true,
				Position = 2
			)]
			[string]
			$SubKey
		)

		$PatentHash = @'
using System;

namespace FileAssoc
{
	public static class PatentHash
	{
		public static uint[] WordSwap(byte[] a, int sz, byte[] md5)
		{
			if (sz < 2 || (sz & 1) == 1) {
				throw new ArgumentException(String.Format("Invalid input size: {0}", sz), "sz");
			}

			unchecked {
				uint o1 = 0;
				uint o2 = 0;
				int ta = 0;
				int ts = sz;
				int ti = ((sz - 2) >> 1) + 1;

				uint c0 = (BitConverter.ToUInt32(md5, 0) | 1) + 0x69FB0000;
				uint c1 = (BitConverter.ToUInt32(md5, 4) | 1) + 0x13DB0000;

				for (uint i = (uint)ti; i > 0; i--) {
					uint n = BitConverter.ToUInt32(a, ta) + o1;
					ta += 8;
					ts -= 2;

					uint v1 = 0x79F8A395 * (n * c0 - 0x10FA9605 * (n >> 16)) + 0x689B6B9F * ((n * c0 - 0x10FA9605 * (n >> 16)) >> 16);
					uint v2 = 0xEA970001 * v1 - 0x3C101569 * (v1 >> 16);
					uint v3 = BitConverter.ToUInt32(a, ta - 4) + v2;
					uint v4 = v3 * c1 - 0x3CE8EC25 * (v3 >> 16);
					uint v5 = 0x59C3AF2D * v4 - 0x2232E0F1 * (v4 >> 16);

					o1 = 0x1EC90001 * v5 + 0x35BD1EC9 * (v5 >> 16);
					o2 += o1 + v2;
				}

				if (ts == 1) {
					uint n = BitConverter.ToUInt32(a, ta) + o1;

					uint v1 = n * c0 - 0x10FA9605 * (n >> 16);
					uint v2 = 0xEA970001 * (0x79F8A395 * v1 + 0x689B6B9F * (v1 >> 16)) - 0x3C101569 * ((0x79F8A395 * v1 + 0x689B6B9F * (v1 >> 16)) >> 16);
					uint v3 = v2 * c1 - 0x3CE8EC25 * (v2 >> 16);

					o1 = 0x1EC90001 * (0x59C3AF2D * v3 - 0x2232E0F1 * (v3 >> 16)) + 0x35BD1EC9 * ((0x59C3AF2D * v3 - 0x2232E0F1 * (v3 >> 16)) >> 16);
					o2 += o1 + v2;
				}

				uint[] ret = new uint[2];
				ret[0] = o1;
				ret[1] = o2;
				return ret;
			}
		}

		public static uint[] Reversible(byte[] a, int sz, byte[] md5)
		{
			if (sz < 2 || (sz & 1) == 1) {
				throw new ArgumentException(String.Format("Invalid input size: {0}", sz), "sz");
			}

			unchecked {
				uint o1 = 0;
				uint o2 = 0;
				int ta = 0;
				int ts = sz;
				int ti = ((sz - 2) >> 1) + 1;

				uint c0 = BitConverter.ToUInt32(md5, 0) | 1;
				uint c1 = BitConverter.ToUInt32(md5, 4) | 1;

				for (uint i = (uint)ti; i > 0; i--) {
					uint n = (BitConverter.ToUInt32(a, ta) + o1) * c0;
					n = 0xB1110000 * n - 0x30674EEF * (n >> 16);
					ta += 8;
					ts -= 2;

					uint v1 = 0x5B9F0000 * n - 0x78F7A461 * (n >> 16);
					uint v2 = 0x1D830000 * (0x12CEB96D * (v1 >> 16) - 0x46930000 * v1) + 0x257E1D83 * ((0x12CEB96D * (v1 >> 16) - 0x46930000 * v1) >> 16);
					uint v3 = BitConverter.ToUInt32(a, ta - 4) + v2;

					uint v4 = 0x16F50000 * c1 * v3 - 0x5D8BE90B * (c1 * v3 >> 16);
					uint v5 = 0x2B890000 * (0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16)) + 0x7C932B89 * ((0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16)) >> 16);

					o1 = 0x9F690000 * v5 - 0x405B6097 * (v5 >> 16);
					o2 += o1 + v2;
				}

				if (ts == 1) {
					uint n = BitConverter.ToUInt32(a, ta) + o1;

					uint v1 = 0xB1110000 * c0 * n - 0x30674EEF * ((c0 * n) >> 16);
					uint v2 = 0x5B9F0000 * v1 - 0x78F7A461 * (v1 >> 16);
					uint v3 = 0x1D830000 * (0x12CEB96D * (v2 >> 16) - 0x46930000 * v2) + 0x257E1D83 * ((0x12CEB96D * (v2 >> 16) - 0x46930000 * v2) >> 16);
					uint v4 = 0x16F50000 * c1 * v3 - 0x5D8BE90B * ((c1 * v3) >> 16);
					uint v5 = 0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16);

					o1 = 0x9F690000 * (0x2B890000 * v5 + 0x7C932B89 * (v5 >> 16)) - 0x405B6097 * ((0x2B890000 * v5 + 0x7C932B89 * (v5 >> 16)) >> 16);
					o2 += o1 + v2;
				}

				uint[] ret = new uint[2];
				ret[0] = o1;
				ret[1] = o2;
				return ret;
			}
		}

		public static long MakeLong(uint left, uint right) {
			return (long)left << 32 | (long)right;
		}
	}
}
'@

		if ( -not ('FileAssoc.PatentHash' -as [type]))
		{
			Add-Type -TypeDefinition $PatentHash
		}

		function Get-KeyLastWriteTime ($SubKey)
		{
			$LM = [RegistryUtils.Action]::GetLastModified([Microsoft.Win32.RegistryHive]::CurrentUser,$SubKey)
			$FT = ([DateTime]::New($LM.Year, $LM.Month, $LM.Day, $LM.Hour, $LM.Minute, 0, $LM.Kind)).ToFileTime()

			return [string]::Format("{0:x8}{1:x8}", $FT -shr 32, $FT -band [uint32]::MaxValue)
		}

		function Get-DataArray
		{
			[OutputType([array])]

			# Secret static string stored in %SystemRoot%\SysWOW64\shell32.dll
			$userExperience        = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
			# Get user SID
			$userSid               = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
			$KeyLastWriteTime      = Get-KeyLastWriteTime -SubKey $SubKey
			$baseInfo              = ("{0}{1}{2}{3}{4}" -f $Extension, $userSid, $ProgId, $KeyLastWriteTime, $userExperience).ToLowerInvariant()
			$StringToUTF16LEArray  = [System.Collections.ArrayList]@([System.Text.Encoding]::Unicode.GetBytes($baseInfo))
			$StringToUTF16LEArray += (0,0)

			return $StringToUTF16LEArray
		}

		function Get-PatentHash
		{
			[OutputType([string])]
			param
			(
				[Parameter(Mandatory = $true)]
				[byte[]]
				$A,

				[Parameter(Mandatory = $true)]
				[byte[]]
				$MD5
			)

			$Size = $A.Count
			$ShiftedSize = ($Size -shr 2) - ($Size -shr 2 -band 1) * 1

			[uint32[]]$A1 = [FileAssoc.PatentHash]::WordSwap($A, [int]$ShiftedSize, $MD5)
			[uint32[]]$A2 = [FileAssoc.PatentHash]::Reversible($A, [int]$ShiftedSize, $MD5)

			$Ret = [FileAssoc.PatentHash]::MakeLong($A1[1] -bxor $A2[1], $A1[0] -bxor $A2[0])

			return [System.Convert]::ToBase64String([System.BitConverter]::GetBytes([Int64]$Ret))
		}

		$DataArray = Get-DataArray
		$DataMD5   = [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash($DataArray)
		$Hash      = Get-PatentHash -A $DataArray -MD5 $DataMD5

		return $Hash
	}
	#endregion functions

	if ($ProgramPath)
	{
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Classes\$ProgId\shell\open\command"))
		{
			New-Item -Path "HKCU:\SOFTWARE\Classes\$ProgId\shell\open\command" -Force
		}
		New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$ProgId\shell\open\command" -Name "(Default)" -PropertyType String -Value "`"$ProgramPath`" `"%1`"" -Force

		$FileNameEXE = Split-Path -Path $ProgramPath -Leaf
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Classes\Applications\$FileNameEXE\shell\open\command"))
		{
			New-Item -Path "HKCU:\SOFTWARE\Classes\Applications\$FileNameEXE\shell\open\command" -Force
		}
		New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Applications\$FileNameEXE\shell\open\command" -Name "(Default)" -PropertyType String -Value "`"$ProgramPath`" `"%1`"" -Force
	}

	if ($Icon)
	{
		Set-Icon -ProgId $ProgId -Icon $Icon
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Please wait..." -Verbose

	# Setting additional parameters to comply with the requirements before configuring the extension
	Write-AdditionalKeys -ProgId $ProgId -Extension $Extension

	# If the file extension specified configure the extension
	Write-ExtensionKeys -ProgId $ProgId -Extension $Extension

	# Refresh the desktop icons
	$UpdateExplorer = @{
		Namespace        = "WinAPI"
		Name             = "UpdateExplorer"
		Language         = "CSharp"
		MemberDefinition = @"
[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

public static void Refresh()
{
	// Update desktop icons
	SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
}
"@
	}
	if (-not ("WinAPI.UpdateExplorer" -as [type]))
	{
		Add-Type @UpdateExplorer
	}

	[WinAPI.UpdateExplorer]::Refresh()
}
	Set-Association -ProgramPath "C:\SumatraPDF.exe" -Extension .pdf -Icon "shell32.dll,100"
	Set-Association -ProgramPath "%ProgramFiles%\Notepad++\notepad++.exe" -Extension .txt -Icon "%ProgramFiles%\Notepad++\notepad++.exe,0"
    # Set-Association -ProgramPath "%ProgramFiles%\Notepad++\notepad++.exe" -Extension .txt -Icon "%ProgramFiles%\Notepad++\notepad++.exe,0"

    #Show recently added apps in the Start menu
    Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -Force -ErrorAction Ignore
    #Show app suggestions in the Start menu
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -PropertyType DWord -Value 1 -Force
    #Run the Windows PowerShell shortcut from the Start menu as Administrator
 	[byte[]]$bytes = Get-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" -AsByteStream -Raw
	$bytes[0x15] = $bytes[0x15] -bor 0x20
	Set-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" -Value $bytes -AsByteStream -Force
	
    # PinToStart -Tiles ControlPanel, DevicesPrinters, PowerShell
		function Add-Tile
		{
			param
			(
				[string]
				$Size,

				[int]
				$Column,

				[int]
				$Row,

				[string]
				$AppID
			)

			[string]$elementName = "start:DesktopApplicationTile"
			[Xml.XmlElement]$Table = $xml.CreateElement($elementName, $StartLayoutNS)
			$Table.SetAttribute("Size", $Size)
			$Table.SetAttribute("Column", $Column)
			$Table.SetAttribute("Row", $Row)
			$Table.SetAttribute("DesktopApplicationID", $AppID)

			$Table
		}

		if (-not (Test-Path -Path $Script:StartLayout))
		{
			# Export the current Start layout
			Export-StartLayout -Path $Script:StartLayout -UseDesktopApplicationID
		}

		[xml]$XML = Get-Content -Path $Script:StartLayout -Encoding UTF8 -Force

	foreach ($Tile in $Tiles)
		{
			switch ($Tile)
			{
				ControlPanel
				{
					$ControlPanel = [WinAPI.GetStr]::GetString(12712)
					Write-Verbose -Message ("The shortcut is being pinned to Start..." -f $ControlPanel) -Verbose
				}
				DevicesPrinters
				{
					Write-Verbose -Message ("The shortcut is being pinned to Start..." -f $DevicesPrinters) -Verbose
				}
				PowerShell
				{
					Write-Verbose -Message ("The shortcut is being pinned to Start..." -f "Windows PowerShell") -Verbose
				}
			}

			$Parameter = $Parameters | Where-Object -FilterScript {$_.Name -eq $Tile}
			$Group = $XML.LayoutModificationTemplate.DefaultLayoutOverride.StartLayoutCollection.StartLayout.Group | Where-Object -FilterScript {$_.Name -eq "ScriptFunct"}

			# If the "ScriptFunct" group exists in Start
			if ($Group)
			{
				$DesktopApplicationID = ($Parameters | Where-Object -FilterScript {$_.Name -eq $Tile}).AppID

				if (-not ($Group.DesktopApplicationTile | Where-Object -FilterScript {$_.DesktopApplicationID -eq $DesktopApplicationID}))
				{
					# Calculate current filled columns
					$CurrentColumns = @($Group.DesktopApplicationTile.Column)
					# Calculate current free columns and take the first one
					$Column = (Compare-Object -ReferenceObject $ValidColumns -DifferenceObject $CurrentColumns).InputObject | Select-Object -First 1
					# If filled cells contain desired ones assign the first free column
					if ($CurrentColumns -contains $Parameter.Column)
					{
						$Parameter.Column = $Column
					}
					$Group.AppendChild((Add-Tile @Parameter)) | Out-Null
				}
			}
			else
			{
				# Create the "ScriptFunct" group
				[Xml.XmlElement]$Group = $XML.CreateElement("start:Group", $StartLayoutNS)
				$Group.SetAttribute("Name","ScriptFunct")
				$Group.AppendChild((Add-Tile @Parameter)) | Out-Null
				$XML.LayoutModificationTemplate.DefaultLayoutOverride.StartLayoutCollection.StartLayout.AppendChild($Group) | Out-Null
			}
		}

		$XML.Save($Script:StartLayout)
	}

	end
	{
		# Temporarily disable changing the Start menu layout
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
		{
			New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -PropertyType DWord -Value 1 -Force
		New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -PropertyType ExpandString -Value $Script:StartLayout -Force

		Start-Sleep -Seconds 3

		# Restart the Start menu
		Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore

		Start-Sleep -Seconds 3

		# Open the Start menu to load the new layout
		$wshell = New-Object -ComObject WScript.Shell
		$wshell.SendKeys("^{ESC}")

		Start-Sleep -Seconds 3

		# Enable changing the Start menu layout
		Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Force -ErrorAction Ignore
		Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Force -ErrorAction Ignore

		Remove-Item -Path $Script:StartLayout -Force

		Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore

		Start-Sleep -Seconds 3

		# Open the Start menu to load the new layout
		$wshell = New-Object -ComObject WScript.Shell
		$wshell.SendKeys("^{ESC}")
	}

    
    #Disable Office Telemetry
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableLogging" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
    #Disable Office Telemetry Agent
    schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
    schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
    schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
    schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
    #Disable Office Subscription Heartbeat
    schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
    schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
    #Disable Office feedback
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    #Disable Office Customer Experience Improvement Program
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force

    #
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type "DWORD" -Value 4 -Force
    Set-Service wlidsvc -StartupType Disabled

    #Disable Visual Studio Code Telemetry
    New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Force
    New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Force
    New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Force
    New-Item -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Force
    New-Item -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type "DWORD" -Value 1 -Force
    Stop-Service "VSStandardCollectorService150"
    Set-Service  "VSStandardCollectorService150" -StartupType Disabled

    #Disable Unnecessary Windows Services
    Stop-Service "MessagingService"
    Set-Service "MessagingService" -StartupType Disabled
    Stop-Service "PimIndexMaintenanceSvc"
    Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled
    Stop-Service "RetailDemo"
    Set-Service "RetailDemo" -StartupType Disabled
    Stop-Service "MapsBroker"
    Set-Service "MapsBroker" -StartupType Disabled
    Stop-Service "wlidsvc"
    Set-Service "wlidsvc" -StartupType Disabled
    Stop-Service "DoSvc"
    Set-Service "DoSvc" -StartupType Disabled
    Stop-Service "OneSyncSvc"
    Set-Service "OneSyncSvc" -StartupType Disabled
    Stop-Service "UnistoreSvc"
    Set-Service "UnistoreSvc" -StartupType Disabled


Start-Job -Name "Enable Privacy and Security Settings" -ScriptBlock {
    #Do not let apps on other devices open and message apps on this device, and vice versa
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 1 -Force
    #Turn off Windows Location Provider
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value "1" -Force

function ScheduledTasks
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# Initialize an array list to store the selected scheduled tasks
	$SelectedTasks = New-Object -TypeName System.Collections.ArrayList($null)

	# The following tasks will have their checkboxes checked
	[string[]]$CheckedScheduledTasks = @(
		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
		"ProgramDataUpdater",

		# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
		"Proxy",

		# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
		"Consolidator",

		# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft
		"UsbCeip",

		# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
		"Microsoft-Windows-DiskDiagnosticDataCollector",

		# This task shows various Map related toasts
		"MapsToastTask",

		# This task checks for updates to maps which you have downloaded for offline use
		"MapsUpdateTask",

		# Initializes Family Safety monitoring and enforcement
		"FamilySafetyMonitor",

		# Synchronizes the latest settings with the Microsoft family features service
		"FamilySafetyRefreshTask",

		# XblGameSave Standby Task
		"XblGameSaveTask"
	)

	# Check if device has a camera
	$DeviceHasCamera = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object -FilterScript {(($_.PNPClass -eq "Camera") -or ($_.PNPClass -eq "Image")) -and ($_.Service -ne "StillCam")}
	if (-not $DeviceHasCamera)
	{
		# Windows Hello
		$CheckedScheduledTasks += "FODCleanupTask"
	}
	#endregion Variables

	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = '
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="450" MinWidth="400"
		SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 10, 5, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="5, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<ScrollViewer Name="Scroll" Grid.Row="0"
				HorizontalScrollBarVisibility="Disabled"
				VerticalScrollBarVisibility="Auto">
				<StackPanel Name="PanelContainer" Orientation="Vertical"/>
			</ScrollViewer>
			<Button Name="Button" Grid.Row="2"/>
		</Grid>
	</Window>
	'
	#endregion XAML Markup

	$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
	$Form = [Windows.Markup.XamlReader]::Load($Reader)
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	#region Functions
	function Get-CheckboxClicked
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$CheckBox
		)

		$Task = $Tasks | Where-Object -FilterScript {$_.TaskName -eq $CheckBox.Parent.Children[1].Text}

		if ($CheckBox.IsChecked)
		{
			[void]$SelectedTasks.Add($Task)
		}
		else
		{
			[void]$SelectedTasks.Remove($Task)
		}

		if ($SelectedTasks.Count -gt 0)
		{
			$Button.IsEnabled = $true
		}
		else
		{
			$Button.IsEnabled = $false
		}
	}

	function DisableButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		[void]$Window.Close()

		$SelectedTasks | ForEach-Object -Process {Write-Verbose $_.TaskName -Verbose}
		$SelectedTasks | Disable-ScheduledTask
	}

	function EnableButton
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		[void]$Window.Close()

		$SelectedTasks | ForEach-Object -Process {Write-Verbose $_.TaskName -Verbose}
		$SelectedTasks | Enable-ScheduledTask
	}

	function Add-TaskControl
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			$Task
		)

		process
		{
			$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
			$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})

			$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
			$TextBlock.Text = $Task.TaskName

			$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
			[void]$StackPanel.Children.Add($CheckBox)
			[void]$StackPanel.Children.Add($TextBlock)
			[void]$PanelContainer.Children.Add($StackPanel)

			# If task checked add to the array list
			if ($CheckedScheduledTasks | Where-Object -FilterScript {$Task.TaskName -match $_})
			{
				[void]$SelectedTasks.Add($Task)
			}
			else
			{
				$CheckBox.IsChecked = $false
			}
		}
	}
	#endregion Functions

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{

			$State = "Disabled"
			$ButtonContent = "Enable"
			$ButtonAdd_Click = {EnableButton}
		}
		"Disable"
		{
			$State = "Ready"
			$ButtonContent = "Disable"
			$ButtonAdd_Click = {DisableButton}
		}
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Please wait..." -Verbose

	# Getting list of all scheduled tasks according to the conditions
	$Tasks = Get-ScheduledTask | Where-Object -FilterScript {($_.State -eq $State) -and ($_.TaskName -in $CheckedScheduledTasks)}

	if (-not ($Tasks))
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Nothing to display" -Verbose

		return
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Displaying the dialog box..." -Verbose

	#region Sendkey function
	# Emulate the Backspace key sending to prevent the console window to freeze
	Start-Sleep -Milliseconds 500

	Add-Type -AssemblyName System.Windows.Forms

	$SetForegroundWindow = @{
		Namespace        = "WinAPI"
		Name             = "ForegroundWindow"
		Language         = "CSharp"
		MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
"@
	}

	if (-not ("WinAPI.ForegroundWindow" -as [type]))
	{
		Add-Type @SetForegroundWindow
	}

	Get-Process | Where-Object -FilterScript {$_.MainWindowTitle -match "Windows 10 Bloatware and Security Hardening Script"} | ForEach-Object -Process {
		# Show window, if minimized
		[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

		Start-Sleep -Milliseconds 100

		# Force move the console window to the foreground
		[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

		Start-Sleep -Milliseconds 100

		# Emulate the Backspace key sending
		[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
	}
	#endregion Sendkey function

	$Window.Add_Loaded({$Tasks | Add-TaskControl})
	$Button.Content = $ButtonContent
	$Button.Add_Click({& $ButtonAdd_Click})

	$Window.Title = "Scheduled tasks"

	# Force move the WPF form to the foreground
	$Window.Add_Loaded({$Window.Activate()})
	$Form.ShowDialog() | Out-Null
}

    #Turn off location scripting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value "1" -Force
    #Turn off location
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value "1" -Type "DWORD" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value "0" -Type "DWORD" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Type "String" -Value "Deny" -Force
    #Deny app access to location
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value "0" -Type "DWORD" -Force
    #Deny app access to motion data
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -Type "DWORD" -Value 2 -Force
    #Deny app access to phone
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type "DWORD" -Value 2 -Force
    #Deny app access to trusted devices
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -Type "DWORD" -Value 2 -Force
    #Deny app sync with devices (unpaired, beacons, TVs etc.)
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type "DWORD" -Value 2 -Force
    #Deny app access to diagnostics info about your other apps
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -Type "String" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type "DWORD" -Value 2 -Force
    #Deny app access to your contacts
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type "DWORD" -Value 2 -Force
    #Deny app access to Notifications
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type "DWORD" -Value 2 -Force
    #Deny app access to Calendar
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type "DWORD" -Value 2 -Force
    #Deny app access to call history
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type "DWORD" -Value 2 -Force
    #Deny app access to email
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type "DWORD" -Value 2 -Force
    #Deny app access to tasks
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Value "Deny" -Type "String" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type "DWORD" -Value 2 -Force
    #Deny app access to messaging (SMS / MMS)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Type "String" -Name "Value" -Value "DENY" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type "DWORD" -Value 2 -Force
    #Deny app access to radios
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Value "Deny" -Type "String" -Force
    #For older Windows (before 1903)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Type "String" -Name "Value" -Value "DENY" -Force
    #Using GPO (re-activation through GUI is not possible)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type "DWORD" -Value 2 -Force
    #Deny app access to bluetooth devices
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Value "Deny" -Type "String" -Force
    #Disable device metadata retrieval (breaks auto updates)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
    #Do not include drivers with Windows Updates
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type "DWORD" -Value 1 -Force
    #Prevent Windows Update for device driver search
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type "DWORD" -Value 0 -Force
    #Disable Customer Experience Improvement (CEIP/SQM)
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value "0" -Force
    #Disable Application Impact Telemetry (AIT)
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value "0" -Force  
    #Disable Sign-in info - The sign-in info to automatically finish setting up device and reopen apps after an update or restart
	$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID"))
		{
		    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force
		}
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force
     #AdvertisingID - The permission for apps to use advertising ID
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo))
		{
			New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force
     #Windows Welcome Experience - The Windows welcome experiences after updates
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 0 -Force
     #Show folder merge conflicts
	    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 1 -Force
     #Open File Explorer to "This PC"
	    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force
     #Show the file transfer dialog box in the detailed mode
	    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
		{
		   New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force
     #Expand the File Explorer ribbon
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon))
		{
			New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -PropertyType DWord -Value 0 -Force
     #Display the recycle bin files delete confirmation dialog
     $ShellState[4] = 51
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState -PropertyType Binary -Value $ShellState -Force
     #Hide the "3D Objects" folder in "This PC" and Quick access
	   	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"))
		{
	    	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force
		}
			New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name ThisPCPolicy -PropertyType String -Value Hide -Force
     #View the Control Panel icons by category
  		if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
		{
			New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 0 -Force
    #Set the default Windows and App mode to dark
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -PropertyType DWord -Value 0 -Force
    #Hide the "New App Installed" indicator
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
			{
				New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -PropertyType DWord -Value 1 -Force
    #Disable first sign-in animation after the upgrade
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force
    #Disable diagnostics telemetry
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
    Stop-Service "dmwappushservice"
    Set-Service "dmwappushservice" -StartupType Disabled
    Stop-Service "diagnosticshub.standardcollector.service"
    Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled
    Stop-Service "diagsvc"
    Set-Service "diagsvc" -StartupType Disabled
    Get-NetFirewallRule -Group DiagTrack | Set-NetFirewallRule -Enabled False -Action Block
    #Disable Customer Experience Improvement Program
    schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
    schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
    schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
    #Disable Webcam Telemetry (devicecensus.exe)
    schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
    # Disable Application Experience (Compatibility Telemetry)
    schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
    #Disable telemetry in data collection policy
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
    #Disable license telemetry
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type "DWORD" -Value "1" -Force
    #Disable error reporting
    #Disable Windows Error Reporting (WER)
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
    #DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Type "DWORD" -Value "0" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultOverrideBehavior" -Type "DWORD" -Value "1" -Force
    #Disable WER sending second-level data
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type "DWORD" -Value "1" -Force
    #Disable WER crash dialogs, popups
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type "DWORD" -Value "1" -Force
    schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
    schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
    #Disable Windows Error Reporting Service
    Stop-Service "WerSvc" 
    Set-Service "WerSvc" -StartupType Disabled
    Stop-Service "wercplsupport" 
    Set-Service "wercplsupport" -StartupType Disabled
    #Hide the Meet Now icon
 	$Settings = Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -ErrorAction Ignore
	$Settings[9] = 128
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -PropertyType Binary -Value $Settings -Force
 	# Save all opened folders in order to restore them after File Explorer restart
	Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
	$OpenedFolders = {(New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process {$_.Document.Folder.Self.Path}}.Invoke()
	Stop-Process -Name explorer -Force
	Start-Sleep -Seconds 3
	# Restoring closed folders
	foreach ($OpenedFolder in $OpenedFolders)
	{
		if (Test-Path -Path $OpenedFolder)
		{
			Invoke-Item -Path $OpenedFolder
		}
	}
 #Disable "News and Interests" on the taskbar
 		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -PropertyType DWord -Value 2 -Force
 #Unpin Taskbar Shortcuts -Shortcuts Edge, Store, Mail
 	# Extract strings from shell32.dll using its' number
	$Signature = @{
		Namespace        = "WinAPI"
		Name             = "GetStr"
		Language         = "CSharp"
		MemberDefinition = @"
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
"@
	}
	if (-not ("WinAPI.GetStr" -as [type]))
	{
		Add-Type @Signature -Using System.Text
	}

	# Extract the localized "Unpin from taskbar" string from shell32.dll
	$LocalizedString = [WinAPI.GetStr]::GetString(5387)

	foreach ($Shortcut in $Shortcuts)
	{
		switch ($Shortcut)
		{
			Edge
			{
				if (Test-Path -Path "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk")
				{
					# Call the shortcut context menu item
					$Shell = (New-Object -ComObject Shell.Application).NameSpace("$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
					$Shortcut = $Shell.ParseName("Microsoft Edge.lnk")
					$Shortcut.Verbs() | Where-Object -FilterScript {$_.Name -eq $LocalizedString} | ForEach-Object -Process {$_.DoIt()}
				}
			}
			Store
			{
				# Start-Job is used due to that the calling this function before UninstallUWPApps breaks the retrieval of the localized UWP apps packages names
				Start-Job -ScriptBlock {
					$Apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
					($Apps | Where-Object -FilterScript {$_.Name -eq "Microsoft Store"}).Verbs() | Where-Object -FilterScript {$_.Name -eq $Using:LocalizedString} | ForEach-Object -Process {$_.DoIt()}
				} | Receive-Job -Wait -AutoRemoveJob
			}
			Mail
			{
				# Start-Job is used due to that the calling this function before UninstallUWPApps breaks the retrieval of the localized UWP apps packages names
				if (Get-AppxPackage -Name microsoft.windowscommunicationsapps)
				{
					Start-Job -ScriptBlock {
						$Apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
						($Apps | Where-Object -FilterScript {$_.Path -eq "microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"}).Verbs() | Where-Object -FilterScript {$_.Name -eq $Using:LocalizedString} | ForEach-Object -Process {$_.DoIt()}
					} | Receive-Job -Wait -AutoRemoveJob
				}
			}
		}
	}

    #Disable all settings sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Type "DWORD" -Value 5 -Force
    #Disable Application Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable App Sync Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable App Sync Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable Desktop Theme Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable Personalization Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable Start Layout Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable Windows Setting Sync
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
    #Disable ad customization with Advertising ID
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type "DWORD" -Value 1 -Force
    #Disable targeted tips
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value "1" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value "1" -Force
    #Turn Off Suggested Content in Settings app
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType "DWord" -Value "0" -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType "DWord" -Value "0" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value "0" -Type "DWORD" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value "0" -Type "DWORD" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value "0" -Type "DWORD" -Force
    #Disable cortana
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent"  -Value 0 -Type "DWORD" -Force 
    #Disable web search in search bar
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type "DWORD" -Force                   
    #Disable search web when searching pc
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type "DWORD" -Value 0 -Force
    #Disable search indexing encrypted items / stores
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowIndexingEncryptedStoresOrItems -Type "DWORD" -Value 0 -Force
    #Disable location based info in searches
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type "DWORD" -Value 0 -Force
    #Disable language detection
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AlwaysUseAutoLangDetection -Type "DWORD" -Value 0 -Force
    #Opt out from Windows privacy consent
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type "DWORD" -Value 0 -Force
    #Disable cloud speech recognation
    New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type "DWORD" -Value 0 -Force
    #Disable text and handwriting collection
    New-Item -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type "DWORD" -Value 0 -Force
    #Disable Windows feedback
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force 
    reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
    #Disable Wi-Fi sense
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type "DWORD" -Value 0 -Force 
    #Disable App Launch Tracking
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type "DWORD" -Force
    #Disable Activity Feed
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value "0" -Type "DWORD" -Force
    #Disable feedback on write (sending typing info)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    #Disable Windows DRM internet access
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
    #Disable game screen recording
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "DWORD" -Value 0 -Force
    #Disable Auto Downloading Maps
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type "DWORD" -Value 0 -Force
    #Disable Website Access of Language List
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type "DWORD" -Value 1 -Force
    #Disable Inventory Collector
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type "DWORD" -Value 1 -Force
    #Do not send Watson events
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericReports" -Type "DWORD" -Value 1 -Force
    #Disable Malicious Software Reporting tool diagnostic data
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type "DWORD" -Value 1 -Force
    #Disable local setting override for reporting to Microsoft MAPS
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type "DWORD" -Value 0 -Force
    #Turn off Windows Defender SpyNet reporting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type "DWORD" -Value 0 -Force
    #Enable Microsoft Defender Exploit Guard network protection
    if ((Get-MpComputerStatus).AntivirusEnabled -eq $true)
			{
	        	Set-MpPreference -EnableNetworkProtection Enabled
		}
}
    #Enable sandboxing for Microsoft Defender
    		{
			if ((Get-MpComputerStatus).AntivirusEnabled -eq $true)
			{
				setx /M MP_FORCE_USE_SANDBOX 1
			}
    #Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -PropertyType DWord -Value 1 -Force
    #Disable events auditing generated when a process is created (starts)
    auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
    #Enable detection for potentially unwanted applications and block them
    if ((Get-MpComputerStatus).AntivirusEnabled -eq $true)
			{
				Set-MpPreference -PUAProtection Enabled
			}
    #Do not send file samples for further analysis
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type "DWORD" -Value 2 -Force
    #Disable live tile data collection
    New-Item -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventLiveTileDataCollection" -Type "DWORD" -Value 1 -Force
    #Disable MFU tracking
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Type "DWORD" -Value 1 -Force
    #Turn off backtracking
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -Type "DWORD" -Value 1 -Force
    #Disable Search Suggestions in Edge
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type "DWORD" -Value 0 -Force
    #Disable Geolocation in Internet Explorer
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type "DWORD" -Value 1 -Force
    #Disable Internet Explorer InPrivate logging
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type "DWORD" -Value 1 -Force
    #Disable Internet Explorer CEIP
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type "DWORD" -Value 0 -Force
    #Disable calling legacy WCM policies
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CallLegacyWCMPolicies" -Type "DWORD" -Value 0 -Force
    #Do not send Windows Media Player statistics
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type "DWORD" -Value 0 -Force
    #Disable metadata retrieval
    New-Item -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"  -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
    #Disable dows Media Player Network Sharing Service
    Stop-Service "WMPNetworkSvc" 
    Set-Service "WMPNetworkSvc" -StartupType Disabled
    #Disable lock screen camera
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type "DWORD" -Value 1 -Force
    #Disable remote Assistance
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type "DWORD" -Value 0 -Force
    #Disable AutoPlay and AutoRun
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "DWORD" -Value 255 -Force 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Type "DWORD" -Value 1 -Force
    #Disable Windows Installer Always install with elevated privileges
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Type "DWORD" -Value 0 -Force
    #Refuse less secure authentication
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Type "DWORD" -Value 5 -Force
    #Disable the Windows Connect Now wizard
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Type "DWORD" -Value 0 -Force
    #Disable online tips
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type "DWORD" -Value 0 -Force
    #Turn off Internet File Association service
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Type "DWORD" -Value 1 -Force
    #Turn off the "Order Prints" picture task
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Type "DWORD" -Value 1 -Force
    #Disable the file and folder Publish to Web option
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Type "DWORD" -Value 1 -Force
    #Prevent downloading a list of providers for wizards
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Type "DWORD" -Value 1 -Force
    #Do not keep history of recently opened documents
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type "DWORD" -Value 1 -Force
    #Clear history of recently opened documents on exit
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type "DWORD" -Value 1 -Force
    #Disable lock screen app notifications
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Type "DWORD" -Value 1 -Force
    #Show frequently used folders in Quick access
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -PropertyType DWord -Value 1 -Force
    #Show Task View Button
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
    #Hide People Button on the taskbar
			if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People))
			{
				New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Force
			}
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -PropertyType DWord -Value 0 -Force
    #Hide the search on the taskbar
   	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
    #UnpinTaskbarShortcuts -Shortcuts Edge, Store, Mail
    function UnpinTaskbarShortcuts
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet("Edge", "Store", "Mail")]
		[string[]]
		$Shortcuts
	)

	# Extract strings from shell32.dll using its' number
	$Signature = @{
		Namespace        = "WinAPI"
		Name             = "GetStr"
		Language         = "CSharp"
		MemberDefinition = @"
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
"@
	}
	if (-not ("WinAPI.GetStr" -as [type]))
	{
		Add-Type @Signature -Using System.Text
	}

	# Extract the localized "Unpin from taskbar" string from shell32.dll
	$LocalizedString = [WinAPI.GetStr]::GetString(5387)

	foreach ($Shortcut in $Shortcuts)
	{
		switch ($Shortcut)
		{
			Edge
			{
				if (Test-Path -Path "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk")
				{
					# Call the shortcut context menu item
					$Shell = (New-Object -ComObject Shell.Application).NameSpace("$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
					$Shortcut = $Shell.ParseName("Microsoft Edge.lnk")
					$Shortcut.Verbs() | Where-Object -FilterScript {$_.Name -eq $LocalizedString} | ForEach-Object -Process {$_.DoIt()}
				}
			}
			Store
			{
				# Start-Job is used due to that the calling this function before UninstallUWPApps breaks the retrieval of the localized UWP apps packages names
				Start-Job -ScriptBlock {
					$Apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
					($Apps | Where-Object -FilterScript {$_.Name -eq "Microsoft Store"}).Verbs() | Where-Object -FilterScript {$_.Name -eq $Using:LocalizedString} | ForEach-Object -Process {$_.DoIt()}
				} | Receive-Job -Wait -AutoRemoveJob
			}
			Mail
			{
				# Start-Job is used due to that the calling this function before UninstallUWPApps breaks the retrieval of the localized UWP apps packages names
				if (Get-AppxPackage -Name microsoft.windowscommunicationsapps)
				{
					Start-Job -ScriptBlock {
						$Apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
						($Apps | Where-Object -FilterScript {$_.Path -eq "microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"}).Verbs() | Where-Object -FilterScript {$_.Name -eq $Using:LocalizedString} | ForEach-Object -Process {$_.DoIt()}
					} | Receive-Job -Wait -AutoRemoveJob
				}
			}
		}
	}
}


function UninstallUWPApps
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[switch]
		$ForAllUsers
	)

	Add-Type -AssemblyName PresentationCore, PresentationFramework

	#region Variables
	# The following UWP apps will have their checkboxes unchecked
	$UncheckedAppxPackages = @(
		# AMD Radeon UWP panel
		"AdvancedMicroDevicesInc*",

		# Intel Graphics Control Center
		"AppUp.IntelGraphicsControlPanel",
		"AppUp.IntelGraphicsExperience",

		# Sticky Notes
		"Microsoft.MicrosoftStickyNotes",

		# Screen Sketch
		"Microsoft.ScreenSketch",

		# Photos (and Video Editor)
		"Microsoft.Windows.Photos",
		"Microsoft.Photos.MediaEngineDLC",

		# HEVC Video Extensions from Device Manufacturer
		"Microsoft.HEVCVideoExtension",

		# Calculator
		"Microsoft.WindowsCalculator",

		# Windows Camera
		"Microsoft.WindowsCamera",

		# Xbox Identity Provider
		"Microsoft.XboxIdentityProvider",

		# Xbox Console Companion
		# Компаньон консоли Xbox
		"Microsoft.XboxApp",

		# Xbox
		"Microsoft.GamingApp",
		"Microsoft.GamingServices",

		# Xbox TCUI
		"Microsoft.Xbox.TCUI",

		# Xbox Speech To Text Overlay
		"Microsoft.XboxSpeechToTextOverlay",

		# Xbox Game Bar
		"Microsoft.XboxGamingOverlay",

		# Xbox Game Bar Plugin
		"Microsoft.XboxGameOverlay",

		# NVIDIA Control Panel
		"NVIDIACorp.NVIDIAControlPanel",

		# Realtek Audio Console
		"RealtekSemiconductorCorp.RealtekAudioControl"
	)

	# The following UWP apps will be excluded from the display
	$ExcludedAppxPackages = @(
		# Microsoft Desktop App Installer
		"Microsoft.DesktopAppInstaller",

		# Store Experience Host
			"Microsoft.StorePurchaseApp",

		# Microsoft Store
		"Microsoft.WindowsStore",

		# Windows Terminal
		"Microsoft.WindowsTerminal",
		"Microsoft.WindowsTerminalPreview",

		# Web Media Extensions
		"Microsoft.WebMediaExtensions"
	)

	#region Variables
	#region XAML Markup
	# The section defines the design of the upcoming dialog box
	[xml]$XAML = '
	<Window
		xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Name="Window"
		MinHeight="400" MinWidth="415"
		SizeToContent="Width" WindowStartupLocation="CenterScreen"
		TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
		FontFamily="Candara" FontSize="16" ShowInTaskbar="True"
		Background="#F1F1F1" Foreground="#262626">
		<Window.Resources>
			<Style TargetType="StackPanel">
				<Setter Property="Orientation" Value="Horizontal"/>
				<Setter Property="VerticalAlignment" Value="Top"/>
			</Style>
			<Style TargetType="CheckBox">
				<Setter Property="Margin" Value="10, 13, 10, 10"/>
				<Setter Property="IsChecked" Value="True"/>
			</Style>
			<Style TargetType="TextBlock">
				<Setter Property="Margin" Value="0, 10, 10, 10"/>
			</Style>
			<Style TargetType="Button">
				<Setter Property="Margin" Value="20"/>
				<Setter Property="Padding" Value="10"/>
				<Setter Property="IsEnabled" Value="False"/>
			</Style>
			<Style TargetType="Border">
				<Setter Property="Grid.Row" Value="1"/>
				<Setter Property="CornerRadius" Value="0"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
				<Setter Property="BorderBrush" Value="#000000"/>
			</Style>
			<Style TargetType="ScrollViewer">
				<Setter Property="HorizontalScrollBarVisibility" Value="Disabled"/>
				<Setter Property="BorderBrush" Value="#000000"/>
				<Setter Property="BorderThickness" Value="0, 1, 0, 1"/>
			</Style>
		</Window.Resources>
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="Auto"/>
				<RowDefinition Height="*"/>
				<RowDefinition Height="Auto"/>
			</Grid.RowDefinitions>
			<Grid Grid.Row="0">
				<Grid.ColumnDefinitions>
					<ColumnDefinition Width="*"/>
					<ColumnDefinition Width="*"/>
				</Grid.ColumnDefinitions>
				<StackPanel Name="PanelSelectAll" Grid.Column="0" HorizontalAlignment="Left">
					<CheckBox Name="CheckBoxSelectAll" IsChecked="False"/>
					<TextBlock Name="TextBlockSelectAll" Margin="10,10, 0, 10"/>
				</StackPanel>
				<StackPanel Name="PanelRemoveForAll" Grid.Column="1" HorizontalAlignment="Right">
					<TextBlock Name="TextBlockRemoveForAll" Margin="10,10, 0, 10"/>
					<CheckBox Name="CheckBoxForAllUsers" IsChecked="False"/>
				</StackPanel>
			</Grid>
			<Border>
				<ScrollViewer>
					<StackPanel Name="PanelContainer" Orientation="Vertical"/>
				</ScrollViewer>
			</Border>
			<Button Name="ButtonUninstall" Grid.Row="2"/>
		</Grid>
	</Window>
	'
	#endregion XAML Markup

	$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
	$Form = [Windows.Markup.XamlReader]::Load($Reader)
	$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
		Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
	}

	$Window.Title               = "UWP apps"
	$ButtonUninstall.Content    = "Uninstall"
	$TextBlockRemoveForAll.Text = "For all users"
	$TextBlockSelectAll.Text    = "Select all"

	$ButtonUninstall.Add_Click({ButtonUninstallClick})
	$CheckBoxForAllUsers.Add_Click({CheckBoxForAllUsersClick})
	$CheckBoxSelectAll.Add_Click({CheckBoxSelectAllClick})
	#endregion Variables

	#UninstallUWPApps -ForAllUsers
	function Get-AppxBundle
	{
		[CmdletBinding()]
		param
		(
			[string[]]
			$Exclude,

			[switch]
			$AllUsers
		)

		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		$AppxPackages = Get-AppxPackage -PackageTypeFilter Bundle -AllUsers:$AllUsers | Where-Object -FilterScript {$_.Name -notin $ExcludedAppxPackages}
		$PackagesIds = [Windows.Management.Deployment.PackageManager, Windows.Web, ContentType = WindowsRuntime]::new().FindPackages().AdditionalTypeData[[Collections.IEnumerable].TypeHandle] | Select-Object -Property DisplayName -ExpandProperty Id | Select-Object -Property Name, DisplayName

		foreach ($AppxPackage in $AppxPackages)
		{
			$PackageId = $PackagesIds | Where-Object -FilterScript {$_.Name -eq $AppxPackage.Name}

			if (-not $PackageId)
			{
				continue
			}

			[PSCustomObject]@{
				Name            = $AppxPackage.Name
				PackageFullName = $AppxPackage.PackageFullName
				DisplayName     = $PackageId.DisplayName
			}
		}
	}

	function Add-Control
	{
		[CmdletBinding()]
		param
		(
			[Parameter(
				Mandatory = $true,
				ValueFromPipeline = $true
			)]
			[ValidateNotNull()]
			[PSCustomObject[]]
			$Packages
		)

		process
		{
			foreach ($Package in $Packages)
			{
				$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
				$CheckBox.Tag = $Package.PackageFullName

				$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock

				if ($Package.DisplayName)
				{
					$TextBlock.Text = $Package.DisplayName
				}
				else
				{
					$TextBlock.Text = $Package.Name
				}

				$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
				$StackPanel.Children.Add($CheckBox) | Out-Null
				$StackPanel.Children.Add($TextBlock) | Out-Null

				$PanelContainer.Children.Add($StackPanel) | Out-Null

				if ($UncheckedAppxPackages.Contains($Package.Name))
				{
					$CheckBox.IsChecked = $false
				}
				else
				{
					$CheckBox.IsChecked = $true
					$PackagesToRemove.Add($Package.PackageFullName)
				}

				$CheckBox.Add_Click({CheckBoxClick})
			}
		}
	}

	function CheckBoxForAllUsersClick
	{
		$PanelContainer.Children.RemoveRange(0, $PanelContainer.Children.Count)
		$PackagesToRemove.Clear()
		$AppXPackages = Get-AppxBundle -Exclude $ExcludedAppxPackages -AllUsers:$CheckBoxForAllUsers.IsChecked
		$AppXPackages | Add-Control

		ButtonUninstallSetIsEnabled
	}

	function ButtonUninstallClick
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Please wait..." -Verbose

		$Window.Close() | Out-Null

		# If Xbox Game Bar is selected to uninstall stop its' processes
		if ($PackagesToRemove -match "Microsoft.XboxGamingOverlay")
		{
			Get-Process -Name GameBar, GameBarFTServer -ErrorAction Ignore | Stop-Process -Force
		}

		$PackagesToRemove | Remove-AppxPackage -AllUsers:$CheckBoxForAllUsers.IsChecked -Verbose
	}

	function CheckBoxClick
	{
		$CheckBox = $_.Source

		if ($CheckBox.IsChecked)
		{
			$PackagesToRemove.Add($CheckBox.Tag) | Out-Null
		}
		else
		{
			$PackagesToRemove.Remove($CheckBox.Tag)
		}

		ButtonUninstallSetIsEnabled
	}

	function CheckBoxSelectAllClick
	{
		$CheckBox = $_.Source

		if ($CheckBox.IsChecked)
		{
			$PackagesToRemove.Clear()

			foreach ($Item in $PanelContainer.Children.Children)
			{
				if ($Item -is [System.Windows.Controls.CheckBox])
				{
					$Item.IsChecked = $true
					$PackagesToRemove.Add($Item.Tag)
				}
			}
		}
		else
		{
			$PackagesToRemove.Clear()

			foreach ($Item in $PanelContainer.Children.Children)
			{
				if ($Item -is [System.Windows.Controls.CheckBox])
				{
					$Item.IsChecked = $false
				}
			}
		}

		ButtonUninstallSetIsEnabled
	}

	function ButtonUninstallSetIsEnabled
	{
		if ($PackagesToRemove.Count -gt 0)
		{
			$ButtonUninstall.IsEnabled = $true
		}
		else
		{
			$ButtonUninstall.IsEnabled = $false
		}
	}
	#endregion Functions

	# Check "For all users" checkbox to uninstall packages from all accounts
	if ($ForAllUsers)
	{
		$CheckBoxForAllUsers.IsChecked = $true
	}

	$PackagesToRemove = [Collections.Generic.List[string]]::new()
	$AppXPackages = Get-AppxBundle -Exclude $ExcludedAppxPackages -AllUsers:$ForAllUsers
	$AppXPackages | Add-Control

	if ($AppxPackages.Count -eq 0)
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Nothing to display" -Verbose
	}
	else
	{
		Write-Information -MessageData "" -InformationAction Continue
		Write-Verbose -Message "Displaying the dialog box..." -Verbose

		#region Sendkey function
		# Emulate the Backspace key sending to prevent the console window to freeze
		Start-Sleep -Milliseconds 500

		Add-Type -AssemblyName System.Windows.Forms

		$SetForegroundWindow = @{
			Namespace        = "WinAPI"
			Name             = "ForegroundWindow"
			Language         = "CSharp"
			MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
"@
		}

		if (-not ("WinAPI.ForegroundWindow" -as [type]))
		{
			Add-Type @SetForegroundWindow
		}

		Get-Process | Where-Object -FilterScript {$_.MainWindowTitle -match "Windows 10 Bloatware and Security Hardening Script"} | ForEach-Object -Process {
			# Show window, if minimized
			[WinAPI.ForegroundWindow]::ShowWindowAsync($_.MainWindowHandle, 10)

			Start-Sleep -Milliseconds 100

			# Force move the console window to the foreground
			[WinAPI.ForegroundWindow]::SetForegroundWindow($_.MainWindowHandle)

			Start-Sleep -Milliseconds 100

			# Emulate the Backspace key sending to prevent the console window to freeze
			[System.Windows.Forms.SendKeys]::SendWait("{BACKSPACE 1}")
		}
		#endregion Sendkey function

		if ($PackagesToRemove.Count -gt 0)
		{
			$ButtonUninstall.IsEnabled = $true
		}

		# Force move the WPF form to the foreground
		$Window.Add_Loaded({$Window.Activate()})
		$Form.ShowDialog() | Out-Null
	}
}
UninstallUWPApps -ForAllUsers

UnpinTaskbarShortcuts -Shortcuts Edge, Store, Mail

    #SetAppGraphicsPerformance
    	if (Get-CimInstance -ClassName Win32_VideoController | Where-Object -FilterScript {($_.AdapterDACType -ne "Internal") -and ($null -ne $_.AdapterDACType)})
	{
		$Title = "Graphics performance preference"
		$Message = "Would you like to set the graphics performance setting of an app of your choice to 'High performance'?"
		$Add = "Add"
		$Skip = "Skip"
		$Options = "&$Add", "&$Skip"
		$DefaultChoice = 1

		do
		{
			$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
			switch ($Result)
			{
				"0"
				{
					Add-Type -AssemblyName System.Windows.Forms
					$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
					$OpenFileDialog.Filter = "*.exe|*.exe|All Files (*.*)|*.*"
					$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
					$OpenFileDialog.Multiselect = $false

					# Force move the open file dialog to the foreground
					$Focus = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
					$OpenFileDialog.ShowDialog($Focus)

					if ($OpenFileDialog.FileName)
					{
						if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences))
						{
							New-Item -Path HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences -Force
						}
						New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences -Name $OpenFileDialog.FileName -PropertyType String -Value "GpuPreference=2;" -Force
						Write-Verbose -Message ("{0}" -f $OpenFileDialog.FileName) -Verbose
					}
				}
				"1"
				{
					Write-Information -MessageData "" -InformationAction Continue
					Write-Verbose -Message "Skip"ped -Verbose
				}
			}
		}
		until ($Result -eq 1)
	}
    #Hide the Windows Ink Workspace button on the taskbar
   	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace -Name PenWorkspaceButtonDesiredVisibility -PropertyType DWord -Value 0 -Force
    #Enable camera on/off OSD notifications
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\OEM\Device\Capture" -Name "NoPhysicalCameraLED" -Value 1 -Type "DWORD" -Force
    #Enable SnapAssist - When I snap a window, show what I can snap next to it
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name SnapAssist -PropertyType DWord -Value 1 -Force
    #Windows Defender Privacy Options
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type "DWORD" -Value 1 -Force
    #Disable Cortana
    Write-Output "disabling cortona"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type "DWORD" -Value 0 -Force
    #Disable Device Metadata Retrieval
    Write-Output "Disable Device Metadata Retrieval"
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "Device Metadata" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Type "DWORD" -Value 1 -Force
    #Disable Find My Device
    Write-Output "Disable Find My Device"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type "DWORD" -Value 0 -Force
    #Enable hardware-accelerated GPU scheduling
    if (Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript {($_.AdapterDACType -ne "Internal") -and ($null -ne $_.AdapterDACType)})
			{
	# Determining whether an OS is not installed on a virtual machine
	if ((Get-CimInstance -ClassName CIM_ComputerSystem).Model -notmatch "Virtual")
			{
	# Checking whether a WDDM verion is 2.7 or higher
	    		$WddmVersion_Min = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\FeatureSetUsage -Name WddmVersion_Min
		    		if ($WddmVersion_Min -ge 2700)
			    		{
					    	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name HwSchMode -PropertyType DWord -Value 2 -Force
				    	}
			}
	}
    #Disable Font Streaming
    Write-Output "Disable Font Streaming"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableFontProviders -Type "DWORD" -Value 0 -Force
    Write-Output "IE Optimizations"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Geolocation" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\" -Name "AutoComplete" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name AutoSuggest -Type "String" -Value no -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name AllowServicePoweredQSA -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Suggested Sites" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name Enabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "FlipAhead" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\FlipAhead" -Name Enabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name BackgroundSyncStatus -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Type "DWORD" -Value 0 -Force
    #Restrict License Manager
    Write-Output "Restrict License Manager"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type "DWORD" -Value 4 -Force
    #Disable Live Tiles
    Write-Output "Disable Live Tiles"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -Type "DWORD" -Value 1 -Force
    #Disable Windows Mail App
    Write-Output "Disable Windows Mail App"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Mail" -Name ManualLaunchAllowed -Type "DWORD" -Value 0 -Force
    #Disable Microsoft Account cloud authentication service
    Write-Output "Disable Microsoft Account cloud authentication service"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\wlidsvc" -Name Start -Type "DWORD" -Value 4 -Force
    #Disable Offline Maps
    Write-Output "Disable Offline Maps"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AutoDownloadAndUpdateMapData -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AllowUntriggeredNetworkTrafficOnSettingsPage -Type "DWORD" -Value 0 -Force

    #Remove Bloatware Windows Apps
    Write-Output "Remove Reinstalled Apps"
    #Weather App
    Write-Output "removing Weather App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingWeather" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Money App
    Write-Output "removing Money App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingFinance" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Sports App
    Write-Output "removing Sports App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingSports" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Twitter App
    Write-Output "removing Twitter App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*.Twitter" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #XBOX App
    Write-Output "removing XBOX App"
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    #Sway App
    Write-Output "removing Sway App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.Sway" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Onenote App
    Write-Output "removing Onenote App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.OneNote" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Get Office App
    Write-Output "removing Get Office App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.MicrosoftOfficeHub" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Get Skype App 
    Write-Output "removing skype App"
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.SkypeApp" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    #Check for UWP Apps Updates"
   	Write-Information -MessageData "" -InformationAction Continue
	Write-Verbose -Message "Please wait..." -Verbose
	Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
    #Do not let UWP apps run in the background
    # Remove all excluded apps running in the background
	Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
	Remove-ItemProperty -Path $_.PsPath -Name * -Force
		}
	# Exclude apps from the Bundle only
	$BackgroundAccessApplications = @((Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications).PSChildName)
	$ExcludedBackgroundAccessApplications = @()
	foreach ($BackgroundAccessApplication in $BackgroundAccessApplications)
		{
    		if (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript {$_.PackageFamilyName -eq $BackgroundAccessApplication})
	    		{
					$ExcludedBackgroundAccessApplications += $BackgroundAccessApplication
				}
			}

	Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | Where-Object -FilterScript {$_.PSChildName -in $ExcludedBackgroundAccessApplications} | ForEach-Object -Process {
	New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
			}

			# Open the "Background apps" page
			Start-Process -FilePath ms-settings:privacy-backgroundapps

    #Download and install the "HEVC Video Extensions from Device Manufacturer"
    	# Check whether the extension is already installed
			if ((-not (Get-AppxPackage -Name Microsoft.HEVCVideoExtension)) -and (Get-AppxPackage -Name Microsoft.Windows.Photos))
			{
				try
				{
					# Check the internet connection
					if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
					{
						try
						{
							# Check whether the https://store.rg-adguard.net site is alive
							if ((Invoke-WebRequest -Uri https://store.rg-adguard.net/api/GetFiles -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
							{
								$API = "https://store.rg-adguard.net/api/GetFiles"
								# HEVC Video Extensions from Device Manufacturer
								$ProductURL = "https://www.microsoft.com/store/productId/9n4wgh0z6vhq"

								$Body = @{
									type = "url"
									url  = $ProductURL
									ring = "Retail"
									lang = "en-US"
								}
								$Raw = Invoke-RestMethod -Method Post -Uri $API -ContentType 'application/x-www-form-urlencoded' -Body $Body

								# Parsing the page
								$Raw | Select-String -Pattern '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*)<\/a>' -AllMatches | ForEach-Object -Process {$_.Matches} | ForEach-Object -Process {
									$TempURL = $_.Groups[1].Value
									$Package = $_.Groups[2].Value

									if ($Package -like "Microsoft.HEVCVideoExtension_*_x64__8wekyb3d8bbwe.appx")
									{
										Write-Information -MessageData "" -InformationAction Continue
										Write-Verbose -Message $Localization.HEVCDownloading -Verbose

										[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

										$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
										$Parameters = @{
											Uri     = $TempURL
											OutFile = "$DownloadsFolder\$Package"
											Verbose = $true
										}
										Invoke-WebRequest @Parameters

										# Installing "HEVC Video Extensions from Device Manufacturer"
										Add-AppxPackage -Path "$DownloadsFolder\$Package" -Verbose

										Remove-Item -Path "$DownloadsFolder\$Package" -Force
									}
								}
							}
						}
						catch [System.Net.WebException]
						{
							Write-Warning -Message ($Localization.NoResponse -f "https://store.rg-adguard.net")
							Write-Error -Message ($Localization.NoResponse -f "https://store.rg-adguard.net") -ErrorAction SilentlyContinue
							return
						}
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
    ##General VM Optimizations
    #Change TTL for ISP throttling workaround
    int ipv4 set glob defaultcurhoplimit=65
    int ipv6 set glob defaultcurhoplimit=65
    #Auto Cert Update
    Write-Output "Auto Cert Update"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot" -Name DisableRootAutoUpdate -Type "DWORD" -Value 0 -Force
    #Turn off Let websites provide locally relevant content by accessing my language list
    Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type "DWORD" -Value 1 -Force
    #Turn off Let Windows track app launches to improve Start and search results
    Write-Output "Turn off Let Windows track app launches to improve Start and search results"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type "DWORD" -Value 0 -Force
    #Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID
    Write-Output "Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID"
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "AdvertisingInfo"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Type "DWORD" -Value 1 -Force
    #Turn off Let websites provide locally relevant content by accessing my language list
    Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type "DWORD" -Value 1 -Force
    #Turn off Let apps on my other devices open apps and continue experiences on this device
    Write-Output "Turn off Let apps on my other devices open apps and continue experiences on this device"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Type "DWORD" -Value 1 -Force
    #Turn off Location for this device
    Write-Output "Turn off Location for this device"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsAccessLocation -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Type "DWORD" -Value 1 -Force
    #Turn off Windows should ask for my feedback
    Write-Output "Turn off Windows should ask for my feedback"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Type "DWORD" -Value 1 -Force
    #Turn Off Send your device data to Microsoft
    Write-Output "Turn Off Send your device data to Microsoft"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type "DWORD" -Value 0 -Force
    #Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data
    Write-Output "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\" -Name "CloudContent" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
    #Turn off Let apps run in the background
    Write-Output "Turn off Let apps run in the background"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type "DWORD" -Value 2 -Force
    #Software Protection Platform
    #Opt out of sending KMS client activation data to Microsoft
    Write-Output "Opt out of sending KMS client activation data to Microsoft"
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\" -Name "Software Protection Platform" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoAcquireGT -Type "DWORD" -Value 1 -Force
    #Turn off Messaging cloud sync
    Write-Output "Turn off Messaging cloud sync"
    New-Item -Path "HKCU:\Software\Microsoft\" -Name "Messaging" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSync -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSyncUserOverride -Type "DWORD" -Value 1 -Force
    #Delivery Optimization
    Write-Output "Delivery Optimization"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Type "DWORD" -Value 99 -Force
    New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 0 -Force
	Delete-DeliveryOptimizationCache -Force
    ###Disable app access to account info
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to calendar
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to call history
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to contacts
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to diagnostic information
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to documents
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to email
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to file system
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to location
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to messaging
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to motion
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to notifications
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Type "String" -Name Value -Value "DENY" -Force
    ###Disable app access to other devices
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name Value -Type "String" -Value "DENY" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to call
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to pictures
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to radios
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable app access to tasks
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name Value -Type "String" -Value "DENY" -Force
    
    ###Disable app access to videos
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name Value -Type "String" -Value "DENY" -Force
    ###Disable Bing in Windows Search ###
    ###Like Google, Bing is a search engine that needs your data to improve its search results. Windows 10, by default, sends everything you search for in the Start Menu to their servers to give you results from Bing search. ###
    ###These searches are then uploaded to Microsoft's Privacy Dashboard.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
    ###Disable Cortana ###
   	if (Get-AppxPackage -Name Microsoft.549981C3F5F10)
			{
	if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId"))
			{
	    		New-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Force
    		}
				New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 1 -Force
			}
    ###With the Anniversary Update, Microsoft hid the option to disable Cortana. This policy makes it possible again. It will block the outbound network connections completely in the Firewall.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type "String" -Value "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
    #Make icons easier to touch in explorer
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name FileExplorerInTouchImprovement -Type "DWORD" -Value 1 -Force

    Write-Output "Disabling Telemetry via Group Policies"
    New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
    Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 
 
    ###Prevent Edge from running in background ###
    ###On the new Chromium version of Microsoft Edge, extensions and other services can keep the browser running in the background even after it's closed. ###
    ###Although this may not be an issue for most desktop PCs, it could be a problem for laptops and low-end devices as these background processes can increase battery consumption and memory usage. The background process displays an icon in the system tray and can always be closed from there. ###
    ###If you run enable this policy the background mode will be disabled.
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Type "DWORD" -Value 0 -Force

    ###Disable synchronization of data ###
    ###This policy will disable synchronization of data using Microsoft sync services.
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type "DWORD" -Value 1 -Force

    ###Disable AutoFill for credit cards ###
    ###Microsoft Edge's AutoFill feature lets users auto complete credit card information in web forms using previously stored information. ###
    ###If you enable this policy, Autofill never suggests or fills credit card information, nor will it save additional credit card information that users might submit while browsing the web.
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type "DWORD" -Value 0 -Force

    ###Disable Game Bar features ###
    ###The Game DVR is a feature of the Xbox app that lets you use the Game bar (Win+G) to record and share game clips and screenshots in Windows 10. However, you can also use the Game bar to record videos and take screenshots of any app in Windows 10. ###
    ###This Policy will disable the Windows Game Recording and Broadcasting.
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "DWORD" -Value 0 -Force
    ###Block suggestions and automatic Installation of apps ###
    ###Microsoft flushes various apps into the system without being asked, especially games such as Candy Crush Saga. Users have to uninstall these manually if they don't want them on their computer. ###
    ###To prevent these downloads from starting in the first place, a small intervention in the registry helps. Suggested apps pinned to Start are basically just advertising. This script will also disable suggested apps (ex: Candy Crush Soda Saga) for all accounts.
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 0 -Force
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent")) {
         New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
       }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value 1 -Force

    #What's New in Windows - Ways I can finish setting up my device to get the most out of Windows
    	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement))
		{
			New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force
    ###Disable Compatibility Telemetry ###
    ###The Windows Compatibility Telemetry process is periodically collecting a variety of technical data about your computer and its performance and sending it to Microsoft for its Windows Customer Experience Improvement Program. It is enabled by default, and the data points are useful for Microsoft to improve Windows 10. ###
    ###The CompatTelRunner.exe file is also used to upgrade your system to the latest OS version and install the latest updates. ###
    ###The process is not generally required for the Windows operating system to run properly and can be stopped or deleted. This script will disable the CompatTelRunner.exe (Compatibility Telemetry process) in a more cleaner way using Image File Execution Options Debugger Value. Setting this value to an executable designed to kill processes disables it. Windows won't re-enable it with almost each update. 
    If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force

 
    ###Disable Customer Experience Improvement Program ###
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
    ###Disable Location tracking ###
    ###When Location Tracking is turned on, Windows and its apps are allowed to detect the current location of your computer or device. ###
    ###This can be used to pinpoint your exact location, e.g. Map traces the location of PC and helps you in exploring nearby restaurants.
    If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Deny" -Force
    ###Disable Telemetry in Windows 10 ###
    ###As you use Windows 10, Microsoft will collect usage information. All its options are available in Settings -> Privacy - Feedback and Diagnostics. There you can set the options "Diagnostic and usage data" to Basic, Enhanced and Full. This will set diagnostic data to Basic, which is the lowest level available for all consumer versions of Windows 10 ###
    ###NOTE: Diagnostic Data must be set to Full to get preview builds from Windows-Insider-Program! Just set the value of the AllowTelemetry key to "3" to revert the policy changes. All other changes remain unaffected.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "DataCollection" -Type "DWORD" -Value 0 -Force
    #Stop and Disable Diagnostic Tracking Service
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force
    Stop-Service -Name DiagTrack
    Set-Service -Name DiagTrack -StartupType Disabled
    #Stop and Disable dmwappushservice Service
    New-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\" -Name "dmwappushsvc" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force
    Stop-Service -Name dmwappushservice
    Set-Service -Name dmwappushservice -StartupType Disabled
    ###Disable Timeline history ###
    ###Microsoft made Timeline available to the public with Windows 10 build 17063. It collects a history of activities you've performed, including files you've opened and web pages you've viewed in Edge.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type "DWORD" -Value 0 -Force
    ###Disable Windows Tips ###
    ###Microsoft uses diagnostic information to determine which tips are appropriate. If you enable this policy, you will no longer see Windows Tips, e.g. Spotlight and Consumer Features, Feedback Notifications etc.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeature" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force

    ###Do not show feedback notifications ###
    ###Windows 10 doesn’t just automatically collect information about your computer usage. It does do that, but it may also pop up from time to time and ask for feedback. This information is used to improve Windows 10 - in theory. As of Windows 10’s “November Update,” the Windows Feedback application is installed by default on all Windows 10 PCs. ###
    ###If you are running Windows 10 in a corporate setting, you should likely disable the Windows Feedback prompts that appear every few weeks.
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force
    ###Prevent using diagnostic data ###
    ###Starting with Windows 10 build 15019, a new privacy setting to "let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data" has been added. By enabling this policy you can prevent Microsoft from using your diagnostic data. 
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value 0 -Force
    #Bing Search in the Start Menu
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
		{
			New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -PropertyType DWord -Value 1 -Force
    #Add "This PC" icon on Desktop
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel))
	 	{
	 		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0 -Force
    ###Turn off Advertising ID for Relevant Ads ###
    ###Windows 10 comes integrated with advertising. Microsoft assigns a unique identificator to track your activity in the Microsoft Store and on UWP apps to target you with relevant ads. ###
    ###If someone is giving you personalized ads, it means they are tracking your data. Turn off the advertising feature from Windows 10 with this policy to stay secure.
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    ###Turn off help Microsoft improve typing and writing ###
    ###When the Getting to know you privacy setting is turned on for inking & typing personalization in Windows 10, you can use your typing history and handwriting patterns to create a local user dictionary for you that is used to make better typing suggestions and improve handwriting recognition for each of the languages you use.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
    ###Disable password reveal button ###
    ###On the new login screen, Microsoft added a password review button that displays what's in the password box in plain text when pressed. Note that, disabling Password Reveal button disables this feature not only in login screen but also in Microsoft Edge, Internet Explorer as well. ###
    ###Visible passwords may be seen by nearby persons, compromising them. The password reveal button can be used to display an entered password and should be disabled with this policy.
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type "DWORD" -Value 1 -Force
    ###Disable Windows Media DRM Internet Access ###
    ###DRM stands for digital rights management. DRM is a technology used by content providers, such as online stores, to control how the digital music and video files you obtain from them are used and distributed. Online stores sell and rent songs and movies that have DRM applied to them. ###
    ###If the Windows Media Digital Rights Management should not get access to the Internet, you can enable this policy to prevent it.
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\WMDRM")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
    ###Disable forced updates ###
    ###This will notify when updates are available, and you decide when to install them.
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type "DWORD" -Value 2 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type "DWORD" -Value 3 -Force

    ###Turn off distributing updates to other computers ###
    ###Windows 10 lets you download updates from several sources to speed up the process of updating the operating system. ###
    ###If you don't want your files to be shared by others and exposing your IP address to random computers, you can apply this policy and turn this feature off. ###
    ###Acceptable selections include:
    ###Bypass (100) 
    ###Group (2)
    ###HTTP only (0) Enabled by SharpApp!
    ###LAN (1)
    ###Simple (99)
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force

    ###Disable Windows Error Reporting ###
    ###The error reporting feature in Windows is what produces those alerts after certain program or operating system errors, prompting you to send the information about the problem to Microsoft.
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force
    Get-ScheduledTask -TaskName "QueueReporting" | Disable-ScheduledTask
    Get-Service -Name WerSvc | Stop-Service -Force
	Get-Service -Name WerSvc | Set-Service -StartupType Disabled
    #Opt-out nVidia Telemetry
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Force
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type "DWORD" -Value 4 -Force
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name 0 -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name "Start" -Type "DWORD" -Value 4 -Force
    Stop-Service NvTelemetryContainer
    Set-Service NvTelemetryContainer -StartupType Disabled
    #Delete NVIDIA residual telemetry files
    Remove-Item -Recurse $env:systemdrive\System32\DriverStore\FileRepository\NvTelemetry*.dll
    Remove-Item -Recurse "$env:ProgramFiles\NVIDIA Corporation\NvTelemetry" | Out-Null

    #Disable Razer Game Scanner service
    Stop-Service "Razer Game Scanner Service"
    Set-Service "Razer Game Scanner Service" -StartupType Disabled

    #Disable Game Bar features
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force

    #Disable Logitech Gaming service
    Stop-Service "LogiRegistryService"
    Set-Service "LogiRegistryService" -StartupType Disabled

    #Disable Visual Studio Telemetry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -Type "DWORD" -Value 1 -Force
    Stop-Service "VSStandardCollectorService150"
    Set-Service "VSStandardCollectorService150" -StartupType Disabled

    #Block Google Chrome Software Reporter Tool
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowRun" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "1" -Type "String" -Value "software_reporter_tool.exe" /f
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force

    #Disable storing sensitive data in Acrobat Reader DC
    Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "String" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type "String" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type "String" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type "String" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type "String" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type "String" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type "String" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type "String" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "String" -Value 0 -Force

    #Disable Adobe Acrobat Update Service
    Set-Service "Adobe Acrobat Update Task" -StartupType Disabled
    Set-Service "Adobe Flash Player Updater" -StartupType Disabled
    Set-Service "adobeflashplayerupdatesvc" -StartupType Disabled
    Set-Service "adobeupdateservice" -StartupType Disabled
    Set-Service "AdobeARMservice" -StartupType Disabled

    #Disable CCleaner Health Check
    Stop-Process -Force -Force -Name  ccleaner.exe
    Stop-Process -Force -Force -Name  ccleaner64.exe
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type "String" -Value 2 -Force

    #Disable CCleaner Monitoring && more
    Stop-Process -Force -Force -Name "IMAGENAME eq CCleaner*"
    schtasks /Change /TN "CCleaner Update" /Disable
    Get-ScheduledTask -TaskName "CCleaner Update" | Disable-ScheduledTask
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)HealthCheck" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickClean" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickCleanIpm" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type "DWORD" -Value 0 -Force

    #Disable Dropbox Update service
    Set-Service dbupdate -StartupType Disabled
    Set-Service dbupdatem -StartupType Disabled
    Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineCore" | Disable-ScheduledTask
    Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineUA" | Disable-ScheduledTask
    #schtasks /Change /TN "DropboxUpdateTaskMachineCore" /Disable
    #schtasks /Change /TN "DropboxUpdateTaskMachineUA" /Disable

    #Disable Google update service
    Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" | Disable-ScheduledTask
    Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" | Disable-ScheduledTask
    #schtasks /Change /TN "GoogleUpdateTaskMachineCore" /Disable
    #schtasks /Change /TN "GoogleUpdateTaskMachineUA" /Disable

    #Disable Media Player Telemetry
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
    Set-Service WMPNetworkSvc -StartupType Disabled

    
    #Disable Microsoft Office Telemetry
    Get-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" | Disable-ScheduledTask
    Get-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" | Disable-ScheduledTask
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force

    #Disable Microsoft Windows Live ID service
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type "DWORD" -Value 4 -Force
    Set-Service wlidsvc -StartupType Disabled

    #Disable Mozilla Firefox Telemetry
    Set-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
    #Disable default browser agent reporting policy
    Set-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type "DWORD" -Value 1 -Force
    #Disable default browser agent reporting services
    schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB"
    schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD"

    Import-Module -DisableNameChecking $PSScriptRoot\..\lib\Mkdir -Force .psm1
    Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

    Write-Output "Defuse Windows search settings"
    Set-WindowsSearchSetting -EnableWebResultsSetting $false

    Write-Output "Set general privacy options"
    #"Let websites provide locally relevant content by accessing my language list"
    Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
    #Locaton aware printing (changes default based on connected network)
    Mkdir "HKCU:\Printers\Defaults" -Force
    New-Item -Path "HKCU:\Printers\" -Name "Defaults" -Force
    Set-ItemProperty "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
    #"Send Microsoft info about how I write to help us improve typing and writing in the future"
    Mkdir "HKCU:\Software\Microsoft\Input\TIPC" -Force
    Set-ItemProperty "HKCU:\Software\Microsoft\Input\TIPC" "Enabled" 0
    #"Let apps use my advertising ID for experiencess across apps"
    Mkdir -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
    #"Turn on SmartScreen Filter to check web content"
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
    Write-Output "Set privacy policy accepted state to 0"
    #Prevents sending speech, inking and typing samples to MS (so Cortana
    #can learn to recognise you)
    Mkdir -Force  "HKCU:\Software\Microsoft\Personalization\Settings"
    Set-ItemProperty "HKCU:\Software\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0

    Write-Output "Do not scan contact informations"
    #Prevents sending contacts to MS (so Cortana can compare speech etc samples)
    Mkdir -Force  "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
    Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

    Write-Output "Inking and typing settings"
    #Handwriting recognition personalization
    Mkdir -Force  "HKCU:\Software\Microsoft\InputPersonalization"
    Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
    Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1

    Write-Output "Microsoft Edge settings"
    Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
    Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
    Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
    Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
    Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
    Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
    Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
    Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0

    Write-Output "Disable background access of default apps"
    foreach ($key in (Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
        Set-ItemProperty ("HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
    }

    Write-Output "Denying device access"
    #Disable sharing information with unpaired devices
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"

    Write-Output "Disable location sensor"
    Mkdir -Force  "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0

    Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
    Takeown-Registry("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Spynet")
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       #write-protected even after takeown ?!
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0

    Write-Output "Do not share wifi networks"
    $user = New-Object System.Security.Principal.NTAccount($env:UserName)
    $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
    Mkdir -Force  ("HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
    Set-ItemProperty ("HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
    Set-ItemProperty "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
    Set-ItemProperty "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0

    #Set the quality factor of the JPEG desktop wallpapers to maximum
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force

    #Start Task Manager in the expanded mode
   	$Taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore
    Start-Sleep -Seconds 1
	if ($Taskmgr)
	{
		$Taskmgr.CloseMainWindow()
	}
	Start-Process -FilePath Taskmgr.exe -PassThru
	Start-Sleep -Seconds 3
	do
	{
		Start-Sleep -Milliseconds 100
		$Preferences = Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences
	}
	until ($Preferences)
	Stop-Process -Name Taskmgr -ErrorAction Ignore
 	$Preferences[28] = 0
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $Preferences -Force

    #Show a notification when your PC requires a restart to finish updating
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 1 -Force
    #Do not add the "- Shortcut" suffix to the file name of created shortcuts
    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates))
		{
			New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Force
		}
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -PropertyType String -Value "%s.lnk" -Force
    #Use the Print screen button to open screen snipping
   	New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force
    #When I grab a windows's title bar and shake it, don't minimize all other windows
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 1 -Force



}


#Enable Disk Compression and Disable File Indexing
Start-Job -Name "Enable Disk Compression and Disable File Indexing" -ScriptBlock {
    $DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
    ForEach ($Drive in $DriveLetters) {
        If (-not ([string]::IsNullOrEmpty($Drive))) {
            $indexing = $Drive.IndexingEnabled
            #Write-Host "Enabling Disk Compression on the $Drive Drive"
            #Enable-NtfsCompression -Path "$Drive"\ -Recurse
            if ("$indexing" -eq $True) {
                Write-Host "Disabling File Index on the $Drive Drive"
                Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'" | Set-WmiInstance -Arguments @{IndexingEnabled = $False } | Out-Null
            }
        }
    }

    #Disable Memory Compression
    Disable-MMAgent -mc
    #Disable Superfetch Service
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    #Lower RAM Usage
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type "DWORD" -Value "04000000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type "String" -Value "2000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type "DWORD" -Value "0ffffffff"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "Background Only" -Type "String" -Value "True"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "Priority" -Type "DWORD" -Value "00000006"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "Scheduling Category" -Type "String" -Value "Medium"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "Background Only" -Type "String" -Value "True"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "Priority" -Type "DWORD" -Value "00000005"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "Scheduling Category" -Type "String" -Value "Medium"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Background Only" -Type "String" -Value "True"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "BackgroundPriority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Scheduling Category" -Type "String" -Value "High"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "Background Only" -Type "String" -Value "True"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "Priority" -Type "DWORD" -Value "00000004"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "Scheduling Category" -Type "String" -Value "Medium"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type "String" -Value "False"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "DWORD" -Value "00000006"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type "String" -Value "High"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type "String" -Value "High"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "Background Only" -Type "String" -Value "False"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "BackgroundPriority" -Type "DWORD" -Value "00000004"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "Priority" -Type "DWORD" -Value "00000003"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "Scheduling Category" -Type "String" -Value "Medium"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "Background Only"="False"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "Priority" -Type "DWORD" -Value "00000001"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "Scheduling Category" -Type "String" -Value "High"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "Background Only" -Type "String" -Value "True"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "Priority" -Type "DWORD" -Value "00000005"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "Scheduling Category" -Type "String" -Value "Medium"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -Name "SFIO Priority" -Type "String" -Value "Normal"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type "String" -Value "False"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type "DWORD" -Value "00002710"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type "DWORD" -Value "00000008"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "DWORD" -Value "00000006"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type "String" -Value "High"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type "String" -Value "High"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type "DWORD" -Value "00000001"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type "DWORD" -Value "00000002"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "Win32_AutoGameModeDefaultProfile" -Type "BINARY" -Value "01,00,01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "Win32_GameModeRelatedProcesses" -Type "BINARY" -Value "01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type "DWORD" -Value "00000000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabledDefault" -Type "DWORD" -Value "00000000"

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\Control Panel\Desktop" -Name "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\Control Panel\Desktop" -Name "MenuShowDelay" -Type "String" -Value "0"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "WaitToKillAppTimeout" -Type "String" -Value "5000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HungAppTimeout" -Type "String" -Value "4000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "AutoEndTasks" -Type "String" -Value "1"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LowLevelHooksTimeout" -Type "DWORD" -Value "00001000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "WaitToKillServiceTimeout" -Type "DWORD" -Value "00002000"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" -Name "Attributes" -Type "DWORD" -Value "00000002"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" -Name "ACSettingIndex" -Type "DWORD" -Value "0"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" -Name "DCSettingIndex" -Type "DWORD" -Value "0"
    Set-ItemProperty -Path "HKLM:\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -Name "ACSettingIndex" -Type "DWORD" -Value "0"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" -Name "ACSettingIndex" -Type "DWORD" -Value "0"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" -Name "DCSettingIndex" -Type "DWORD" -Value "0"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -Name "ACSettingIndex" -Type "DWORD" -Value "0"

}

Start-Job -Name "STIG Addendum" -ScriptBlock {
    #This is for STIG settings that may not be covered in GPO or require configuration globally rather than per user as in the STIG
    #Basic authentication for RSS feeds over HTTP must not be used.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "Feeds" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Type "DWORD" -Value 0 -Force
    #InPrivate browsing in Microsoft Edge must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowInPrivate" -Type "DWORD" -Value 0 -Force
    #Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\" -Name "Privacy" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Privacy" -Name ClearBrowsingHistoryOnExit -Type "DWORD" -Value 0 -Force
    #Check for publishers certificate revocation must be enforced.
    New-Item -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    #AutoComplete feature for forms must be disallowed.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    #Turn on the auto-complete feature for user names and passwords on forms must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    #Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -Type "MultiString" -Value "NistP384 NistP256" -Force
    #Zone information must be preserved when saving attachments.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    #Toast notifications to the lock screen must be turned off.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\" -Name "PushNotifications" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    #Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CloudContent" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    #Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name "LetAppsActivateWithVoice" -Type "DWORD" -Value 2 -Force
    #The Windows Explorer Preview pane must be disabled for Windows 10.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    #The use of a hardware security device with Windows Hello for Business must be enabled.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "PassportForWork" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\" -Name "RequireSecurityDevice" -Type "DWORD" -Value 1 -Force
}

Start-Job -Name "Adobe Reader DC STIG" -ScriptBlock {
    #Adobe Reader DC STIG
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cCloud -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cDefaultLaunchURLPerms -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cServices -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cSharePoint -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWebmailProfiles -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWelcomeScreen -Force
    Set-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bAcroSuppressUpsell -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisablePDFHandlerSwitching -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedFolders -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedSites -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnableFlash -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityInBrowser -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityStandalone -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bProtectedMode -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iFileAttachmentPerms -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iProtectedView -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name bAdobeSendPluginToggle -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iURLPerms -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iUnknownURLPerms -Type "DWORD" -Value 3 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeDocumentServices -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeSign -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bTogglePrefsSync -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleWebConnectors -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bUpdater -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name bDisableSharePointFeatures -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name bDisableWebmail -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name bShowWelcomeScreen -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type "DWORD" -Value 1 -Force
}

Start-Job -Name "Image Cleanup" -ScriptBlock {
    #Delete "windows.old" folder
    #Cmd.exe /c Cleanmgr /sageset:65535 
    Cmd.exe /c Cleanmgr /sagerun:65535
    Write-Verbose "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use"
    Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
    #Delete "RetailDemo" content (if it exits)
    Write-Verbose "Removing Retail Demo content (if it exists)"
    Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue
    #Delete not in-use anything in the C:\Windows\Temp folder
    Write-Verbose "Removing all files not in use in $env:windir\TEMP"
    Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
    #Clear out Windows Error Reporting (WER) report archive folders
    Write-Verbose "Cleaning up WER report archive"
    Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
    #Delete not in-use anything in your $env:TEMP folder
    Write-Verbose "Removing files not in use in $env:TEMP directory"
    Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
    #Clear out ALL visible Recycle Bins
    Write-Verbose "Clearing out ALL Recycle Bins"
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    #Clear out BranchCache cache
    Write-Verbose "Clearing BranchCache cache"
    Clear-BCCache -Force -ErrorAction SilentlyContinue
    #Clear volume backups (shadow copies)
    vssadmin delete shadows /all /quiet
    #Empty trash bin
    Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
    #Delete controversial default0 user
    net user defaultuser0 /delete 2>nul
    #Clear thumbnail cache
    Remove-Item /f /s /q /a $env:LocalAppData\Microsoft\Windows\Explorer\*.db
    #Clear Windows temp files
    Remove-Item /f /q $env:localappdata\Temp\*
    Remove-Item /s /q "$env:WINDIR\Temp"
    Remove-Item /s /q "$env:TEMP"
    #Clear main telemetry file
    takeown /f "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r -Value y
    icacls "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
    Write-Output"" > "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    Write-Output Clear successful: "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    #Clear Distributed Transaction Coordinator logs
    Remove-Item /f /q $env:SystemRoot\DtcInstall.log
    #Clear Optional Component Manager and COM+ components logs
    Remove-Item /f /q $env:SystemRoot\comsetup.log
    #Clear Pending File Rename Operations logs
    Remove-Item /f /q $env:SystemRoot\PFRO.log
    #Clear Windows Deployment Upgrade Process Logs
    Remove-Item /f /q $env:SystemRoot\setupact.log
    Remove-Item /f /q $env:SystemRoot\setuperr.log
    #Clear Windows Setup Logs
    Remove-Item /f /q $env:SystemRoot\setupapi.log
    Remove-Item /f /q $env:SystemRoot\Panther\*
    Remove-Item /f /q $env:SystemRoot\inf\setupapi.app.log
    Remove-Item /f /q $env:SystemRoot\inf\setupapi.dev.log
    Remove-Item /f /q $env:SystemRoot\inf\setupapi.offline.log
    #Clear Windows System Assessment Tool logs
    Remove-Item /f /q $env:SystemRoot\Performance\WinSAT\winsat.log
    #Clear Password change events
    Remove-Item /f /q $env:SystemRoot\debug\PASSWD.LOG
    #Clear user web cache database
    Remove-Item /f /q $env:LocalAppData\Microsoft\Windows\WebCache\*.*
    #Clear system temp folder when noone is logged in
    Remove-Item /f /q $env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
    #Clear DISM (Deployment Image Servicing and Management) Logs
    Remove-Item /f /q  $env:SystemRoot\Logs\CBS\CBS.log
    Remove-Item /f /q  $env:SystemRoot\Logs\DISM\DISM.log
    #Clear Server-initiated Healing Events Logs
    Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
    #Common Language Runtime Logs
    Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0\UsageTraces\*"
    Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0_32\UsageTraces\*"
    #Network Setup Service Events Logs
    Remove-Item /f /q "$env:SystemRoot\Logs\NetSetup\*"
    #Disk Cleanup tool (Cleanmgr.exe) Logs
    Remove-Item /f /q "$env:SystemRoot\System32\LogFiles\setupcln\*"
    #Clear Windows update and SFC scan logs
    Remove-Item /f /q $env:SystemRoot\Temp\CBS\*
    #Clear Windows Update Medic Service logs
    takeown /f $env:SystemRoot\Logs\waasmedic /r -Value y
    icacls $env:SystemRoot\Logs\waasmedic /grant administrators:F /t
    Remove-Item /s /q $env:SystemRoot\Logs\waasmedic
    #Clear Cryptographic Services Traces
    Remove-Item /f /q $env:SystemRoot\System32\catroot2\dberr.txt
    Remove-Item /f /q $env:SystemRoot\System32\catroot2.log
    Remove-Item /f /q $env:SystemRoot\System32\catroot2.jrs
    Remove-Item /f /q $env:SystemRoot\System32\catroot2.edb
    Remove-Item /f /q $env:SystemRoot\System32\catroot2.chk
    #Windows Update Events Logs
    Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
    #Windows Update Logs
    Remove-Item /f /q "$env:SystemRoot\Traces\WindowsUpdate\*"
    #Clear Internet Explorer traces
    Remove-Item /f /q "$env:LocalAppData\Microsoft\Windows\INetCache\IE\*"
    reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
    reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f
    Remove-Item /s /q "$env:LocalAppData\Microsoft\Internet Explorer"
    Remove-Item /s /q "$env:APPDATA\Microsoft\Windows\Cookies"
    Remove-Item /s /q "$env:USERPROFILE\Cookies"
    Remove-Item /s /q "$env:USERPROFILE\Local Settings\Traces"
    Remove-Item /s /q "$env:LocalAppData\Temporary Internet Files"
    Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\Temporary Internet Files"
    Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\INetCookies\PrivacIE"
    Remove-Item /s /q "$env:LocalAppData\Microsoft\Feeds Cache"
    Remove-Item /s /q "$env:LocalAppData\Microsoft\InternetExplorer\DOMStore"
    #Clear Google Chrome traces
    Remove-Item /f /q "$env:LocalAppData\Google\Software Reporter Tool\*.log"
    Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Google\Chrome\User Data"
    Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data"
    Remove-Item /s /q "$env:LocalAppData\Google\CrashReports\""
    Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data\Crashpad\reports\""
    #Clear Opera traces
    Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Opera\Opera"
    Remove-Item /s /q "$env:APPDATA\Opera\Opera"
    Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Opera\Opera"
    #Clear Safari traces
    Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Traces"
    Remove-Item /s /q "$env:APPDATA\Apple Computer\Safari"
    Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Cache.db"
    Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\WebpageIcons.db"
    Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Traces"
    Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
    Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Safari\WebpageIcons.db"
    #Clear Listary indexes
    Remove-Item /f /s /q $env:APPDATA\Listary\UserData > nul
    #Clear Java cache
    Remove-Item /s /q "$env:APPDATA\Sun\Java\Deployment\cache"
    #Clear Flash traces
    Remove-Item /s /q "$env:APPDATA\Macromedia\Flash Player"
    #Clear Steam dumps, logs and traces
    Remove-Item /f /q %ProgramFiles(x86)%\Steam\Dumps
    Remove-Item /f /q %ProgramFiles(x86)%\Steam\Traces
    Remove-Item /f /q %ProgramFiles(x86)%\Steam\appcache\*.log
    #Clear Visual Studio telemetry and feedback data
    Remove-Item /s /q "$env:APPDATA\vstelemetry" 2>nul
    Remove-Item /s /q "$env:LocalAppData\Microsoft\VSApplicationInsights" 2>nul
    Remove-Item /s /q "$env:ProgramData\Microsoft\VSApplicationInsights" 2>nul
    Remove-Item /s /q "$env:TEMP\Microsoft\VSApplicationInsights" 2>nul
    Remove-Item /s /q "$env:TEMP\VSFaultInfo" 2>nul
    Remove-Item /s /q "$env:TEMP\VSFeedbackPerfWatsonData" 2>nul
    Remove-Item /s /q "$env:TEMP\VSFeedbackVSRTCLogs" 2>nul
    Remove-Item /s /q "$env:TEMP\VSRemoteControl" 2>nul
    Remove-Item /s /q "$env:TEMP\VSTelem" 2>nul
    Remove-Item /s /q "$env:TEMP\VSTelem.Out" 2>nul
    #Clear Dotnet CLI telemetry
    Remove-Item /s /q "$env:USERPROFILE\.dotnet\TelemetryStorageService" 2>nul
    #Clear regedit last key
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
    #Clear regedit favorites
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
    #Clear list of recent programs opened
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
    #Clear Adobe Media Browser MRU
    reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f
    #Clear MSPaint MRU
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
    #Clear Wordpad MRU
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
    #Clear Map Network Drive MRU MRU
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
    #Clear Windows Search Assistant history
    reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
    #Clear list of Recent Files Opened, by Filetype
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
    #Clear windows media player recent files and urls
    reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
    reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
    #Clear Most Recent Application's Use of DirectX
    reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
    #Clear Windows Run MRU & typedpaths
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
    #Clear recently accessed files
    Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
    #Clear user pins
    Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"

    #Clear regedit last key
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
}

#The "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates
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
			Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
				Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
			}

			$VolumeCaches = @(
				# Delivery Optimization Files
				"Delivery Optimization Files",

				# Device driver packages
				"Device Driver Packages",

				# Previous Windows Installation(s)
				"Previous Installations",

				# Setup log files
				"Setup Log Files",

				# Temporary Setup Files
				"Temporary Setup Files",

				# Windows Update Cleanup
				"Update Cleanup",

				# Microsoft Defender
				"Windows Defender",

				# Windows upgrade log files
				"Windows Upgrade Log Files"
			)
			foreach ($VolumeCache in $VolumeCaches)
			{
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
			}

			$CleanupTask = @"
Get-Process -Name cleanmgr | Stop-Process -Force
Get-Process -Name Dism | Stop-Process -Force
Get-Process -Name DismHost | Stop-Process -Force

`$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
`$ProcessInfo.FileName = """$env:SystemRoot\system32\cleanmgr.exe"""
`$ProcessInfo.Arguments = """/sagerun:1337"""
`$ProcessInfo.UseShellExecute = `$true
`$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

`$Process = New-Object -TypeName System.Diagnostics.Process
`$Process.StartInfo = `$ProcessInfo
`$Process.Start() | Out-Null

Start-Sleep -Seconds 3

[int]`$SourceMainWindowHandle = (Get-Process -Name cleanmgr | Where-Object -FilterScript {`$_.PriorityClass -eq """BelowNormal"""}).MainWindowHandle

function MinimizeWindow
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = `$true)]
		`$Process
	)

	`$ShowWindowAsync = @{
		Namespace = """WinAPI"""
		Name = """Win32ShowWindowAsync"""
		Language = """CSharp"""
		MemberDefinition = @'
[DllImport("""user32.dll""")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
'@
	}

	if (-not ("""WinAPI.Win32ShowWindowAsync""" -as [type]))
	{
		Add-Type @ShowWindowAsync
	}
	`$MainWindowHandle = (Get-Process -Name `$Process | Where-Object -FilterScript {`$_.PriorityClass -eq """BelowNormal"""}).MainWindowHandle
	[WinAPI.Win32ShowWindowAsync]::ShowWindowAsync(`$MainWindowHandle, 2)
}

while (`$true)
{
	[int]`$CurrentMainWindowHandle = (Get-Process -Name cleanmgr | Where-Object -FilterScript {`$_.PriorityClass -eq """BelowNormal"""}).MainWindowHandle
	if (`$SourceMainWindowHandle -ne `$CurrentMainWindowHandle)
	{
		MinimizeWindow -Process cleanmgr
		break
	}
	Start-Sleep -Milliseconds 5
}

`$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
`$ProcessInfo.FileName = """`$env:SystemRoot\system32\dism.exe"""
`$ProcessInfo.Arguments = """/Online /English /Cleanup-Image /StartComponentCleanup /NoRestart"""
`$ProcessInfo.UseShellExecute = `$true
`$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

`$Process = New-Object -TypeName System.Diagnostics.Process
`$Process.StartInfo = `$ProcessInfo
`$Process.Start() | Out-Null
"@

			# Create the "Windows Cleanup" task
			$Action     = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -Command $CleanupTask"
			$Settings   = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
			$Principal  = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
			$Parameters = @{
				TaskName    = "Windows Cleanup"
				TaskPath    = "ScriptFunct"
				Principal   = $Principal
				Action      = $Action
				Description = "Cleaning up Windows unused files and updates using built-in Disk cleanup app"
				Settings    = $Settings
			}
			Register-ScheduledTask @Parameters -Force

			# Persist the Settings notifications to prevent to immediately disappear from Action Center
			if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"))
			{
				New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Force
			}
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force

			# Register the "WindowsCleanup" protocol to be able to run the scheduled task by clicking the "Run" button in a toast
			if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command))
			{
				New-Item -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command -Force
			}
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name "(default)" -PropertyType String -Value "URL:WindowsCleanup" -Force
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name "URL Protocol" -Value "" -Force
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name EditFlags -PropertyType DWord -Value 2162688 -Force

			# Start the "Windows Cleanup" task if the "Run" button clicked
			New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command -Name "(default)" -PropertyType String -Value 'powershell.exe -Command "& {Start-ScheduledTask -TaskPath ''\ScriptFunct\'' -TaskName ''Windows Cleanup''}"' -Force

			$ToastNotification = @"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

[xml]`$ToastTemplate = @"""
<toast duration="""Long""" scenario="""reminder""">
	<visual>
		<binding template="""ToastGeneric""">
			<text>$("Important Information")</text>
			<group>
				<subgroup>
					<text hint-style="""title""" hint-wrap="""true""">$("Run task to clean up Windows unused files and updates?")</text>
				</subgroup>
			</group>
			<group>
				<subgroup>
					<text hint-style="""body""" hint-wrap="""true""">$("Windows cleanup won't take long. Next time this notification will appear in 30 days")</text>
				</subgroup>
			</group>
		</binding>
	</visual>
	<audio src="""ms-winsoundevent:notification.default""" />
	<actions>
		<input id="""SnoozeTimer""" type="""selection""" title="""$("Select a Reminder Interval")""" defaultInput="""1""">
			<selection id="""1""" content="""$("1 minute")""" />
			<selection id="""30""" content="""$("30 minutes")""" />
			<selection id="""240""" content="""$("4 hours")""" />
		</input>
		<action activationType="""system""" arguments="""snooze""" hint-inputId="""SnoozeTimer""" content="""""" id="""test-snooze"""/>
		<action arguments="""WindowsCleanup:""" content="""$("Run")""" activationType="""protocol"""/>
		<action arguments="""dismiss""" content="""""" activationType="""system"""/>
	</actions>
</toast>
"""@

`$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
`$ToastXml.LoadXml(`$ToastTemplate.OuterXml)

`$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New(`$ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("""windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel""").Show(`$ToastMessage)
"@

			# Create the "Windows Cleanup Notification" task
			$Action    = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -Command $ToastNotification"
			$Settings  = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
			$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
			$Trigger   = New-ScheduledTaskTrigger -Daily -DaysInterval 30 -At 9pm
			$Parameters = @{
				TaskName    = "Windows Cleanup Notification"
				TaskPath    = "ScriptFunct"
				Action      = $Action
				Settings    = $Settings
				Principal   = $Principal
				Trigger     = $Trigger
				Description = "Pop-up notification reminder about cleaning up Windows unused files and updates"
			}
			Register-ScheduledTask @Parameters -Force
		}
		"Delete"
		{
			Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
				Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
			}

			Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Name ShowInActionCenter -Force -ErrorAction Ignore

			Unregister-ScheduledTask -TaskName "Windows Cleanup" -Confirm:$false
			Unregister-ScheduledTask -TaskName "Windows Cleanup Notification" -Confirm:$false

			Remove-Item -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Recurse -Force -ErrorAction Ignore
		}
	}
}
CleanupTask -Register
SoftwareDistributionTask -Register
TempTask -Register

    # Ask for confirmation to Show OneDrive within File Explorer
    $ShowOneDrive = Read-Host "Do you want to show OneDrive within File Explorer? (Y/N)"
    if ($ShowOneDrive -eq 'Y') { 
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 1 -Force
    } 
    else {
    Write-Host "Disabling OneDrive"
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
    }
    # Ask for confirmation to Install Onedrive
    $InstallOneDrive = Read-Host "Would you like to Install Onedrive? (Y/N)"
    if ($InstallOneDrive -eq 'Y') { 
Start-Job -Name "Install OneDrive" -ScriptBlock {
   			$OneDrive = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -Force -ErrorAction Ignore
			if (-not $OneDrive)
			{
				if (Test-Path -Path $env:SystemRoot\SysWOW64\OneDriveSetup.exe)
				{
					Write-Information -MessageData "" -InformationAction Continue
					Write-Verbose -Message "Installing OneDrive..." -Verbose
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
							Write-Verbose -Message "Downloading OneDrive..." -Verbose

							# Parse XML to get the URL
							# https://go.microsoft.com/fwlink/p/?LinkID=844652
							$Parameters = @{
								Uri             = "https://g.live.com/1rewlive5skydrive/OneDriveProduction"
								UseBasicParsing = $true
								Verbose         = $true
							}
							$Content = Invoke-RestMethod @Parameters

							# Remove invalid chars
							[xml]$OneDriveXML = $Content -replace "ï»¿", ""

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
						Write-Warning -Message "No Internet connection"
						Write-Error -Message "No Internet connection" -ErrorAction SilentlyContinue

						Write-Error -Message ("Please re-run the function" -f $MyInvocation.Line) -ErrorAction SilentlyContinue

						return
					}
				}

				Get-ScheduledTask -TaskName "Onedrive* Update*" | Enable-ScheduledTask
			 }
	   }
 }  


Start-Job -Name "Nessus Plugin ID 63155 - Microsoft Windows Unquoted Service Path Enumeration" -ScriptBlock {
    # https://github.com/VectorBCO/windows-path-enumerate/blob/development/Windows_Path_Enumerate.ps1
    ForEach ($i in 1..2) {
        # Get all services
        $FixParameters = @()
        If ($i = 1) {
            $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath" }
        }
        If ($i = 2) {
            $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString" }
            # If OS x64 - adding paths for x86 programs
            If (Test-Path "$($env:SystemDrive)\Program Files (x86)\") {
                $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString" }
            }
        }
        $PTElements = @()
        ForEach ($FixParameter in $FixParameters) {
            Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
                $SpCharREGEX = '([\[\]])'
                $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX, '`$1'
                $OriginalPath = (Get-ItemProperty "$RegistryPath")
                $ImagePath = $OriginalPath.$($FixParameter.ParamName)
                If ($i = 1, 2) {
                    If ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%') {
                        $EnvVar = $Matches['envVar']
                        $FullVar = (Get-ChildItem env: | Where-Object { $_.Name -eq $EnvVar }).value
                        $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%", $FullVar
                        Clear-Variable Matches
                    } # End If
                } # End If $fixEnv
                # Get all services with vulnerability
                If (($ImagePath -like "* *") -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                    # Skip MsiExec.exe in uninstall strings
                    If ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?') -and ($ImagePath -Match '^((\w\:)|(%[-\w_()]+%))\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                        $NewPath = ($ImagePath -split ".exe ")[0]
                        $key = ($ImagePath -split ".exe ")[1]
                        $trigger = ($ImagePath -split ".exe ")[2]
                        $NewValue = ''
                        # Get service with vulnerability with key in ImagePath
                        If (-not ($trigger | Measure-Object).count -ge 1) {
                            If (($NewPath -like "* *") -and ($NewPath -notLike "*.exe")) {
                                $NewValue = "`"$NewPath.exe`" $key"
                            } # End If
                            # Get service with vulnerability with out key in ImagePath
                            ElseIf (($NewPath -like "* *") -and ($NewPath -like "*.exe")) {
                                $NewValue = "`"$NewPath`""
                            } # End ElseIf
                            If ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                                try {
                                    $soft_service = $(if ($FixParameter.ParamName -Eq 'ImagePath') { 'Service' }Else { 'Software' })
                                    $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                    Write-Host "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                    Write-Host "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                    if ($Passthru) {
                                        $PTElements += '' | Select-Object `
                                        @{n = 'Name'; e = { $OriginalPath.PSChildName } }, `
                                        @{n = 'Type'; e = { $soft_service } }, `
                                        @{n = 'ParamName'; e = { $FixParameter.ParamName } }, `
                                        @{n = 'Path'; e = { $OriginalPSPathOptimized } }, `
                                        @{n = 'OriginalValue'; e = { $OriginalPath.$($FixParameter.ParamName) } }, `
                                        @{n = 'ExpectedValue'; e = { $NewValue } }
                                    }
                                    If (! ($i -gt 2)) {
                                        Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                        $DisplayName = ''
                                        $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                        If ($soft_service -match 'Software') {
                                            $DisplayName = $keyTmp.DisplayName
                                        }
                                        If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue) {
                                            Write-Host "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$($OriginalPath.PSChildName)' $(if($DisplayName){"($DisplayName)"})"
                                        } # End If
                                        Else {
                                            Write-Host "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                        } # End Else
                                    } # End If
                                } # End try
                                Catch {
                                    Write-Host "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                    Write-Host "$(get-date -format u)  :  ERROR  : $_"
                                } # End Catch
                                Clear-Variable NewValue
                            } # End If
                        } # End Main If
                    } # End if (Skip not needed strings)
                } # End If
                If (($trigger | Measure-Object).count -ge 1) {
                    Write-Host "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
                } # End If
            } # End Foreach
        } # End Foreach
    } # End Foreach   
} # End Job
CleanupTask -Register

Write-Host "simeononsecurity/FireFox-STIG-Script" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/FireFox-STIG-Script" -ForegroundColor Green -BackgroundColor Black 

#https://www.itsupportguides.com/knowledge-base/tech-tips-tricks/how-to-customise-firefox-installs-using-mozilla-cfg/
$firefox64 = "C:\Program Files\Mozilla Firefox"
$firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
Write-Host "Installing Firefox Configurations - Please Wait." -ForegroundColor White -BackgroundColor Black
Write-Host "Window will close after install is complete" -ForegroundColor White -BackgroundColor Black
If (Test-Path -Path $firefox64) {
    Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox64 -Force -Recurse
    Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox64 -Force
    Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox64 -Force 
    Write-Host "Firefox 64-Bit Configurations Installed" -ForegroundColor Green -BackgroundColor Black
}
Else {
    Write-Host "FireFox 64-Bit Is Not Installed" -ForegroundColor Red -BackgroundColor Black
}
If (Test-Path -Path $firefox32) {
    Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox32 -Force -Recurse
    Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox32 -Force
    Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox32 -Force 
    Write-Host "Firefox 32-Bit Configurations Installed" -ForegroundColor Green -BackgroundColor Black
}
Else {
    Write-Host "FireFox 32-Bit Is Not Installed" -ForegroundColor Red -BackgroundColor Black
}

Write-Host "Implementing simeononsecurity/JAVA-STIG-Script" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/JAVA-STIG-Script" -ForegroundColor Green -BackgroundColor Black 

#https://gist.github.com/MyITGuy/9628895
#http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

#<Windows Directory>\Sun\Java\Deployment\deployment.config
#- or -
#<JRE Installation Directory>\lib\deployment.config

If (Test-Path -Path "C:\Windows\Sun\Java\Deployment\deployment.config") {
    Write-Host "JAVA Deployment Config Already Installed" -ForegroundColor Green -BackgroundColor Black
}
Else {
    Write-Host "Installing JAVA Deployment Config...." -ForegroundColor Green -BackgroundColor Black
    Mkdir "C:\Windows\Sun\Java\Deployment\"
    Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.config -Destination "C:\Windows\Sun\Java\Deployment\" -Force
    Write-Host "JAVA Configs Installed" -ForegroundColor White -BackgroundColor Black
}
If (Test-Path -Path "C:\temp\JAVA\") {
    Write-Host "JAVA Configs Already Deployed" -ForegroundColor Green -BackgroundColor Black
}
Else {
    Write-Host "Installing JAVA Configurations...." -ForegroundColor Green -BackgroundColor Black
    Mkdir "C:\temp\JAVA"
    Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.properties -Destination "C:\temp\JAVA\" -Force
    Copy-Item -Path .\Files\"JAVA Configuration Files"\exception.sites -Destination "C:\temp\JAVA\" -Force
    Write-Host "JAVA Configs Installed" -ForegroundColor White -BackgroundColor Black
}

#SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
#https://github.com/simeononsecurity
#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
#https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

Write-Host "Implementing simeononsecurity/.NET-STIG-Script" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/.NET-STIG-Script" -ForegroundColor Green -BackgroundColor Black 

#Setting Netframework path variables
$NetFramework32 = "C:\Windows\Microsoft.NET\Framework"
$NetFramework64 = "C:\Windows\Microsoft.NET\Framework64"

Write-Host "Beginning .NET STIG Script" -ForegroundColor Green -BackgroundColor Black

#Vul ID: V-7055	   	Rule ID: SV-7438r3_rule	   	STIG ID: APPNET0031
#Removing registry value
If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification") {
    Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
    Write-Host ".Net StrongName Verification Registry Removed"
} 
Else {
    Write-Host ".Net StrongName Verification Registry Does Not Exist" -ForegroundColor Green -BackgroundColor Black
}

#Vul ID: V-7061	   	Rule ID: SV-7444r3_rule   	STIG ID: APPNET0046
#The Trust Providers Software Publishing State must be set to 0x23C00.
New-PSDrive HKU Registry HKEY_USERS | Out-Null
ForEach ($UserSID in (Get-ChildItem "HKU:\")) {
    Write-Output $UserSID.Name | ConvertFrom-String -Delimiter "\\" -PropertyNames "PATH", "SID" | Set-Variable -Name "SIDs"
    ForEach ($SID in $SIDs.SID) {
        #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
        If (Test-Path -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\State") {
            Set-ItemProperty -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Value "0x23C00" -Force | Out-Null
            Write-Host "Set Trust Providers Software Publishing State to 146432/0x23C00 for SID $SID" -ForegroundColor White -BackgroundColor Black
        }
        Else {
            New-Item -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Force | Out-Null
            New-ItemProperty -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Value "0x23C00" -Force | Out-Null
            Write-Host "Set Trust Providers Software Publishing State to 146432/0x23C00 for SID $SID" -ForegroundColor White -BackgroundColor Black
        }
    }
}
[gc]::collect()


<#
Creating secure configuration Function. It needs to be called in the
two foreach loops as it has to touch every config file in each
.net framework version folder
#>
Function Set-SecureConfig {
    param (
        $VersionPath,
        $SecureMachineConfigPath
    )
    
    #Declaration and error prevention
    $SecureMachineConfig = $Null
    $MachineConfig = $Null
    [system.gc]::Collect() 
    
    #Getting Secure Machine.Configs
    $SecureMachineConfig = [xml](Get-Content $SecureMachineConfigPath)
        
    #Write-Host "Still using test path at $(Get-CurrentLine)"
    #$MachineConfigPath = "C:\Users\hiden\Desktop\NET-STIG-Script-master\Files\secure.machine - Copy.config"
    $MachineConfigPath = "$VersionPath"
    $MachineConfig = [xml](Get-Content $MachineConfigPath)
    #Ensureing file is closed
    [IO.File]::OpenWrite((Resolve-Path $MachineConfigPath).Path).close()

    <#Apply Machine.conf Configurations
    #Pulled XML assistance from https://stackoverflow.com/questions/9944885/powershell-xml-importnode-from-different-file
    #Pulled more XML details from http://www.maxtblog.com/2012/11/add-from-one-xml-data-to-another-existing-xml-file/
    #>
    Write-Host "Begining work on $MachineConfigPath..." -ForegroundColor White -BackgroundColor Black
   
    # Do out. Automate each individual childnode for infinite nested. Currently only goes two deep
    $SecureChildNodes = $SecureMachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name
    $MachineChildNodes = $MachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name


    #Checking if each secure node is present in the XML file
    ForEach ($SecureChildNode in $SecureChildNodes) {
        #If it is not present, easy day. Add it in.
        If ($SecureChildNode -notin $MachineChildNodes) {
            #Adding node from the secure.machine.config file and appending it to the XML file
            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
            $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
            #Saving changes to XML file
            $MachineConfig.Save($MachineConfigPath)
        }
        Elseif ($MachineConfig.configuration.$SecureChildNode -eq "") {
            #Turns out element sometimes is present but entirely empty. If that is the case we need to remove it
            # and add what we want         
            $MachineConfig.configuration.ChildNodes | Where-Object name -eq $SecureChildNode | ForEach-Object { $MachineConfig.configuration.RemoveChild($_) } | Out-Null
            $MachineConfig.Save($MachineConfigPath)
            #Adding node from the secure.machine.config file and appending it to the XML file            
            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
            $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
            #Saving changes to XML file
            $MachineConfig.Save($MachineConfigPath)
        }
        Else {
            
            #If it is present... we have to check if the node contains the elements we want.
            #Going through each node in secure.machine.config for comparison
            $SecureElements = $SecureMachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name        
            #Pull the Machine.config node and childnode and get the data properties for comparison
            $MachineElements = $MachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name

            #I feel like there has got to be a better way to do this as we're three loops deep
            foreach ($SElement in $SecureElements) {
                #Comparing Element pulled earlier against Machine Elements.  If it's not present we will add it in
                If ($SElement -notin $MachineElements) {
                    #Adding in element that is not present
                    If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -NE "") {
                        $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                        #Saving changes to XML file
                        $MachineConfig.Save($MachineConfigPath)
                    }
                    Else {
                        #This is for when the value declared is empty.
                        $NewNode = $MachineConfig.CreateElement("$SElement")                     
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                        #Saving changes to XML file
                        $MachineConfig.Save($MachineConfigPath)
                    }
                }
                Else {
                    $OldNode = $MachineConfig.SelectSingleNode("//$SElement")
                    $MachineConfig.configuration.$SecureChildNode.RemoveChild($OldNode) | Out-Null
                    $MachineConfig.Save($MachineConfigPath)
                    If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -EQ "") {
                        $NewElement = $MachineConfig.CreateElement("$SElement")
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewElement) | Out-Null
                    }
                    Else {
                        $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                    }
                
                    #Saving changes to XML file
                    $MachineConfig.Save($MachineConfigPath)               
                }#End else
            }#Foreach Element within SecureElements
        }#Else end for an if statement checking if the desired childnode is in the parent file
    }#End of iterating through SecureChildNodes
   
    Write-Host "Merge Complete" -ForegroundColor White -BackgroundColor Black
}


# .Net 32-Bit
ForEach ($DotNetVersion in (Get-ChildItem $netframework32 -Directory)) {
    Write-Host ".Net 32-Bit $DotNetVersion Is Installed" -ForegroundColor Green -BackgroundColor Black
    #Starting .net exe/API to pass configuration Arguments
    If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
        # Comment lines above and uncomment lines below to see output
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
        Write-Host "Set CAS policy for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\SchUseStrongCrypto") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "$DotNetVersion" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }

    <# Source for specifying configs for specific .Net versions
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)
    #>
    
    #Ensuring .net version has machine.config
    If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config") {
        #.net Version testing.
        If (($DotNetVersion -Split "v" )[1] -ge 2) {
            #.net version testing.
            If (($DotNetVersion -Split "v" )[1] -ge 4) {
                Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v4.config"
            }
            else {
                Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v2.config"
            }
        }
        else {
            Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow -BackgroundColor Black
        }#End dotnet version test
    }
    else {
        Write-Host "No Machine.Conf file exists for .Net version $DotNetVersion" -ForegroundColor Red -BackgroundColor Black
    }#End testpath
}

# .Net 64-Bit
ForEach ($DotNetVersion in (Get-ChildItem $netframework64 -Directory)) {  
    Write-Host ".Net 64-Bit $DotNetVersion Is Installed" -ForegroundColor Green -BackgroundColor Black
    #Starting .net exe/API to pass configuration Arguments
    If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
        # Comment lines above and uncomment lines below to see output
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
        Write-Host "Set CAS policy for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "$DotNetVersion" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }

    <# Source for specifying configs for specific .Net versions
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)
    #>
    
    #Ensuring current version has a machine.config to use
    If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config") {
        #version testing
        If (($DotNetVersion -Split "v" )[1] -ge 2) {
            #More version testing.
            If (($DotNetVersion -Split "v" )[1] -ge 4) {
                Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v4.config"
            }
            else {
                Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v2.config"
            }
        }
        else {
            Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow -BackgroundColor Black
        }#End .net version test
    }
    else {
        Write-Host "No Machine.Conf file exists for .Net version $DotNetVersion" -ForegroundColor Red -BackgroundColor Black
    }#End testpath
}

Write-Host "Implementing simeononsecurity/System-Wide-Windows-Ad-Blocker" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker" -ForegroundColor Green -BackgroundColor Black

#Specify host file location
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"

#Use only latest .Net 
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force | Out-Null

    Write-Host "Writing to System Host File...." -ForegroundColor White -BackgroundColor Black
    Try {
        Write-Output "" | Out-File -Encoding ASCII $hosts_file
        Get-Content $PSScriptRoot/Files/hosts.txt | Out-File -Encoding ASCII -Append $hosts_file
        Write-Host "Write Successful.." -ForegroundColor Green -BackgroundColor Black
    }
    Catch {
        Write-Host "Error writing to System Host File...." -ForegroundColor Red -BackgroundColor Black
    }    

Write-Host "Implementing simeononsecurity/Automate-Sysmon" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/Automate-Sysmon" -ForegroundColor Green -BackgroundColor Black 

Start-Process "$($PSScriptRoot)\Files\Sysmon\sysmon.exe" -ArgumentList "-u" -WindowStyle Hidden 
Start-Process "$($PSScriptRoot)\Files\Sysmon\sysmon.exe"  -ArgumentList "-accepteula -i $PSScriptRoot\Files\Sysmon\sysmonconfig-export.xml" -WindowStyle Hidden 

Write-Host "Implementing simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green -BackgroundColor Black 

New-Item -Force -ItemType "Directory" "C:\temp"
Copy-Item $PSScriptRoot\files\auditing\auditbaseline.csv C:\temp\auditbaseline.csv 

#Clear Audit Policy
auditpol /clear /y

#Enforce the Audit Policy Baseline
auditpol /restore /file:C:\temp\auditbaseline.csv

#Confirm Changes
auditpol /list /user /v
auditpol.exe /get /category:*

Write-Host "Importing Group Policies" -ForegroundColor Green -BackgroundColor Black
#GPO Configurations
$gposdir = "$(Get-Location)\Files\GPOs"
Foreach ($gpocategory in Get-ChildItem "$(Get-Location)\Files\GPOs") {
    
    Write-Host "Importing $gpocategory GPOs..." -ForegroundColor White -BackgroundColor Black

    Foreach ($gpo in (Get-ChildItem "$(Get-Location)\Files\GPOs\$gpocategory")) {
        $gpopath = "$gposdir\$gpocategory\$gpo"
        Write-Host "Importing $gpo" -ForegroundColor White -BackgroundColor Black
        .\Files\LGPO\LGPO.exe /g $gpopath > $null 2>&1
        Write-Host "Done" -ForegroundColor Green -BackgroundColor Black
    }
}
Add-Type -AssemblyName PresentationFramework
$Answer = [System.Windows.MessageBox]::Show("Reboot to make changes effective?", "Restart Computer", "YesNo", "Question")
Switch ($Answer) {
    "Yes" { Write-Host "Performing Gpupdate"; Get-Job; Gpupdate /force /boot; Write-Warning "Restarting Computer in 15 Seconds"; Start-sleep -seconds 15; Restart-Computer -Force }
    "No" { Write-Host "Performing Gpupdate" ; Get-Job; Gpupdate /force; Write-Warning "A reboot is required for all changed to take effect" }
    Default { Write-Warning "A reboot is required for all changed to take effect" }
}

Register-ArgumentCompleter @Parameters

Write-Information -MessageData "" -InformationAction Continue
Write-Verbose -Message "ScriptFunct -Functions <tab>" -Verbose
Write-Verbose -Message "ScriptFunct -Functions temp<tab>" -Verbose
Write-Verbose -Message "ScriptFunct -Functions `"DiagTrackService -Disable`", `"DiagnosticDataLevel -Minimal`", UninstallUWPApps" -Verbose
Write-Information -MessageData "" -InformationAction Continue
Write-Verbose -Message "UninstallUWPApps, `"PinToStart -UnpinAll`"" -Verbose
Write-Verbose -Message "`"Set-Association -ProgramPath ```"%ProgramFiles%\Notepad++\notepad++.exe```" -Extension .txt -Icon ```"%ProgramFiles%\Notepad++\notepad++.exe,0```"`"" -Verbose


function RefreshEnvironment
{
	$UpdateEnvironment = @{
		Namespace        = "WinAPI"
		Name             = "UpdateEnvironment"
		Language         = "CSharp"
		MemberDefinition = @"
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
		Add-Type @UpdateEnvironment
	}

	# Simulate pressing F5 to refresh the desktop
	[WinAPI.UpdateEnvironment]::PostMessage()

	# Refresh desktop icons, environment variables, taskbar
	[WinAPI.UpdateEnvironment]::Refresh()

	# Restart the Start menu
	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore

	# Turn on Controlled folder access if it was turned off
	if ($Script:ControlledFolderAccess)
	{
		Set-MpPreference -EnableControlledFolderAccess Enabled
	}

	Write-Information -MessageData "" -InformationAction Continue
	Write-Warning -Message "Make sure to restart your PC"

	<#
		.NOTES
		Load the WinRT.Runtime.dll and Microsoft.Windows.SDK.NET.dll assemblies in the current session in order to get localized UWP apps names

		.LINK
		https://github.com/microsoft/CsWinRT
		https://www.nuget.org/packages/Microsoft.Windows.SDK.NET.Ref
	#>

	Add-Type -AssemblyName "$PSScriptRoot\..\Libraries\WinRT.Runtime.dll"
	Add-Type -AssemblyName "$PSScriptRoot\..\Libraries\Microsoft.Windows.SDK.NET.dll"
}
#endregion Refresh Environment
RefreshEnvironment

# Errors output
function Errors
{
	if ($Global:Error)
	{
		($Global:Error | ForEach-Object -Process {
			# Some errors may have the Windows nature and don't have a path to any of the module's files
			$ErrorInFile = if ($_.InvocationInfo.PSCommandPath)
			{
				Split-Path -Path $_.InvocationInfo.PSCommandPath -Leaf
			}

			[PSCustomObject]@{
				"Line"    = $_.InvocationInfo.ScriptLineNumber
				"File"    = $ErrorInFile
				"Errors/Warnings" = $_.Exception.Message
			}
		} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-String).Trim()
	}
}
Errors
