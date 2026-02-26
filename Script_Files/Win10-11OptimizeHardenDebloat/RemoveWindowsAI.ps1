param(
    [switch]$nonInteractive,
    [ValidateSet('DisableRegKeys',          
        'PreventAIPackageReinstall',     
        'DisableCopilotPolicies',       
        'RemoveAppxPackages',        
        'RemoveRecallFeature', 
        'RemoveCBSPackages',         
        'RemoveAIFiles',               
        'HideAIComponents',            
        'DisableRewrite',       
        'RemoveRecallTasks')]
    [array]$Options,
    [switch]$AllOptions,
    [switch]$revertMode,
    [switch]$backupMode,
    [ValidateSet('photoviewer', 'mspaint', 'snippingtool', 'notepad', 'photoslegacy')]
    [array]$InstallClassicApps,
    [string]$LogFilePath
)

if ($nonInteractive) {
    if (!($AllOptions) -and (!$Options -or $Options.Count -eq 0) -and !($InstallClassicApps)) {
        throw 'Non-Interactive mode was supplied without any options -  Please use -Options or -AllOptions when using Non-Interactive Mode'
        exit
    }
}

$Host.UI.RawUI.WindowTitle = "Remove Windows AI - Win10_11Util"

# Checking whether all files were expanded before running
$ScriptFiles = @(
    "$PSScriptRoot\Localizations\Win10_11Util.psd1",  # Localization file
    "$PSScriptRoot\Module\Win10_11Util.psm1",        # Module definition
    "$PSScriptRoot\Manifest\Win10_11Util.psd1"      # Manifest file
)

if (($ScriptFiles | Test-Path) -contains $false)
{
	Write-Information -MessageData "" -InformationAction Continue
	Write-Warning -Message "There are no files in the script folder. Please, re-download the archive."
	Write-Information -MessageData "" -InformationAction Continue
	exit
}

Remove-Module -Name Win10_11Util -Force -ErrorAction Ignore
try
{
	Import-LocalizedData -BindingVariable Global:Localization -UICulture $PSUICulture -BaseDirectory $PSScriptRoot\Localizations -FileName Win10_11Util -ErrorAction Stop
}
catch
{
	Import-LocalizedData -BindingVariable Global:Localization -UICulture en-US -BaseDirectory $PSScriptRoot\Localizations -FileName Win10_11Util
}

# Checking whether script is the correct PowerShell version
try
{
	Import-Module -Name $PSScriptRoot\Manifest\Win10_11Util.psd1 -PassThru -Force -ErrorAction Stop | Out-Null
}

catch [System.InvalidOperationException]
{
	Write-Warning -Message $Localization.UnsupportedPowerShell
	exit
}

#get powershell version to ensure RunTrusted doesnt enter an infinite loop
$version = $PSVersionTable.PSVersion
if ($version -like '7*') {
    $Global:psversion = 7
}
else {
    $Global:psversion = 5
}

if ($psversion -ge 7) {
    Write-Host 'ERROR: This script requires Windows PowerShell 5.1 (powershell.exe).' -ForegroundColor Red
    Write-Host "You are currently running PowerShell version $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)." -ForegroundColor Red
    Write-Host 'PowerShell 7+ (pwsh.exe) is not supported. Please run the script using the classic Windows PowerShell 5.1.' -ForegroundColor Red
    if (-not $nonInteractive) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show(
                "This script must be run in Windows PowerShell 5.1.`n`nCurrent version: $($PSVersionTable.PSVersion)`n`nPlease use powershell.exe instead of pwsh.exe.",
                'PowerShell Version Error',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        catch { }
    }
    exit 1
}

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    #leave out the trailing " to add supplied params first 
    $arglist = "-NoProfile -ExecutionPolicy Bypass -C `"& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/sdmanson8/scripts/refs/heads/main/Script_Files/Win10-11OptimizeHardenDebloat/Win11/RemoveWindowsAI.ps1')))"
    #pass the correct params if supplied
    if ($nonInteractive) {
        $arglist = $arglist + ' -nonInteractive'

        if ($AllOptions) {
            $arglist = $arglist + ' -AllOptions'
        }

        if ($revertMode) {
            $arglist = $arglist + ' -revertMode'
        }

        if ($backupMode) {
            $arglist = $arglist + ' -backupMode'
        }


        if ($Options -and $Options.count -ne 0) {
            #if options and alloptions is supplied just do all options
            if ($AllOptions) {
                #double check arglist has all options (should already have it)
                if (!($arglist -like '*-AllOptions*')) {
                    $arglist = $arglist + ' -AllOptions'
                }
            }
            else {
                $arglist = $arglist + " -Options $Options"
            }
        }

        if ($InstallClassicApps -and $InstallClassicApps.Count -ne 0) {
            $arglist = $arglist + " -InstallClassicApps $InstallClassicApps"
        }
    }

    #add the trailing quote 
    $arglist = $arglist + '"'
    Start-Process PowerShell.exe -ArgumentList $arglist -Verb RunAs
    Exit	
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

function RunTrusted {
    param(
        [String]$command, 
        $psversion,
        [string]$logFile
        ) 

    function RunAsTI {
        param(
            [Parameter(Position = 0)]$cmd, 
            [Parameter(ValueFromRemainingArguments)]$xargs
        )

        $Ex = $xargs -contains '-Exit'
        $xargs = $xargs | Where-Object { $_ -ne '-Exit' }
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $id = 'RunAsTI'
        $key = "Registry::HKU\$($wi.User.Value)\Volatile Environment"
        $arg = ''
        #$rs = $false
        $csf = Get-PSCallStack | Where-Object { $_.ScriptName -and $_.ScriptName -like '*.ps1' } | Select-Object -l 1
        $cs = if ($csf) { $csf.ScriptName } else { $null }

        if (!$cmd) {
            if ((whoami /groups) -like '*S-1-16-16384*') { return }

            #$rs = $true
            $arr = [Environment]::GetCommandLineArgs()
            $i = [array]::IndexOf($arr, '-File')
            if ($i -lt 0) { 
                $i = [array]::IndexOf($arr, '-f') 
            }

            if ($i -ge 0 -and ($i + 1) -lt $arr.Count) { 
                if (!$cs) { 
                    $cs = $arr[$i + 1] 
                } 

                if (($i + 2) -lt $arr.Count) { 
                    $arg = ($arr[($i + 2)..($arr.Count - 1)] | ForEach-Object { "`"$($_-replace'"','""')`"" }) -join ' ' 
                } 
            }
            else {
                $cp = if ($csf) { $csf.InvocationInfo.BoundParameters } else { Get-Variable PSBoundParameters -sc 1 -va -ea 0 } 

                $ca = if ($csf) { $csf.InvocationInfo.UnboundArguments } else { Get-Variable args -sc 1 -va -ea 0 }

                if ($null -eq $cp) { 
                    $cp = @{} 
                }
                if ($null -eq $ca) { 
                    $ca = @() 
                }

                $arg = (@($cp.GetEnumerator() | ForEach-Object { if (($_.Value -is [switch] -and $_.Value.IsPresent) -or ($_.Value -eq $true)) { "-$($_.Key)" }elseif ($_.Value -isnot [switch] -and $_.Value -ne $true -and $_.Value -ne $false) { "-$($_.Key) `"$($_.Value-replace'"','""')`"" } }) + @($ca | ForEach-Object { "`"$($_-replace'"','""')`"" })) -join ' '
            }

            if ($cs) { 
                $cmd = 'powershell'
                $arg = "-nop -ep bypass -f `"$cs`" $arg" 
            }
            else { 
                $cmd = 'powershell'
                $arg = '-nop -ep bypass' 
            }
        }
        elseif ($xargs) { 
            $arg = $xargs -join ' ' 
        } 

        $V = ''
        'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }

        Set-ItemProperty $key $id $($V, @'
 $I=[int32];$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$P=$I.module.gettype("System.Int`Ptr");$S=[string]
 $D=@();$T=@();$DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1);$Z=[uintptr]::size
 0..5|%{$D+=$DM."Defin`eType"("AveYo_$_",1179913,[ValueType])};$D+=[uintptr];4..6|%{$D+=$D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|%{$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|%{$k=$_;$n=1;$DF[$_-1]|%{$9=$D[$k]."Defin`eField"('f'+$n++,$_,6)}};0..5|%{$T+=$D[$_]."Creat`eType"()}
 0..5|%{nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo};function F($1,$2){$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*S-1-16-16384*';$As=0
 if(!$TI){'TrustedInstaller','lsass','winlogon'|%{if(!$As){$9=sc.exe start $_;$As=@(gps -name $_ -ea 0|%{$_})[0]}}
 function M($1,$2,$3){$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)};$H=@();$Z,(4*$Z+16)|%{$H+=M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle);$A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1
 $A2.f6=$A1;$A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1];M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2-as$D[2]),$A4.f2,$false)
 $Run=@($null,"powershell -win hidden -nop -c iex `$env:R; # $id",0,0,0,0x0E080600,0,$null,($A4-as$T[4]),($A5-as$T[5]))
 F 'CreateProcess' $Run;return};$env:R='';rp $key $id -force;$priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege'|%{$priv.Invoke($null,@("$_",2))}
 $HKU=[uintptr][uint32]2147483651;$NT='S-1-5-18';$reg=($HKU,$NT,8,2,($HKU-as$D[9]));F 'RegOpenKeyEx' $reg;$LNK=$reg[4]
 function L($1,$2,$3){sp 'HKLM\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 L ($key-split'\\')[1] $LNK '';$R=[diagnostics.process]::start($cmd,$arg);if($R){$R.WaitForExit()};L '.Default' $LNK 'Interactive User'
'@) -type 7

        $a = "-win hidden -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R"
        if ($Ex) { 
            $wshell = New-Object -ComObject WScript.Shell
            $exe = 'powershell.exe'
            $wshell.Run("$exe $a", 0, $false) >$null
        }
        else { 
            $wshell = New-Object -ComObject WScript.Shell
            $exe = 'powershell.exe'
            $wshell.Run("$exe $a", 0, $true) >$null # true to -wait
        } 

        # if ($rs -or $Ex) { exit }
    } 
    # lean & mean snippet by AveYo; refined by RapidOS [haslate]

    $psexe = 'PowerShell.exe'

    # If log file not provided, use current
    if (!$logFile -and (Get-LogFilePath)) {
        $logFile = Get-LogFilePath
    }
    
    # Pass log file to the new process
    if ($logFile) {
        $command = @"
`$env:REMOVE_WINDOWS_AI_LOG = '$logFile'
Import-Module '$scriptPath\Logging.psm1' -Force
Set-LogFile -Path `$env:REMOVE_WINDOWS_AI_LOG
$command
"@
    }
    
    # Convert to base64
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)


    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue | Out-Null -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    
    # trusted installer proc not found (128) or access denied (1)
    if ($LASTEXITCODE -eq 128 -or $LASTEXITCODE -eq 1) {
       # LogWarning 'Failed to stop TrustedInstaller.exe -  Using fallback method!'
        RunAsTI $psexe "-win hidden -encodedcommand $base64Command"
        Start-Sleep 1
        return 
    }

    #get bin path to revert later
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    #make sure path is valid and the correct location
    $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
    if ($DefaultBinPath -ne $trustedInstallerPath) {
        $DefaultBinPath = $trustedInstallerPath
    }
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c $psexe -encodedcommand $base64Command" | Out-Null
    #run the command
    sc.exe start TrustedInstaller | Out-Null
    #set bin back to default
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue | Out-Null -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
}

#setup script
#=====================================================================================

function Write-Status {
    param(
        [string]$msg,
        [switch]$errorOutput,
        [switch]$warningOutput
    )
    if ($errorOutput) {
        #Write-Host "[ ! ERROR ] $msg" -ForegroundColor Red
    }
    elseif ($warningOutput) {
        #Write-Host "[ * WARNING ] $msg" -ForegroundColor Yellow
    }
    else {
        Write-Host "$msg" -NoNewline
    }
}

#Log file
# Import logging module
Import-Module -Name "$PSScriptRoot\Module\Logging.psm1" -Force

# Set up logging - priority: parameter > environment > global > default
if ($LogFilePath) {
    Set-LogFile -Path $LogFilePath
    #LogInfo "Using log file from parameter: $LogFilePath"
} elseif ($env:REMOVE_WINDOWS_AI_LOG) {
    Set-LogFile -Path $env:REMOVE_WINDOWS_AI_LOG
    #LogInfo "Using log file from environment: $env:REMOVE_WINDOWS_AI_LOG"
} elseif ($global:LogFilePath) {
    Set-LogFile -Path $global:LogFilePath
    #LogInfo "Using log file from global: $global:LogFilePath"
} else {
    $defaultLog = Join-Path $env:TEMP "Remove Windows AI.txt"
    Set-LogFile -Path $defaultLog
    #LogInfo "Using default log file: $defaultLog"
}

#LogInfo "Child script started with PID: $pid"
#LogInfo "Parameters: nonInteractive=$nonInteractive, revertMode=$revertMode, AllOptions=$AllOptions"

# Helper function to get current log file path
function Get-LogFilePath {
    if ($global:LogFilePath) { return $global:LogFilePath }
    if ($env:REMOVE_WINDOWS_AI_LOG) { return $env:REMOVE_WINDOWS_AI_LOG }
    return $null
}

function Write-FileSafely {
    param(
        [string]$Path,
        [string]$Value,
        [switch]$Append
    )
    
    $mutexName = "Global\RemoveWindowsAILogLock"
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    
    $acquired = $mutex.WaitOne(5000)
    try {
        if ($acquired) {
            if ($Append) {
                Add-Content -Path $Path -Value $Value -Encoding UTF8
            } else {
                Set-Content -Path $Path -Value $Value -Encoding UTF8
            }
        }
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
    }
}

if ($revertMode) {
    $Global:revert = 1
}
else {
    $Global:revert = 0
}

if ($backupMode) {
    $Global:backup = 1
}
else {
    $Global:backup = 0
}

$Global:tempDir = ([System.IO.Path]::GetTempPath())

#=====================================================================================

function CreateRestorePoint {
    param(
        [switch]$nonInteractive
    )

    #check vss service first
    $vssService = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vssService -and $vssService.StartType -eq 'Disabled') {
        try {
            Write-Status -msg 'Enabling VSS Service - '
            LogInfo 'Enabling VSS Service'
            Set-Service -Name 'VSS' -StartupType Manual -ErrorAction SilentlyContinue | Out-Null
            Start-Service -Name 'VSS' -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            LogError 'Unable to Start VSS Service -  Can not create restore point!'
            return
        }
        
    }
    #enable system protection to allow restore points
    $restoreEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if (!$restoreEnabled) {
       # Write-Status -msg 'Enabling Restore Points on System - '
       # LogInfo 'Enabling Restore Points on System'
        Enable-ComputerRestore -Drive "$env:SystemDrive\" 
        
    }

    if ($nonInteractive) {
        #allow restore point to be created even if one was just made
        $restoreFreqPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $restoreFreqKey = 'SystemRestorePointCreationFrequency'
        $currentValue = (Get-ItemProperty -Path $restoreFreqPath -Name $restoreFreqKey -ErrorAction SilentlyContinue).$restoreFreqKey
        if ($currentValue -ne 0) {
            Set-ItemProperty -Path $restoreFreqPath -Name $restoreFreqKey -Value 0 -Force
        }

        $restorePointName = "RemoveWindowsAI-$(Get-Date -Format 'yyyy-MM-dd')"
        Write-Status -msg "Creating Restore Point - "
        LogInfo "Creating Restore Point: [$restorePointName]"
       # Write-Status -msg 'This may take a moment - please wait'
        Checkpoint-Computer -Description $restorePointName -RestorePointType 'MODIFY_SETTINGS' 
        Write-Host "success!" -ForegroundColor Green
    }
    else {
      <#  #Write-Status -msg 'Opening Restore Point Dialog - '
        try {
            $proc = Start-Process 'SystemPropertiesProtection.exe' -ErrorAction SilentlyContinue -PassThru
        }
        catch {
            $proc = Start-Process 'C:\Windows\System32\control.exe' -ArgumentList 'sysdm.cpl ,4' -PassThru
        }
        #click configure on the window
        Start-Sleep 1
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%c') 
        Wait-Process -Id $proc.Id -ErrorAction SilentlyContinue
        #>

        #allow restore point to be created even if one was just made
        $restoreFreqPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $restoreFreqKey = 'SystemRestorePointCreationFrequency'
        $currentValue = (Get-ItemProperty -Path $restoreFreqPath -Name $restoreFreqKey -ErrorAction SilentlyContinue).$restoreFreqKey
        if ($currentValue -ne 0) {
            Set-ItemProperty -Path $restoreFreqPath -Name $restoreFreqKey -Value 0 -Force
        }

        $restorePointName = "RemoveWindowsAI-$(Get-Date -Format 'yyyy-MM-dd')"
        Write-Status -msg "Creating Restore Point - "
        LogInfo "Creating Restore Point: [$restorePointName]"
       # Write-Status -msg 'This may take a moment - please wait'
        Checkpoint-Computer -Description $restorePointName -RestorePointType 'MODIFY_SETTINGS' 
        Write-Host "success!" -ForegroundColor Green
    }

}

function Set-UwpAppRegistryEntry {
    # modified to work in windows powershell from https://github.com/agadiffe/WindowsMize/blob/fe78912ccb1c83d440bd2123f5e43a6156fab31a/src/modules/applications/settings/public/Set-UwpAppSetting.ps1
    <# 
    .SYNOPSIS
        Modifies UWP app registry entries in the settings.dat file.
    
    .EXAMPLE
        PS> $setting = [PSCustomObject]@{
                Name  = 'VideoAutoplay'
                Value = '0'
                Type  = '5f5e10b'
            }
        PS> $setting | Set-UwpAppRegistryEntry -FilePath $FilePath
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,

        [Parameter(Mandatory)]
        [string] $FilePath
    )

    begin {
        $AppSettingsRegPath = 'HKEY_USERS\APP_SETTINGS'
        $RegContent = "Windows Registry Editor Version 5.00`n"

        reg.exe UNLOAD $AppSettingsRegPath 2>&1 | Out-Null

        $max = 30
        $attempts = 0
        $ProcessToStop = @(
            'AppActions'
            'SearchHost'
            'FESearchHost'
            'msedgewebview2'
            'TextInputHost'
            'VisualAssistExe'
            'WebExperienceHostApp'
        )
        Stop-Process -Name $ProcessToStop -Force -ErrorAction SilentlyContinue | Out-Null
        # do while is needed here because wait-process in this case is not working maybe cause its just a trash function lol
        # using microsofts own example found in the docs does not work 
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/wait-process?view=powershell-7.5#example-1-stop-a-process-and-wait

        # since we are trying multiple times while the processes are stopping this will work as soon as the file is freed 
        do {
            reg.exe LOAD $AppSettingsRegPath $FilePath *>$null
            $attempts++
        } while ($LASTEXITCODE -ne 0 -and $attempts -lt $max)
    
        if ($LASTEXITCODE -ne 0) {
            LogError 'Unable to load settings.dat'
            return
        }
      
    }

    process {
        $Value = $InputObject.Value
        $Value = switch ($InputObject.Type) {
            '5f5e10b' { 
                # Single byte for boolean
                '{0:x2}' -f [byte][int]$Value
            }
            '5f5e10c' { 
                # Unicode string 
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value + "`0")
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' ' 
            }
            '5f5e104' { 
                # Int32
                $bytes = [BitConverter]::GetBytes([int]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
            '5f5e105' { 
                # UInt32
                $bytes = [BitConverter]::GetBytes([uint32]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
            '5f5e106' { 
                # Int64
                $bytes = [BitConverter]::GetBytes([int64]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
        }

        $Value = $Value -replace '\s+', ','
    
        # create timestamp for remaining bytes
        $timestampBytes = [BitConverter]::GetBytes([int64](Get-Date).ToFileTime())
        $Timestamp = ($timestampBytes | ForEach-Object { '{0:x2}' -f $_ }) -join ','
    
        # build registry content
        if ($InputObject.Path) {
            $RegKey = $InputObject.Path
        }
        else {
            $RegKey = 'LocalState'
        }
        $RegContent += "`n[$AppSettingsRegPath\$RegKey]
        ""$($InputObject.Name)""=hex($($InputObject.Type)):$Value,$Timestamp`n" -replace '(?m)^ *'
    }

    end {
        $SettingRegFilePath = "$($tempDir)uwp_app_settings.reg"
        $RegContent | Out-File -FilePath $SettingRegFilePath

        reg.exe IMPORT $SettingRegFilePath 2>&1 | Out-Null
        reg.exe UNLOAD $AppSettingsRegPath | Out-Null

        Remove-Item -Path $SettingRegFilePath
    }
}

function Disable-Registry-Keys {
    #maybe add params for particular parts

    #disable ai registry keys
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Copilot and Recall - "
    LogInfo "$(@('Disabling', 'Enabling')[$revert]) Copilot and Recall"
    <#
    #new keys related to windows ai schedled task 
    #npu check 
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'HardwareCompatibility' /t REG_DWORD /d '0' /f 
    #dont know
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'ITManaged' /t REG_DWORD /d '0' /f
    #enabled by windows ai schedled task 
    #set to 1 in the us 
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'AllowedInRegion' /t REG_DWORD /d '0' /f
    #enabled by windows ai schelded task 
    # policy enabled = 1 when recall is enabled in group policy 
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'PolicyConfigured' /t REG_DWORD /d '0' /f
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'PolicyEnabled' /t REG_DWORD /d '0' /f
    #dont know
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'FTDisabledState' /t REG_DWORD /d '0' /f
    #prob the npu check failing
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'MeetsAdditionalDriverRequirements' /t REG_DWORD /d '0' /f
    #sucess from last run 
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'LastOperationKind' /t REG_DWORD /d '2' /f
    #doesnt install recall for me so 0
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'AttemptedInstallCount' /t REG_DWORD /d '0' /f
    #windows build
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'LastBuild' /t REG_DWORD /d '7171' /f
    #5 for no good reason
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /v 'MaxInstallAttemptsAllowed' /t REG_DWORD /d '5' /f
    #>

    if (!$revert) {
        #removing it does not get remade on restart so we will just remove it for now 
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /f *>$null

        Reg.exe delete 'HKCU\Software\Microsoft\Windows\Shell\Copilot' /v 'CopilotLogonTelemetryTime' /f *>$null
        Reg.exe delete 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Copilot_8wekyb3d8bbwe\Copilot.StartupTaskId' /f *>$null
        Reg.exe delete 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId' /f *>$null
        Reg.exe delete 'HKCU\Software\Microsoft\Copilot' /v 'WakeApp' /f *>$null
    }
    
    #set for local machine and current user to be sure
    $hives = @('HKLM', 'HKCU')
    foreach ($hive in $hives) {
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v 'TurnOffWindowsCopilot' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableAIDataAnalysis' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'AllowRecallEnablement' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'TurnOffSavingSnapshots' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableSettingsAgent' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableAgentConnectors' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableAgentWorkspaces' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableRemoteAgentConnectors' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        #only for insiders using enterprise or education as of right now (12/23/25)
        #Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableRecallDataProviders' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat" /v 'IsUserEligible' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v 'IsCopilotAvailable' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v 'CopilotDisabledReason' /t REG_SZ /d @('FeatureIsDisabled', ' ')[$revert] /f *>$null
    }
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Copilot_8wekyb3d8bbwe' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels' /v 'RecordUsageData' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps' /v 'AgentActivationEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCopilotButton' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\input\Settings' /v 'InsightsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\Shell\ClickToDo' /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Write-Host "success!" -ForegroundColor Green
    #remove copilot from search
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Copilot In Windows Search - "
    LogInfo "$(@('Disabling', 'Enabling')[$revert]) Copilot In Windows Search"
    Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchBoxSuggestions' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Write-Host "success!" -ForegroundColor Green
    #disable copilot in edge
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Copilot In Edge - "
    LogInfo "$(@('Disabling', 'Enabling')[$revert]) Copilot In Edge"
    #keeping depreciated policies incase user has older versions of edge

    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotCDPPageContext' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null #depreciated shows Unknown policy in edge://policy
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'HubsSidebarEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeEntraCopilotPageContext' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'Microsoft365CopilotChatIconEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null #depreciated shows Unknown policy in edge://policy
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeHistoryAISearchEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ComposeInlineEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'GenAILocalFoundationalModelSettings' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'BuiltInAIAPIsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AIGenThemesEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'DevToolsGenAiSettings' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShareBrowsingHistoryWithCopilotSearchAllowed' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable edge copilot mode 
    # "enabled_labs_experiments":["edge-copilot-mode@2"]
    # view flags at edge://flags
    taskkill.exe /im msedge.exe /f *>$null
    $config = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
    if (Test-Path $config) {
        #powershell core bug where json that has empty strings will error
        try {
            $jsonContent = (Get-Content $config).Replace('""', '"_empty"') | ConvertFrom-Json -ErrorAction Stop
            $fail = $false
        }
        catch {
            LogError 'Unable to set Edge flags to disable Copilot due to a different langauge being used'
            LogError 'You can manually disable the Copilot flags at [edge://flags] in the browser'
            $fail = $true
        }
        
        if (!$fail) {
            try {
                if ($null -eq ($jsonContent.browser | Get-Member -MemberType NoteProperty enabled_labs_experiments -ErrorAction SilentlyContinue)) {
                    $jsonContent.browser | Add-Member -MemberType NoteProperty -Name enabled_labs_experiments -Value @() -ErrorAction SilentlyContinue
                    }
                $flags = @(
                    'edge-copilot-mode@2', 
                    'edge-ntp-composer@2', #disables the copilot search in new tab page 
                    'edge-compose@2' #disables the ai writing help 
                )
                if ($revert) {
                    $jsonContent.browser.enabled_labs_experiments = $jsonContent.browser.enabled_labs_experiments | Where-Object { $_ -notin $flags }
                }
                else {
                    foreach ($flag in $flags) {
                        if ($jsonContent.browser.enabled_labs_experiments -notcontains $flag) {
                            $jsonContent.browser.enabled_labs_experiments += $flag
                        }
                    }
                }
        
                $newContent = $jsonContent | ConvertTo-Json -Compress -Depth 10 
                #add back the empty strings 
                $newContent = $newContent.replace('"_empty"', '""')
                Set-Content $config -Value $newContent -Encoding UTF8 -Force -ErrorAction SilentlyContinue
            }
            catch {
                #LogError 'Edge Browser has never been opened on this machine unable to set flags '
                #LogError 'Open Edge once and run this tweak again'
            }
        }
        
    }
   
    #disable office ai with group policy
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\training\general' /v 'disabletraining' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\training\specific\adaptivefloatie' /v 'disabletrainingofadaptivefloatie' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable connected experiences in office should prevent copilot from working 
    Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\common\privacy' /v 'controllerconnectedservicesenabled' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\common\privacy' /v 'usercontentdisabled' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    #disable copilot buttons in word
    #Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\word\disabledcmdbaritemslist' /v 'TCID1' /t REG_SZ /d '47229' /f
    #Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\word\disabledcmdbaritemslist' /v 'TCID2' /t REG_SZ /d '43223' /f
    #Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\word\disabledcmdbaritemslist' /v 'TCID3' /t REG_SZ /d '34872' /f
    #Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\word\disabledcmdbaritemslist' /v 'TCID4' /t REG_SZ /d '42552' /f
    #disable copilot in word
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\Word\Options' /v 'EnableCopilot' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot in excel
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\Excel\Options' /v 'EnableCopilot' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot in onenote
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\OneNote\Options\Copilot' /v 'CopilotEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\OneNote\Options\Copilot' /v 'CopilotNotebooksEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\OneNote\Options\Copilot' /v 'CopilotSkittleEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable office ai content safety
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\general' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\alternativetext' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\imagequestionandanswering' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\promptassistance' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\rewrite' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\summarization' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\summarizationwithreferences' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\texttotable' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable additional keys
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'AutoOpenCopilotLargeScreens' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI' /v 'Value' /t REG_SZ /d @('Deny', 'Allow')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels' /v 'Value' /t REG_SZ /d @('Deny', 'Allow')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessGenerativeAI' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessSystemAIModels' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot' /v 'AllowCopilotRuntime' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'CopilotPWAPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'RecallPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot background app access 
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe' /v 'DisabledByUser' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe' /v 'Disabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe' /v 'SleepDisabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'DisabledByUser' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'Disabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'SleepDisabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable for all users
    $sids = (Get-ChildItem 'registry::HKEY_USERS').Name | Where-Object { $_ -like 'HKEY_USERS\S-1-5-21*' -and $_ -notlike '*Classes*' } 
    foreach ($sid in $sids) {
        Reg.exe add "$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v 'CopilotPWAPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v 'RecallPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    }
    #disable ai actions
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1853569164' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\4098520719' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\929719951' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #enable new feature to hide ai actions in context menu when none are avaliable 
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1646260367' /v 'EnabledState' /t REG_DWORD /d @('2', '0')[$revert] /f *>$null
    #disable additional ai velocity ids found from: https://github.com/phantomofearth/windows-velocity-feature-lists
    #keep in mind these may or may not do anything depending on the windows build 
    #disable copilot nudges
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1546588812' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\203105932' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\2381287564' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\3189581453' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\3552646797' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable copilot in taskbar and systray
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\3389499533' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\4027803789' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\450471565' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #enable removing ai componets (not sure what this does yet)
    #Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\2931206798' /v 'EnabledState' /t REG_DWORD /d '2' /f
    #Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\3098978958' /v 'EnabledState' /t REG_DWORD /d '2' /f
    #Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\3233196686' /v 'EnabledState' /t REG_DWORD /d '2' /f
    #disable core ai / click to do with feature management 
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\2283032206' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\502943886' /v 'EnabledState' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable ask copilot (taskbar search)
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarCompanion' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\Shell\BrandedKey' /v 'BrandedKeyChoiceType' /t REG_SZ /d @('Search', 'App')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\Shell\BrandedKey' /v 'AppAumid' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
    Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CopilotKey' /v 'SetCopilotHardwareKey' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
    #disable recall customized homepage 
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers' /v 'A9HomeContentEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable typing data harvesting for ai training 
    Reg.exe add 'HKCU\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization' /v 'Value' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #hide copilot ads in settings home page 
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableConsumerAccountStateContent' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable office hub startup
    Reg.exe add 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId' /v 'State' /t REG_DWORD /d @('1', '2')[$revert] /f *>$null
    Write-Host "success!" -ForegroundColor Green
    #disable ai image creator in paint
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Image Creator In Paint - "
    LogInfo "$(@('Disabling', 'Enabling')[$revert]) Image Creator In Paint"
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableImageCreator' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableCocreator' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableGenerativeFill' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableGenerativeErase' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableRemoveBackground' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    # disable experimental agentic features
    # Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IsoEnvBroker" /v "Enabled" /t REG_DWORD /d "0" /f
    # Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\IsoEnvBroker" /v "Enabled" /t REG_DWORD /d "0" /f
    # leaving commented since its still only in preview builds

    #apply reg keys for default user to disable for any new users created
    #unload just incase
    [GC]::Collect()
    reg.exe unload 'HKU\DefaultUser' *>$null
    try {
        reg.exe load 'HKU\DefaultUser' "$env:SystemDrive\Users\Default\NTUSER.DAT" >$null
        $hiveloaded = $true
    }
    catch {
        LogError 'Unable to Load Default User Hive'
        $hiveloaded = $false
    }
    Write-Host "success!" -ForegroundColor Green
    if ($hiveloaded) {
        Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) AI for new users - " 
        LogInfo "$(@('Disabling', 'Enabling')[$revert]) AI for new users"
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' /v 'TurnOffWindowsCopilot' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAIDataAnalysis' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'AllowRecallEnablement' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'TurnOffSavingSnapshots' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableSettingsAgent' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAgentConnectors' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAgentWorkspaces' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableRemoteAgentConnectors' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat' /v 'IsUserEligible' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\Shell\Copilot' /v 'IsCopilotAvailable' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\Shell\Copilot' /v 'CopilotDisabledReason' /t REG_SZ /d @('FeatureIsDisabled', ' ')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Copilot_8wekyb3d8bbwe' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps' /v 'AgentActivationEnabled' /t REG_DWORD /d @('0', '1')[$revert]  /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCopilotButton' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\input\Settings' /v 'InsightsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\Shell\ClickToDo' /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchBoxSuggestions' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot' /v 'AllowCopilotRuntime' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'CopilotPWAPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'RecallPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarCompanion' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\Shell\BrandedKey' /v 'BrandedKeyChoiceType' /t REG_SZ /d @('Search', 'App')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\Shell\BrandedKey' /v 'AppAumid' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\CopilotKey' /v 'SetCopilotHardwareKey' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers' /v 'A9HomeContentEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization' /v 'Value' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        if ($revert) {
            Reg.exe delete 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}' /f *>$null
        }
        else {
            Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}' /t REG_SZ /d 'Ask Copilot' /f *>$null
        }

        reg.exe unload 'HKU\DefaultUser' *>$null
    }

    #disable ask copilot in context menu
    if ($revert) {
        Reg.exe delete 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}' /f *>$null
    }
    else {
        Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}' /t REG_SZ /d 'Ask Copilot' /f *>$null
    }
    #Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WSAIFabricSvc' /v 'Start' /t REG_DWORD /d @('4', '2')[$revert] /f *>$null
    try {
        Stop-Service -Name WSAIFabricSvc -Force -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        #ignore error when svc is already removed
    }
    Write-Host "success!" -ForegroundColor Green
    $backupPath = "$PSScriptRoot\RemoveWindowsAI\Backup"
    $backupFileWSAI = 'WSAIFabricSvc.reg'
    $backupFileAAR = 'AARSVC.reg'
    if ($revert) {
        if (Test-Path "$backupPath\$backupFileWSAI") {
            Reg.exe import "$backupPath\$backupFileWSAI" *>$null
            sc.exe create WSAIFabricSvc binPath= "$env:windir\System32\svchost.exe -k WSAIFabricSvcGroup -p" *>$null
        }
        else {
            LogError "Path Not Found: $backupPath\$backupFileWSAI"
        }
        
    }
    else {
        if ($backup) {
            Write-Status -msg 'Backing up WSAIFabricSvc - '
            LogInfo 'Backing up WSAIFabricSvc'
            #export the service to a reg file before removing it 
            if (!(Test-Path $backupPath)) {
                New-Item $backupPath -Force -ItemType Directory | Out-Null
            }
            #this will hang if the service has already been exported
            # if (!(Test-Path "$backupPath\$backupFileWSAI")) {
            Reg.exe export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSAIFabricSvc' "$backupPath\$backupFileWSAI" /y > $null 2>&1 #add overwrite file /y switch
            # }
            Write-Host "success!" -ForegroundColor Green
        }
        Write-Status -msg 'Removing WSAIFabricSvc - '
        LogInfo 'Removing WSAIFabricSvc'
        #delete the service
        sc.exe delete WSAIFabricSvc *>$null
        Write-Host "success!" -ForegroundColor Green
    }
    if (!$revert) {
        #remove conversational agent service (used to be used for cortana, prob going to be updated for new ai agents and copilot)
        try {
            $aarSVCName = (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.name -like '*aarsvc*' }).Name
        }
        catch {
            #aarsvc already removed
        }
        

        if ($aarSVCName) {
            if ($backup) {
                Write-Status -msg 'Backing up Agent Activation Runtime Service - '
                LogInfo 'Backing up Agent Activation Runtime Service'
                #export the service to a reg file before removing it 
                if (!(Test-Path $backupPath)) {
                    New-Item $backupPath -Force -ItemType Directory | Out-Null
                }
                #this will hang if the service has already been exported
                # if (!(Test-Path "$backupPath\$backupFileAAR")) {
                Reg.exe export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc' "$backupPath\$backupFileAAR" /y > $null 2>&1
                # }
                Write-Host "success!" -ForegroundColor Green
            }
            Write-Status -msg 'Removing Agent Activation Runtime Service - '
            LogInfo 'Removing Agent Activation Runtime Service'
            #delete the service
            try {
                Stop-Service -Name $aarSVCName -Force -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                try {
                    Stop-Service -Name AarSvc -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    #neither are running
                }
                
            }
            
            sc.exe delete AarSvc *>$null
            Write-Host "success!" -ForegroundColor Green
        }
    }
    else {
        Write-Status 'Restoring Agent Activation Runtime Service - '
        LogInfo 'Restoring Agent Activation Runtime Service'

        if (Test-Path "$backupPath\$backupFileAAR") {
            Reg.exe import "$backupPath\$backupFileAAR" *>$null
            sc.exe create AarSvc binPath= "$env:windir\system32\svchost.exe -k AarSvcGroup -p" *>$null
        }
        else {
            LogError "Path Not Found: $backupPath\$backupFileAAR"
        }
        Write-Host "success!" -ForegroundColor Green
    }
  
    #block copilot from communicating with server
    if ($revert) {
        Write-Status -msg 'Adding .copilot File Extension - ' 
        LogInfo 'Adding .copilot File Extension'
        if ((Test-Path "$backupPath\HKCR_Copilot.reg") -or (Test-Path "$backupPath\HKCU_Copilot.reg")) {
            Reg.exe import "$backupPath\HKCR_Copilot.reg" *>$null
            Reg.exe import "$backupPath\HKCU_Copilot.reg" *>$null
        }
        else {
           # LogInfo -msg "Unable to Find HKCR_Copilot.reg or HKCU_Copilot.reg in [$backupPath]"  
        }
        Write-Host "success!" -ForegroundColor Green
    }
    else {
        if ($backup) {
            #backup .copilot file extension
            Reg.exe export 'HKEY_CLASSES_ROOT\.copilot' "$backupPath\HKCR_Copilot.reg" /y *>$null
            Reg.exe export 'HKEY_CURRENT_USER\Software\Classes\.copilot' "$backupPath\HKCU_Copilot.reg" /y *>$null
        }
        Write-Status -msg 'Removing .copilot File Extension - ' 
        LogInfo 'Removing .copilot File Extension'
        Reg.exe delete 'HKCU\Software\Classes\.copilot' /f *>$null
        Reg.exe delete 'HKCR\.copilot' /f *>$null
        Write-Host "success!" -ForegroundColor Green
    }

    #disabling and removing voice access, recently added ai powered
    Reg.exe add 'HKCU\Software\Microsoft\VoiceAccess' /v 'RunningState' /t REG_DWORD /d @('0', '1')[$revert] /f >$null
    Reg.exe add 'HKCU\Software\Microsoft\VoiceAccess' /v 'TextCorrection' /t REG_DWORD /d @('1', '2')[$revert] /f >$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp' /v @('0', '1')[$revert] /t REG_DWORD /d '0' /f >$null
    $startMenu = "$env:appdata\Microsoft\Windows\Start Menu\Programs\Accessibility"
    $voiceExe = "$env:windir\System32\voiceaccess.exe"
    if ($backup) {
        Write-Status -msg 'Backing up Voice Access - '
        LogInfo 'Backing up Voice Access'
        if (!(Test-Path $backupPath)) {
            New-Item $backupPath -Force -ItemType Directory | Out-Null
        }
        Copy-Item $voiceExe -Destination $backupPath -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item "$startMenu\VoiceAccess.lnk" -Destination $backupPath -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "success!" -ForegroundColor Green
    }
    
    if ($revert) {
        if ((Test-Path "$backupPath\VoiceAccess.exe") -and (Test-Path "$backupPath\VoiceAccess.lnk")) {
            Write-Status -msg 'Restoring Voice Access - '
           LogInfo 'Restoring Voice Access'
            Move-Item "$backupPath\VoiceAccess.exe" -Destination "$env:windir\System32" -Force | Out-Null
            Move-Item "$backupPath\VoiceAccess.lnk" -Destination $startMenu -Force | Out-Null
            Write-Host "success!" -ForegroundColor Green
        }
        else {
           LogError 'Voice Access Backup NOT Found!' 
        }
        
    }
    else {
        Write-Status -msg 'Removing Voice Access - '
        LogInfo 'Removing Voice Access'
        $command = "Remove-item -path $env:windir\System32\voiceaccess.exe -force -ErrorAction SilentlyContinue -Recurse | Out-Null"
        RunTrusted -command $command -psversion $psversion -logFile $logFile
        Start-Sleep 1
        Remove-Item "$startMenu\VoiceAccess.lnk" -Force -ErrorAction SilentlyContinue
        Write-Host "success!" -ForegroundColor Green
    }
    
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture'
    $allFX = (Get-ChildItem $root -Recurse).Name | Where-Object { $_ -like '*FxProperties' }
    #search the fx props for VocalEffectPack and add {1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5 = 1
    foreach ($fxPath in $allFX) {
        $keys = Get-ItemProperty "registry::$fxPath"
        foreach ($key in $keys) {
            if ($key | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -like '{*},*' } | Where-Object { $_.Definition -like '*#VocaEffectPack*' }) {
                Write-Status -msg "$(@('Disabling','Enabling')[$revert]) AI Voice Effects - "
                LogInfo "$(@('Disabling','Enabling')[$revert]) AI Voice Effects"
                $regPath = Convert-Path $key.PSPath
                if ($revert) {
                    #enable
                    $command = "Reg.exe delete '$regPath' /v '{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5' /f"
                    RunTrusted -command $command -psversion $psversion -logFile $logFile
                }
                else {
                    #disable
                    $command = "Reg.exe add '$regPath' /v '{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5' /t REG_DWORD /d '1' /f"
                    RunTrusted -command $command -psversion $psversion -logFile $logFile
                }
            Write-Host "success!" -ForegroundColor Green    
            }
        }
    }

    #disable gaming copilot 
    #found from: https://github.com/meetrevision/playbook/issues/197
    #not sure this really does anything in my testing gaming copilot still appears 
    if ($revert) {
        $command = "reg delete 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions' /f"
        RunTrusted -command $command -psversion $psversion -logFile $logFile
    }
    else {
        $command = "reg add 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions' /v 'ActivationType' /t REG_DWORD /d 0 /f;
    reg add 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions' /v 'Server' /t REG_SZ /d `" `" /f
    "
        RunTrusted -command $command -psversion $psversion -logFile $logFile
    }
    

    #remove windows ai dll contracts 
    $command = "
    Reg delete 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\WellKnownContracts' /v 'Windows.AI.Actions.ActionsContract' /f
    Reg delete 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\WellKnownContracts' /v 'Windows.AI.Agents.AgentsContract' /f
    Reg delete 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\WellKnownContracts' /v 'Windows.AI.MachineLearning.MachineLearningContract' /f 
    Reg delete 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\WellKnownContracts' /v 'Windows.AI.MachineLearning.Preview.MachineLearningPreviewContract' /f
    "
    RunTrusted -command $command -psversion $psversion -logFile $logFile

    #disable ai setting in uwp photos app
    $uwpPhotosSettings = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\Settings\settings.dat"
    if (Test-Path $uwpPhotosSettings) {
        [GC]::Collect()
        reg.exe unload 'HKU\TEMP' *>$null
        taskkill /im photos.exe /f *>$null
        reg.exe load HKU\TEMP $uwpPhotosSettings >$null
        if (!$revert) {
            $regContent = @'
Windows Registry Editor Version 5.00

[HKEY_USERS\TEMP\LocalState] 
"ImageCategorizationConsentDismissed"=hex(5f5e10c):74,00,72,00,75,00,65,00,00,\
  00,4c,a0,89,0c,f7,2e,dc,01
"ImageCategorizationConsent"=hex(5f5e10c):66,00,61,00,6c,00,73,00,65,00,00,00,\
  6c,c4,53,ae,c5,51,dc,01
'@
        }
        else {
            $regContent = @'
Windows Registry Editor Version 5.00

[HKEY_USERS\TEMP\LocalState]
"ImageCategorizationConsentDismissed"=hex(5f5e10c):74,00,72,00,75,00,65,00,00,\
  00,4c,a0,89,0c,f7,2e,dc,01
"ImageCategorizationConsent"=hex(5f5e10c):74,00,72,00,75,00,65,00,00,00,79,e7,\
  fe,c5,c4,51,dc,01
'@
        }
       
        
        New-Item "$($tempDir)DisableAIPhotos.reg" -Value $regContent -Force >$null
        regedit.exe /s "$($tempDir)DisableAIPhotos.reg" >$null
        Start-Sleep 1
        reg unload HKU\TEMP >$null
        Remove-Item "$($tempDir)DisableAIPhotos.reg" -Force -ErrorAction SilentlyContinue >$null
    }

    #disable app actions
    #method credit : https://github.com/agadiffe/WindowsMize
    $settingsDat = "$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Settings\settings.dat"

    if (Test-Path $settingsDat) {
        Write-Status -msg "$(@('Disabling','Enabling')[$revert]) App Actions - "
        LogInfo "$(@('Disabling','Enabling')[$revert]) App Actions"

        $apps = @(
            'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' 
            'Microsoft.Office.ActionsServer_8wekyb3d8bbwe' 
            'MSTeams_8wekyb3d8bbwe' 
            'Microsoft.Paint_8wekyb3d8bbwe' 
            'Microsoft.Windows.Photos_8wekyb3d8bbwe'
            'MicrosoftWindows.Client.CBS_cw5n1h2txyewy' #describe image (system)
        )
     
        foreach ($app in $apps) {
            $setting = [PSCustomObject]@{
                Name  = $app
                Path  = 'LocalState\DisabledApps'
                Value = @('1', '0')[$revert] # 1 = disable    0 = enable
                Type  = '5f5e10b'
            }
            
            $setting | Set-UwpAppRegistryEntry -FilePath $settingsDat
        }
        Write-Host "success!" -ForegroundColor Green
    }
    

    #force policy changes
    #Write-Status -msg 'Applying Registry Changes'
    LogInfo "Applying Registry Changes"
    gpupdate /force /wait:0 >$null


}

function Install-NOAIPackage {
    
    if (!$revert) {
        $package = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*SdManson8*' }
        if (!$package) {
            #check cpu arch
            $arm = ((Get-CimInstance -Class Win32_ComputerSystem).SystemType -match 'ARM64') -or ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64')
            $arch = if ($arm) { 'arm64' } else { 'amd64' }
            #add cert to registry
            $certRegPath = 'HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344'
            if (!(Test-Path "$certRegPath")) {
                New-Item -Path $certRegPath -Force >$null
            }

            #check if script is being ran locally 
            if ((Test-Path "$PSScriptRoot\RemoveWindowsAIPackage\amd64") -and (Test-Path "$PSScriptRoot\RemoveWindowsAIPackage\arm64")) {
                #Write-Status -msg 'RemoveWindowsAI Packages Found Locally'
                LogInfo "RemoveWindowsAI Packages Found Locally"
                #Write-Status -msg 'Installing RemoveWindowsAI Package'
                LogInfo "Installing RemoveWindowsAI Package"

                try {
                    Add-WindowsPackage `
                         -Online `
                         -PackagePath "$PSScriptRoot\RemoveWindowsAIPackage\$arch\SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" `
                         -NoRestart `
                         -IgnoreCheck `
                         -ErrorAction SilentlyContinue `
                         *> $null
                }
                catch {
                    #user is using powershell 7 use dism command as fallback
                    dism.exe /Online /Add-Package /PackagePath:"$PSScriptRoot\RemoveWindowsAIPackage\$arch\SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" -NoRestart -IgnoreCheck -ErrorAction SilentlyContinue >$null
                }
            }
            else {
                #Write-Status -msg 'Downloading RemoveWindowsAI Package From Github'
                LogInfo "Downloading RemoveWindowsAI Package From Github"

                $ProgressPreference = 'SilentlyContinue'
                try {
                    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/tree/main/Script_Files/Win10-11OptimizeHardenDebloat/RemoveWindowsAIPackage/$arch/SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" -OutFile "$($tempDir)SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    LogError "Unable to Download Package at: https://github.com/sdmanson8/scripts/tree/main/Script_Files/Win10-11OptimizeHardenDebloat/RemoveWindowsAIPackage/$arch/SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" 
                    return
                }

                #Write-Status -msg 'Installing RemoveWindowsAI Package'
                LogInfo "Installing RemoveWindowsAI Package"
                try {
                    Add-WindowsPackage `
                         -Online `
                         -PackagePath "$($tempDir)SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" `
                         -NoRestart `
                         -IgnoreCheck `
                         -ErrorAction SilentlyContinue `
                         *> $null
                }
                catch {
                    dism.exe /Online /Add-Package /PackagePath:"$($tempDir)SdManson8RemoveWindowsAI-$($arch)1.0.0.0.cab" -IgnoreCheck -ErrorAction SilentlyContinue >$null
                }
            }
        }
        else {
            LogError 'Update package already installed'
        }

       # Write-Status -msg 'Checking update package install status - '
        LogInfo "Checking update package install status"
        $package = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*SdManson8*' }
        if ($package.PackageState -eq 'InstallPending') {
            LogError 'Package installed incorrectly -  Uninstalling!'
            try {
                Remove-WindowsPackage -Online -PackageName $package.PackageName -NoRestart -IgnoreCheck -ErrorAction SilentlyContinue >$null
            }
            catch {
                dism.exe /Online /remove-package /PackageName:$($package.PackageName) -NoRestart -IgnoreCheck -ErrorAction SilentlyContinue >$null
            }
            #remove reg install location 
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
            Get-ChildItem $regPath | ForEach-Object {
                $value = try { Get-ItemProperty "registry::$($_.Name)" -ErrorAction SilentlyContinue } catch { $null }
                if ($value -and $value.PSPath -like '*SdManson8*') {
                    Remove-Item -Path $value.PSPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }
    else {
        
        $package = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*SdManson8*' }
        if ($package) {
            Write-Status 'Removing Custom Windows Update Package - ' 
            LogInfo 'Removing Custom Windows Update Package'
            try {
                Remove-WindowsPackage -Online -PackageName $package.PackageName -NoRestart -IgnoreCheck -ErrorAction SilentlyContinue >$null
            }
            catch {
                dism.exe /Online /remove-package /PackageName:$($package.PackageName) -NoRestart -IgnoreCheck -ErrorAction SilentlyContinue >$null
            }
            #remove reg install location 
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
            Get-ChildItem $regPath | ForEach-Object {
                $value = try { Get-ItemProperty "registry::$($_.Name)" -ErrorAction SilentlyContinue } catch { $null }
                if ($value -and $value.PSPath -like '*SdManson8*') {
                    Remove-Item -Path $value.PSPath -Recurse -Force -ErrorAction SilentlyContinue| Out-Null
                }
            }
            Write-Host "success!" -ForegroundColor Green
        }
        else {
            LogError 'Unable to Find Update Package'
        }
        
    }

}  
    
function Disable-Copilot-Policies {
    #disable copilot policies in region policy json
    $JSONPath = "$env:windir\System32\IntegratedServicesRegionPolicySet.json"
    if (Test-Path $JSONPath) {
       # Write-Host "$(@('Disabling','Enabling')[$revert]) CoPilot Policies in " -NoNewline -ForegroundColor Cyan
       # Write-Host "[$JSONPath]" -ForegroundColor Yellow
        LogInfo "$(@('Disabling','Enabling')[$revert]) CoPilot Policies in [$JSONPath]"

        #takeownership
        takeown /f $JSONPath *>$null
        icacls $JSONPath /grant *S-1-5-32-544:F /t *>$null

        #edit the content
        $jsonContent = Get-Content $JSONPath | ConvertFrom-Json
        try {
            $copilotPolicies = $jsonContent.policies | Where-Object { $_.'$comment' -like '*CoPilot*' }
            foreach ($policies in $copilotPolicies) {
                $policies.defaultState = @('disabled', 'enabled')[$revert]
            }
            $recallPolicies = $jsonContent.policies | Where-Object { $_.'$comment' -like '*A9*' -or $_.'$comment' -like '*Manage Recall*' -or $_.'$comment' -like '*Settings Agent*' }
            foreach ($recallPolicy in $recallPolicies) {
                if ($recallPolicy.'$comment' -like '*A9*') {
                    $recallPolicy.defaultState = @('enabled', 'disabled')[$revert]
                }
                elseif ($recallPolicy.'$comment' -like '*Manage Recall*') {
                    $recallPolicy.defaultState = @('disabled', 'enabled')[$revert]
                }
                elseif ($recallPolicy.'$comment' -like '*Settings Agent*') {
                    $recallPolicy.defaultState = @('enabled', 'disabled')[$revert]
                }
            }
            $newJSONContent = $jsonContent | ConvertTo-Json -Depth 100
            Set-Content $JSONPath -Value $newJSONContent -Force
            $total = ($copilotPolicies.count) + ($recallPolicies.count)
            Write-Status -msg "CoPilot Policies $(@('Disabled','Enabled')[$revert]) - " 
            LogInfo "$total CoPilot Policies $(@('Disabled','Enabled')[$revert])"
            Write-Host "success!" -ForegroundColor Green
        }
        catch {
            LogError 'CoPilot Not Found in IntegratedServicesRegionPolicySet'
        }

    
    }

    #additional json path for visual assist 
    $visualAssistPath = "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssist\VisualAssistActions.json"
    if (Test-Path $visualAssistPath) {
        Write-Status -msg "$(@('Disabling','Enabling')[$revert]) Generative AI in Visual Assist - "
        LogInfo "$(@('Disabling','Enabling')[$revert]) Generative AI in Visual Assist"

        takeown /f $visualAssistPath *>$null
        icacls $visualAssistPath /grant *S-1-5-32-544:F /t *>$null

        $jsoncontent = Get-Content $visualAssistPath | ConvertFrom-Json
        $jsonContent.actions | Add-Member -MemberType NoteProperty -Name usesGenerativeAI -Value @($false, $true)[$revert] -force
        $newJSONContent = $jsonContent | ConvertTo-Json -Depth 100
        Set-Content $visualAssistPath -Value $newJSONContent -Force
        Write-Host "success!" -ForegroundColor Green
    }
    
}

#function from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Wrapper-Functions/DownloadAppxPackage-Function.ps1
function DownloadAppxPackage {
    param(
        # there has to be an alternative, as sometimes the API fails on PackageFamilyName
        [string]$PackageFamilyName,
        [string]$ProductId,
        [string]$outputDir
    )
    if (-Not ($PackageFamilyName -Or $ProductId)) {
        # can't do anything without at least one
        LogError 'Missing either PackageFamilyName or ProductId.'
        return $null
    }
      
    try {
        $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome # needed as sometimes the API will block things when it knows requests are coming from PowerShell
    }
    catch {
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
      
    $DownloadedFiles = @()
    $errored = $false
    $allFilesDownloaded = $true
      
    $apiUrl = 'https://store.rg-adguard.net/api/GetFiles'
    $versionRing = 'Retail'
      
    $architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
        'x86' { 'x86' }
        { @('x64', 'amd64') -contains $_ } { 'x64' }
        'arm' { 'arm' }
        'arm64' { 'arm64' }
        default { 'neutral' } # should never get here
    }
      
    if (Test-Path $outputDir -PathType Container) {
        New-Item -Path "$outputDir\$PackageFamilyName" -ItemType Directory -Force | Out-Null
        $downloadFolder = "$outputDir\$PackageFamilyName"
    }
    else {
        
        $downloadFolder = Join-Path $tempDir $PackageFamilyName
        if (!(Test-Path $downloadFolder -PathType Container)) {
            New-Item $downloadFolder -ItemType Directory -Force | Out-Null
        }
    }
        
    $body = @{
        type = if ($ProductId) { 'ProductId' } else { 'PackageFamilyName' }
        url  = if ($ProductId) { $ProductId } else { $PackageFamilyName }
        ring = $versionRing
        lang = 'en-US'
    }

    $headers = @{
        'User-Agent'       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        'Accept'           = 'application/json, text/javascript, */*; q=0.01'
        'Content-Type'     = 'application/x-www-form-urlencoded; charset=UTF-8'
        'X-Requested-With' = 'XMLHttpRequest'
        'Origin'           = 'https://store.rg-adguard.net'
        'Referer'          = 'https://store.rg-adguard.net/'
    }
      
    # required due to the api being protected behind Cloudflare now
    if (-Not $apiWebSession) {
        $global:apiWebSession = $null
        $apiHostname = (($apiUrl.split('/'))[0..2]) -Join '/'
        Invoke-WebRequest -Uri $apiHostname -UserAgent $UserAgent -SessionVariable $apiWebSession -UseBasicParsing 
    }
      
    $raw = $null
    try {
        $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $body -WebSession $apiWebSession
    }
    catch {
        $errorMsg = 'An error occurred: ' + $_
        LogError $errorMsg
        $errored = $true
        return $false
    }
      
    # hashtable of packages by $name
    #  > values = hashtables of packages by $version
    #    > values = arrays of packages as objects (containing: url, filename, name, version, arch, publisherId, type)
    [Collections.Generic.Dictionary[string, Collections.Generic.Dictionary[string, array]]] $packageList = @{}
    # populate $packageList
    $patternUrlAndText = '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*\.(app|msi)x.*)<\/a>'
    $raw | Select-String $patternUrlAndText -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object {
        $url = ($_.Groups['url']).Value
        $text = ($_.Groups['text']).Value
        $textSplitUnderscore = $text.split('_')
        $name = $textSplitUnderscore.split('_')[0]
        $version = $textSplitUnderscore.split('_')[1]
        $arch = ($textSplitUnderscore.split('_')[2]).ToLower()
        $publisherId = ($textSplitUnderscore.split('_')[4]).split('.')[0]
        $textSplitPeriod = $text.split('.')
        $type = ($textSplitPeriod[$textSplitPeriod.length - 1]).ToLower()
      
        # create $name hash key hashtable, if it doesn't already exist
        if (!($packageList.keys -match ('^' + [Regex]::escape($name) + '$'))) {
            $packageList["$name"] = @{}
        }
        # create $version hash key array, if it doesn't already exist
        if (!(($packageList["$name"]).keys -match ('^' + [Regex]::escape($version) + '$'))) {
            ($packageList["$name"])["$version"] = @()
        }
       
        # add package to the array in the hashtable
        ($packageList["$name"])["$version"] += @{
            url         = $url
            filename    = $text
            name        = $name
            version     = $version
            arch        = $arch
            publisherId = $publisherId
            type        = $type
        }
    }
      
    # an array of packages as objects, meant to only contain one of each $name
    $latestPackages = @()
    # grabs the most updated package for $name and puts it into $latestPackages
    $packageList.GetEnumerator() | ForEach-Object { ($_.value).GetEnumerator() | Select-Object -Last 1 } | ForEach-Object {
        $packagesByType = $_.value
        $msixbundle = ($packagesByType | Where-Object { $_.type -match '^msixbundle$' })
        $appxbundle = ($packagesByType | Where-Object { $_.type -match '^appxbundle$' })
        $msix = ($packagesByType | Where-Object { ($_.type -match '^msix$') -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
        $appx = ($packagesByType | Where-Object { ($_.type -match '^appx$') -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
        if ($msixbundle) { $latestPackages += $msixbundle }
        elseif ($appxbundle) { $latestPackages += $appxbundle }
        elseif ($msix) { $latestPackages += $msix }
        elseif ($appx) { $latestPackages += $appx }
    }
      
    # download packages
    $latestPackages | ForEach-Object {
        $url = $_.url
        $filename = $_.filename
        # TODO: may need to include detection in the future of expired package download URLs - .. in the case that downloads take over 10 minutes to complete
      
        $downloadFile = Join-Path $downloadFolder $filename
      
        # If file already exists, ask to replace it
        if (Test-Path $downloadFile) {
            Write-Host "`"${filename}`" already exists at `"${downloadFile}`"."
            $confirmation = ''
            while (!(($confirmation -eq 'Y') -Or ($confirmation -eq 'N'))) {
                $confirmation = Read-Host "`nWould you like to re-download and overwrite the file at `"${downloadFile}`" (Y/N)?"
                $confirmation = $confirmation.ToUpper()
            }
            if ($confirmation -eq 'Y') {
                Remove-Item -Path $downloadFile -Force
            }
            else {
                $DownloadedFiles += $downloadFile
            }
        }
      
        if (!(Test-Path $downloadFile)) {
            # Write-Host "Attempting download of `"${filename}`" to `"${downloadFile}`" . . ."
            $fileDownloaded = $null
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue' # avoids slow download when using Invoke-WebRequest
            try {
                Invoke-WebRequest -Uri $url -OutFile $downloadFile
                $fileDownloaded = $?
            }
            catch {
                $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
                $errorMsg = 'An error occurred: ' + $_
                LogError $errorMsg
                $errored = $true
                break $false
            }
            $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
            if ($fileDownloaded) { $DownloadedFiles += $downloadFile }
            else { $allFilesDownloaded = $false }
        }
    }
      
    if ($errored) { LogError 'Completed with some errors.' }
    if (-Not $allFilesDownloaded) { LogWarning 'Not all packages could be downloaded.'}
    return $DownloadedFiles
}


function Remove-AI-Appx-Packages {

    if ($revert) {
        Write-Status -msg 'Installing AI Appx Packages - '
        LogInfo 'Installing AI Appx Packages'
        #download appx packages from store
        $appxBackup = "$PSScriptRoot\RemoveWindowsAI\Backup\AppxBackup"
        if (Test-Path $appxBackup) {
            $familyNames = Get-Content "$appxBackup\PackageFamilyNames.txt" -ErrorAction SilentlyContinue
            foreach ($package in $familyNames) {
                $downloadedFiles = DownloadAppxPackage -PackageFamilyName $package -outputDir $appxBackup
                $bundle = $downloadedFiles | Where-Object { $_ -match '\.appxbundle$' -or $_ -match '\.msixbundle$' } | Select-Object -First 1
                if ($bundle) {
                    Add-AppPackage $bundle  
                }
            }

            #cleanup
            Remove-Item "$appxBackup\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            LogError 'Unable to Find AppxBackup in User Directory!'
        }
        Write-Host "success!" -ForegroundColor Green
    }
    else {

        #to make this part faster make a txt file in temp with chunck of removal 
        #code and then just run that from run 
        #trusted function due to the design of having it hidden from the user
        
        $packageRemovalPath = "$($tempDir)aiPackageRemoval.ps1"
        if (!(test-path $packageRemovalPath)) {
            New-Item $packageRemovalPath -Force | Out-Null
        }

        #needed for separate powershell sessions
        $aipackages = @(
            # 'MicrosoftWindows.Client.Photon'
            'MicrosoftWindows.Client.AIX'
            'MicrosoftWindows.Client.CoPilot'
            'Microsoft.Windows.Ai.Copilot.Provider'
            'Microsoft.Copilot'
            'Microsoft.MicrosoftOfficeHub'
            'MicrosoftWindows.Client.CoreAI'
            'Microsoft.Edge.GameAssist'
            'Microsoft.Office.ActionsServer'
            'aimgr'
            'Microsoft.WritingAssistant'
            #ai component packages installed on copilot+ pcs
            'MicrosoftWindows.*.Voiess'
            'MicrosoftWindows.*.Speion'
            'MicrosoftWindows.*.Livtop'
            'MicrosoftWindows.*.InpApp'
            'MicrosoftWindows.*.Filons'
            'WindowsWorkload.Data.Analysis.Stx.*'
            'WindowsWorkload.Manager.*'
            'WindowsWorkload.PSOnnxRuntime.Stx.*'
            'WindowsWorkload.PSTokenizer.Stx.*'
            'WindowsWorkload.QueryBlockList.*'
            'WindowsWorkload.QueryProcessor.Data.*'
            'WindowsWorkload.QueryProcessor.Stx.*'
            'WindowsWorkload.SemanticText.Data.*'
            'WindowsWorkload.SemanticText.Stx.*'
            'WindowsWorkload.Data.ContentExtraction.Stx.*'
            'WindowsWorkload.ScrRegDetection.Data.*'
            'WindowsWorkload.ScrRegDetection.Stx.*'
            'WindowsWorkload.TextRecognition.Stx.*'
            'WindowsWorkload.Data.ImageSearch.Stx.*'
            'WindowsWorkload.ImageContentModeration.*'
            'WindowsWorkload.ImageContentModeration.Data.*'
            'WindowsWorkload.ImageSearch.Data.*'
            'WindowsWorkload.ImageSearch.Stx.*'
            'WindowsWorkload.ImageSearch.Stx.*'
            'WindowsWorkload.ImageTextSearch.Data.*'
            'WindowsWorkload.PSOnnxRuntime.Stx.*'
            'WindowsWorkload.PSTokenizerShared.Data.*'
            'WindowsWorkload.PSTokenizerShared.Stx.*'
            'WindowsWorkload.ImageTextSearch.Stx.*'
            'WindowsWorkload.ImageTextSearch.Stx.*'
        )

        if ($backup) {

            #create file with package family names for reverting
            $appxBackup = "$PSScriptRoot\RemoveWindowsAI\Backup\AppxBackup"
            if (!(Test-Path $appxBackup)) {
                New-Item $appxBackup -ItemType Directory -Force | Out-Null
            }

            $backuppath = New-Item $appxBackup -Name 'PackageFamilyNames.txt' -ItemType File -Force

            $familyNames = get-appxpackage -allusers | Where-Object { $aipackages -contains $_.Name } 
            foreach ($familyName in $familyNames) {
                Add-Content -Path $backuppath.FullName -Value $familyName.PackageFamilyName | Out-Null
            }

        }

        $code = @'
$aipackages = @(
    'MicrosoftWindows.Client.AIX'
    'MicrosoftWindows.Client.CoPilot'
    'Microsoft.Windows.Ai.Copilot.Provider'
    'Microsoft.Copilot'
    'Microsoft.MicrosoftOfficeHub'
    'MicrosoftWindows.Client.CoreAI'
    'Microsoft.Edge.GameAssist'
    'Microsoft.Office.ActionsServer'
    'aimgr'
    'Microsoft.WritingAssistant'
    'MicrosoftWindows.*.Voiess'
    'MicrosoftWindows.*.Speion'
    'MicrosoftWindows.*.Livtop'
    'MicrosoftWindows.*.InpApp'
    'MicrosoftWindows.*.Filons'
    'WindowsWorkload.Data.Analysis.Stx.*'
    'WindowsWorkload.Manager.*'
    'WindowsWorkload.PSOnnxRuntime.Stx.*'
    'WindowsWorkload.PSTokenizer.Stx.*'
    'WindowsWorkload.QueryBlockList.*'
    'WindowsWorkload.QueryProcessor.Data.*'
    'WindowsWorkload.QueryProcessor.Stx.*'
    'WindowsWorkload.SemanticText.Data.*'
    'WindowsWorkload.SemanticText.Stx.*'
    'WindowsWorkload.Data.ContentExtraction.Stx.*'
    'WindowsWorkload.ScrRegDetection.Data.*'
    'WindowsWorkload.ScrRegDetection.Stx.*'
    'WindowsWorkload.TextRecognition.Stx.*'
    'WindowsWorkload.Data.ImageSearch.Stx.*'
    'WindowsWorkload.ImageContentModeration.*'
    'WindowsWorkload.ImageContentModeration.Data.*'
    'WindowsWorkload.ImageSearch.Data.*'
    'WindowsWorkload.ImageSearch.Stx.*'
    'WindowsWorkload.ImageSearch.Stx.*'
    'WindowsWorkload.ImageTextSearch.Data.*'
    'WindowsWorkload.PSOnnxRuntime.Stx.*'
    'WindowsWorkload.PSTokenizerShared.Data.*'
    'WindowsWorkload.PSTokenizerShared.Stx.*'
    'WindowsWorkload.ImageTextSearch.Stx.*'
    'WindowsWorkload.ImageTextSearch.Stx.*'
)

$provisioned = get-appxprovisionedpackage -online 
$appxpackage = get-appxpackage -allusers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

#use eol trick to uninstall some locked packages
foreach ($choice in $aipackages) {
    foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {

        $PackageName = $appx.PackageName 
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force
     
        Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0
       
        foreach ($sid in $users) { 
            New-Item "$store\EndOfLife\$sid\$PackageName" -force
        }  
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers
    }
    foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {

        $PackageFullName = $appx.PackageFullName
        $PackageFamilyName = $appx.PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force
        Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0
       
        #remove inbox apps
        $inboxApp = "$store\InboxApplications\$PackageFullName"
        Remove-Item -Path $inboxApp -Force
       
        #get all installed user sids for package due to not all showing up in reg
        foreach ($user in $appx.PackageUserInformation) { 
            $sid = $user.UserSecurityID.SID
            if ($users -notcontains $sid) {
                $users += $sid
            }
            New-Item "$store\EndOfLife\$sid\$PackageFullName" -force
            remove-appxpackage -package $PackageFullName -User $sid 
        } 
        remove-appxpackage -package $PackageFullName -allusers
    }
}
'@
        Set-Content -Path $packageRemovalPath -Value $code -Force | Out-Null
        #allow removal script to run
        try {
            Set-ExecutionPolicy Unrestricted -Force -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            #user has set powershell execution policy via group policy or via settings, to change it we need to update the registry 
            try {
                $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue | Out-Null
                Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
                Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                $Global:executionPolicyUser = $false
                $Global:executionPolicyMachine = $false
                $Global:executionPolicyWow64 = $false
                $Global:executionPolicyUserPol = $false
            }
            catch {
                try {
                    $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue | Out-Null
                    Reg.exe add 'HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                    $Global:executionPolicyUser = $true
                    $Global:executionPolicyMachine = $false
                    $Global:executionPolicyWow64 = $false
                    $Global:executionPolicyUserPol = $false
                }
                catch {
                    try {
                        $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue | Out-Null
                        Reg.exe add 'HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                        $Global:executionPolicyUser = $false
                        $Global:executionPolicyMachine = $true
                        $Global:executionPolicyWow64 = $false
                        $Global:executionPolicyUserPol = $false
                    }
                    catch {
                        try {
                            $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue | Out-Null
                            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                            $Global:executionPolicyUser = $false
                            $Global:executionPolicyMachine = $false
                            $Global:executionPolicyWow64 = $true
                            $Global:executionPolicyUserPol = $false

                        }
                        catch {
                            $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' 
                            Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
                            Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                            $Global:executionPolicyUser = $false
                            $Global:executionPolicyMachine = $false
                            $Global:executionPolicyWow64 = $false
                            $Global:executionPolicyUserPol = $true
                        }
                        

                    }
                    
                }
               
            }
            
           
        }


        Write-Status -msg 'Removing AI Appx Packages - '
        LogInfo 'Removing AI Appx Packages'
        $command = "&`"$($tempDir)aiPackageRemoval.ps1`""
        RunTrusted -command $command -psversion $psversion -logFile $logFile

        #check packages removal
        #exit loop after 10 tries
        $attempts = 0
        do {
            Start-Sleep 1
            $packages = get-appxpackage -AllUsers | Where-Object { $aipackages -contains $_.Name }
            if ($packages) {
                $attempts++
                $command = "&`"$($tempDir)aiPackageRemoval.ps1`""
                RunTrusted -command $command -psversion $psversion -logFile $logFile
            }
    
        }while ($packages -and $attempts -lt 10)

        Write-Host "success!" -ForegroundColor Green
        #tell windows copilot pwa is already installed
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' /v 'CopilotPWAPreinstallCompleted' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' /v 'Microsoft.Copilot_8wekyb3d8bbwe' /t REG_DWORD /d '1' /f *>$null
        #incase the user is on 25h2 and is using education or enterprise (required for this policy to work)
        #uninstalls copilot with group policy (will ensure it doesnt get reinstalled)
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' /v 'Enabled' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Copilot_8wekyb3d8bbwe' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null

        ## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
        #  $eolPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife'
        #  $eolKeys = (Get-ChildItem $eolPath).Name
        #  foreach ($path in $eolKeys) {
        #      Remove-Item "registry::$path" -Recurse -Force -ErrorAction SilentlyContinue
        #  }
    }
}

function Remove-Recall-Optional-Feature {
    if (!$revert) {
        #doesnt seem to work just gets stuck (does anyone really want this shit lol)
        #Enable-WindowsOptionalFeature -Online -FeatureName 'Recall' -All -NoRestart
        #remove recall optional feature 
        Write-Status -msg 'Removing Recall Optional Feature - '
        LogInfo "Removing Recall Optional Feature"
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName 'Recall' -ErrorAction SilentlyContinue | Out-Null).State
            if ($state -and $state -ne 'DisabledWithPayloadRemoved') {
                $ProgressPreference = 'SilentlyContinue'
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -Remove -NoRestart -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    #incase get-windowsoptionalfeature works but disable doesnt 
                    dism.exe /Online /Disable-Feature /FeatureName:Recall /Remove /NoRestart /Quiet *>$null
                }
            }
        }
        catch {
            #if get-windowsoptionalfeature errors fallback to dism
            $dismOutput = dism.exe /Online /Get-FeatureInfo /FeatureName:Recall
    
            if ($LASTEXITCODE -eq 0) {
                $isDisabledWithPayloadRemoved = $dismOutput | Select-String -Pattern 'State\s*:\s*Disabled with Payload Removed'
        
                if (!$isDisabledWithPayloadRemoved) {
                    dism.exe /Online /Disable-Feature /FeatureName:Recall /Remove /NoRestart /Quiet *>$null
                }
            }
        }
        Write-Host "success!" -ForegroundColor Green
    }
}

# not restoring for now shouldnt cause any issues (also may not even be possible to restore)
function Remove-AI-CBS-Packages {
    if (!$revert) {
        #additional hidden packages
        Write-Status -msg 'Removing Additional Hidden AI Packages - '
        LogInfo "Removing Additional Hidden AI Packages"
        #unhide the packages from dism, remove owners subkey for removal 
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
        $ProgressPreference = 'SilentlyContinue'
        Get-ChildItem $regPath | ForEach-Object {
            $value = try { Get-ItemPropertyValue "registry::$($_.Name)" -Name Visibility -ErrorAction SilentlyContinue | Out-Null } catch { $null }
    
            if ($null -ne $value) {
                if ($value -eq 2 -and $_.PSChildName -like '*AIX*' -or $_.PSChildName -like '*Recall*' -or $_.PSChildName -like '*Copilot*' -or $_.PSChildName -like '*CoreAI*') {
                    Set-ItemProperty "registry::$($_.Name)" -Name Visibility -Value 1 -Force | Out-Null
                    New-ItemProperty "registry::$($_.Name)" -Name DefVis -PropertyType DWord -Value 2 -Force | Out-Null
                    Remove-Item "registry::$($_.Name)\Owners" -Force -ErrorAction SilentlyContinue | Out-Null
                    Remove-Item "registry::$($_.Name)\Updates" -Force -ErrorAction SilentlyContinue | Out-Null
                    try {
                        Remove-WindowsPackage -Online -PackageName $_.PSChildName -NoRestart -ErrorAction SilentlyContinue | Out-Null
                        $paths = Get-ChildItem "$env:windir\servicing\Packages" -Filter "*$($_.PSChildName)*" -ErrorAction SilentlyContinue | Out-Null
                        foreach ($path in $paths) {
                            if ($path) {
                                Remove-Item $path.FullName -Force -ErrorAction SilentlyContinue | Out-Null
                            }
                        }
                        
                    }
                    catch {
                        #fallback to dism when user is using powershell 7
                        dism.exe /Online /Remove-Package /PackageName:$($_.PSChildName) /NoRestart *>$null
                        $paths = Get-ChildItem "$env:windir\servicing\Packages" -Filter "*$($_.PSChildName)*" -ErrorAction SilentlyContinue | Out-Null
                        foreach ($path in $paths) {
                            if ($path) {
                                Remove-Item $path.FullName -Force -ErrorAction SilentlyContinue | Out-Null
                            }
                        }                    
                    }
        
                }
            }
            
        }
        Write-Host "success!" -ForegroundColor Green
    }
}


function Remove-AI-Files {
    #prob add params here for each file removal 


    if ($revert) {
        if (Test-Path "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles") {
            Write-Status -msg 'Restoring Appx Package Files - '
            LogInfo 'Restoring Appx Package Files'
            $paths = Get-Content "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\backupPaths.txt"
            foreach ($path in $paths) {
                $fileName = Split-Path $path -Leaf
                $dest = Split-Path $path -Parent
                try {
                    Move-Item -Path "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\$fileName" -Destination $dest -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    $command = "Move-Item -Path `"$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\$fileName`" -Destination `"$dest`" -Force"
                    RunTrusted -command $command -psversion $psversion -logFile $logFile
                    Start-Sleep 1
                }
            }

            if (Test-Path "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI") {
                Write-Status -msg 'Restoring Office AI Files - '
                LogInfo 'Restoring Office AI Files'
                Move-Item "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI\x64\AI" -Destination "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16" -Force | Out-Null
                Move-Item "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI\x86\AI" -Destination "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16" -Force | Out-Null
                Move-Item "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI\RootAI\AI" -Destination "$env:ProgramFiles\Microsoft Office\root\Office16" -Force | Out-Null
                Move-Item "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI\ActionsServer\ActionsServer" -Destination "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16" -Force | Out-Null
                Get-ChildItem "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI" -Filter '*.msix' | ForEach-Object {
                    Move-Item $_.FullName -Destination "$env:ProgramFiles\Microsoft Office\root\Integration\Addons" -Force | Out-Null
                }
            }
            Write-Host "success!" -ForegroundColor Green

            Write-Status -msg 'Restoring AI URIs - '
            LogInfo 'Restoring AI URIs'
            $regs = Get-ChildItem "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\URIHandlers"
            foreach ($reg in $regs) {
                Reg.exe import $reg.FullName *>$null
            }
           
            #Write-Status -msg 'Files Restored -  You May Need to Repair the Apps Using the Microsoft Store'
            LogInfo 'Files Restored -  You May Need to Repair the Apps Using the Microsoft Store'
        }
        else {
            LogError 'Unable to Find Backup Files!'
        }

        <#
        if (Test-Path "$PSScriptRoot\RemoveWindowsAI\Backup\CompStorage"){
            Get-ChildItem "$PSScriptRoot\RemoveWindowsAI\Backup\CompStorage" -Filter "*.reg"
        }else{
            LogError -msg 'Unable to Find Component Storage Backup!' 
        }
        #>
    }
    else {

        $aipackages = @(
            # 'MicrosoftWindows.Client.Photon'
            'MicrosoftWindows.Client.AIX'
            'MicrosoftWindows.Client.CoPilot'
            'Microsoft.Windows.Ai.Copilot.Provider'
            'Microsoft.Copilot'
            'Microsoft.MicrosoftOfficeHub'
            'MicrosoftWindows.Client.CoreAI'
            'Microsoft.Edge.GameAssist'
            'Microsoft.Office.ActionsServer'
            'aimgr'
            'Microsoft.WritingAssistant'
            #ai component packages installed on copilot+ pcs
            'WindowsWorkload'
            'Voiess'
            'Speion'
            'Livtop'
            'InpApp'
            'Filons'
        )

        Write-Status -msg 'Removing Appx Package Files - '
        LogInfo 'Removing Appx Package Files'
       #LogWarning 'This could take a while on some systems, please be patient!'
        #-----------------------------------------------------------------------remove files
        $appsPath = "$env:SystemRoot\SystemApps"
        if (!(Test-Path $appsPath)) {
            $appsPath = "$env:windir\SystemApps"
        }
        $appsPath2 = "$env:ProgramFiles\WindowsApps"
    
        $appsPath3 = "$env:ProgramData\Microsoft\Windows\AppRepository"
    
        $appsPath4 = "$env:SystemRoot\servicing\Packages"
        if (!(Test-Path $appsPath4)) {
            $appsPath4 = "$env:windir\servicing\Packages"
        }
    
        $appsPath5 = "$env:SystemRoot\System32\CatRoot"
        if (!(Test-Path $appsPath5)) {
            $appsPath5 = "$env:windir\System32\CatRoot"
        }

        $appsPath6 = "$env:SystemRoot\SystemApps\SxS"
        if (!(Test-Path $appsPath6)) {
            $appsPath6 = "$env:windir\SystemApps\SxS"
        }
        $pathsSystemApps = (Get-ChildItem -Path $appsPath -Directory -Force -ErrorAction SilentlyContinue).FullName 
        $pathsWindowsApps = (Get-ChildItem -Path $appsPath2 -Directory -Force -ErrorAction SilentlyContinue).FullName 
        $pathsAppRepo = (Get-ChildItem -Path $appsPath3 -Directory -Force -Recurse -ErrorAction SilentlyContinue).FullName 
        $pathsServicing = (Get-ChildItem -Path $appsPath4 -Directory -Force -Recurse -ErrorAction SilentlyContinue).FullName
        $pathsCatRoot = (Get-ChildItem -Path $appsPath5 -Directory -Force -Recurse -ErrorAction SilentlyContinue).FullName 
        $pathsSXS = (Get-ChildItem -Path $appsPath6 -Directory -Force -ErrorAction SilentlyContinue).FullName 

        $packagesPath = @()
        #get full path
        foreach ($package in $aipackages) {
    
            foreach ($path in $pathsSystemApps) {
                if ($path -like "*$package*") {
                    $packagesPath += $path
                }
            }
    
            foreach ($path in $pathsWindowsApps) {
                if ($path -like "*$package*") {
                    $packagesPath += $path
                }
            }
    
            foreach ($path in $pathsAppRepo) {
                if ($path -like "*$package*") {
                    $packagesPath += $path
                }
            }

            foreach ($path in $pathsSXS) {
                if ($path -like "*$package*") {
                    $packagesPath += $path
                }
            }
    
        }
    
        #get additional files
        foreach ($path in $pathsServicing) {
            if ($path -like '*UserExperience-AIX*' -or $path -like '*Copilot*' -or $path -like '*UserExperience-Recall*' -or $path -like '*CoreAI*') {
                $packagesPath += $path
            }
        }
    
        foreach ($path in $pathsCatRoot) {
            if ($path -like '*UserExperience-AIX*' -or $path -like '*Copilot*' -or $path -like '*UserExperience-Recall*' -or $path -like '*CoreAI*') {
                $packagesPath += $path
            }
        }

        #add app actions mcp host
        $paths = @(
            "$env:LOCALAPPDATA\Microsoft\WindowsApps\ActionsMcpHost.exe"
            "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\ActionsMcpHost.exe"
            "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionsMcpHost.exe"
            "$env:LOCALAPPDATA\Microsoft\WindowsApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionsMcpHost.exe"
        )

        foreach ($path in $paths) {
            if (Test-Path $path) {
                $packagesPath += $path
            }
        }

        foreach ($packageName in $aipackages) {
            $path = Get-ChildItem "$env:LOCALAPPDATA\Packages" -Filter "*$packageName*" 
            if ($path) {
                $packagesPath += $path.FullName
            }
            
        }

        Write-Host "success!" -ForegroundColor Green

        if ($backup) {
            Write-Status -msg 'Backing Up AI Files - '
            LogInfo 'Backing Up AI Files'
            $backupDir = "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles"
            if (!(Test-Path $backupDir)) {
                New-Item $backupDir -Force -ItemType Directory | Out-Null
            }
            Write-Host "success!" -ForegroundColor Green
        }

        foreach ($Path in $packagesPath) {
            #only remove dlls from photon to prevent startmenu from breaking
            # if ($path -like '*Photon*') {
            #     $command = "`$dlls = (Get-ChildItem -Path $Path -Filter *.dll).FullName; foreach(`$dll in `$dlls){Remove-item ""`$dll"" -force}"
            #     RunTrusted -command $command -psversion $psversion -logFile $logFile
            #     Start-Sleep 1
            # }
            # else {

            if ($backup) {
                $backupFiles = "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\backupPaths.txt"
                if (!(Test-Path $backupFiles -PathType Leaf)) {
                    New-Item $backupFiles -Force -ItemType File | Out-Null
                }
                try {
                    Copy-Item -Path $Path -Destination $backupDir -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                    Add-Content -Path $backupFiles -Value $Path
                }
                catch {
                    #ignore any errors
                }
            }
            $command = "Remove-item ""$Path"" -force -ErrorAction SilentlyContinue -Recurse | Out-Null"
            RunTrusted -command $command -psversion $psversion -logFile $logFile
            Start-Sleep 1
        
        }
    
        #remove machine learning dlls
        $paths = @(
            "$env:SystemRoot\System32\Windows.AI.MachineLearning.dll"
            "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.dll"
            "$env:SystemRoot\System32\Windows.AI.MachineLearning.Preview.dll"
            "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.Preview.dll"
            "$env:SystemRoot\System32\SettingsHandlers_Copilot.dll"
            "$env:SystemRoot\System32\SettingsHandlers_A9.dll"
        )
        foreach ($path in $paths) {
            if (Test-Path $path) {
                takeown /f $path *>$null
                icacls $path /grant *S-1-5-32-544:F /t *>$null
                try {
                    Remove-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    #takeown didnt work remove file with system priv
                    $command = "Remove-Item -Path $path -Force -ErrorAction SilentlyContinue -Recurse | Out-Null"
                    RunTrusted -command $command -psversion $psversion -logFile $logFile
                }
            }
        }

       
        Write-Status -msg 'Removing Hidden Copilot Installers - '
        LogInfo 'Removing Hidden Copilot Installers'
        #remove package installers in edge dir
        #installs Microsoft.Windows.Ai.Copilot.Provider
        $dir = "${env:ProgramFiles(x86)}\Microsoft"
        $folders = @(
            'Edge',
            'EdgeCore',
            'EdgeWebView'
        )
        foreach ($folder in $folders) {
            if ($folder -eq 'EdgeCore') {
                #edge core doesnt have application folder
                $fullPath = (Get-ChildItem -Path "$dir\$folder\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
            
            }
            else {
                $fullPath = (Get-ChildItem -Path "$dir\$folder\Application\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
            }
            if ($null -ne $fullPath) { Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue }
        }
    

        #remove copilot update in edge update dir
        $dir = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate"
        if (Test-Path $dir) {
            $paths = Get-ChildItem $dir -Recurse -Filter '*CopilotUpdate.exe*' 
            foreach ($path in $paths) {
                if (Test-Path $path.FullName) {
                    Remove-Item $path.FullName -Force -ErrorAction SilentlyContinue -Recurse | Out-Null
                }
            }
        }

        $dir = "${env:ProgramFiles(x86)}\Microsoft"
        if (Test-Path $dir) {
            $paths = Get-ChildItem $dir -Recurse -Filter '*Copilot_setup*' 
            foreach ($path in $paths) {
                if (Test-Path $path.FullName) {
                    Remove-Item $path.FullName -Force -ErrorAction SilentlyContinue -Recurse | Out-Null
                }
            }
        }

        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\EdgeUpdate' /v 'CopilotUpdatePath' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate' /v 'CopilotUpdatePath' /f *>$null
    
        #remove additional installers
        $inboxapps = 'C:\Windows\InboxApps'
        $installers = Get-ChildItem -Path $inboxapps -Filter '*Copilot*' -ErrorAction SilentlyContinue | Out-Null
        foreach ($installer in $installers) {
            takeown /f $installer.FullName *>$null
            icacls $installer.FullName /grant *S-1-5-32-544:F /t *>$null
            try {
                Remove-Item -Path $installer.FullName -Force -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                #takeown didnt work remove file with system priv
                $command = "Remove-Item -Path $($installer.FullName) -Force -ErrorAction SilentlyContinue -Recurse | Out-Null"
                RunTrusted -command $command -psversion $psversion -logFile $logFile
            }
        
        }
    
        #remove ai from outlook/office
        $aiPaths = @(
            "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\AI",
            "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\AI",
            "$env:ProgramFiles\Microsoft Office\root\Office16\AI",
            "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\ActionsServer",
            "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\aimgr.msix",
            "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\WritingAssistant.msix",
            "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\ActionsServer.msix"
        )
    
        foreach ($path in $aiPaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                if ($backup) {
                    Write-Status -msg 'Backing Up Office AI Files - '
                    LogInfo 'Backing Up Office AI Files'
                    $backupDir = "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI"
                    if (!(Test-Path $backupDir)) {
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }

                    if ($path -eq "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\AI") {
                        $backupDir = "$backupDir\x64"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    elseif ($path -eq "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\AI") {
                        $backupDir = "$backupDir\x86"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    elseif ($path -eq "$env:ProgramFiles\Microsoft Office\root\Office16\AI") {
                        $backupDir = "$backupDir\RootAI"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    elseif ($path -eq "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\ActionsServer") {
                        $backupDir = "$backupDir\ActionsServer"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    else {
                        $backupDir = "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\OfficeAI"
                    }
                    Copy-Item -Path $path -Destination $backupDir -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                }
                try {
                    Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    $command = "Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null"
                    RunTrusted -command $command -psversion $psversion -logFile $logFile
                    Start-Sleep 1
                }
                
            }
        }
        
        Write-Host "success!" -ForegroundColor Green

        #remove any screenshots from recall
        Write-Status -msg 'Removing Any Screenshots By Recall - '
        LogInfo 'Removing Any Screenshots By Recall'
        Remove-Item -Path "$env:LOCALAPPDATA\CoreAIPlatform*" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
        Write-Host "success!" -ForegroundColor Green

        #remove ai uri handlers
        Write-Status -msg 'Removing AI URI Handlers - '
        LogInfo 'Removing AI URI Handlers'
        $uris = @(
            'registry::HKEY_CLASSES_ROOT\ms-office-ai'
            'registry::HKEY_CLASSES_ROOT\ms-copilot'
            'registry::HKEY_CLASSES_ROOT\ms-clicktodo'
        )

        foreach ($uri in $uris) {
            if ($backup) {
                if (Test-Path $uri) {
                    $backupDir = "$PSScriptRoot\RemoveWindowsAI\Backup\AIFiles\URIHandlers"
                    if (!(Test-Path $backupDir)) {
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    $regExportPath = "$backupDir\$($uri -replace 'registry::HKEY_CLASSES_ROOT\\', '').reg"
                    Reg.exe export ($uri -replace 'registry::', '') $regExportPath /y *>$null
                }
            }
            Remove-Item $uri -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Write-Host "success!" -ForegroundColor Green

        #prefire copilot nudges package by deleting the registry keys 
        Write-Status -msg 'Removing Copilot Nudges Registry Keys - '
        LogInfo 'Removing Copilot Nudges Registry Keys'
        $keys = @(
            'registry::HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.AppX*.wwa',
            'registry::HKCR\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.wwa',
            'registry::HKCR\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\Applications\MicrosoftWindows.Client.Core_cw5n1h2txyewy!Global.CopilotNudges',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\Applications\MicrosoftWindows.Client.Core_cw5n1h2txyewy!Global.CopilotNudges',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.Core_cw5n1h2txyewy!Global.CopilotNudges',
            'HKLM:\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.AppX*.wwa',
            'HKLM:\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.AppX*.mca',
            'HKLM:\SOFTWARE\Classes\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.wwa'
        )
        #get full paths and remove
        $fullkey = @()
        foreach ($key in $keys) {
            try {
                $fullKey = Get-Item -Path $key -ErrorAction SilentlyContinue | Out-Null
                if ($null -eq $fullkey) { continue }
                if ($fullkey.Length -gt 1) {
                    foreach ($multikey in $fullkey) {
                        $command = "Remove-Item -Path `"registry::$multikey`" -Force -ErrorAction SilentlyContinue -Recurse | Out-Null"
                        RunTrusted -command $command -psversion $psversion -logFile $logFile
                        Start-Sleep 1
                        #remove any regular admin that have trusted installer bug
                        Remove-Item -Path "registry::$multikey" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                    }
                }
                else {
                    $command = "Remove-Item -Path `"registry::$fullKey`" -Force -ErrorAction SilentlyContinue -Recurse | Out-Null"
                    RunTrusted -command $command -psversion $psversion -logFile $logFile
                    Start-Sleep 1
                    #remove any regular admin that have trusted installer bug
                    Remove-Item -Path "registry::$fullKey" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                }
         
            }
            catch {
                continue
            }
        }

        #remove ai app checks in updates (not sure if this does anything)
        $command = "Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy' /f"
        RunTrusted -command $command -psversion $psversion -logFile $logFile
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIX' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'CopilotNudges' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIContext' /f *>$null

        reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\ActionsMcpHost.exe' /f *>$null
        reg.exe delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\ActionsMcpHost.exe' /f *>$null

        #remove app actions files 
        #these will get remade when updating
        taskkill.exe /im AppActions.exe /f *>$null
        taskkill.exe /im VisualAssist.exe /f *>$null
        $paths = @(
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionUI"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssist"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AppActions.exe"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AppActions.dll"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssistExe.exe"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssistExe.dll"
        )

        Write-Host "success!" -ForegroundColor Green

        Write-Status -msg 'Removing App Actions Files - '
        LogInfo 'Removing App Actions Files'
        foreach ($path in $paths) {
            if (Test-Path $path) {
                if ((Get-Item $path).PSIsContainer) {
                    takeown /f "$path" /r /d Y *>$null
                    icacls "$path" /grant *S-1-5-32-544:F /t *>$null
                    Remove-Item "$path" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                }
                else {
                    takeown /f "$path" *>$null
                    icacls "$path" /grant *S-1-5-32-544:F /t *>$null
                    Remove-Item "$path" -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
       
        }
        Write-Host "success!" -ForegroundColor Green

        Write-Status -msg 'Removing AI From Component Store (WinSxS) - '
        LogInfo 'Removing AI From Component Store (WinSxS)'
       # Write-Status -msg 'This could take a while on some systems, please be patient!'
        #additional dirs and reg keys
        $aiKeyWords = @(
            'AIX',
            'Copilot',
            'Recall',
            'CoreAI',
            'aimgr'
        )
        $regLocations = @(
            'registry::HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage',
            'registry::HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages',
            'registry::HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData',
            'registry::HKCR\PackagedCom\Package',
            'HKCU:\Software\Classes\PackagedCom\Package',
            'HKCU:\Software\RegisteredApplications',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners'
        )
        $dirs = @(
            'C:\Windows\WinSxS',
            'C:\Windows\System32\CatRoot'
        )
        
        New-Item "$($tempDir)PathsToDelete.txt" -ItemType File -Force | Out-Null
        foreach ($keyword in $aiKeyWords) {
            foreach ($location in $regLocations) {
                Get-ChildItem $location -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "*$keyword*" } | ForEach-Object {
                    try {
                        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                    }
                    catch {
                        #ignore when path is null
                    }
                    
                }
            }

        }

        foreach ($dir in $dirs) {
            Get-ChildItem $dir -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                $_.FullName -like "*$($aiKeyWords[0])*" -or 
                $_.FullName -like "*$($aiKeyWords[1])*" -or 
                $_.FullName -like "*$($aiKeyWords[2])*" -or
                $_.FullName -like "*$($aiKeyWords[3])*" -or
                $_.FullName -like "*$($aiKeyWords[4])*" -and
                $(Test-Path $_.FullName -PathType Container) -eq $true 
            } | ForEach-Object {
                #add paths to txt to delete with trusted installer
                Add-Content "$($tempDir)PathsToDelete.txt" -Value $_.FullName | Out-Null
            } 
        }
        
        
        $command = "Get-Content `"$($tempDir)PathsToDelete.txt`" | ForEach-Object {Remove-Item `$_ -Force -Recurse -EA 0}"
        RunTrusted -command $command -psversion $psversion -logFile $logFile
        Start-Sleep 1
        Write-Host "success!" -ForegroundColor Green
    }

    #TEST:
    # remove ai components from component storage
    # this will prevent sfc from trying to repair files removed 
    # but seems to prevent windows update from working
    <#
    $compPath = "$env:systemroot\System32\config\COMPONENTS"

    reg.exe query 'HKLM\COMPONENTS' /ve *>$null
    if ($LASTEXITCODE -ne 0) {
        reg.exe load 'HKLM\COMPONENTS' $compPath >$null
    }

    if ($LASTEXITCODE -ne 0) {
        LogError "Unable to Load $compPath"
    }
    else {
        $paths = Get-ChildItem 'registry::HKLM\COMPONENTS\DerivedData\Components' | Where-Object { $_.PSChildName -like '*copilot*' -or
            $_.PSChildName -like '*userexperience-aix*' -or
            $_.PSChildName -like '*userexperience-recall*' -or
            $_.PSChildName -like '*userexperience-coreai*' } 

        if ($paths) {
            Write-Status -msg 'Removing AI Components Found in Component Storage - '
            #backup by default for now
            $backupPath = "$PSScriptRoot\RemoveWindowsAI\Backup\CompStorage"
            if (!(Test-Path $backupPath)) {
                New-Item $backupPath -ItemType Directory | Out-Null
            }

            foreach ($path in $paths) {
                reg.exe export $path.Name "$backupPath\$($path.PSChildName).reg" /y >$null
                reg.exe delete $path.Name /f
            }
            
        }
        else {
            Write-Status -msg 'No Ai Components Found in Component Storage'
        }

    }
    #>
}


function Hide-AI-Components {
    #hide ai components in immersive settings
    Write-Status -msg "$(@('Hiding','Unhiding')[$revert]) Ai Components in Settings - "
    LogInfo "$(@('Hiding','Unhiding')[$revert]) Ai Components in Settings"

    $existingSettings = try { Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'SettingsPageVisibility' -ErrorAction SilentlyContinue }catch {}
    #early return if the user has already customized this with showonly rather than hide, in this event ill assume the user has knowledge of this key and aicomponents is likely not shown anyway
    if ($existingSettings -like '*showonly*') {
        LogError 'SettingsPageVisibility contains "showonly" - Skipping!'
        return 
    }
    
    if ($revert) {
        #if the key is not just hide ai components then just remove it and retain the rest
        if ($existingSettings -ne 'hide:aicomponents;appactions;') {
            #in the event that this is just aicomponents but multiple times newkey will just be hide: which is valid
            $newKey = $existingSettings -replace 'aicomponents;appactions;', ''
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d $newKey /f >$null
        }
        else {
            Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /f >$null
        }
    }
    else {
        if ($existingSettings -and $existingSettings -notlike '*aicomponents;*') {
           
            if (!($existingSettings.endswith(';'))) {
                #doesnt have trailing ; so need to add it 
                $newval = $existingSettings + ';aicomponents;appactions;'
            }
            else {
                $newval = $existingSettings + 'aicomponents;appactions;'
            }
            
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d $newval /f >$null
        }
        elseif ($null -eq $existingSettings) {
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d 'hide:aicomponents;appactions;' /f >$null
        }
       
    }
        Write-Host "success!" -ForegroundColor Green
}

function Disable-Notepad-Rewrite {
    #disable rewrite for notepad
    Write-Status -msg "$(@('Disabling','Enabling')[$revert]) Rewrite Ai Feature for Notepad - "
    LogInfo "$(@('Disabling','Enabling')[$revert]) Rewrite Ai Feature for Notepad"
    <#
    taskkill /im notepad.exe /f *>$null
    #load notepad settings
    reg load HKU\TEMP "$env:LOCALAPPDATA\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\Settings\settings.dat" >$null
    #add disable rewrite
    $regContent = @'
Windows Registry Editor Version 5.00

[HKEY_USERS\TEMP\LocalState]
"RewriteEnabled"=hex(5f5e10b):00,e0,d1,c5,7f,ee,83,db,01
'@
    New-Item "$env:TEMP\DisableRewrite.reg" -Value $regContent -Force | Out-Null
    regedit.exe /s "$env:TEMP\DisableRewrite.reg"
    Start-Sleep 1
    reg unload HKU\TEMP >$null
    Remove-Item "$env:TEMP\DisableRewrite.reg" -Force -ErrorAction SilentlyContinue
    #>
    #above is old method before this policy to disable ai in notepad, [DEPRECIATED]
    Reg.exe add 'HKLM\SOFTWARE\Policies\WindowsNotepad' /v 'DisableAIFeatures' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Write-Host "success!" -ForegroundColor Green
}



function Remove-Recall-Tasks {
    if (!$revert) {
        #remove recall tasks
        Write-Status -msg 'Removing Recall Scheduled Tasks - '
        LogInfo 'Removing Recall Scheduled Tasks'
        #believe it or not to disable and remove these you need system priv
        #create another sub script for removal
        $code = @"
Get-ScheduledTask -TaskPath '*WindowsAI*' -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
Remove-Item "`$env:Systemroot\System32\Tasks\Microsoft\Windows\WindowsAI" -Recurse -Force -ErrorAction SilentlyContinue
`$initConfigID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration" -Name 'Id'
`$policyConfigID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration" -Name 'Id'
if(`$initConfigID -and `$policyConfigID){
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$initConfigID" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$policyConfigID" -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI" -Force -Recurse -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName "*Office Actions Server*" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Remove-Item "`$env:Systemroot\System32\Tasks\Microsoft\Office\Office Actions Server" -ErrorAction SilentlyContinue -Force
    `$officeConfigID = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Office\Office Actions Server' -Name 'Id'
    if (`$officeConfigID) {
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$officeConfigID" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Office\Office Actions Server' -Recurse -Force -ErrorAction SilentlyContinue
"@
        
        $subScript = "$($tempDir)RemoveRecallTasks.ps1"
        New-Item "$subScript" -Force | Out-Null
        Set-Content "$subScript" -Value $code -Force | Out-Null

        $command = "&`"$subScript`""
        RunTrusted -command $command -psversion $psversion -logFile $logFile
        Start-Sleep 1
        
        #when just running this option alone the tasks will be remade so we need to at least ensure they are disabled
        $command = "
        Get-ScheduledTask -TaskName '*Office Actions Server*' -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskPath '*WindowsAI*' | Disable-ScheduledTask -ErrorAction SilentlyContinue
        "
        RunTrusted -command $command -psversion $psversion -logFile $logFile
        Write-Host "success!" -ForegroundColor Green
    }
}

function install-photoviewer {
    
    #restore classic photoviewer
    $extensions = @('.Bmp', '.Cr2', '.Dib', '.Gif', '.JFIF', '.Jpe', '.Jpeg', '.Jpg', '.Jxr', '.Png', '.Tif', '.Tiff', '.Wdp')

    foreach ($ext in $extensions) {
        if ($ext -in @('.JFIF', '.Jpeg', '.Gif', '.Png', '.Wdp')) {
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext" /v 'EditFlags' /t REG_DWORD /d 65536 /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext" /v 'ImageOptionFlags' /t REG_DWORD /d 1 /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext" /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055' /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\DefaultIcon" /ve /t REG_SZ /d '%SystemRoot%\System32\imageres.dll,-72' /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\shell\open" /v 'MuiVerb' /t REG_EXPAND_SZ /d '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043' /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\shell\open\command" /ve /t REG_EXPAND_SZ /d "%SystemRoot%\System32\rundll32.exe \`"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll\`", ImageView_Fullscreen %1" /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\shell\open\DropTarget" /v 'Clsid' /t REG_SZ /d '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' /f >$null
        }
    
        if ($ext -in @('.Cr2', '.Tif')) {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f >$null
        }
        elseif ($ext -in @('.Dib', '.Bmp')) {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d 'PhotoViewer.FileAssoc.Bitmap' /f >$null
        }
        elseif ($ext -in @('.Jpg', '.Jpe', '.Jpeg')) {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d 'PhotoViewer.FileAssoc.Jpeg' /f >$null
        }
        else {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d "PhotoViewer.FileAssoc$ext" /f >$null
        }
    }
}

function install-paint {
    param(
        [string]$path
    )

    get-appxpackage '*Microsoft.Paint*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    
    $command = "
    copy-item `"$path\paint\mspaint.exe`" -Destination `"$env:systemroot\system32\mspaint.exe`" -Force
    copy-item `"$path\paint\mspaint.exe.mui`" -Destination `"$env:systemroot\System32\en-US\mspaint.exe.mui`" -Force
    copy-item `"$path\paint\mspaint.exe.mun`" -Destination `"$env:systemroot\SystemResources`" -Force
"
    RunTrusted -command $command
    Start-Sleep 1

    $command = "regedit.exe /s `"$path\paint\paint.reg`""
    RunTrusted -command $command
    
    $langID = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage').InstallLanguage
    $languageMap = @{
        '0804' = @{PAD = 'zh-CN'; Name = 'Chinese (Simplified)' }
        '0412' = @{PAD = 'ko-KR'; Name = 'Korean' }
        '0404' = @{PAD = 'zh-TW'; Name = 'Chinese (Traditional)' }
        '0422' = @{PAD = 'uk-UA'; Name = 'Ukrainian' }
        '041f' = @{PAD = 'tr-TR'; Name = 'Turkish' }
        '041e' = @{PAD = 'th-TH'; Name = 'Thai' }
        '241a' = @{PAD = 'sr-Latn-RS'; Name = 'Serbian (Latin)' }
        '0424' = @{PAD = 'sl-SI'; Name = 'Slovenian' }
        '041b' = @{PAD = 'sk-SK'; Name = 'Slovak' }
        '0419' = @{PAD = 'ru-RU'; Name = 'Russian' }
        '0418' = @{PAD = 'ro-RO'; Name = 'Romanian' }
        '0816' = @{PAD = 'pt-PT'; Name = 'Portuguese (Portugal)' }
        '0416' = @{PAD = 'pt-BR'; Name = 'Portuguese (Brazil)' }
        '0415' = @{PAD = 'pl-PL'; Name = 'Polish' }
        '0413' = @{PAD = 'nl-NL'; Name = 'Dutch' }
        '0414' = @{PAD = 'nb-NO'; Name = 'Norwegian' }
        '0426' = @{PAD = 'lv-LV'; Name = 'Latvian' }
        '0427' = @{PAD = 'lt-LT'; Name = 'Lithuanian' }
        '0411' = @{PAD = 'ja-JP'; Name = 'Japanese' }
        '0410' = @{PAD = 'it-IT'; Name = 'Italian' }
        '040e' = @{PAD = 'hu-HU'; Name = 'Hungarian' }
        '041a' = @{PAD = 'hr-HR'; Name = 'Croatian' }
        '040d' = @{PAD = 'he-IL'; Name = 'Hebrew' }
        '040c' = @{PAD = 'fr-FR'; Name = 'French (France)' }
        '0c0c' = @{PAD = 'fr-CA'; Name = 'French (Canada)' }
        '040b' = @{PAD = 'fi-FI'; Name = 'Finnish' }
        '0425' = @{PAD = 'et-EE'; Name = 'Estonian' }
        '080a' = @{PAD = 'es-MX'; Name = 'Spanish (Mexico)' }
        '040a' = @{PAD = 'es-ES'; Name = 'Spanish (Spain)' }
        '0809' = @{PAD = 'en-GB'; Name = 'English (UK)' }
        '0408' = @{PAD = 'el-GR'; Name = 'Greek' }
        '0407' = @{PAD = 'de-DE'; Name = 'German' }
        '0406' = @{PAD = 'da-DK'; Name = 'Danish' }
        '0405' = @{PAD = 'cs-CZ'; Name = 'Czech' }
        '0402' = @{PAD = 'bg-BG'; Name = 'Bulgarian' }
        '0401' = @{PAD = 'ar-SA'; Name = 'Arabic' }
        '041d' = @{PAD = 'sv-SE'; Name = 'Swedish' }
    }

    if ($languageMap.ContainsKey($langID)) {
        $lang = $languageMap[$langID]
        $pad = $lang.PAD
    
        # Copy language specific MUI file
        $command = "Copy-Item -Path `"$path\paint\paint_lang_files\$pad\mspaint.exe.mui`" -Destination `"$env:SYSTEMROOT\System32\$pad\mspaint.exe.mui`" -Force"
        RunTrusted -command $command

        Write-Status -msg "Copied $pad language file"
        LogInfo "Copied $pad language file"
    }
   
    
    #create start shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Paint.lnk')
    $Shortcut.TargetPath = 'C:\Windows\System32\mspaint.exe'
    $Shortcut.Save()

}

function install-snipping {
    param(
        [string]$path
    )
    # uninstall uwp
    Get-AppxPackage '*ScreenSketch*' -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

    $command = "
    copy-item `"$path\snipping\SnippingTool.exe`" -Destination `"$env:systemroot\system32\SnippingTool.exe`" -Force
    copy-item `"$path\snipping\SnippingTool.exe.mui`" -Destination `"$env:systemroot\System32\en-US\SnippingTool.exe.mui`" -Force
"
    RunTrusted -command $command
    Start-Sleep 1

    $langID = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage').InstallLanguage
    $languageMap = @{
        '0804' = @{PAD = 'zh-CN'; Name = 'Chinese (Simplified)' }
        '0412' = @{PAD = 'ko-KR'; Name = 'Korean' }
        '0404' = @{PAD = 'zh-TW'; Name = 'Chinese (Traditional)' }
        '0422' = @{PAD = 'uk-UA'; Name = 'Ukrainian' }
        '041f' = @{PAD = 'tr-TR'; Name = 'Turkish' }
        '041e' = @{PAD = 'th-TH'; Name = 'Thai' }
        '241a' = @{PAD = 'sr-Latn-RS'; Name = 'Serbian (Latin)' }
        '0424' = @{PAD = 'sl-SI'; Name = 'Slovenian' }
        '041b' = @{PAD = 'sk-SK'; Name = 'Slovak' }
        '0419' = @{PAD = 'ru-RU'; Name = 'Russian' }
        '0418' = @{PAD = 'ro-RO'; Name = 'Romanian' }
        '0816' = @{PAD = 'pt-PT'; Name = 'Portuguese (Portugal)' }
        '0416' = @{PAD = 'pt-BR'; Name = 'Portuguese (Brazil)' }
        '0415' = @{PAD = 'pl-PL'; Name = 'Polish' }
        '0413' = @{PAD = 'nl-NL'; Name = 'Dutch' }
        '0414' = @{PAD = 'nb-NO'; Name = 'Norwegian' }
        '0426' = @{PAD = 'lv-LV'; Name = 'Latvian' }
        '0427' = @{PAD = 'lt-LT'; Name = 'Lithuanian' }
        '0411' = @{PAD = 'ja-JP'; Name = 'Japanese' }
        '0410' = @{PAD = 'it-IT'; Name = 'Italian' }
        '040e' = @{PAD = 'hu-HU'; Name = 'Hungarian' }
        '041a' = @{PAD = 'hr-HR'; Name = 'Croatian' }
        '040d' = @{PAD = 'he-IL'; Name = 'Hebrew' }
        '040c' = @{PAD = 'fr-FR'; Name = 'French (France)' }
        '0c0c' = @{PAD = 'fr-CA'; Name = 'French (Canada)' }
        '040b' = @{PAD = 'fi-FI'; Name = 'Finnish' }
        '0425' = @{PAD = 'et-EE'; Name = 'Estonian' }
        '080a' = @{PAD = 'es-MX'; Name = 'Spanish (Mexico)' }
        '040a' = @{PAD = 'es-ES'; Name = 'Spanish (Spain)' }
        '0809' = @{PAD = 'en-GB'; Name = 'English (UK)' }
        '0408' = @{PAD = 'el-GR'; Name = 'Greek' }
        '0407' = @{PAD = 'de-DE'; Name = 'German' }
        '0406' = @{PAD = 'da-DK'; Name = 'Danish' }
        '0405' = @{PAD = 'cs-CZ'; Name = 'Czech' }
        '0402' = @{PAD = 'bg-BG'; Name = 'Bulgarian' }
        '0401' = @{PAD = 'ar-SA'; Name = 'Arabic' }
        '041d' = @{PAD = 'sv-SE'; Name = 'Swedish' }
    }

    if ($languageMap.ContainsKey($langID)) {
        $lang = $languageMap[$langID]
        $pad = $lang.PAD
    
        # Copy language specific MUI file
        $command = "Copy-Item -Path `"$path\snipping\snipping_lang_files\$pad\SnippingTool.exe.mui`" -Destination `"$env:SYSTEMROOT\System32\$pad\SnippingTool.exe.mui`" -Force"
        RunTrusted -command $command

        Write-Status -msg "Copied $pad language file"
        LogInfo "Copied $pad language file"
    
    }
   

    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\SnippingTool.lnk')
    $Shortcut.TargetPath = ('C:\Windows\System32\SnippingTool.exe')
    $Shortcut.Save()

}


function install-notepad {

    #uninstall new notepad 
    taskkill.exe /im notepad.exe /f *>$null
    taskkill.exe /im dllhost.exe /f *>$null
    get-appxpackage '*notepad*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    #enable win10 notepad
    Add-WindowsCapability -Online -Name Microsoft.Windows.Notepad.System~~~~0.0.1.0 -LimitAccess | Out-Null
    # fix registry 
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Applications\notepad.exe' -Name NoOpenWith -Force -ErrorAction SilentlyContinue
    reg.exe add 'HKLM\SOFTWARE\Classes\*\OpenWithList\notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.htm\OpenWithList' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.htm\OpenWithList\notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.inf' /ve /t REG_SZ /d 'inffile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.ini' /ve /t REG_SZ /d 'inifile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.log' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.ps1' /ve /t REG_SZ /d 'Microsoft.PowerShellScript.1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.psd1' /ve /t REG_SZ /d 'Microsoft.PowerShellData.1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.psm1' /ve /t REG_SZ /d 'Microsoft.PowerShellModule.1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.scp' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.txt' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.txt\ShellNew' /v 'ItemName' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\notepad.exe,-470' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.txt\ShellNew' /v 'NullFile' /t REG_SZ /d ' ' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.wtx' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\edit' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\edit\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile' /ve /t REG_SZ /d 'Setup Information' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d '@%SystemRoot%\System32\setupapi.dll,-2000' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\DefaultIcon' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\System32\imageres.dll,-69' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\print' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\print\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE /p %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile' /ve /t REG_SZ /d 'Configuration Settings' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile' /v 'EditFlags' /t REG_DWORD /d 0x00200000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile' /v 'FriendlyTypeName' /t REG_SZ /d '@shell32.dll,-10151' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\DefaultIcon' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\imageres.dll,-69' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\print' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\print\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE /p %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1' /v 'EditFlags' /t REG_DWORD /d 0x00020000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d "@\`"%systemroot%\system32\windowspowershell\v1.0\powershell.exe\`",-104" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1\Shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1\Shell\Open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1\Shell\Open\Command' /ve /t REG_SZ /d "\`"C:\Windows\System32\notepad.exe\`" \`"%1\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1' /v 'EditFlags' /t REG_DWORD /d 0x00020000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d "@\`"%systemroot%\system32\windowspowershell\v1.0\powershell.exe\`",-106" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1\Shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1\Shell\Open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1\Shell\Open\Command' /ve /t REG_SZ /d "\`"C:\Windows\System32\notepad.exe\`" \`"%1\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1' /v 'EditFlags' /t REG_DWORD /d 0x00020000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d "@\`"%systemroot%\system32\windowspowershell\v1.0\powershell.exe\`",-103" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\DefaultIcon' /ve /t REG_SZ /d "\`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe\`",1" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell\Open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell\Open\Command' /ve /t REG_SZ /d "\`"C:\Windows\System32\notepad.exe\`" \`"%1\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\OpenWithList' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\OpenWithList\Notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\edit' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\edit\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile' /ve /t REG_SZ /d 'Text Document' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile' /v 'EditFlags' /t REG_DWORD /d 0x00210000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\notepad.exe,-469' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\DefaultIcon' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\imageres.dll,-102' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\print' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\print\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE /p %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\printto' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\printto\command' /ve /t REG_EXPAND_SZ /d "%SystemRoot%\system32\notepad.exe /pt \`"%1\`" \`"%2\`" \`"%3\`" \`"%4\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities' /v 'ApplicationDescription' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\NOTEPAD.EXE,-9' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities' /v 'ApplicationName' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\NOTEPAD.EXE,-9' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.ini' /t REG_SZ /d 'inifile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.log' /t REG_SZ /d 'logfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.scp' /t REG_SZ /d 'scpfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.txt' /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.wtx' /t REG_SZ /d 'wtxfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\RegisteredApplications' /v 'Notepad' /t REG_SZ /d 'Software\Microsoft\Windows\Notepad\Capabilities' /f >$null
    reg.exe add 'HKCU\Software\Microsoft\Notepad' /v 'ShowStoreBanner' /t REG_DWORD /d 0x00000000 /f >$null

    #create start shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk')
    $Shortcut.TargetPath = 'C:\Windows\System32\Notepad.exe'
    $Shortcut.Save()

}

function install-photoslegacy {

    $appx = Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -like '*PhotosLegacy*' }

    if (!$appx) {

        try {
            Get-Command store -ErrorAction SilentlyContinue | Out-Null
            #install photos legacy using new store cmdlet
            store install 9NV2L4XVMCXM
        }
        catch {
            Remove-Item "$($tempDir)Microsoft.PhotosLegacy_8wekyb3d8bbwe*" -Force -Recurse -ErrorAction SilentlyContinue
            $downloadedfiles = DownloadAppxPackage -PackageFamilyName 'Microsoft.PhotosLegacy_8wekyb3d8bbwe' -outputDir "$tempDir"
            $package = $downloadedfiles | Where-Object { $_ -match '\.appxbundle$' } | Select-Object -First 1
            $dependencies = $downloadedfiles | Where-Object { $_ -match '\.appx$' } 
            if ($package) {
                try {
                    Add-AppPackage $package -DependencyPath $dependencies -ForceApplicationShutdown
                }
                catch {
                    LogError "Can't install PhotosLegacy via appxbundle -  make sure you have the appx service enabled"
                }
                
            }
            else {
                LogError "Can't find PhotosLegacy Installer"
            }
        }
        
    }
}

function install-classicapps {
    param(
        [ValidateSet('photoviewer', 'mspaint', 'snippingtool', 'notepad', 'photoslegacy')]
        [array]$app
    )

    #check if files are downloaded locally
    if (Test-Path "$PSScriptroot\ClassicApps") {
        Write-Status -msg 'Classic Apps Files Found Locally'
        LogInfo 'Classic Apps Files Found Locally'
        $classicApps = "$PSScriptroot\ClassicApps"
    }
    else {
        #check if they are already downloaded if not download them
        
        if (!(Test-Path "$($tempDir)ClassicApps")) {
            $ProgressPreference = 'SilentlyContinue'
            Write-Status -msg 'Downloading Classic Apps Files from Github - '
            $url = 'https://github.com/sdmanson8/scripts/archive/refs/heads/main.zip'
            try {
                Invoke-WebRequest -Uri $url -OutFile "$($tempDir)main.zip" -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                LogError 'Unable to Download Github Repo'
                return
            }
            Expand-Archive -Path "$($tempDir)main.zip" -DestinationPath "$tempDir" -Force
            $sourceDir = "$($tempDir)RemoveWindowsAI-main\ClassicApps"
            $destDir = "$($tempDir)ClassicApps"
            Copy-Item -Path $sourceDir -Destination $destDir -Recurse -Force
            Remove-Item "$($tempDir)RemoveWindowsAI-main" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "$($tempDir)main.zip" -Recurse -Force -ErrorAction SilentlyContinue
        }

        $classicApps = "$($tempDir)ClassicApps"
    }


    switch ($app) {
        'photoviewer' {  
            Write-Status -msg 'Installing Classic Photo Viewer - '
            install-photoviewer
        }
        'mspaint' {
            Write-Status -msg 'Installing Classic Paint - '
            install-paint -path $classicApps
        }
        'snippingtool' {
            Write-Status -msg 'Installing Classic Snipping Tool - '
            install-snipping -path $classicApps
        }
        'notepad' {
            Write-Status -msg 'Installing Classic Notepad - '
            install-notepad
        }
        'photoslegacy' {
            Write-Status -msg 'Installing Photos Legacy - '
            install-photoslegacy
        }
        Default {
            LogError 'Unknown Classic App Option'
        }
    }
}


if ($nonInteractive) {
    if ($backup) {
        CreateRestorePoint -nonInteractive
    }
    if ($AllOptions) {
        Disable-Registry-Keys 
        Install-NOAIPackage
        Disable-Copilot-Policies 
        Remove-AI-Appx-Packages 
        Remove-Recall-Optional-Feature 
        Remove-AI-CBS-Packages 
        Remove-AI-Files 
        Hide-AI-Components 
        Disable-Notepad-Rewrite 
        Remove-Recall-Tasks 
    }
    else {
        #loop through options array and run desired tweaks
        switch ($Options) {
            'DisableRegKeys' { Disable-Registry-Keys }
            'Prevent-AI-Package-Reinstall' { Install-NOAIPackage }
            'DisableCopilotPolicies' { Disable-Copilot-Policies }
            'RemoveAppxPackages' { Remove-AI-Appx-Packages }
            'RemoveRecallFeature' { Remove-Recall-Optional-Feature }
            'RemoveCBSPackages' { Remove-AI-CBS-Packages }
            'RemoveAIFiles' { Remove-AI-Files }
            'HideAIComponents' { Hide-AI-Components }
            'DisableRewrite' { Disable-Notepad-Rewrite }
            'RemoveRecallTasks' { Remove-Recall-Tasks }
        }
    }

    if ($InstallClassicApps) {
        foreach ($app in $InstallClassicApps) {
            install-classicapps -app $app
        }
    }
}
else {

    #===============================================================================
    #BEGIN UI
    #===============================================================================

    $functionDescriptions = @{
        'Disable-Registry-Keys'          = 'Disables Copilot and Recall through registry modifications, including Windows Search integration and Edge Copilot features. Also disables AI image creator in Paint and various AI-related privacy settings.'
        'Prevent-AI-Package-Reinstall'   = 'Installs a custom Windows Update Package to prevent Windows Update and DISM from reinstalling AI packages.'
        'Disable-Copilot-Policies'       = 'Disables Copilot policies in the Windows integrated services region policy JSON file by setting their default state to disabled.'
        'Remove-AI-Appx-Packages'        = 'Removes AI-related AppX packages including Copilot, AIX, CoreAI, and various WindowsWorkload AI components using advanced removal techniques.'
        'Remove-Recall-Optional-Feature' = 'Removes the Recall optional Windows feature completely from the system, including payload removal.'
        'Remove-AI-CBS-Packages'         = 'Removes additional hidden AI packages from Component Based Servicing (CBS) by unhiding them and forcing removal.'
        'Remove-AI-Files'                = 'Removes AI-related files from SystemApps, WindowsApps, and other system directories. Also removes machine learning DLLs and Copilot installers.'
        'Hide-AI-Components'             = 'Hides AI components in Windows Settings by modifying the SettingsPageVisibility policy to prevent user access to AI settings.'
        'Disable-Notepad-Rewrite'        = 'Disables the AI Rewrite feature in Windows Notepad through registry modifications and group policy settings.'
        'Remove-Recall-Tasks'            = 'Removes Recall-related scheduled tasks from the Windows Task Scheduler to prevent AI data collection processes from running.'
    }

    $window = New-Object System.Windows.Window
    $window.Title = 'Remove Windows AI'
    $window.Width = 600
    $window.Height = 700
    $window.WindowStartupLocation = 'CenterScreen'
    $window.ResizeMode = 'NoResize'

    $window.Background = [System.Windows.Media.Brushes]::Black
    $window.Foreground = [System.Windows.Media.Brushes]::White

    $mainGrid = New-Object System.Windows.Controls.Grid
    $window.Content = $mainGrid

    $titleRow = New-Object System.Windows.Controls.RowDefinition
    $titleRow.Height = [System.Windows.GridLength]::new(80)
    $mainGrid.RowDefinitions.Add($titleRow) | Out-Null

    $contentRow = New-Object System.Windows.Controls.RowDefinition
    $contentRow.Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $mainGrid.RowDefinitions.Add($contentRow) | Out-Null

    $toggleRow = New-Object System.Windows.Controls.RowDefinition
    $toggleRow.Height = [System.Windows.GridLength]::new(130) 
    $mainGrid.RowDefinitions.Add($toggleRow) | Out-Null

    $bottomRow = New-Object System.Windows.Controls.RowDefinition
    $bottomRow.Height = [System.Windows.GridLength]::new(80)
    $mainGrid.RowDefinitions.Add($bottomRow) | Out-Null

   
    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = 'Remove Windows AI'
    $title.FontSize = 18
    $title.FontWeight = 'Bold'
    $title.Foreground = [System.Windows.Media.Brushes]::Cyan
    $title.HorizontalAlignment = 'Center'
    $title.VerticalAlignment = 'Center'
    $title.Margin = '0,20,0,0'
    [System.Windows.Controls.Grid]::SetRow($title, 0)
    $mainGrid.Children.Add($title) | Out-Null

    $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
    $scrollViewer.VerticalScrollBarVisibility = 'Auto'
    $scrollViewer.Margin = '20,10,20,10'
    [System.Windows.Controls.Grid]::SetRow($scrollViewer, 1)
    $mainGrid.Children.Add($scrollViewer) | Out-Null

    $scrollViewerStyle = @'
<Style xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
       xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
       TargetType="{x:Type ScrollViewer}">
    <Setter Property="Template">
        <Setter.Value>
            <ControlTemplate TargetType="{x:Type ScrollViewer}">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <ScrollContentPresenter Grid.Column="0" Margin="0,0,15,0"/>
                    <ScrollBar Grid.Column="1" 
                               Name="PART_VerticalScrollBar"
                               Value="{TemplateBinding VerticalOffset}"
                               Maximum="{TemplateBinding ScrollableHeight}"
                               ViewportSize="{TemplateBinding ViewportHeight}"
                               Visibility="{TemplateBinding ComputedVerticalScrollBarVisibility}"
                               Width="12"
                               Margin="3,0,8,0">
                        <ScrollBar.Style>
                            <Style TargetType="ScrollBar">
                                <Setter Property="Background" Value="#2B2B2B"/>
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="ScrollBar">
                                            <Grid>
                                                <Border Background="{TemplateBinding Background}" CornerRadius="6"/>
                                                <Track Name="PART_Track" IsDirectionReversed="True">
                                                    <Track.Thumb>
                                                        <Thumb>
                                                            <Thumb.Style>
                                                                <Style TargetType="Thumb">
                                                                    <Setter Property="Background" Value="#5A5A5A"/>
                                                                    <Setter Property="Template">
                                                                        <Setter.Value>
                                                                            <ControlTemplate TargetType="Thumb">
                                                                                <Border Background="{TemplateBinding Background}" 
                                                                                        CornerRadius="6"
                                                                                        Margin="2"/>
                                                                            </ControlTemplate>
                                                                        </Setter.Value>
                                                                    </Setter>
                                                                    <Style.Triggers>
                                                                        <Trigger Property="IsMouseOver" Value="True">
                                                                            <Setter Property="Background" Value="#7A7A7A"/>
                                                                        </Trigger>
                                                                    </Style.Triggers>
                                                                </Style>
                                                            </Thumb.Style>
                                                        </Thumb>
                                                    </Track.Thumb>
                                                </Track>
                                            </Grid>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </ScrollBar.Style>
                    </ScrollBar>
                </Grid>
            </ControlTemplate>
        </Setter.Value>
    </Setter>
</Style>
'@

    $reader = New-Object System.Xml.XmlNodeReader([xml]$scrollViewerStyle)
    $scrollViewer.Style = [Windows.Markup.XamlReader]::Load($reader)


    $stackPanel = New-Object System.Windows.Controls.StackPanel
    $stackPanel.Orientation = 'Vertical'
    $scrollViewer.Content = $stackPanel

    $checkboxes = @{}
    $functions = @(
        'Disable-Registry-Keys'          
        'Prevent-AI-Package-Reinstall'
        'Disable-Copilot-Policies'       
        'Remove-AI-Appx-Packages'        
        'Remove-Recall-Optional-Feature' 
        'Remove-AI-CBS-Packages'         
        'Remove-AI-Files'               
        'Hide-AI-Components'            
        'Disable-Notepad-Rewrite'       
        'Remove-Recall-Tasks'           
    )

    foreach ($func in $functions) {
        $optionContainer = New-Object System.Windows.Controls.DockPanel
        $optionContainer.Margin = '0,5,0,5'
        $optionContainer.LastChildFill = $false
    
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $func.Replace('-', ' ')
        $checkbox.FontSize = 14
        $checkbox.Foreground = [System.Windows.Media.Brushes]::White
        $checkbox.Margin = '0,0,10,0'
        $checkbox.VerticalAlignment = 'Center'
        $checkbox.IsChecked = $true
        [System.Windows.Controls.DockPanel]::SetDock($checkbox, 'Left')
        $checkboxes[$func] = $checkbox
    
        $infoButton = New-Object System.Windows.Controls.Button
        $infoButton.Content = '?'
        $infoButton.Width = 25
        $infoButton.Height = 25
        $infoButton.FontSize = 12
        $infoButton.FontWeight = 'Bold'
        $infoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
        $infoButton.Foreground = [System.Windows.Media.Brushes]::White
        $infoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
        $infoButton.BorderThickness = 0
        $infoButton.VerticalAlignment = 'Center'
        $infoButton.Cursor = 'Hand'
        [System.Windows.Controls.DockPanel]::SetDock($infoButton, 'Right')
    
        $infoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
        $infoButton.Template = [System.Windows.Markup.XamlReader]::Parse($infoTemplate)
    
        $infoButton.Add_Click({
                param($sender, $e)
                $funcName = $functions | Where-Object { $checkboxes[$_] -eq $optionContainer.Children[0] }
                if (!$funcName) {
                    # Find the function name by looking at the parent container
                    $parentContainer = $sender.Parent
                    $checkboxInContainer = $parentContainer.Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
                    $funcName = $functions | Where-Object { ($checkboxes[$_].Content -replace ' ', '-') -eq ($checkboxInContainer.Content -replace ' ', '-') }
                }
        
                # Find the correct function name
                foreach ($f in $functions) {
                    if ($checkboxes[$f].Parent -eq $sender.Parent) {
                        $funcName = $f
                        break
                    }
                }
        
                $description = $functionDescriptions[$funcName]
                [System.Windows.MessageBox]::Show($description, $funcName, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            })
    
        $optionContainer.Children.Add($checkbox) | Out-Null
        $optionContainer.Children.Add($infoButton) | Out-Null
        $stackPanel.Children.Add($optionContainer) | Out-Null
    }

    #add switches for backup and revert modes
    function Add-iOSToggleToUI {
        param(
            [Parameter(Mandatory = $true)]
            [System.Windows.Controls.Panel]$ParentControl,
            [bool]$IsChecked = $false,
            [string]$Name = 'iOSToggle'
        )
                
        $styleXaml = @'
            <ResourceDictionary 
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                
                <Style x:Key="CleanToggleStyle" TargetType="{x:Type ToggleButton}">
                    <Setter Property="Background" Value="Transparent"/>
                    <Setter Property="BorderBrush" Value="Transparent"/>
                    <Setter Property="BorderThickness" Value="0"/>
                    <Setter Property="Width" Value="40"/>
                    <Setter Property="Height" Value="24"/>
                    <Setter Property="Cursor" Value="Hand"/>
                    <Setter Property="Focusable" Value="False"/>
                    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
                    <Setter Property="Template">
                        <Setter.Value>
                            <ControlTemplate TargetType="{x:Type ToggleButton}">
                                <Grid>
                                    <!-- Switch Track -->
                                    <Border x:Name="SwitchTrack" 
                                            Width="40" Height="24" 
                                            Background="#E5E5E7" 
                                            CornerRadius="12"
                                            BorderThickness="0">
                                        
                                        <!-- Switch Thumb -->
                                        <Border x:Name="SwitchThumb" 
                                                Width="20" Height="20" 
                                                Background="White" 
                                                CornerRadius="10"
                                                HorizontalAlignment="Left"
                                                VerticalAlignment="Center"
                                                Margin="2,0,0,0">
                                            <Border.Effect>
                                                <DropShadowEffect Color="#00000040" 
                                                                  Direction="270" 
                                                                  ShadowDepth="1" 
                                                                  BlurRadius="3"
                                                                  Opacity="0.4"/>
                                            </Border.Effect>
                                            <Border.RenderTransform>
                                                <TranslateTransform x:Name="ThumbTransform" X="0"/>
                                            </Border.RenderTransform>
                                        </Border>
                                    </Border>
                                </Grid>
                                
                                <ControlTemplate.Triggers>
                                    <!-- Checked State (ON) -->
                                    <Trigger Property="IsChecked" Value="True">
                                        <Trigger.EnterActions>
                                            <BeginStoryboard>
                                                <Storyboard>
                                                    <!-- Slide thumb to right -->
                                                    <DoubleAnimation 
                                                        Storyboard.TargetName="ThumbTransform"
                                                        Storyboard.TargetProperty="X"
                                                        To="16" 
                                                        Duration="0:0:0.2"/>
                                                    <!-- Change track color to green -->
                                                    <ColorAnimation 
                                                        Storyboard.TargetName="SwitchTrack"
                                                        Storyboard.TargetProperty="Background.Color"
                                                        To="#34C759" 
                                                        Duration="0:0:0.2"/>
                                                </Storyboard>
                                            </BeginStoryboard>
                                        </Trigger.EnterActions>
                                        <Trigger.ExitActions>
                                            <BeginStoryboard>
                                                <Storyboard>
                                                    <!-- Slide thumb to left -->
                                                    <DoubleAnimation 
                                                        Storyboard.TargetName="ThumbTransform"
                                                        Storyboard.TargetProperty="X"
                                                        To="0" 
                                                        Duration="0:0:0.2"/>
                                                    <!-- Change track color to gray -->
                                                    <ColorAnimation 
                                                        Storyboard.TargetName="SwitchTrack"
                                                        Storyboard.TargetProperty="Background.Color"
                                                        To="#E5E5E7" 
                                                        Duration="0:0:0.2"/>
                                                </Storyboard>
                                            </BeginStoryboard>
                                        </Trigger.ExitActions>
                                    </Trigger>
                                </ControlTemplate.Triggers>
                            </ControlTemplate>
                        </Setter.Value>
                    </Setter>
                </Style>
            </ResourceDictionary>
'@
                
        $reader = New-Object System.Xml.XmlNodeReader([xml]$styleXaml)
        $resourceDict = [Windows.Markup.XamlReader]::Load($reader)
                
        $toggleButton = New-Object System.Windows.Controls.Primitives.ToggleButton
        $toggleButton.Name = $Name
        $toggleButton.IsChecked = $IsChecked
        $toggleButton.Style = $resourceDict['CleanToggleStyle']
        $ParentControl.Children.Add($toggleButton) | Out-Null
                
        return $toggleButton
    }
    
    $divider = New-Object System.Windows.Controls.Separator
    $divider.Margin = '0,10,0,10'
    $divider.Background = [System.Windows.Media.Brushes]::DarkGray
    $stackPanel.Children.Add($divider) | Out-Null

    $classicAppsHeader = New-Object System.Windows.Controls.TextBlock
    $classicAppsHeader.Text = 'Install Classic Windows Apps'
    $classicAppsHeader.FontSize = 16
    $classicAppsHeader.FontWeight = 'Bold'
    $classicAppsHeader.Foreground = [System.Windows.Media.Brushes]::Cyan
    $classicAppsHeader.Margin = '0,10,0,10'
    $stackPanel.Children.Add($classicAppsHeader) | Out-Null

    $classicAppsFunctions = @(
        'Install-Classic-Photoviewer'
        'Install-Classic-Mspaint'
        'Install-Classic-SnippingTool'
        'Install-Classic-Notepad'
        'Install-Photos-Legacy'
    )

    $classicAppsDescriptions = @{
        'Install-Classic-Photoviewer'  = 'Installs the classic Windows Photo Viewer from Windows 7/8, allowing you to view images with the traditional viewer instead of the modern Photos app.'
        'Install-Classic-Mspaint'      = 'Installs the classic Microsoft Paint application from older Windows versions.'
        'Install-Classic-SnippingTool' = 'Installs the classic Snipping Tool, replacing the modern Snip & Sketch app.'
        'Install-Classic-Notepad'      = 'Installs the classic Notepad from Windows 10, replacing the modern uwp version.'
        'Install-Photos-Legacy'        = 'Installs the legacy Windows Photos app from the Microsoft Store.'
    }

    $functionDescriptions += $classicAppsDescriptions
    foreach ($func in $classicAppsFunctions) {
        $optionContainer = New-Object System.Windows.Controls.DockPanel
        $optionContainer.Margin = '0,5,0,5'
        $optionContainer.LastChildFill = $false
    
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $func.Replace('-', ' ')
        $checkbox.FontSize = 14
        $checkbox.Foreground = [System.Windows.Media.Brushes]::White
        $checkbox.Margin = '0,0,10,0'
        $checkbox.VerticalAlignment = 'Center'
        $checkbox.IsChecked = $false  
        [System.Windows.Controls.DockPanel]::SetDock($checkbox, 'Left')
        $checkboxes[$func] = $checkbox
    
        $infoButton = New-Object System.Windows.Controls.Button
        $infoButton.Content = '?'
        $infoButton.Width = 25
        $infoButton.Height = 25
        $infoButton.FontSize = 12
        $infoButton.FontWeight = 'Bold'
        $infoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
        $infoButton.Foreground = [System.Windows.Media.Brushes]::White
        $infoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
        $infoButton.BorderThickness = 0
        $infoButton.VerticalAlignment = 'Center'
        $infoButton.Cursor = 'Hand'
        [System.Windows.Controls.DockPanel]::SetDock($infoButton, 'Right')
    
        $infoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
        $infoButton.Template = [System.Windows.Markup.XamlReader]::Parse($infoTemplate)
    
        $infoButton.Add_Click({
                param($sender, $e)
        
                # Find the correct function name
                foreach ($f in $classicAppsFunctions) {
                    if ($checkboxes[$f].Parent -eq $sender.Parent) {
                        $funcName = $f
                        break
                    }
                }
        
                $description = $functionDescriptions[$funcName]
                [System.Windows.MessageBox]::Show($description, $funcName, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            })
    
        $optionContainer.Children.Add($checkbox) | Out-Null
        $optionContainer.Children.Add($infoButton) | Out-Null
        $stackPanel.Children.Add($optionContainer) | Out-Null
    }

    $allFunctions = $functions + $classicAppsFunctions
    
    $toggleGrid = New-Object System.Windows.Controls.Grid
    [System.Windows.Controls.Grid]::SetRow($toggleGrid, 2)  
    $toggleGrid.Margin = '20,10,55,15'
        
    $row1 = New-Object System.Windows.Controls.RowDefinition
    $row1.Height = [System.Windows.GridLength]::Auto
    $row2 = New-Object System.Windows.Controls.RowDefinition
    $row2.Height = [System.Windows.GridLength]::Auto
    $toggleGrid.RowDefinitions.Add($row1) | Out-Null
    $toggleGrid.RowDefinitions.Add($row2) | Out-Null
        
    $mainGrid.Children.Add($toggleGrid) | Out-Null

    $togglePanel1 = New-Object System.Windows.Controls.DockPanel
    $togglePanel1.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $togglePanel1.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $togglePanel1.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10) 
    $togglePanel1.LastChildFill = $false
    [System.Windows.Controls.Grid]::SetRow($togglePanel1, 0)
        
    $toggleLabel1 = New-Object System.Windows.Controls.TextBlock
    $toggleLabel1.Text = 'Revert Mode:'
    $toggleLabel1.Foreground = [System.Windows.Media.Brushes]::White
    $toggleLabel1.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $toggleLabel1.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
    [System.Windows.Controls.DockPanel]::SetDock($toggleLabel1, 'Left')
    $togglePanel1.Children.Add($toggleLabel1) | Out-Null
        
    $revertModeToggle = Add-iOSToggleToUI -ParentControl $togglePanel1 -IsChecked $revert
    [System.Windows.Controls.DockPanel]::SetDock($revertModeToggle, 'Left')

    $revertInfoButton = New-Object System.Windows.Controls.Button
    $revertInfoButton.Content = '?'
    $revertInfoButton.Width = 25
    $revertInfoButton.Height = 25
    $revertInfoButton.FontSize = 12
    $revertInfoButton.FontWeight = 'Bold'
    $revertInfoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
    $revertInfoButton.Foreground = [System.Windows.Media.Brushes]::White
    $revertInfoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $revertInfoButton.BorderThickness = 0
    $revertInfoButton.VerticalAlignment = 'Center'
    $revertInfoButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
    $revertInfoButton.Cursor = 'Hand'
    [System.Windows.Controls.DockPanel]::SetDock($revertInfoButton, 'Right')

    $revertInfoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $revertInfoButton.Template = [System.Windows.Markup.XamlReader]::Parse($revertInfoTemplate)
    $revertInfoButton.Add_Click({
            $description = 'Revert Mode will undo changes made by this tool, restoring AI features and settings to their original state. Selected options above will be reverted/enabled when this mode is selected.'
            [System.Windows.MessageBox]::Show($description, 'Revert Mode', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        })

    $togglePanel1.Children.Add($revertInfoButton) | Out-Null
    $toggleGrid.Children.Add($togglePanel1) | Out-Null

    $togglePanel2 = New-Object System.Windows.Controls.DockPanel
    $togglePanel2.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $togglePanel2.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $togglePanel2.LastChildFill = $false
    [System.Windows.Controls.Grid]::SetRow($togglePanel2, 1)
        
    $toggleLabel2 = New-Object System.Windows.Controls.TextBlock
    $toggleLabel2.Text = 'Backup Mode:'
    $toggleLabel2.Foreground = [System.Windows.Media.Brushes]::White
    $toggleLabel2.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $toggleLabel2.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
    [System.Windows.Controls.DockPanel]::SetDock($toggleLabel2, 'Left')
    $togglePanel2.Children.Add($toggleLabel2) | Out-Null
        
    $backupModeToggle = Add-iOSToggleToUI -ParentControl $togglePanel2 -IsChecked $backup
    [System.Windows.Controls.DockPanel]::SetDock($backupModeToggle, 'Left')

    $backupInfoButton = New-Object System.Windows.Controls.Button
    $backupInfoButton.Content = '?'
    $backupInfoButton.Width = 25
    $backupInfoButton.Height = 25
    $backupInfoButton.FontSize = 12
    $backupInfoButton.FontWeight = 'Bold'
    $backupInfoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
    $backupInfoButton.Foreground = [System.Windows.Media.Brushes]::White
    $backupInfoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $backupInfoButton.BorderThickness = 0
    $backupInfoButton.VerticalAlignment = 'Center'
    $backupInfoButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
    $backupInfoButton.Cursor = 'Hand'
    [System.Windows.Controls.DockPanel]::SetDock($backupInfoButton, 'Right')

    $backupInfoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $backupInfoButton.Template = [System.Windows.Markup.XamlReader]::Parse($backupInfoTemplate)
    $backupInfoButton.Add_Click({
            $description = 'Backup Mode keeps necessary files in your User directory allowing revert mode to work properly, use this option while removing AI if you would like to fully revert the removal process.'
            [System.Windows.MessageBox]::Show($description, 'Backup Mode', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        })

    $togglePanel2.Children.Add($backupInfoButton) | Out-Null
    $toggleGrid.Children.Add($togglePanel2) | Out-Null
    # ensure that backup mode and revert mode arent both selected at the same time (cant believe i have to do this - .)
    $backupModeToggle.Add_Checked({ 
            $Global:backup = 1
            $revertModeToggle.IsChecked = $false
        }) | Out-Null

    $backupModeToggle.Add_Unchecked({ 
            $Global:backup = 0 
        }) | Out-Null

    $revertModeToggle.Add_Checked({ 
            $Global:revert = 1 
            $backupModeToggle.IsChecked = $false
        }) | Out-Null

    $revertModeToggle.Add_Unchecked({ 
            $Global:revert = 0 
        }) | Out-Null
   
    $bottomGrid = New-Object System.Windows.Controls.Grid
    [System.Windows.Controls.Grid]::SetRow($bottomGrid, 3)
    $bottomGrid.Margin = '25,15,25,15'

    $leftColumn = New-Object System.Windows.Controls.ColumnDefinition
    $leftColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $bottomGrid.ColumnDefinitions.Add($leftColumn) | Out-Null

    $rightColumn = New-Object System.Windows.Controls.ColumnDefinition
    $rightColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $bottomGrid.ColumnDefinitions.Add($rightColumn) | Out-Null

    $actionPanel = New-Object System.Windows.Controls.StackPanel
    $actionPanel.Orientation = 'Horizontal'
    $actionPanel.HorizontalAlignment = 'Right'
    $actionPanel.VerticalAlignment = 'Center'
    [System.Windows.Controls.Grid]::SetColumn($actionPanel, 1)

    $cancelButton = New-Object System.Windows.Controls.Button
    $cancelButton.Content = 'Cancel'
    $cancelButton.Width = 80
    $cancelButton.Height = 35
    $cancelButton.Background = [System.Windows.Media.Brushes]::DarkRed
    $cancelButton.Foreground = [System.Windows.Media.Brushes]::White
    $cancelButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $cancelButton.BorderThickness = 0
    $cancelButton.Margin = '0,0,10,0'
    $cancelButton.Cursor = 'Hand'

    $cancelTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="17">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $cancelButton.Template = [System.Windows.Markup.XamlReader]::Parse($cancelTemplate)
    $cancelButton.Add_Click({
            $window.Close()
        })

    $applyButton = New-Object System.Windows.Controls.Button
    $applyButton.Content = 'Apply'
    $applyButton.Width = 80
    $applyButton.Height = 35
    $applyButton.Background = [System.Windows.Media.Brushes]::DarkGreen
    $applyButton.Foreground = [System.Windows.Media.Brushes]::White
    $applyButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $applyButton.BorderThickness = 0
    $applyButton.Cursor = 'Hand'

    $applyTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="17">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $applyButton.Template = [System.Windows.Markup.XamlReader]::Parse($applyTemplate)
    $applyButton.Add_Click({
            Write-Status -msg 'Killing AI Processes - '
            #kill ai processes to ensure script runs smoothly

    start-process msedge.exe 
    Start-Sleep 2
    get-process msedge | Stop-Process | Out-Null 

            $aiProcesses = @(
                'ai.exe'
                'Copilot.exe'
                'aihost.exe'
                'aicontext.exe'
                'ClickToDo.exe'
                'aixhost.exe'
                'WorkloadsSessionHost.exe'
                'WebViewHost.exe'
                'aimgr.exe'
                'AppActions.exe'
            )
            foreach ($procName in $aiProcesses) {
                taskkill /im $procName /f *>$null
            }
            Write-Host "success!" -ForegroundColor Green

            $progressWindow = New-Object System.Windows.Window
            $progressWindow.Title = 'Processing - '
            $progressWindow.Width = 400
            $progressWindow.Height = 200
            $progressWindow.WindowStartupLocation = 'CenterOwner'
            $progressWindow.Owner = $window
            $progressWindow.Background = [System.Windows.Media.Brushes]::Black
            $progressWindow.Foreground = [System.Windows.Media.Brushes]::White
            $progressWindow.ResizeMode = 'NoResize'
    
            $progressGrid = New-Object System.Windows.Controls.Grid
            $progressWindow.Content = $progressGrid
    
            $progressText = New-Object System.Windows.Controls.TextBlock
            $progressText.Text = 'Initializing - '
            $progressText.FontSize = 14
            $progressText.Foreground = [System.Windows.Media.Brushes]::Cyan
            $progressText.HorizontalAlignment = 'Center'
            $progressText.VerticalAlignment = 'Center'
            $progressText.TextWrapping = 'Wrap'
            $progressGrid.Children.Add($progressText) | Out-Null
    
            $progressWindow.Show()
    
            $selectedFunctions = @()
            foreach ($func in $allFunctions) {
                if ($checkboxes[$func].IsChecked) {
                    $selectedFunctions += $func
                }
            }
    
            if ($selectedFunctions.Count -eq 0) {
                $progressWindow.Close()
                [System.Windows.MessageBox]::Show('No options selected.', 'Nothing to Process', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
    
            try {
                if ($backup) {
                    CreateRestorePoint
                }
                foreach ($func in $selectedFunctions) {
                    $progressText.Text = "Executing: $($func.Replace('-', ' '))"
                    $progressWindow.UpdateLayout()
                    [System.Windows.Forms.Application]::DoEvents()

                    switch ($func) {
                        'Disable-Registry-Keys' { Disable-Registry-Keys }
                        'Prevent-AI-Package-Reinstall' { Install-NOAIPackage }
                        'Disable-Copilot-Policies' { Disable-Copilot-Policies }
                        'Remove-AI-Appx-Packages' { Remove-AI-Appx-Packages }
                        'Remove-Recall-Optional-Feature' { Remove-Recall-Optional-Feature }
                        'Remove-AI-CBS-Packages' { Remove-AI-CBS-Packages }
                        'Remove-AI-Files' { Remove-AI-Files }
                        'Hide-AI-Components' { Hide-AI-Components }
                        'Disable-Notepad-Rewrite' { Disable-Notepad-Rewrite }
                        'Remove-Recall-Tasks' { Remove-Recall-Tasks }
                        'Install-Classic-Photoviewer' { install-classicapps -app 'photoviewer' }
                        'Install-Classic-Mspaint' { install-classicapps -app 'mspaint' }
                        'Install-Classic-SnippingTool' { install-classicapps -app 'snippingtool' }
                        'Install-Classic-Notepad' { install-classicapps -app 'notepad' }
                        'Install-Photos-Legacy' { install-classicapps -app 'photoslegacy' }
                    }
            
                    Start-Sleep -Milliseconds 500
                }
        
                $progressText.Text = 'Completed successfully!'
                Start-Sleep -Seconds 2
                $progressWindow.Close()
        
                $result = [System.Windows.MessageBox]::Show("AI removal process completed successfully!`n`nWould you like to restart your computer now to ensure all changes take effect?", 'Process Complete', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        
                if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                    #cleanup code
                    try {
                        Remove-Item "$($tempDir)aiPackageRemoval.ps1" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}
                    try {
                        Remove-Item "$($tempDir)RemoveRecallTasks.ps1" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}
                    try {
                        Remove-Item "$($tempDir)PathsToDelete.txt" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}  
                    try {
                        Remove-Item "$($tempDir)SdManson8RemoveWindowsAI-*1.0.0.0.cab" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}

                    #set executionpolicy back to what it was
                    if ($ogExecutionPolicy) {
                        if ($Global:executionPolicyUser) {
                            Reg.exe add 'HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
                        }
                        elseif ($Global:executionPolicyMachine) {
                            Reg.exe add 'HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
                        }
                        elseif ($Global:executionPolicyWow64) {
                            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
                        }
                        elseif ($Global:executionPolicyUserPol) {
                            Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
                        }
                        else {
                            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
                        }
                    }
                    Restart-Computer -Force
                }
        
                $window.Close()
            }
            catch {
                $progressWindow.Close()
                [System.Windows.MessageBox]::Show("An error occurred: $($_.Exception.Message)", 'Error', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        })


    $actionPanel.Children.Add($cancelButton) | Out-Null
    $actionPanel.Children.Add($applyButton) | Out-Null

    $bottomGrid.Children.Add($actionPanel) | Out-Null
    $mainGrid.Children.Add($bottomGrid) | Out-Null

    $window.ShowDialog() | Out-Null
}

#cleanup code
try {
    Remove-Item "$($tempDir)aiPackageRemoval.ps1" -Force -ErrorAction SilentlyContinue
}
catch {}
try {
    Remove-Item "$($tempDir)RemoveRecallTasks.ps1" -Force -ErrorAction SilentlyContinue
}
catch {}
try {
    Remove-Item "$($tempDir)PathsToDelete.txt" -Force -ErrorAction SilentlyContinue
}
catch {}
try {
    Remove-Item "$($tempDir)SdManson8RemoveWindowsAI-*1.0.0.0.cab" -Force -ErrorAction SilentlyContinue
}
catch {}

#set executionpolicy back to what it was
if ($ogExecutionPolicy) {
    if ($Global:executionPolicyUser) {
        Reg.exe add 'HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
    elseif ($Global:executionPolicyMachine) {
        Reg.exe add 'HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
    elseif ($Global:executionPolicyWow64) {
        Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
    elseif ($Global:executionPolicyUserPol) {
        Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
    else {
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
}


