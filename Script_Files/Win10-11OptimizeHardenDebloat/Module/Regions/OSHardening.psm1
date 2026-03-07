using module ..\Logging.psm1
using module ..\Helpers.psm1

#region OS Hardening
<#
    .SYNOPSIS
    Disable legacy remote command surfaces and device metadata handlers.

    .DESCRIPTION
    Disables DCOM remote activation behavior and removes the device metadata
    file associations this preset treats as unnecessary remote command paths.

    .EXAMPLE
    Disable-RemoteCommands

    .NOTES
    Machine-wide
#>
function Disable-RemoteCommands {
    Write-Host "Disable Remote Commands - " -NoNewline
	LogInfo "Disabling Remote Commands"
    try
    {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\OLE" -Name "EnableDCOM" -Value "N" -ErrorAction Stop | Out-Null

        # Ensure the registry key exists before trying to remove the value
        if (Test-Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms")
		{
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Name "default" -Force -ErrorAction Stop | Out-Null
        }

        if (Test-Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms")
		{
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Name "default" -Force -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable remote commands: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Restrict wireless sign-in options on the lock screen.

    .DESCRIPTION
    Hides the network selection UI from the sign-in screen to reduce wireless
    attack surface before a user signs in.

    .EXAMPLE
    Suspend-AirstrikeAttack

    .NOTES
    Machine-wide
#>
function Suspend-AirstrikeAttack
{
    Write-Host "Restrict local Windows wireless exploitation - " -NoNewline
	LogInfo "Restricting local Windows wireless exploitation"
    try
    {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to restrict lock screen network selection: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Disable SMBv3 compression.

    .DESCRIPTION
    Turns off SMB compression at the server service level as part of the
    module's network hardening preset.

    .EXAMPLE
    Disable-SMBv3Compression

    .NOTES
    Machine-wide
#>
function Disable-SMBv3Compression
{
    Write-Host "Disable SMB version 3 Compression - " -NoNewline
	LogInfo "Disabling SMB version 3 Compression"
    try
    {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable SMBv3 compression: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Apply hardened Microsoft Office security settings.

    .DESCRIPTION
    Sets Office macro and content execution policies for supported Office
    versions to reduce document-based attack surface in Word and Publisher.

    .EXAMPLE
    Protect-MSOffice

    .NOTES
    Current user
#>
function Protect-MSOffice
{
    Write-Host "Configure Office to be Hardened - " -NoNewline
	LogInfo "Configuring Office to be Hardened"
    try
    {
        $officeVersions = @("12.0", "14.0", "15.0", "16.0")

        foreach ($version in $officeVersions)
		{
            $wordPath = "HKCU:\Software\Policies\Microsoft\Office\$version\Word\Security"
            $publisherPath = "HKCU:\Software\Policies\Microsoft\Office\$version\Publisher\Security"

            if (Test-Path $wordPath)
			{
                Set-ItemProperty -Path $wordPath -Name "vbawarnings" -Value 4 -ErrorAction Stop | Out-Null
            }

            if (Test-Path $publisherPath)
			{
                Set-ItemProperty -Path $publisherPath -Name "vbawarnings" -Value 4 -ErrorAction Stop | Out-Null
            }
        }

        $word15Path = "HKCU:\Software\Policies\Microsoft\Office\15.0\Word\Security"
        $word16Path = "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security"

        if (Test-Path $word15Path)
		{
            Set-ItemProperty -Path $word15Path -Name "blockcontentexecutionfrominternet" -Value 1 -ErrorAction Stop | Out-Null
        }

        if (Test-Path $word16Path)
		{
            Set-ItemProperty -Path $word16Path -Name "blockcontentexecutionfrominternet" -Value 1 -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure Office hardening settings: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Apply core operating system hardening settings.

    .DESCRIPTION
    Enables the OS-wide registry values used by this preset for credential,
    UAC, virtualization, and TCP/IP hardening.

    .EXAMPLE
    Protect-OS

    .NOTES
    Machine-wide
#>
function Protect-OS
{
    Write-Host "Configure OS to be Hardened - " -NoNewline
	LogInfo "Configuring OS to be Hardened"
    try
    {
        $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        if (Test-Path $wdigestPath)
		{
            Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -ErrorAction Stop | Out-Null
        }

        $kerberosPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        if (Test-Path $kerberosPath)
		{
            Set-ItemProperty -Path $kerberosPath -Name "SupportedEncryptionTypes" -Value 2147483640 -ErrorAction Stop | Out-Null
        }

        $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        if (Test-Path $tcpipPath)
		{
            Set-ItemProperty -Path $tcpipPath -Name "DisableIPSourceRouting" -Value 2 -ErrorAction Stop | Out-Null
        }

        $systemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (Test-Path $systemPath)
		{
            Set-ItemProperty -Path $systemPath -Name "EnableLUA" -Value 1 -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path $systemPath -Name "EnableVirtualization" -Value 1 -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path $systemPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure OS hardening settings: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Enable DLL hijacking prevention settings.

    .DESCRIPTION
    Configures the Session Manager DLL search order protections used by this
    preset to reduce common DLL hijacking paths.

    .EXAMPLE
    Set-DLLHijackingPrevention

    .NOTES
    Machine-wide
#>
function Set-DLLHijackingPrevention
{
    Write-Host "Configure DLL Hijacking Prevention - " -NoNewline
	LogInfo "Configuring DLL Hijacking Prevention"
    try
    {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -Value 2 -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDLLSearchMode" -Value 1 -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure DLL hijacking prevention: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Disable IPv6.

    .EXAMPLE
    Disable-IPv6

    .NOTES
    Machine-wide
#>
function Disable-IPv6
{
    Write-Host "Disable IPv6 - " -NoNewline
	LogInfo "Disabling IPv6"
    try
    {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\tcpip6\parameters" -Name "DisabledComponents" -Value 0xFF -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable IPv6: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Disable TCP timestamps.

    .EXAMPLE
    Disable-TCPTimestamps

    .NOTES
    Machine-wide
#>
function Disable-TCPTimestamps
{
    Write-Host "Disable TCP Timestamps - " -NoNewline
	LogInfo "Disabling TCP Timestamps"
    try
	{
        netsh int tcp set global timestamps=disabled 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0)
        {
            throw "netsh returned exit code $LASTEXITCODE"
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable TCP timestamps: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Enable anti-spoofing protection for Windows Hello biometrics.

    .DESCRIPTION
    Creates the required policy path if necessary and enables enhanced
    anti-spoofing for supported biometric sign-in hardware.

    .EXAMPLE
    Enable-BiometricsAntiSpoofing

    .NOTES
    Machine-wide
#>
function Enable-BiometricsAntiSpoofing
{
    Write-Host "Enable Biometrics Anti-Spoofing - " -NoNewline
    LogInfo "Enabling Biometrics Anti-Spoofing"
    $path = "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"

    # Ensure the path exists, creating it if necessary
    if (-not (Test-Path -Path "HKLM:\$path"))
	{
        try
		{
            New-Item -Path "HKLM:\$path" -Force | Out-Null
        }
		catch
		{
            LogError "Failed to create registry path: $path"
        }
    }

    try
    {
        Set-ItemProperty -Path "HKLM:\$path" -Name "EnhancedAntiSpoofing" -Value 1 -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to enable biometrics anti-spoofing: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Ensure a registry path exists before other hardening settings use it.

    .PARAMETER path
    The registry path to create if it does not already exist.

    .EXAMPLE
    Update-RegistryPaths -path 'HKLM:\Software\Example'

    .NOTES
    Machine-wide
#>
function Update-RegistryPaths
{
    param (
        [string]$path
    )

    # Ensure $path is not empty before proceeding
    if ([string]::IsNullOrWhiteSpace($path))
	{
        return
    }

    if (-not (Test-Path -Path $path))
	{
        try
		{
            New-Item -Path $path -Force | Out-Null
        }
		catch
		{
           LogError "Failed to create registry path: $path"
        }
    }
}

<#
    .SYNOPSIS
    Disable AutoRun for current-user and machine-wide Explorer policies.

    .DESCRIPTION
    Creates the Explorer policy paths if needed and sets the AutoRun block
    value used by this preset for both HKLM and HKCU.

    .EXAMPLE
    Disable-AutoRun

    .NOTES
    Current user, Machine-wide
#>
function Disable-AutoRun
{
    Write-Host "Disable AutoRun - " -NoNewline
    LogInfo "Disabling Autorun"
    # Ensure paths exist or suppress the error
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )

    # Create missing paths and set registry values
    try
    {
        foreach ($path in $paths)
		{
            if (-not (Test-Path -Path $path))
			{
                New-Item -Path $path -Force -ErrorAction Stop | Out-Null
            }

            New-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 0xFF -Force -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable AutoRun: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Disable SCHANNEL cipher entries defined in this preset.

    .EXAMPLE
    Disable-AESCiphers

    .NOTES
    Machine-wide
#>
function Disable-AESCiphers
{
    Write-Host "Disable AES Ciphers - " -NoNewline
	LogInfo "Disabling AES Ciphers"
    try
	{
        $ciphers = @(
            'AES 128/128', 'AES 256/256', 'DES 56/56', 'RC2 128/128', 'RC4 128/128'
        )
        foreach ($cipher in $ciphers)
		{
            $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"

            if (-not (Test-Path $cipherPath))
			{
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" -Name $cipher -Force -ErrorAction Stop | Out-Null
            }

            Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable AES ciphers: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Disable RC2 and RC4 SCHANNEL ciphers.

    .EXAMPLE
    Disable-RC2RC4Ciphers

    .NOTES
    Machine-wide
#>
function Disable-RC2RC4Ciphers
{
    Write-Host "Disable RC2 and RC4 Ciphers - " -NoNewline
	LogInfo "Disabling RC2 and RC4 Ciphers"
    try
	{
        $rcCiphers = @("RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128")
        foreach ($cipher in $rcCiphers)
		{
            $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"

            if (-not (Test-Path $cipherPath))
			{
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" -Name $cipher -Force -ErrorAction Stop | Out-Null
            }

            Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable RC2 and RC4 ciphers: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Disable the Triple DES SCHANNEL cipher.

    .EXAMPLE
    Disable-TripleDESCipher

    .NOTES
    Machine-wide
#>
function Disable-TripleDESCipher
{
    Write-Host "Disable Triple DES Ciphers - " -NoNewline
	LogInfo "Disabling Triple DES Ciphers"
    try
	{
        $cipherPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'

        if (-not (Test-Path $cipherPath))
		{
            New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Name 'Triple DES 168' -Force -ErrorAction Stop | Out-Null
        }

        Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to disable the Triple DES cipher: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Configure SCHANNEL hash algorithm settings.

    .EXAMPLE
    Disable-HashAlgorithms

    .NOTES
    Machine-wide
#>
function Disable-HashAlgorithms
{
    Write-Host "Disable Hash Algorithms - " -NoNewline
	LogInfo "Disabling Hash Algorithms"
    try
	{
        $hashes = @('MD5', 'SHA', 'SHA256', 'SHA384', 'SHA512')

        foreach ($hash in $hashes)
		{
            $hashPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hash"

            if (-not (Test-Path $hashPath))
			{
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes" -Name $hash -Force -ErrorAction Stop | Out-Null
            }

            Set-ItemProperty -Path $hashPath -Name 'Enabled' -Value 0xffffffff -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure SCHANNEL hash algorithms: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Configure SCHANNEL key exchange algorithm settings.

    .EXAMPLE
    Update-KeyExchanges

    .NOTES
    Machine-wide
#>
function Update-KeyExchanges
{
    Write-Host "Configure Key Exchanges - " -NoNewline
	LogInfo "Configuring Key Exchanges"
    try
	{
        $keyPaths = @(
            'Diffie-Hellman', 'ECDH', 'PKCS'
        )

        foreach ($keyPath in $keyPaths)
		{
            $fullPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$keyPath"

            if (-not (Test-Path $fullPath))
			{
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms" -Name $keyPath -Force -ErrorAction Stop | Out-Null
            }

            Set-ItemProperty -Path $fullPath -Name 'Enabled' -Value 0xffffffff -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure key exchange algorithms: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Configure SSL and TLS protocol settings in SCHANNEL.

    .DESCRIPTION
    Creates and updates the SCHANNEL protocol keys used by this preset to
    disable older protocols and define the preferred TLS configuration.

    .EXAMPLE
    Update-Protocols

    .NOTES
    Machine-wide
#>
function Update-Protocols
{
    Write-Host "Configure SSL/TLS Protocols - " -NoNewline
	LogInfo "Configuring SSL/TLS Protocols"
    try
	{
        $protocols = @{
            'Multi-Protocol Unified Hello\Client' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'Multi-Protocol Unified Hello\Server' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'PCT 1.0\Client' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'PCT 1.0\Server' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'SSL 2.0\Client' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'SSL 2.0\Server' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'SSL 3.0\Client' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'SSL 3.0\Server' = @{'Enabled' = 0; 'DisabledByDefault' = 1}
            'TLS 1.0\Client' = @{'Enabled' = 0xffffffff; 'DisabledByDefault' = 0}
            'TLS 1.0\Server' = @{'Enabled' = 0xffffffff; 'DisabledByDefault' = 0}
            'TLS 1.1\Client' = @{'Enabled' = 0xffffffff; 'DisabledByDefault' = 0}
            'TLS 1.1\Server' = @{'Enabled' = 0xffffffff; 'DisabledByDefault' = 0}
            'TLS 1.2\Client' = @{'Enabled' = 0xffffffff; 'DisabledByDefault' = 0}
            'TLS 1.2\Server' = @{'Enabled' = 0xffffffff; 'DisabledByDefault' = 0}
        }
        foreach ($protocol in $protocols.Keys)
		{
            foreach ($key in $protocols[$protocol].Keys)
			{
                $protocolPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol"

                if (Update-RegistryPaths -path $protocolPath)
				{
                    Set-ItemProperty -Path $protocolPath -Name $key -Value $protocols[$protocol][$key] -ErrorAction Stop | Out-Null
				}
            }
        }
        Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure SSL/TLS protocol settings: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Configure the SCHANNEL cipher suite list used by this preset.

    .EXAMPLE
    Update-CipherSuites

    .NOTES
    Machine-wide
#>
function Update-CipherSuites
{
    Write-Host "Configure Cipher Suites - " -NoNewline
	LogInfo "Configuring Cipher Suites"
    try
	{
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" -Name "TLS_RSA_WITH_AES_256_CBC_SHA256" -Value 0x1 -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" -Name "TLS_RSA_WITH_AES_128_CBC_SHA256" -Value 0x1 -ErrorAction Stop | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure cipher suites: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Enable strong .NET authentication behavior.

    .EXAMPLE
    Update-DotNetStrongAuth

    .NOTES
    Machine-wide
#>
function Update-DotNetStrongAuth
{
    Write-Host "Use Strong .Net Authentication - " -NoNewline
	LogInfo "Using Strong .Net Authentication"
    try
	{
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
        )

        foreach ($path in $paths)
        {
            if (-not (Test-Path -Path $path))
            {
                New-Item -Path $path -Force -ErrorAction Stop | Out-Null
            }

            New-ItemProperty -Path $path -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $path -Name "SystemDefaultTlsVersions" -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
        }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to enable strong .NET authentication: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Increase the Security event log size.

    .EXAMPLE
    Update-EventLogSize

    .NOTES
    Machine-wide
#>
function Update-EventLogSize
{
    Write-Host "Configure Event Log Sizes - " -NoNewline
	LogInfo "Configuring Event Log Sizes"
    try
	{
        wevtutil sl Security /ms:1024000 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wevtutil returned exit code $LASTEXITCODE" }
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        Write-Host "Failed! Check logs for details." -ForegroundColor Red
        LogError "Failed to configure the Security event log size: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    Apply the Adobe Reader DC security settings used by this preset.

    .DESCRIPTION
    Updates the Adobe Reader DC policy path used by this preset when that
    product is installed for the current user.

    .EXAMPLE
    Update-AdobereaderDCSTIG

    .NOTES
    Current user
#>
function Update-AdobereaderDCSTIG
{
    Write-Host "Configure Adobe Reader Security - " -NoNewline
	LogInfo "Configuring Adobe Reader Security"
    # Check if the Adobe Reader registry path exists
    $adobePath = "Software\Policies\Adobe\Acrobat Reader\DC\Privileged"
    if (Test-Path -Path "HKCU:\$adobePath")
	{
        Set-ItemProperty -Path "HKCU:\$adobePath" -Name "bProtectedMode" -Value 0 -ErrorAction SilentlyContinue | Out-Null
        Write-Host "success!" -ForegroundColor Green
    }
    else
	{
        Write-Host "success!" -ForegroundColor Green
        LogWarning "Adobe Reader is not installed or the registry path does not exist. Skipping configuration."
    }

}
#endregion OS Hardening
