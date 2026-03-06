using module ..\Logging.psm1
using module ..\Helpers.psm1

#region OS Hardening
function Disable-RemoteCommands {
    Write-Host "Disable Remote Commands - " -NoNewline
	LogInfo "Disabling Remote Commands"
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\OLE" -Name "EnableDCOM" -Value "N" | Out-Null

    # Ensure the registry key exists before trying to remove the value
    if (Test-Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms")
	{
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Name "default" -Force | Out-Null
    }

    if (Test-Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms")
	{
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Name "default" -Force | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Suspend-AirstrikeAttack
{
    Write-Host "Restrict local Windows wireless exploitation - " -NoNewline
	LogInfo "Restricting local Windows wireless exploitation"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Disable-SMBv3Compression
{
    Write-Host "Disable SMB version 3 Compression - " -NoNewline
	LogInfo "Disabling SMB version 3 Compression"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Protect-MSOffice
{
    Write-Host "Configure Office to be Hardened - " -NoNewline
	LogInfo "Configuring Office to be Hardened"
    $officeVersions = @("12.0", "14.0", "15.0", "16.0")

    foreach ($version in $officeVersions)
	{
        $wordPath = "HKCU:\Software\Policies\Microsoft\Office\$version\Word\Security"
        $publisherPath = "HKCU:\Software\Policies\Microsoft\Office\$version\Publisher\Security"

        # Check if the Word registry path exists before setting vbawarnings
        if (Test-Path $wordPath)
		{
            Set-ItemProperty -Path $wordPath -Name "vbawarnings" -Value 4 | Out-Null
        }

        # Check if the Publisher registry path exists before setting vbawarnings
        if (Test-Path $publisherPath)
		{
            Set-ItemProperty -Path $publisherPath -Name "vbawarnings" -Value 4 | Out-Null
        }
    }

    # Check and apply settings for blockcontentexecutionfrominternet for Office 15.0 and 16.0 Word
    $word15Path = "HKCU:\Software\Policies\Microsoft\Office\15.0\Word\Security"
    $word16Path = "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security"

    if (Test-Path $word15Path)
	{
        Set-ItemProperty -Path $word15Path -Name "blockcontentexecutionfrominternet" -Value 1 | Out-Null
    }

    if (Test-Path $word16Path)
	{
        Set-ItemProperty -Path $word16Path -Name "blockcontentexecutionfrominternet" -Value 1 | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Protect-OS
{
    Write-Host "Configure OS to be Hardened - " -NoNewline
	LogInfo "Configuring OS to be Hardened"
    # Check if the WDigest registry path exists before setting the value
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (Test-Path $wdigestPath)
	{
        Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 | Out-Null
    }

    # Check if the Kerberos Parameters registry path exists before setting the value
    $kerberosPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    if (Test-Path $kerberosPath)
	{
        Set-ItemProperty -Path $kerberosPath -Name "SupportedEncryptionTypes" -Value 2147483640 | Out-Null
    }

    # Check if the Tcpip Parameters registry path exists before setting the value
    $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    if (Test-Path $tcpipPath)
	{
        Set-ItemProperty -Path $tcpipPath -Name "DisableIPSourceRouting" -Value 2 | Out-Null
    }

    # Check if the System registry path exists before setting EnableLUA
    $systemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (Test-Path $systemPath)
	{
        Set-ItemProperty -Path $systemPath -Name "EnableLUA" -Value 1 | Out-Null
        Set-ItemProperty -Path $systemPath -Name "EnableVirtualization" -Value 1 | Out-Null
        Set-ItemProperty -Path $systemPath -Name "ConsentPromptBehaviorAdmin" -Value 2 | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Set-DLLHijackingPrevention
{
    Write-Host "Configure DLL Hijacking Prevention - " -NoNewline
	LogInfo "Configuring DLL Hijacking Prevention"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -Value 2 | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDLLSearchMode" -Value 1 | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Disable-IPv6
{
    Write-Host "Disable IPv6 - " -NoNewline
	LogInfo "Disabling IPv6"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\tcpip6\parameters" -Name "DisabledComponents" -Value 0xFF | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Disable-TCPTimestamps
{
    Write-Host "Disable TCP Timestamps - " -NoNewline
	LogInfo "Disabling TCP Timestamps"
    netsh int tcp set global timestamps=disabled | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

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

    Set-ItemProperty -Path "HKLM:\$path" -Name "EnhancedAntiSpoofing" -Value 1 -ErrorAction SilentlyContinue | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

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

function Disable-AutoRun
{
    Write-Host "Disable AutoRun - " -NoNewline
    LogInfo "Disabling Autorun"
    # Ensure paths exist or suppress the error
    $paths = @(
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )

    # Create missing paths and set registry values
    foreach ($path in $paths)
	{
        if (-not (Test-Path -Path $path))
		{
            New-Item -Path $path -Force | Out-Null
        }

        Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Value 0xFF -ErrorAction SilentlyContinue | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Disable-AESCiphers
{
    Write-Host "Disable AES Ciphers - " -NoNewline
	LogInfo "Disabling AES Ciphers"
    $ciphers = @(
        'AES 128/128', 'AES 256/256', 'DES 56/56', 'RC2 128/128', 'RC4 128/128'
    )
    foreach ($cipher in $ciphers)
	{
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"

        if (-not (Test-Path $cipherPath))
		{
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" -Name $cipher -Force | Out-Null
        }

        Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Disable-RC2RC4Ciphers
{
    Write-Host "Disable RC2 and RC4 Ciphers - " -NoNewline
	LogInfo "Disabling RC2 and RC4 Ciphers"
    $rcCiphers = @("RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128")
    foreach ($cipher in $rcCiphers)
	{
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"

        if (-not (Test-Path $cipherPath))
		{
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" -Name $cipher -Force | Out-Null
        }

        Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Disable-TripleDESCipher
{
    Write-Host "Disable Triple DES Ciphers - " -NoNewline
	LogInfo "Disabling Triple DES Ciphers"
    $cipherPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'

    if (-not (Test-Path $cipherPath))
	{
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Name 'Triple DES 168' -Force | Out-Null
    }

    Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Disable-HashAlgorithms
{
    Write-Host "Disable Hash Algorithms - " -NoNewline
	LogInfo "Disabling Hash Algorithms"
    $hashes = @('MD5', 'SHA', 'SHA256', 'SHA384', 'SHA512')

    foreach ($hash in $hashes)
	{
        $hashPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hash"

        # Check if the registry key exists, if not, create it
        if (-not (Test-Path $hashPath))
		{
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes" -Name $hash -Force | Out-Null
        }

        # Set the 'Enabled' value to 0xffffffff
        Set-ItemProperty -Path $hashPath -Name 'Enabled' -Value 0xffffffff | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Update-KeyExchanges
{
    Write-Host "Configure Key Exchanges - " -NoNewline
	LogInfo "Configuring Key Exchanges"
    $keyPaths = @(
        'Diffie-Hellman', 'ECDH', 'PKCS'
    )

    foreach ($keyPath in $keyPaths)
	{
        $fullPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$keyPath"

        if (-not (Test-Path $fullPath))
		{
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms" -Name $keyPath -Force | Out-Null
        }

        Set-ItemProperty -Path $fullPath -Name 'Enabled' -Value 0xffffffff | Out-Null
    }
	Write-Host "success!" -ForegroundColor Green
}

function Update-Protocols
{
    Write-Host "Configure SSL/TLS Protocols - " -NoNewline
	LogInfo "Configuring SSL/TLS Protocols"
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
    Write-Host "success!" -ForegroundColor Green
    foreach ($protocol in $protocols.Keys)
	{
        foreach ($key in $protocols[$protocol].Keys)
		{
            $protocolPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol"

            # Ensure the registry path exists before setting properties
            if (Update-RegistryPaths -path $protocolPath)
			{
				Write-Host "Updating SSL/TLS Registry Paths - " -NoNewline
				LogInfo "Updating SSL/TLS Registry Paths"
                Set-ItemProperty -Path $protocolPath -Name $key -Value $protocols[$protocol][$key] | Out-Null
			}
        }
    }
}

function Update-CipherSuites
{
    Write-Host "Configure Cipher Suites - " -NoNewline
	LogInfo "Configuring Cipher Suites"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" -Name "TLS_RSA_WITH_AES_256_CBC_SHA256" -Value 0x1 | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" -Name "TLS_RSA_WITH_AES_128_CBC_SHA256" -Value 0x1 | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Update-DotNetStrongAuth
{
    Write-Host "Use Strong .Net Authentication - " -NoNewline
	LogInfo "Using Strong .Net Authentication"
    Set-ItemProperty -Path "HKLM\Software\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "EnableLegacyStrongNameBehavior" -Value 0 -ErrorAction SilentlyContinue | Out-Null
	Write-Host "success!" -ForegroundColor Green
}

function Update-EventLogSize
{
    Write-Host "Configure Event Log Sizes - " -NoNewline
	LogInfo "Configuring Event Log Sizes"
    try
	{
        wevtutil sl Security /ms:1024000 | Out-Null
		Write-Host "success!" -ForegroundColor Green
    }
    catch
	{
        LogError "Wevtutil cmdlet not available, skipping."
    }
}

function Update-AdobereaderDCSTIG
{
    Write-Host "Configure Adobe Reader Security - " -NoNewline
	LogInfo "Configuring Adobe Reader Security"
    # Check if the Adobe Reader registry path exists
    $adobePath = "Software\Policies\Adobe\Acrobat Reader\DC\Privileged"
    if (Test-Path -Path "HKCU:\$adobePath")
	{
        Set-ItemProperty -Path "HKCU:\$adobePath" -Name "bProtectedMode" -Value 0 -ErrorAction SilentlyContinue | Out-Null
    }
    else
	{
        LogInfo "Adobe Reader is not installed or the registry path does not exist. Skipping configuration."
    }
	Write-Host "success!" -ForegroundColor Green
}
#endregion OS Hardening
