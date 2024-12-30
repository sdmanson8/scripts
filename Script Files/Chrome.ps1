#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Chrome Installer"

########################### Script Starting ###################################
###############################################################################

Write-Host 'Preparing to Install Google Chrome'

# Install Google Chrome x64 on 64-Bit systems? $True or $False
$Installx64 = $True

# Define the temporary location to cache the installer.
$TempDirectory = "$ENV:Temp\Chrome"

# Run the script silently, $True or $False
$RunScriptSilent = $True

# Set the system architecture as a value.
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

Function Download-Chrome {
    Write-Host 'Downloading Chrome... ' -NoNewline
    # Test internet connection
    if (Test-Connection google.com -Count 3 -Quiet) {
		if ($OSArchitecture -eq "64-Bit" -and $Installx64 -eq $True){
			$Link = 'http://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi'
		} ELSE {
			$Link = 'http://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise.msi'
		}
    

        # Download the installer from Google
        try {
	        New-Item -ItemType Directory "$TempDirectory" -Force | Out-Null
	        (New-Object System.Net.WebClient).DownloadFile($Link, "$TempDirectory\Chrome.msi")
            Write-Host 'success!' -ForegroundColor Green
        } catch {
	        Write-Host 'failed. There was a problem with the download.' -ForegroundColor Red
#            if ($RunScriptSilent -NE $True){
#                Read-Host 'Press [Enter] to exit'
#            }
	        exit
        }
    } else {
        Write-Host "failed. Unable to connect to Google's servers." -ForegroundColor Red
#        if ($RunScriptSilent -NE $True){
#            Read-Host 'Press [Enter] to exit'
#        }
	    exit
    }
}

Function Install-Chrome {
    Write-Host 'Installing Chrome... ' -NoNewline    
    # Install Chrome
    $ChromeMSI = """$TempDirectory\Chrome.msi"""
	$ExitCode = (Start-Process -filepath msiexec -argumentlist "/i $ChromeMSI /qn /norestart" -Wait -PassThru).ExitCode
    
    if ($ExitCode -eq 0) {
        Write-Host 'success!' -ForegroundColor Green
    } else {
        Write-Host "failed. There was a problem installing Google Chrome. MsiExec returned exit code $ExitCode." -ForegroundColor Red
        Clean-Up
 #       if ($RunScriptSilent -NE $True){
 #           Read-Host 'Press [Enter] to exit'
#        }
	    exit
    }
}
Function Clean-Up {
    Write-Host 'Removing Chrome installer... ' -NoNewline

    try {
        # Remove the installer
        Remove-Item "$TempDirectory\Chrome.msi" -ErrorAction Stop
        Write-Host 'success!' -ForegroundColor Green
    } catch {
        Write-Host "failed. You will have to remove the installer yourself from $TempDirectory\." -ForegroundColor Yellow
    }
}

Download-Chrome
Install-Chrome
Clean-Up

#if ($RunScriptSilent -NE $True){
#    Read-Host 'Install complete! Press [Enter] to exit'
#}
