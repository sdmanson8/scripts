#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Install HP Software and Drivers"

########################### Script Starting ###################################
###############################################################################

Clear-Host

    # HP Driver Pack
    Write-Host "Preparing to Download Drivers [Search for correct Laptop]"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/HP_Driverpack_Matrix_x64.html"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/HP_Driverpack_Matrix_x64.html"
}
function Pause{ $null = Read-Host 'Press Enter if Application downloaded' }
	Pause
    Write-Host "Installing HP Drivers"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -Wait -FilePath "$downloads\sp*.exe"
    Remove-Item "$downloads\sp*.exe"
    Remove-Item $env:SystemRoot\SWSetup -Force -ErrorAction SilentlyContinue -Confirm:$false
}  
    PAUSE
    Write-Host "Installing HP Drivers"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -Wait -FilePath "$downloads\sp*.exe"
    Remove-Item "$downloads\sp*.exe"
    Remove-Item C:\SWSetup -Force -ErrorAction SilentlyContinue -Confirm:$false

    # HP Software Framework
    Write-Host "Downloading HP Software Framework"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "http://ftp.ext.hp.com//pub/caps-softpaq/cmit/softpaq/CASLSetup.exe" -OutFile "$downloads\CASLSetup.exe" -UseBasicParsing
    Write-Host "Installing HP Software Framework"
    Start-Process -Wait -FilePath "$downloads\CASLSetup.exe"
    Remove-Item "$downloads\CASLSetup.exe" -Force -ErrorAction SilentlyContinue -Confirm:$false

    # HP Support Assistant
    Write-Host "Preparing to Download HP Support Assistant"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host "https://support.hp.com/us-en/help/hp-support-assistant"
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "https://support.hp.com/us-en/help/hp-support-assistant"
}
function Pause{ $null = Read-Host 'Press Enter if Application downloaded' }
	Pause
    Write-Host "Installing HP Support Assistant"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -Wait -FilePath "$downloads\sp*.exe"
    Remove-Item "$downloads\sp*.exe"
    Remove-Item "$downloads\SWSetup" -Force -ErrorAction SilentlyContinue -Confirm:$false
