#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Install Domain Apps"

########################### Script Starting ###################################
###############################################################################

Clear-Host
    # Avaya Agent Desktop
    Write-Host Opening Webpage to Download Prerequisites
    Start-Process http://avaya-accs/agentdesktop/setup.exe
    PAUSE
    Write-Host "Installing Avaya Agent Prerequisites"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process $downloads\setup.exe
    PAUSE
    Remove-Item $downloads\setup.exe
    Write-Host Opening Webpage to Download Avaya Agent Desktop
    Start-Process http://avaya-accs/agentdesktop/CCADClickOnce.application

    # Office 365 Work or School (Sign in to download Licensed version)
    Write-Host "Opening Webpage to Download Office 365"
    Start-Process "https://aka.ms/office-install"
    Write-Host "Sign in and Select Install Office"
    PAUSE
    Write-Host "Installing Office 365"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process $downloads\OfficeSetup.exe
    PAUSE
    Remove-Item $downloads\OfficeSetup.exe -Force 

    # Install Avaya Workplace
    Write-Output "Installing Avaya Workplace"
    msiexec.exe /i '\\reflex.co.za\Shared\Company Folder\Avaya IX Workplace Setup 3.8.0.136.14.msi' 

    # Install Ninja
    Write-Output "Installing Ninja"
    msiexec.exe /i '\\reflex.co.za\Shared\Company Folder\BU - EUC\BU - Managed Services\#Software\#NINJA_INSTALLS\REFLEX\reflexsolutionsworkstationmainoffice-4.4.6012-windows-installer.msi'

    # Install ESET
    Write-Output "Installing ESET"
    Start-Process -Wait -FilePath '\\reflex.co.za\Shared\Company Folder\BU - EUC\BU - Managed Services\#Software\ESET\AIO_FOR_ALL_CLIENTS\_WORK_STATION_AIO_ALL_CLIENTS_x64_en_US.exe' -ArgumentList '/S' -PassThru

    # Install Seco VPN
    Write-Output "Installing Seco VPN"
    Start-Process -Wait -FilePath '\\reflex.co.za\Shared\Company Folder\secoclient-win-64-7.0.5.1.exe' -ArgumentList '/S' -PassThru

    # Install Reflex Remote Support
    Write-Output "Installing Reflex Remote Support"
    msiexec.exe /i '\\reflex.co.za\Shared\Company Folder\BU - EUC\BU - Managed Services\#Software\RS\Reflex Internal\Reflex_RS_PCs.msi'

