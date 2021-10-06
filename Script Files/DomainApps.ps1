
    # Avaya Agent Desktop
    Write-Host Opening Webpage to Download Prerequisites
    Start-Process http://avaya-accs/agentdesktop/setup.exe
    PAUSE
    Write-Host "Installing Avaya Agent Prerequisites"
    Start-Process $env:USERPROFILE\Downloads\setup.exe
    PAUSE
    Remove-Item $env:USERPROFILE\Downloads\setup.exe
    Write-Host Opening Webpage to Download Avaya Agent Desktop
    Start-Process http://avaya-accs/agentdesktop/CCADClickOnce.application

    # Office 365 Work or School (Sign in to download Licensed version)
    Write-Host "Opening Webpage to Download Office 365"
    Start-Process "https://aka.ms/office-install"
    Write-Host "Sign in and Select Install Office"
    PAUSE
    Write-Host "Installing Office 365"
    Start-Process $env:USERPROFILE\Downloads\OfficeSetup.exe
    PAUSE
    Remove-Item $env:USERPROFILE\Downloads\OfficeSetup.exe -Force 

Start-Process -FilePath "\\reflex.co.za\Shared\Company Folder"
PAUSE
(New-Object -comObject Shell.Application).Windows() | ? { $_.FullName -ne $null} | ? {
$_.FullName.toLower().Endswith('\explorer.exe') } | % { $_.Quit() }
    # Install Avaya Workplace
    Write-Output "Installing Avaya Workplace"
    msiexec.exe /i '\\zarbkfs01\Company Folder\Avaya IX Workplace Setup 3.8.0.136.14.msi' 

Start-Process -FilePath "\\reflex.co.za\Shared\Company Folder"
PAUSE
(New-Object -comObject Shell.Application).Windows() | ? { $_.FullName -ne $null} | ? {
$_.FullName.toLower().Endswith('\explorer.exe') } | % { $_.Quit() }
    # Install Ninja
    Write-Output "Installing Ninja"
    msiexec.exe /i '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\#NINJA_INSTALLS\REFLEX\reflexsolutionsworkstationmainoffice-4.4.6012-windows-installer.msi'

Start-Process -FilePath "\\reflex.co.za\Shared\Company Folder"
PAUSE
(New-Object -comObject Shell.Application).Windows() | ? { $_.FullName -ne $null} | ? {
$_.FullName.toLower().Endswith('\explorer.exe') } | % { $_.Quit() }
    # Install ESET
    Write-Output "Installing ESET"
    Start-Process -Wait -FilePath '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\ESET\AIO_FOR_ALL_CLIENTS\_WORK_STATION_AIO_ALL_CLIENTS_x64_en_US.exe' -ArgumentList '/S' -PassThru

Start-Process -FilePath "\\reflex.co.za\Shared\Company Folder"
PAUSE
(New-Object -comObject Shell.Application).Windows() | ? { $_.FullName -ne $null} | ? {
$_.FullName.toLower().Endswith('\explorer.exe') } | % { $_.Quit() }
    # Install FortiClient VPN
    Write-Output "Installing Seco VPN"
    Start-Process -Wait -FilePath '\\zarbkfs01\Company Folder\secoclient-win-64-7.0.5.1.exe' -ArgumentList '/S' -PassThru

Start-Process -FilePath "\\reflex.co.za\Shared\Company Folder"
PAUSE
(New-Object -comObject Shell.Application).Windows() | ? { $_.FullName -ne $null} | ? {
$_.FullName.toLower().Endswith('\explorer.exe') } | % { $_.Quit() }
    # Install Reflex Remote Support
    Write-Output "Installing Reflex Remote Support"
    msiexec.exe /i '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\RS\Reflex Internal\Reflex_RS_PCs.msi'

