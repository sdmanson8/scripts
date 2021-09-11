cls
Set-ExecutionPolicy Unrestricted

cls
$msg     = 'Do you want to update Powershell, Type Y/N?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to update Powershell
    Write-Output "Updating Powershell"
    & 'C:\scripts\Script Files\Powershell.ps1'
    }
} until ($response -eq 'n')

cls
$msg     = 'Do you want to run Remove-Windows10-Bloat by matthewjberger, Type Y/N?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Remove-Windows10-Bloat by matthewjberger
    Write-Output "Running Remove-Windows10-Bloat by matthewjberger"
    & 'C:\scripts\Script Files\debloat.ps1'
    }
} until ($response -eq 'n')

cls
$msg     = 'Do you want to download PatchMyPC, Type Y/N?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to download PatchMyPC
    Write-Output "Downloading PatchMyPC"
    & 'C:\scripts\Script Files\PatchMyPC.bat'
    }
} until ($response -eq 'n')

cls
$msg     = 'Do you want to run Remove-Windows10-Bloat, Type Y/N?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Remove-Windows10-Bloat
    Write-Output "Running Remove-Windows10-Bloat"
    & 'C:\scripts\Script Files\Remove-Windows10-Bloat.bat'
    }
} until ($response -eq 'n')

cls
$msg     = 'Do you want to run Sophia Script (Expert) for Windows 10, Type Y/N?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Sophia Script for Windows 10
    Write-Output "Running Sophia Script for Windows 10"
    & 'C:\scripts\Script Files\Sophia Script Windows 10.ps1'
    }
} until ($response -eq 'n')

cls
$msg     = 'Do you want to run Sophia Script (Expert) for Windows 11, Type Y/N?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        # prompt to run Sophia Script for Windows 11
    Write-Output "Running Sophia Script for Windows 11"
    & 'C:\scripts\Script Files\Sophia Script Windows 11.ps1'
    }
} until ($response -eq 'n')