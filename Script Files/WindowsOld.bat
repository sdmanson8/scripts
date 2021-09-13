$Drive = (Get-Partition | Where-Object {((Test-Path ($_.DriveLetter + ':\Windows.old')) -eq $True)}).DriveLetter
If ((Test-Path ($Drive + ':\Windows.old')) -eq $true) {
    $Directory = $Drive + ':\Windows.old'
    cmd.exe /c rmdir /S /Q $Directory
}
