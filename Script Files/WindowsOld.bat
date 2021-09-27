takeown /F c:\Windows.old\* /R /A /D Y
cacls c:\Windows.old\*.* /T /grant administrators:F
Remove-Item c:\Windows.old\ -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false

echo "Clearing Component Store (WinSxS)"
timeout 5
dism /online /cleanup-image /StartComponentCleanup /ResetBase
