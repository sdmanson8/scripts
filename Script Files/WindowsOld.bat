takeown /F c:\Windows.old\* /R /A /D Y
cacls c:\Windows.old\*.* /T /grant administrators:F
rmdir /S /Q c:\Windows.old

dism /online /cleanup-image /AnalyzeComponentStore
Start-Sleep -Seconds 5
dism /online /cleanup-image /StartComponentCleanup /ResetBase
