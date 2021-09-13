takeown /F c:\Windows.old\* /R /A /D Y
cacls c:\Windows.old\*.* /T /grant administrators:F
rmdir /S /Q c:\Windows.old
