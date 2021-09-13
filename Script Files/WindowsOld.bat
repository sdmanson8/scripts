TAKEOWN /F C:\Windows.old  /R /D  Y
icacls C:\Windows.old /grant administrators:F /T
RD /S \\?\C:\Windows.old
