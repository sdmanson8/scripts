TAKEOWN /F "C:\Windows.old" /A /R /D Y
ICACLS "C:\Windows.old" /T /grant :r Administrators:F
RD /S /Q "C:\Windows.old"
