TAKEOWN /F "%SystemDrive%\Windows.old" /A /R /D Y
ICACLS "%SystemDrive%\Windows.old" /T /grant :r Administrators:F
RD /S /Q "%SystemDrive%\Windows.old"
