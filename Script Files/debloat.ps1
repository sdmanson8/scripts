#Create Restore Point
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -Command "Checkpoint-Computer -Description "Windows Tweak/Optimizer Tool" -RestorePointType "MODIFY_SETTINGS"; " ' " -Verb RunAs}"
iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JJ8R4'))
