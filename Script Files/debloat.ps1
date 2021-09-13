#Create Restore Point
Checkpoint-Computer -Description "Tweak/Bloatware for Windows" -RestorePointType MODIFY_SETTINGS
iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JJ8R4'))
