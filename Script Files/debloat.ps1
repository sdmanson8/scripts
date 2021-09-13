#Create Restore Point
Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Tweak/Bloatware for Windows", 100, 12
iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JJ8R4'))
