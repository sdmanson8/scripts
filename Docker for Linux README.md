# Docker for Linux 

Install SSH 
sudo apt install -y ssh

Open your SSH terminal
Install powershell

wget -O - https://raw.githubusercontent.com/PowerShell/PowerShell/master/tools/install-powershell.sh | bash -s

Create Main Script File

nano Script.ps1

Enter the Below in the .ps1 file

$ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1
Invoke-Expression $($ScriptFromGithHub.Content)

Save and exit

CTRL + X, Save (Y), Press Enter to use the same file name

Run the Powershell Script

chmod +x Script.ps1 && pwsh ./Script.ps1

---------------------------------------------------------

Config Instructions


