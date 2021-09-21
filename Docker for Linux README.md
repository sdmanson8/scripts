# Docker for Linux 

Install SSH 
```
sudo apt install -y ssh
```
Open your SSH terminal
Install powershell
```
wget -O - https://raw.githubusercontent.com/PowerShell/PowerShell/master/tools/install-powershell.sh | bash -s
```
Create Main Script File
```
nano Script.ps1
```
Enter the Below in the .ps1 file
```
$ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1
Invoke-Expression $($ScriptFromGithHub.Content)
```
Save and exit

CTRL + X, Save (Y), Press Enter to use the same file name

Run the Powershell Script
```
chmod +x Script.ps1 && pwsh ./Script.ps1
```
---------------------------------------------------------

Config Instructions


After running the Update + Install Requires Apps [Script](https://github.com/sdmanson8/scripts/blob/main/Script%20Files/ConfigureLinuxForDocker.ps1) and rebooted your System run:
```
Rclone config
```
![image](https://user-images.githubusercontent.com/90516190/134173943-32ea4514-e922-43a9-89da-3fee16a4426f.png)

Assuming you have a Google Drive Business or Enterprise Account proceed and create a new Google Drive [remote](https://rclone.org/drive/)

If you don't use Google Drive use the config for your existing [remote](https://rclone.org/overview/)
