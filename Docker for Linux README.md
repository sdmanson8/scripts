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
Save and exit **CTRL + X, Save (Y), Press Enter to use the same file name**

Run the Powershell Script
```
chmod +x Script.ps1 && pwsh ./Script.ps1
```
---------------------------------------------------------

Config Instructions


After running the Update + Install Requires Apps [Script](https://github.com/sdmanson8/scripts/blob/main/Script%20Files/PrepLinuxForDocker.sh) and rebooted your System run the second script using Scipt.ps1

When the second script has finished running run the below commands to edit the required files

Edit the Rclone Systemd File to meet your requirements
```
sudo nano /etc/systemd/system/rclone.service
```
Edit the Rclone Upload Script to meet your requirements
```
sudo nano ~/scripts/rclone-upload.sh
```

Start the Rclone and MergerFS service
```
sudo systemctl daemon-reload 
```
```
sudo systemctl enable rclone
```
If you didn't recieve any errors then continue
```
sudo systemctl enable mergerfs
```
If you didn't recieve any errors then continue
```
sudo systemctl restart rclone
```
If you didn't recieve any errors then continue
```
sudo systemctl restart mergerfs
```

Run the below command to Create a Rclone Remote
```
Rclone config
```
![image](https://user-images.githubusercontent.com/90516190/134173943-32ea4514-e922-43a9-89da-3fee16a4426f.png)

Assuming you have a Google Drive Business or Enterprise Account proceed and create a new Google Drive [remote](https://rclone.org/drive/)

If you don't use Google Drive use the config for your existing [remote](https://rclone.org/overview/)

If you are running Rclone Config on SSH or Ubuntu Server press **N (No)**

![image](https://user-images.githubusercontent.com/90516190/134175801-dce9d5b4-8fef-4073-8e58-df417419dd39.png)

After signing in to your Workspace Account click **Allow**

![image](https://user-images.githubusercontent.com/90516190/134176384-22ccddac-692a-4318-b79c-9bd170d7d6c9.png)

Copy the given Verification Code and Paste it in the SSH Terminal

Continue with Script.ps1 **option 2**
