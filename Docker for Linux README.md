# Docker for Linux 

Install SSH 
```
sudo apt install -y ssh
```

Change Root Password **(DO NOT USE AN EASY PASSWORD)**
```
sudo passwd root
```
![image](https://user-images.githubusercontent.com/90516190/134331678-37104c42-ce77-4c48-8c77-483b5532fb4d.png)

Open your SSH terminal
Install powershell
```
wget -O - https://bit.ly/39oUK3f | bash -s
```
Download the Main Script File
```
wget https://bit.ly/3zqVHCJ -O ~/Script.ps1
```
Run the Powershell Script
```
cd ~/ && chmod +x Script.ps1 && pwsh ./Script.ps1
```
---------------------------------------------------------

Rclone Config Instructions


**After running the Update + Install Requires Apps [Script](https://github.com/sdmanson8/scripts/blob/main/Script%20Files/PrepLinuxForDocker.sh) and rebooted your System run the below commands to Create your Rclone Remote.**

```
rclone config
```
![image](https://user-images.githubusercontent.com/90516190/134173943-32ea4514-e922-43a9-89da-3fee16a4426f.png)

Assuming you have a Google Drive Business or Enterprise Account proceed and create a new Google Drive [remote](https://rclone.org/drive/)

If you don't use Google Drive create the config for your existing [remote](https://rclone.org/overview/)

If you are running Rclone Config on SSH or Ubuntu Server press **N (No)**

![image](https://user-images.githubusercontent.com/90516190/134175801-dce9d5b4-8fef-4073-8e58-df417419dd39.png)

After signing in to your Workspace Account click **Allow**

![image](https://user-images.githubusercontent.com/90516190/134176384-22ccddac-692a-4318-b79c-9bd170d7d6c9.png)

Copy the given Verification Code and Paste it in the SSH Terminal

Press *q* to exit rclone config

-------------------------------------------------------------------------
**Edit Rclone Systemd File and Rclone Upload Script**

**Proceed with Script.ps1. Choose the second option to Download the Script Files. When the second script has finished exit and running run the below commands:**

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
```
sudo systemctl restart rclone
```
If you didn't recieve any errors then continue
```
sudo systemctl restart mergerfs
```

![image](https://user-images.githubusercontent.com/90516190/134328805-800c98aa-13be-4a15-bb53-6720dc6d9e29.png)

**If you recieved errors edit the required file to fix the issue then run**
```
sudo systemctl daemon-reload
sudo systemctl restart <service>
```
-------------------------------------------------
**Prep For Docker**

Do the following and save the output information:
Change <password> to a password you will use for MariaDB
```
python3 -c 'import crypt; print(crypt.crypt("<password>", crypt.mksalt(crypt.METHOD_SHA512)))' 
```
Take down PUID and PGID
```
id
```
Check if Timezone is correct
```
timedatectl
```
•	Change Time Zone if needed – check timezone list 
  ```
  timedatectl list-timezones
  ```
•	Set Time Zone 
  ```
  sudo timedatectl set-timezone <your time zone>
  ```
Setup Environment Variables for docker
```
sudo nano /etc/environment
```
Add the below to the file
  
![image](https://user-images.githubusercontent.com/90516190/134481740-7efb4cab-5850-4115-867f-3d9b8a60ca83.png)

```
PUID=
PGID=
TZ=
USERDIR=
MYSQL_ROOT_PASSWORD=
```
**Save and Exit File**

**Continue with Script.ps1 choosing option 3**
