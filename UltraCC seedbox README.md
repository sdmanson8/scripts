log onto https://cp.ultraseedbox.com/ 

Install Transmission, Plex, Ombi, Tautulli, etc and whatever you require

Under Access Details:

Set a SSH password
Copy the hostname

Open your SSH terminal and enter <username>@<hostname>
enter created password

If you use putty or something similar enter <hostname> and use port 22
enter your username and created password

Edit Transmission settings to your desired config:

app-transmission stop
nano ~/.config/transmission-daemon/settings.json

After saving and closing editor app-transmission start

Download Transmission Disk Space check Script
mkdir ~/scripts
wget https://bit.ly/3oqLjao -O ~/scripts/torrent-disk-check.sh

Check Disk Quota assigned to your slot
quota -s

Use a calculator and use 100 divided by slot limit
Copy the Filesystem value

nano ~/scripts/torrent-disk-check.sh
If you don't use transmission change values to use rutorrent or deluge 
Edit this using the above calculated answer example 0.1074 or 0.0089, etc

    # Change the quota value into percentage
            pctUsed=$(awk -vn="${QuotaUsed}" 'BEGIN{printf("%.0f\n",n*0.1074)}')
Edit the <user> fields to your slot username (Get this value by running whoami)
Paste the <filesystem> value

cd ~/scripts

Set permissions for scripts
chmod +x torrent-disk-check.sh
./torrent-disk-check.sh

If Plex was installed use the below to update to the latest version
app-plex upgrade --plex-version=public

Setup Rclone
mkdir -p ~/{local,mergerfs,remote}

Install MergerFS
mkdir ~/bin/mergerfs
wget https://raw.githubusercontent.com/ultraseedbox/UltraSeedbox-Scripts/master/MergerFS-Rclone/Installer%20Scripts/mergerfs-install.sh
bash mergerfs-install.sh
rm mergerfs-install.sh

Choose the latest version

Update rclone to the latest version
curl https://raw.githubusercontent.com/ultraseedbox/UltraSeedbox-Scripts/master/MergerFS-Rclone/Installer%20Scripts/rclone-install-stable.sh | bash

Check the version
~/bin/rclone version

Download Script files 
wget -P ~/.config/systemd/user/ https://bit.ly/30eqSoM -O ~/.config/systemd/user/rclone-vfs.service
wget -P ~/.config/systemd/user/ https://bit.ly/3HjPxt1 -O ~/.config/systemd/user/mergerfs.service
wget https://bit.ly/3c38nGw -O ~/scripts/excludes
wget https://bit.ly/30iUwZT -O ~/scripts/rclone-upload.sh

Configure Rclone
rclone config

Edit the below files to meet your requirements
nano ~/.config/systemd/user/rclone-vfs.service
nano ~/.config/systemd/user/mergerfs.service

Edit the Rclone Upload Script to meet your requirements
replace <user> with slot username (Get this value by running whoami)
nano ~/scripts/rclone-upload.sh

Edit Excludes File to add or remove file extensions from being uploaded
~/scripts/excludes

Reload Systemd daemom
systemctl --user daemon-reload

Enable and start the systemd services
systemctl --user enable --now rclone-vfs && systemctl --user enable --now mergerfs

Add the below to cron and edit as desired

# Rclone Upload ->
# Every 6 Hours
0 */6 * * * /home/sheldon/scripts/rclone-upload.sh
# Midnight Everyday
0 0 * * * /home/sheldon/scripts/rclone-upload.sh

# Torrent Disk Check cron ->
# Every 5 Minutes
*/5 * * * * /home/sheldon/scripts/torrent-disk-check.sh

Start using Radarr, Sonarr, Plex, etc