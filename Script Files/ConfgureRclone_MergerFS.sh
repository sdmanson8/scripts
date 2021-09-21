#!/bin/bash

clear
# Creating Scripts Folder
printf '\nCreating Scrpts Folder.. Please Wait\n\n'
sudo mkdir ~/scripts
sleep 1s

# Download Rclone Systemd File
printf '\nDownloading Rclone Systemd File.. Please Wait\n\n'
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/rclone.service -O /etc/systemd/system/rclone.service
sleep 1s

# Download MergerFS Systemd File
printf '\nDownloading MergerFS Systemd File.. Please Wait\n\n'
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/mergerfs.service -O /etc/systemd/system/mergerfs.service
sleep 1s

# Enable Systemd Services for Rclone and Mergerfs
printf '\nEnabling Systemd Services for Rclone and Mergerfs.. Please Wait\n\n'
sudo systemctl daemon-reload && sudo systemctl enable rclone && sudo systemctl enable mergerfs
sudo systemctl restart rclone && sudo systemctl restart mergerfs
sleep 1s

# Download Rclone Upload Script
printf '\nDownloading Rclone Upload Script.. Please Wait\n\n'
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/rclone-upload.sh -O ~/scripts/rclone-upload.sh
sleep 1s
