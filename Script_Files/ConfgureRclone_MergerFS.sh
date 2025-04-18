#!/bin/bash
#requires -version 7.0
#Requires -RunAsAdministrator

clear
# Assign Rclone the correct Permissions
sleep 1s
sudo chown $USER:$USER ~/.config/rclone/rclone.conf
sudo chown $USER:$USER -R /mnt
sudo chmod 755 ~/.config/rclone/rclone.conf
sudo chmod 777 -R /mnt

# Creating Scripts Folder
printf '\nCreating Scrpts Folder.. Please Wait\n\n'
sudo mkdir ~/scripts
sudo chown $USER:$USER -R ~/scripts
sudo chmod 777 -R ~/scripts
sleep 1s

# Download Rclone Systemd File
printf '\nDownloading Rclone Systemd File.. Please Wait\n\n'
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/rclone.service -O /etc/systemd/system/rclone.service
sleep 1s

# Download MergerFS Systemd File
printf '\nDownloading MergerFS Systemd File.. Please Wait\n\n'
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/mergerfs.service -O /etc/systemd/system/mergerfs.service
sleep 1s

# Download Rclone Upload Script
printf '\nDownloading Rclone Upload Script.. Please Wait\n\n'
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/rclone-upload.sh -O ~/scripts/rclone-upload.sh
sudo wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/excludes -O ~/scripts/excludes
sleep 1s
