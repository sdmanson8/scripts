#!/bin/bash

clear

# Change Root Password
printf '\nChange Root Password (DO NOT USE A EASY PASSWORD)\n\n'
sleep 2s
sudo passwd root &
read -p "Press any key to continue... " -n1 -s

#Run Rclone Config
printf '\nPreparing to Run Rclone Config.. Please Wait\n\n'
sleep 1s
sudo rclone config 
read -p "Press any key to continue... " -n1 -s
