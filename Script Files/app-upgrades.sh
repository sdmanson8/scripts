#!/bin/bash

# Logging
LOGDIRECTORY="/home/sheldon/scripts"
SCRIPT_NAME="app-upgrades"

export LOGFILE=$LOGDIRECTORY/${SCRIPT_NAME}.log
touch $LOGFILE

# Output to console and to logfile
exec > >(tee "$LOGFILE")
exec 2>&1

# Debugging
#set -o xtrace

# exit if something goes wrong
set -e

DATE="$(date +"%x %r")"

            printf "%s\n"
            echo $DATE
            printf "%s\n"


echo "Upgrading Plex Media Server"
sleep 2
app-plex upgrade --plex-version=public

            printf "%s\n"
            echo $DATE
            printf "%s\n"
			
echo "Preparing to Upgrade Rclone"

sleep 5
    echo "Rclone is running. Please wait..."
    echo "Stopping Services"
    systemctl --user stop --now rclone-vfs.service && systemctl --user stop --now mergerfs.service
if pgrep "rclone";
then
    echo "Stopping Process"
    killall -9 rclone
else
    echo "Unmounting Mount Points"
    fusermount -uz "$HOME"/remote
    fusermount -uz "$HOME"/mergerfs
fi
    echo "Upgrading Rclone..."
    mkdir -p "$HOME"/.rclone-tmp
    wget https://downloads.rclone.org/rclone-current-linux-amd64.zip -O "$HOME"/.rclone-tmp/rclone.zip
    unzip -o "$HOME"/.rclone-tmp/rclone.zip -d "$HOME"/.rclone-tmp/
    cp "$HOME"/.rclone-tmp/rclone-v*/rclone "$HOME"/bin

clear

if [[ $("$HOME"/bin/rclone version) ]]; then
    echo "rclone is installed correctly!"
    rm -rf "$HOME"/.rclone-tmp
    echo "Starting Rclone Service"
    systemctl --user start --now rclone-vfs.service && systemctl --user start --now mergerfs.service
    exit 0
else
    echo "rclone install somehow failed. Please run this again!"
    rm -rf "$HOME"/.rclone-tmp
    exit 1
fi
