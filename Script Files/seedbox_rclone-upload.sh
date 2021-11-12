#!/bin/bash
# RCLONE UPLOAD CRON TAB SCRIPT 
# chmod a+x /pathtoscript/scripts/rclone-upload.sh
# Type crontab -e and add line below (without #) and with correct path to the script
# * * * * * /pathtoscript/scripts/rclone-upload.sh >/dev/null 2>&1

set -e

# RClone Config file
RCLONE_CONFIG=/home/<user>/.config/rclone/rclone.conf; export RCLONE_CONFIG
RCLONE_USER_AGENT=<user>; export RCLONE_USER_AGENT

# Local Drive - This must be a local mount point on your server that is used for the source of files
# WARNING: If you make this your rclone Google Drive mount, it will create a move loop
# and DELETE YOUR FILES!
# Make sure to set this to the local path you are moving from!!
LOCAL=/home/<user>/local
HOME=/home/<user>
REMOTE="gdrive"

# Bandwidth limits: specify the desired bandwidth in kBytes/s, or use a suffix b|k|M|G. Or 'off' or '0' for unlimited.  The script uses --drive-stop-on-upload-limit which stops the script if the 750GB/day limit is achieved, so you no longer have to slow 'trickle' your files all day if you don't want to e.g. could just do an unlimited job overnight.
BWLimit1Time="00:00"
BWLimit1="0"
BWLimit2Time="19:00"
BWLimit2="0"

# Exit if running
if [[ $(pidof -x "$(basename "$0")" -o %PPID) ]]; then
echo "Already running, exiting..."; exit 1; fi

# Check for excludes file
if [[ ! -f $HOME/scripts/excludes ]]; then
echo "excludes file not found, aborting..."; exit 1; fi

# Is $LOCAL actually a local disk?
if /bin/findmnt $LOCAL -o FSTYPE -n | grep fuse; then
echo "FUSE file system found, exiting..."; exit 1; fi

# Move older local files to the cloud...
 $HOME/bin/rclone move $LOCAL $REMOTE: \
 --log-file $HOME/scripts/rclone-upload.log \
 -v \
 --exclude-from $HOME/scripts/excludes \
 --drive-stop-on-upload-limit \
 --delete-empty-src-dirs \
 --fast-list \
 --min-age 1m \
 --max-transfer 740G \
 --bwlimit "${BWLimit1Time},${BWLimit1} ${BWLimit2Time},${BWLimit2}"
