#!/bin/bash

#Logging
# Edit <user> with your seedbox username [run command - "whoami"]
LOGDIRECTORY="/home/<user>/scripts"
SCRIPT_NAME="torrent-disk-check"

export LOGFILE=$LOGDIRECTORY/${SCRIPT_NAME}.log
touch $LOGFILE

# Output to console and to logfile
exec > >(tee "$LOGFILE")
exec 2>&1

# Debugging
#set -o xtrace

# exit if something goes wrong
set -e

fileSystem="$HOME" # Filesystem you want to monitor
Threshold1="90" # Free space 1st threshold percentage
Threshold2="88" # Free space 2nd threshold percentage
checkInterval="3600" # Interval between checks in seconds
DATE="$(date +"%x %r")"

# Get the output of Quota and put in a variable for parsing
      QuotaOutPut=$(quota -s "$USER" 2>/dev/null)

# Exctract the fields containing total and available 1K-blocks
      QuotaUsed=$(echo "${QuotaOutPut}" | awk 'END{print substr($2, 1, length($2)-1)}')

# Change the quota value into percentage
# Calculate 100 divided by "slot limit (command - quota -s)" = 0.0xyz
     pctUsed=$(awk -vn="${QuotaUsed}" 'BEGIN{printf("%.0f\n",n*0.1074)}')

# Check if free space percentage is below threshold value
       if [ "${pctUsed}" -ge "$Threshold1" ]; then

          printf "%s\n"
          echo $DATE

# Check whether the instance of thread exists:
       if pgrep -x transmission-da >/dev/null;then
          printf '\n%s used percentage: %s\n' "$fileSystem": "$pctUsed"%
          printf 'There is no Disk Space left on '"$fileSystem"', Is Transmission running?\n'
          printf 'Yes, Killing Transmission\n'
          pkill -9 transmission
      else
          printf '\n%s used percentage: %s\n' "$fileSystem": "$pctUsed"%
          printf 'Disk Space is above Threshold\n'
          printf 'Transmission is not running,exiting\n'
       fi

# Check if free space percentage is below threshold value
      else
       if [ "$Threshold2" -ge "${pctUsed}" ]; then

         printf "%s\n"
         echo $DATE

# Check whether the instance of thread exists:
       if pgrep -x transmission-da >/dev/null;then
         printf '\n%s used percentage: %s\n' "$fileSystem": "$pctUsed"%
         printf 'There is still Disk Space left on '"$fileSystem"
         printf '\nTransmission is Running!\n'
      else
         printf '\n%s used percentage: %s\n' "$fileSystem": "$pctUsed"%
         printf '\nThere is free Disk Space but Transmission is Offline\n'
         printf 'Trying to start Transmission ...\n'
         app-transmission restart
         printf 'Transmission is running, exiting\n'
       fi
   fi
fi
