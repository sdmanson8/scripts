#!/bin/bash
#requires -version 7.0
#Requires -RunAsAdministrator

#Script File
<COMMAND
# Remove Old files
printf '\nRemoving old files.. Please Wait\n\n'
sleep 1s
rm ~/docker/RealTraefikCert.yml
rm ~/docker/traefik/rules/middlewares.yml

# Downloading docker-compose.yml file
printf '\nDownloading docker-compose.yml file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/docker-compose.yml -O ~/docker/docker-compose.yml

# Create macvlan docker network
printf '\nCreating macvlan docker network.. Please Wait\n\n'
sleep 1s
docker network create -d macvlan -o parent="$(ip route get 8.8.8.8 | awk -- '{printf $5}')" br0
COMMAND
# Downloading Container Files
printf '\nDownloading Container Files.. Please Wait\n\n'
sleep 1s
wget https://github.com/sdmanson8/scripts/archive/refs/heads/main.zip -O ~/main.zip

# Extracting Container Files
printf '\Extracting Container Files.. Please Wait\n\n'
sleep 1s
unzip -d ~/Main ~/main.zip
rm main.zip

# Copying Container Files to ~/docker
printf '\nCopying Container Files to ~/docker.. Please Wait\n\n'
sleep 1s
cd ~/Main/scripts-main/Script\ Files
cp -r Authelia/ prometheus/ qbittorrent/ telegraf/ traefik/ transmission/ ~/docker/ && cd ~/ && rm -Rf Main/


cd ~/docker
