#!/bin/bash
#requires -version 7.0
#Requires -RunAsAdministrator

#Script File

# Remove Old files
printf '\nRemoving old files.. Please Wait\n\n'
sleep 1s
rm ~/docker/RealTraefikCert.yml

# Downloading docker-compose.yml file
printf '\nDownloading docker-compose.yml file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/docker-compose.yml -O ~/docker/docker-compose.yml

# Create macvlan docker network
printf '\nCreating macvlan docker network.. Please Wait\n\n'
sleep 1s
docker network create -d macvlan -o parent="$(ip route get 8.8.8.8 | awk -- '{printf $5}')" br0

cd ~/docker
clear
