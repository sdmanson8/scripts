#!/bin/bash

# Script File

# Create Docker Folder and files
printf '\nCreating Docker Folder and files.. Please Wait\n\n'
sleep 1s
mkdir -p ~/docker
sudo setfacl -Rdm g:docker:rwx ~/docker
sudo chmod -R 775 ~/docker
mkdir -p ~/docker/traefik/acme
touch ~/docker/traefik/acme/acme.json
chmod 600 ~/docker/traefik/acme/acme.json
touch ~/docker/traefik/traefik.log
mkdir ~/docker/traefik/rules
mkdir ~/docker/shared
cd ~/docker


#Downloading .env file
printf '\nDownloading .env file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/.env -O ~/docker/.env

#Downloading .passwd file
printf '\nDownloading .passwd file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/.htpasswd -O ~/docker/shared/.htpasswd

# Create Traefik Proxy Network
printf '\nCreating Traefik Proxy Network.. Please Wait\n\n'
sleep 1s
docker network create web-proxy

#Downloading CreateDummyTraefikCert.yml file
printf '\nDownloading CreateDummyTraefikCert.yml file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/CreateDummyTraefikCert.yml -O ~/docker/CreateDummyTraefikCert.yml

#Downloading middlewares.yml file
printf '\nDownloading middlewares.yml file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/middlewares.yml -O ~/docker/traefik/rules/middlewares.yml

clear
