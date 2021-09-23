# Script File

# Remove Old files
printf '\nRemoving old files.. Please Wait\n\n'
sleep 1s
rm ~/docker/CreateDummyTraefikCert.yml
rm ~/docker/traefik/traefik.log
rm ~/docker/traefik/acme/acme.json

# Remove docker container for Traefik
printf '\nRemoving Traefik Container.. Please Wait\n\n'
sleep 1s
docker rm traefik

# Create new files
printf '\nCreating new files.. Please Wait\n\n'
sleep 1s
touch ~/docker/traefik/acme/acme.json
chmod 600 ~/docker/traefik/acme/acme.json
touch ~/docker/traefik/traefik.log

# #Downloading RealTraefikCert.yml file
printf '\nDownloading RealTraefikCert.yml file.. Please Wait\n\n'
sleep 1s
wget https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/RealTraefikCert.yml -O ~/docker/RealTraefikCert.yml
