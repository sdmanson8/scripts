#!/bin/bash

clear
<<COMMAND
# Edit Sudoers File
sudo gpasswd --add $USER sudo
sudo gpasswd --add $USER root

# Update FileSystem
printf '\nPreparing to Update FileSystem.. Please Wait\n\n'
sleep 2s
sudo apt-get update -y && sudo apt-get dist-upgrade -y

# Docker
printf '\nPreparing to Install Docker.. Please Wait\n\n'
sleep 3s
sudo apt remove --yes docker docker-engine docker.io containerd runc || true
sudo apt update
sudo apt --yes --no-install-recommends install apt-transport-https ca-certificates
wget --quiet --output-document=- https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository --yes "deb [arch=$(dpkg --print-architecture)] https://download.docker.com/linux/ubuntu $(lsb_release --codename --short) stable"
sudo apt update
sudo apt --yes --no-install-recommends install docker-ce docker-ce-cli containerd.io
sudo systemctl enable docker
printf '\nDocker installed successfully\n\n'

printf 'Waiting for Docker to start...\n\n'
sleep 2s

# Docker Compose
printf '\nPreparing to Install Docker-Compose.. Please Wait\n\n'
sleep 2s
sudo wget --output-document=/usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/$(wget --quiet --output-document=- https://api.github.com/repos/docker/compose/releases/latest | grep --perl-regexp --only-matching '"tag_name": "\K.*?(?=")')/run.sh"
sudo chmod +x /usr/local/bin/docker-compose
sudo wget --output-document=/etc/bash_completion.d/docker-compose "https://raw.githubusercontent.com/docker/compose/$(docker-compose version --short)/contrib/completion/bash/docker-compose"
printf '\nDocker Compose installed successfully\n\n'
COMMAND
# Install docker-cleanup command
sudo mkdir /usr/local/bin/docker-cleanup
cd /tmp
git clone https://gist.github.com/76b450a0c986e576e98b.git
cd 76b450a0c986e576e98b
sudo mv docker-cleanup /usr/local/bin/docker-cleanup
sudo chmod +x /usr/local/bin/docker-cleanup
sudo rm -R /tmp/76b450a0c986e576e98b -f

cd ~/
#Refresh Ubuntu Package List
printf '\nPreparing to Refresh Ubuntu Package List.. Please Wait\n\n'
sleep 2s
sudo apt-get update

# Add User to Docker Group
sudo gpasswd --add $USER docker
sleep 2s

printf '\nRestarting your Computer.. Please Wait\n\n'
sudo shutdown -r now
