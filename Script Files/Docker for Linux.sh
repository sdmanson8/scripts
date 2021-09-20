#!/bin/bash

# Edit Sudoers File
printf 'Add Current User to Sudoers File\n\n'
start-sleep -seconds 5
sudo visudo

# Update FileSystem
printf '\nUpdating FileSystem\n\n'
start-sleep -seconds 5
sudo apt-get update -y && sudo apt-get dist-upgrade -y

# Docker
printf '\nInstalling Docker\n\n'
start-sleep -seconds 5
sudo apt remove --yes docker docker-engine docker.io containerd runc || true
sudo apt update
sudo apt --yes --no-install-recommends install apt-transport-https ca-certificates
wget --quiet --output-document=- https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository --yes "deb [arch=$(dpkg --print-architecture)] https://download.docker.com/linux/ubuntu $(lsb_release --codename --short) stable"
sudo apt update
sudo apt --yes --no-install-recommends install docker-ce docker-ce-cli containerd.io
sudo usermod --append --groups docker "$USER"
sudo systemctl enable docker
printf '\nDocker installed successfully\n\n'

printf 'Waiting for Docker to start...\n\n'
start-sleep -seconds 2

# Docker Compose
printf '\nInstalling Docker-Compose\n\n'
start-sleep -seconds 5
sudo wget --output-document=/usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/$(wget --quiet --output-document=- https://api.github.com/repos/docker/compose/releases/latest | grep --perl-regexp --only-matching '"tag_name": "\K.*?(?=")')/run.sh"
sudo chmod +x /usr/local/bin/docker-compose
sudo wget --output-document=/etc/bash_completion.d/docker-compose "https://raw.githubusercontent.com/docker/compose/$(docker-compose version --short)/contrib/completion/bash/docker-compose"
printf '\nDocker Compose installed successfully\n\n'

# Install docker-cleanup command
mkdir /usr/local/bin/docker-cleanup
cd /tmp
git clone https://gist.github.com/76b450a0c986e576e98b.git
cd 76b450a0c986e576e98b
sudo mv docker-cleanup /usr/local/bin/docker-cleanup
sudo chmod +x /usr/local/bin/docker-cleanup
sudo rm -R /tmp/76b450a0c986e576e98b -f

# Add User to Docker Group
printf '\nAdding Current User to Docker Group\n\n'
sudo usermod -aG docker ${USER}
