#!/bin/bash

clear
<<COMMAND
# Add Current User to Sudoers and Root
sudo gpasswd --add $USER sudo
sudo gpasswd --add $USER root
COMMAND

# Change Root Password
printf '\nChange Root Password (DO NOT USE A EASY PASSWORD)\n\n'
sleep 2s
sudo passwd root

<<COMMAND
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
COMMAND

# Install Samba
printf '\nPreparing to Install Samba.. Please Wait\n\n'
sleep 2s
sudo apt update -y && sudo apt install samba -y

# Edit Samba File
printf '\nEdit Samba Config File\n\n'
sleep 1s
sudo nano /etc/samba/smb.conf

# Install Rclone
printf '\nPreparing to Install Rclone.. Please Wait\n\n'
sleep 2s
curl https://rclone.org/install.sh | sudo bash

# Assign Rclone the correct Permissions
printf '\nAssigning Rclone the correct Permissions.. Please Wait\n\n'
sleep 1s
sudo chown $USER:$USER ~/.config/rclone/rclone.conf
sudo chmod 755 ~/.config/rclone/rclone.conf

# Create Directories for Rclone
printf '\nCreating Directories for Rclone.. Please Wait\n\n'
sleep 1s
cd /mnt/
sudo mkdir -p local/{Media,downloads}
sudo mkdir -p remote/Media
sudo mkdir -p mergerfs/Media/{Movies,TV}

# Install Fuse
printf '\nPreparing to Install Fuse.. Please Wait\n\n'
sleep 2s
sudo apt-get install -y fuse

# Edit Fuse File
printf '\nEditing Fuse Config File\n\n'
sleep 1s
printf '/etc/fuse.conf "#user_allow_other" > /etc/fuse.conf "user_allow_other"'
sudo sed -i 's/#user_allow_other/user_allow_other/g' /etc/fuse.conf

<<COMMAND
# Install Mergerfs for Ubuntu Focal Release
printf '\nPreparing to Install Mergerfs for Ubuntu Focal Release.. Please Wait\n\n'
sleep 2s
DOWNLOAD_URL=$(curl -s https://api.github.com/repos/trapexit/mergerfs/releases/latest \
        | grep browser_download_url \
        | grep "ubuntu-focal_amd64.deb" \
        | cut -d '"' -f 4)
curl -s -L -o ~/mergerfs.deb "$DOWNLOAD_URL"
sudo apt install -y ~/mergerfs.deb
rm -f ~/mergerfs.deb
COMMAND

<<COMMAND
printf '\nRestarting your Computer in 10 Seconds\n\n'
sleep 10s
sudo shutdown -r now
COMMAND
