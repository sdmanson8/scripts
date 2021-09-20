#!/bin/bash

# Edit Sudoers File
echo "Add user to Sudoers File"
wait 5
sudo visudo

# Update FileSystem
echo ""
echo "Updating FileSystem"
wait 5
sudo apt-get update -y && sudo apt-get dist-upgrade -y

# Install Docker
echo ""
echo "Installing Docker"
wait 5
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update -y
sudo apt-get install docker-ce -y

# Install Docker-Compose
echo ""
echo "Installing Docker-Compose"
wait 5
install-docker-compose () {
    fname="docker-compose-$(uname -s)-$(uname -m)"
    fbin="~/.local/bin/docker-compose"
    repos_dl="https://github.com/docker/compose/releases/download"
    repos_api="https://api.github.com/repos/docker/compose/releases/latest"
    version=$(curl -sSL $repos_api | jq -r '. | .tag_name')
    /bin/rm -f "$fbin"
    curl -sSL $repos_dl/"$version"/"$fname" -o "$fbin"
    chmod +x $fbin
}
sudo sh -c "curl -L https://raw.githubusercontent.com/docker/compose/${COMPOSE_VERSION}/contrib/completion/bash/docker-compose > /etc/bash_completion.d/docker-compose"

# Install docker-cleanup command
cd /tmp
git clone https://gist.github.com/76b450a0c986e576e98b.git
cd 76b450a0c986e576e98b
sudo mv docker-cleanup /usr/local/bin/docker-cleanup
sudo chmod +x /usr/local/bin/docker-cleanup
sudo rm -R /tmp/76b450a0c986e576e98b -f

# Add User to Docker Group
sudo usermod -aG docker ${USER}
