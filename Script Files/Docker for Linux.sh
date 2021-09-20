#/bin/bash

# Update FileSystem
#echo "Updating FileSystem"
#sudo apt-get update -y && sudo apt-get dist-upgrade -y

# Install Docker 
echo "Installing Docker"
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update -y
sudo apt-get install docker-ce -y

# Install Docker-Compose
echo "Installing Docker-Compose"
COMPOSE_VERSION=$(git ls-remote https://github.com/docker/compose | tail -n8 | awk '{print $2}' | grep -Po 'refs/tags/\K([\d.]{5})(?!-\w+)' | tail -n1)
sudo sh -c "curl -L https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose"
sudo chmod +x /usr/local/bin/docker-compose
sudo sh -c "curl -L https://raw.githubusercontent.com/docker/compose/${COMPOSE_VERSION}/contrib/completion/bash/docker-compose > /etc/bash_completion.d/docker-compose"

# Install docker-cleanup command
cd /tmp
git clone https://gist.github.com/76b450a0c986e576e98b.git
cd 76b450a0c986e576e98b
sudo mv docker-cleanup /usr/local/bin/docker-cleanup
sudo chmod +x /usr/local/bin/docker-cleanup

# Add User to Docker Group
sudo usermod -aG docker ${USER}
