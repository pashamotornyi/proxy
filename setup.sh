#!/bin/bash
wget -q -O - https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
DEBIAN_FRONTEND=noninteractive apt update
DEBIAN_FRONTEND=noninteractive apt upgrade -y
DEBIAN_FRONTEND=noninteractive apt install -y mc nano net-tools htop apt-transport-https ca-certificates curl software-properties-common docker-ce build-essential zip httpie

DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip python-is-python3

# Drop-in replacement for default 'cat' utility
DEBIAN_FRONTEND=noninteractive apt install -y bat && echo 'alias cat="batcat $1"' >> .bashrc

# Improved text-search (replacement for 'grep -r sometext *')
DEBIAN_FRONTEND=noninteractive apt install -y ripgrep && echo 'Installed cross-directory text-search (ripgrep module)'

# Faster file-search (replacement for 'find --name filename')
DEBIAN_FRONTEND=noninteractive apt install -y fd-find && ln -s $(which fdfind) /usr/local/bin/fd

curl -L https://github.com/docker/compose/releases/download/1.29.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose

# Docker monitoring tool
curl -L https://github.com/bcicen/ctop/releases/download/v0.7.7/ctop-0.7.7-linux-amd64 -o /usr/local/bin/ctop && chmod +x /usr/local/bin/ctop

# Hardware monitoring tool (like htop but better)
pip3 install glances

# PostgreSQL cli on steroids
DEBIAN_FRONTEND=noninteractive apt install -y libpq-dev python3-dev && pip3 install pgcli
