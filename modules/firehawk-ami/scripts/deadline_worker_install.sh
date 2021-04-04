#!/bin/bash

# This installs certificates with the DB.

set -e
# pwd=$(pwd)
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script

# User vars
installers_bucket="software.dev.firehawkvfx.com" # TODO these must become vars
deadlineuser_name="ubuntu" # TODO these must become vars
deadline_version="10.1.9.2" # TODO these must become vars
dbport="27100"
db_host_name="deadlinedb.service.consul" # TODO these must become vars
deadline_proxy_certificate="Deadline10RemoteClient.pfx"

# Script vars (implicit)
deadline_proxy_root_dir="$db_host_name:4433"
deadline_client_certificate_basename="${deadline_client_certificate%.*}"
deadline_linux_installers_tar="/tmp/Deadline-${deadline_version}-linux-installers.tar" # temp dir since we just keep the extracted contents for repeat installs.
deadline_linux_installers_filename="$(basename $deadline_linux_installers_tar)"
deadline_linux_installers_basename="${deadline_linux_installers_filename%.*}"
deadline_installer_dir="/home/$deadlineuser_name/Downloads/$deadline_linux_installers_basename"
deadline_client_installer_filename="DeadlineClient-${deadline_version}-linux-x64-installer.run"

# # set hostname
# cat /etc/hosts | grep -m 1 "127.0.0.1   $db_host_name" || echo "127.0.0.1   $db_host_name" | sudo tee -a /etc/hosts
# sudo hostnamectl set-hostname $db_host_name

# Functions
function has_yum {
  [[ -n "$(command -v yum)" ]]
}
function has_apt_get {
  [[ -n "$(command -v apt-get)" ]]
}

# ensure directory exists
sudo mkdir -p "/home/$deadlineuser_name/Downloads"
sudo chown $deadlineuser_name:$deadlineuser_name "/home/$deadlineuser_name/Downloads"

# Download deadline
if [[ -f "$deadline_linux_installers_tar" ]]; then
    echo "File already exists: $deadline_linux_installers_tar"
else
    aws s3api head-object --bucket $installers_bucket --key "Deadline-${deadline_version}-linux-installers.tar"
    exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        echo "...Downloading Deadline from: $installers_bucket"
        aws s3api get-object --bucket $installers_bucket --key "${deadline_linux_installers_filename}" "${deadline_linux_installers_tar}"
    else
        echo "...Downloading Deadline from: thinkbox-installers"
        aws s3api get-object --bucket thinkbox-installers --key "Deadline/${deadline_version}/Linux/${deadline_linux_installers_basename}" "${deadline_linux_installers_tar}"
    fi
fi

# Directories and permissions
sudo mkdir -p /opt/Thinkbox
sudo chown $deadlineuser_name:$deadlineuser_name /opt/Thinkbox
sudo chmod u=rwX,g=rX,o-rwx /opt/Thinkbox

# Client certs live here
deadline_client_certificates_location="/opt/Thinkbox/certs"
sudo mkdir -p "$deadline_client_certificates_location"
sudo chown $deadlineuser_name:$deadlineuser_name $deadline_client_certificates_location
sudo chmod u=rwX,g=rX,o-rwx $deadline_client_certificates_location

sudo mkdir -p $deadline_installer_dir

# Extract Installer
sudo tar -xvf $deadline_linux_installers_tar -C $deadline_installer_dir

# sudo apt-get install -y xdg-utils
# sudo apt-get install -y lsb # required for render nodes as well
sudo mkdir -p /usr/share/desktop-directories

# Install Deadline Worker
sudo $deadline_installer_dir/$deadline_client_installer_filename \
--mode unattended \
--debuglevel 2 \
--prefix /opt/Thinkbox/Deadline10 \
--connectiontype Remote \
--noguimode true \
--licensemode UsageBased \
--launcherdaemon true \
--slavestartup 1 \
--daemonuser $deadlineuser_name \
--enabletls true \
--tlsport 4433 \
--httpport 8080 \
--proxyrootdir $deadline_proxy_root_dir \
--proxycertificate $deadline_client_certificates_location/$deadline_proxy_certificate
# --proxycertificatepassword {{ deadline_proxy_certificate_password }}

# finalize permissions post install:
sudo chown $deadlineuser_name:$deadlineuser_name /opt/Thinkbox/certs/*
sudo chmod u=wr,g=r,o-rwx /opt/Thinkbox/certs/*
sudo chmod u=wr,g=r,o=r /opt/Thinkbox/certs/ca.crt

# sudo service deadline10launcher restart

echo "Validate that a connection with the database can be established with the config"
/opt/Thinkbox/DeadlineDatabase10/mongo/application/bin/deadline_mongo --eval 'printjson(db.getCollectionNames())'
