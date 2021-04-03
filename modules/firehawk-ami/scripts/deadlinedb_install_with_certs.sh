#!/bin/bash

# This installs certificates with the DB.

set -e
pwd=$(pwd)
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script

# User vars
cert_org="Firehawk VFX"
cert_ou="CG"
installers_bucket="software.dev.firehawkvfx.com"
deadlineuser_name="ubuntu"
deadline_version="10.1.9.2"
mongo_url="https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.19.tgz"
dbport="27100"
host_name="deadlinedb.service.consul"
deadline_client_certificate="Deadline10Client.pfx"
deadline_proxy_certificate="Deadline10RemoteClient.pfx"

# Script vars (implicit)
server_cert_basename="$host_name"
deadline_proxy_root_dir="$host_name:4433"
deadline_client_certificate_basename="${deadline_client_certificate%.*}"
deadline_proxy_certificate_basename="${deadline_proxy_certificate%.*}"
deadline_linux_installers_tar="/tmp/Deadline-${deadline_version}-linux-installers.tar" # temp dir since we just keep the extracted contents for repeat installs.
deadline_linux_installers_filename="$(basename $deadline_linux_installers_tar)"
deadline_linux_installers_basename="${deadline_linux_installers_filename%.*}"
deadline_installer_dir="/home/$deadlineuser_name/Downloads/$deadline_linux_installers_basename"
deadline_db_installer_filename="DeadlineRepository-${deadline_version}-linux-x64-installer.run"
deadline_client_installer_filename="DeadlineClient-${deadline_version}-linux-x64-installer.run"
mongo_installer_tgz="/home/$deadlineuser_name/Downloads/$(basename $mongo_url)"

# set hostname
cat /etc/hosts | grep -m 1 "127.0.0.1   $host_name" || echo "127.0.0.1   $host_name" | sudo tee -a /etc/hosts
sudo hostnamectl set-hostname $host_name

# Functions
function replace_line() {
  local -r filepath=$1
  local -r start=$2
  local -r end=$3
  PYTHON_CODE=$(cat <<END
import argparse
import sys
import fileinput
print("open: {} replace after: {} with: {}".format( "$filepath", "$start", "$end" ))
for line in fileinput.input(["$filepath"], inplace=True):
    if line.startswith("$start"):
        line = '{}\n'.format( "$end" )
    sys.stdout.write(line)
END
)
  sudo python3 -c "$PYTHON_CODE"
}
function replace_value() {
  local -r filepath=$1
  local -r start=$2
  local -r end=$3
  PYTHON_CODE=$(cat <<END
import argparse
import sys
import fileinput
print("open: {} replace after: {} with: {}".format( "$filepath", "$start", "$end" ))
for line in fileinput.input(["$filepath"], inplace=True):
    if line.startswith("$start"):
        line = '{}{}\n'.format( "$start", "$end" )
    sys.stdout.write(line)
END
)
  sudo python3 -c "$PYTHON_CODE"
}

# ensure directory exists
sudo mkdir -p "/home/$deadlineuser_name/Downloads"
sudo chown $deadlineuser_name:$deadlineuser_name "/home/$deadlineuser_name/Downloads"

# Download mongo
if [[ -f "$mongo_installer_tgz" ]]; then
    echo "File already exists: $mongo_installer_tgz"
else
    wget $mongo_url -O $mongo_installer_tgz
fi
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

deadline_certificates_location="/opt/Thinkbox/certs"
sudo mkdir -p "$deadline_certificates_location"
sudo chown $deadlineuser_name:$deadlineuser_name $deadline_certificates_location
sudo chmod u=rwX,g=rX,o-rwx "$deadline_certificates_location"

sudo mkdir -p $deadline_installer_dir

# Install Deadline DB
sudo tar -xvf $deadline_linux_installers_tar -C $deadline_installer_dir
cd $deadline_installer_dir
sudo $deadline_installer_dir/$deadline_db_installer_filename \
--mode unattended \
--debuglevel 2 \
--prefix /opt/Thinkbox/DeadlineRepository10 \
--setpermissions true \
--installmongodb true \
--prepackagedDB $mongo_installer_tgz \
--dbOverwrite true \
--mongodir /opt/Thinkbox/DeadlineDatabase10 \
--dbListeningPort $dbport \
--dbhost $host_name \
--dbport $dbport \
--dbuser $deadlineuser_name \
--dbauth true \
--certgen_outdir /opt/Thinkbox/DeadlineDatabase10/certs \
--createX509dbuser true \
--requireSSL true \
--dbssl true \
--dbpassword avaultpassword \
--certgen_password avaultpassword \
--dbcertpass avaultpassword

# # Generate Certs
# sudo apt-get install -y python-openssl
# sudo rm -frv "/home/${deadlineuser_name}/Downloads/SSLGeneration" # if this is a repeated install, clear the keys
# git clone https://github.com/ThinkboxSoftware/SSLGeneration.git "/home/${deadlineuser_name}/Downloads/SSLGeneration"
# cd /home/$deadlineuser_name/Downloads/SSLGeneration
# ssl_keygen_path="/home/${deadlineuser_name}/Downloads/SSLGeneration/keys"

# # CA
# python ssl_gen.py --ca --cert-org "$cert_org" --cert-ou "$cert_ou"
# # Server Cert
# python ssl_gen.py --server --cert-name "$server_cert_basename"
# # Create PEM key - undocumented by Thinkbox
# cat "${ssl_keygen_path}/${server_cert_basename}.crt" "${ssl_keygen_path}/${server_cert_basename}.key" | sudo tee "${ssl_keygen_path}/${server_cert_basename}.pem"
# # RCS proxy cert
# python ssl_gen.py --client --cert-name "$deadline_proxy_certificate_basename"
# python ssl_gen.py --pfx --cert-name "$deadline_proxy_certificate_basename"
# # Remote Client Cert ? not sure how this works yet, sinc RCS is supposed to create that.
# python ssl_gen.py --client --cert-name $deadline_client_certificate_basename
# python ssl_gen.py --pfx --cert-name $deadline_client_certificate_basename

# # Relocate certs
# sudo rm -frv $deadline_certificates_location/* # Remove invalid previous certs if present
# sudo mv -v keys/* "$deadline_certificates_location"
# # Certs Permissions
# sudo chmod u=r,g=r,o=r "${deadline_certificates_location}/${deadline_client_certificate}"
# sudo chmod o-rwx ${deadline_certificates_location}/*.pem
# sudo chmod o-rwx ${deadline_certificates_location}/*.key
# sudo chmod o-rwx ${deadline_certificates_location}/*.pfx

# stop service before updating config.
# sudo service Deadline10db stop
# Configure Mongo : /opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf
# replace_value "/opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf"        "    mode:" " requireSSL"
# replace_line "/opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf"      "    #CAFile:" "    CAFile: ERROR_DURING_REPLACEMENT" # if you can read this result, something went wrong
# replace_value "/opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf"      "    CAFile:" " $deadline_certificates_location/ca.crt"
# replace_line "/opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf"  "    #PEMKeyFile:" "    PEMKeyFile: ERROR_DURING_REPLACEMENT" # if you can read this result, something went wrong
# replace_value "/opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf"  "    PEMKeyFile:" " $deadline_certificates_location/$server_cert_basename.pem"
# replace_value "/opt/Thinkbox/DeadlineDatabase10/mongo/data/config.conf" "  authorization:" " enabled" # ? not sure what this should be

# After DB install, certs exist here
# ls -ltriah /opt/Thinkbox/DeadlineDatabase10/certs/
# total 24K
# 522562 drwxr-xr-x 4 root   root   4.0K Apr  3 23:27 ..
# 768030 -r--r----- 1 ubuntu ubuntu 1.2K Apr  3 23:27 ca.crt
# 768038 -r--r----- 1 ubuntu ubuntu 3.3K Apr  3 23:27 Deadline10Client.pfx
# 768034 -r--r----- 1 ubuntu ubuntu 2.9K Apr  3 23:27 deadlinedb.service.consul.pem
# 768036 -r--r----- 1 ubuntu ubuntu 3.0K Apr  3 23:27 mongo_client.pem

# and after RCS:
# ls -ltriah /opt/Thinkbox/certs/
# total 20K
# 521283 -r-------- 1 ubuntu root   1.2K Apr  3 23:29 ca.crt
# 521289 -r-------- 1 ubuntu root   3.3K Apr  3 23:29 deadlinedb.service.consul.pfx
# 521292 -r-------- 1 root   root   3.3K Apr  3 23:29 Deadline10RemoteClient.pfx

# config file state:
#MongoDB config file
# systemLog:
#   destination: file
#   # Mongo DB's output will be logged here.
#   path: /opt/Thinkbox/DeadlineDatabase10/mongo/data/logs/log.txt
#   # Default to quiet mode to limit log output size. Set to 'false' when debugging.
#   quiet: true
#   # Increase verbosity level for more debug messages (max: 5)
#   verbosity: 0
# net:
#   # Port MongoDB will listen on for incoming connections
#   port: 27100
#   ipv6: true
#   ssl:
#     # SSL/TLS options
#     mode: requireSSL
#     # If enabling TLS, the below options need to be set:
#     PEMKeyFile: /opt/Thinkbox/DeadlineDatabase10/certs/deadlinedb.service.consul.pem
#     CAFile: /opt/Thinkbox/DeadlineDatabase10/certs/ca.crt
#   # By default mongo will only use localhost, this will allow us to use the IP Address
#   bindIpAll: true
# storage:
#   # Database files will be stored here
#   dbPath: /opt/Thinkbox/DeadlineDatabase10/mongo/data
#   engine: wiredTiger
# security:
#   authorization: enabled

sudo chown ubuntu:ubuntu /opt/Thinkbox/DeadlineDatabase10/certs/*

# finalize permissions post install:
sudo chown $deadlineuser_name:$deadlineuser_name /opt/Thinkbox/
sudo chmod u+rX,g+rX,o-rwx /opt/Thinkbox/

sudo chown $deadlineuser_name:$deadlineuser_name $deadline_certificates_location
sudo chmod u+rX,g+rX,o-rwx $deadline_certificates_location

sudo chown -R $deadlineuser_name:$deadlineuser_name /opt/Thinkbox/DeadlineRepository10
sudo chmod -R u=rX,g=rX,o-rwx /opt/Thinkbox/DeadlineRepository10

sudo chown -R $deadlineuser_name:$deadlineuser_name /opt/Thinkbox/DeadlineRepository10/jobs
sudo chmod -R u=rwX,g=rwX,o-rwx /opt/Thinkbox/DeadlineRepository10/jobs

sudo chown -R $deadlineuser_name:$deadlineuser_name /opt/Thinkbox/DeadlineRepository10/jobsArchived
sudo chmod -R u=rwX,g=rwX,o-rwx /opt/Thinkbox/DeadlineRepository10/jobsArchived

sudo chown -R $deadlineuser_name:$deadlineuser_name /opt/Thinkbox/DeadlineRepository10/reports
sudo chmod -R u=rwX,g=rwX,o-rwx /opt/Thinkbox/DeadlineRepository10/reports

# Restart Deadline / Mongo service
sudo systemctl daemon-reload
sudo service Deadline10db start

# Directories and Permissions
sudo apt-get install -y xdg-utils
sudo apt-get install -y lsb # required for render nodes as well
sudo mkdir -p /usr/share/desktop-directories
sudo mkdir -p /opt/Thinkbox/DeadlineRepository10
sudo chmod u=rwX,g=rwX,o=r /opt/Thinkbox/DeadlineRepository10

# Install RCS
sudo $deadline_installer_dir/$deadline_client_installer_filename \
--mode unattended \
--launcherdaemon true \
--enable-components proxyconfig \
--servercert "${deadline_certificates_location}/${deadline_client_certificate}" \
--debuglevel 2 \
--prefix /opt/Thinkbox/Deadline10 \
--connectiontype Repository \
--repositorydir /opt/Thinkbox/DeadlineRepository10/ \
--dbsslcertificate "${deadline_certificates_location}/${deadline_client_certificate}" \
--dbsslpassword avaultpassword \
--licensemode UsageBased \
--daemonuser "$deadlineuser_name" \
--connserveruser "$deadlineuser_name" \
--httpport 8080 \
--tlsport 4433 \
--enabletls true \
--tlscertificates generate  \
--generatedcertdir "${deadline_certificates_location}/" \
--clientcert_pass avaultpassword \
--slavestartup false \
--proxycertificatepassword avaultpassword \
--proxyrootdir $deadline_proxy_root_dir \
--proxycertificate $deadline_certificates_location/$deadline_proxy_certificate

# Configure /var/lib/Thinkbox/Deadline10/deadline.ini
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "LaunchPulseAtStartup=" "True"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "LaunchRemoteConnectionServerAtStartup=" "True"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "ProxyRoot=" "$deadline_proxy_root_dir"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "ProxyUseSSL=" "True"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "DbSSLCertificate=" "$deadline_certificates_location/$deadline_client_certificate"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "ProxySSLCertificate=" "$deadline_certificates_location/$deadline_proxy_certificate"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "ProxyRoot0=" "$deadline_proxy_root_dir;$deadline_certificates_location/$deadline_proxy_certificate"
replace_value "/var/lib/Thinkbox/Deadline10/deadline.ini" "NetworkRoot0=" "/opt/Thinkbox/DeadlineRepository10/;$deadline_certificates_location/$deadline_client_certificate"

sudo service deadline10launcher restart

echo "Validate that a connection with the database can be established with the config"
/opt/Thinkbox/DeadlineDatabase10/mongo/application/bin/deadline_mongo --sslPEMKeyPassword "avaultpassword" --eval 'printjson(db.getCollectionNames())'

cd $pwd