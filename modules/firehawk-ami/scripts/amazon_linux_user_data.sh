# Amazon linux needs stack size to be increased and for some reason this is not easy in packer.
# This script is a workaround to increase the stack size.
set -e

# Log start of script
echo "User data script started" >>/var/log/user_data.log

# ...existing code...

# Send the log output from this script to user-data.log, syslog, and the console. From: https://alestic.com/2010/12/ec2-user-data-output/
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

echo "Begin user-data script"

# catch errors
trap 'catch $? $LINENO' EXIT
catch() {
  if [ "$1" != "0" ]; then
    # error handling goes here
    echo "Error: $1 occurred on $2"
  else
    echo "Script successfully completed!"
  fi
}

# Log the given message. All logs are written to stderr with a timestamp.
function log {
  local -r message="$1"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo >&2 -e "$timestamp $message"
}

log "USER DATA SCRIPT"

echo "SET UP STACK SIZE"
sudo sed -i '/# End of file/i * soft nofile unlimited' /etc/security/limits.conf
sudo -i '/# End of file/i * hard nofile unlimited' /etc/security/limits.conf
sudo -i '/# End of file/i * soft nproc unlimited' /etc/security/limits.conf
sudo sed -i '/# End of file/i * hard nproc unlimited' /etc/security/limits.conf
echo "DONE SETTING UP STACK SIZE"
sudo cat /etc/security/limits.conf

# Log end of script
echo "User data script completed" >>/var/log/user_data.log
