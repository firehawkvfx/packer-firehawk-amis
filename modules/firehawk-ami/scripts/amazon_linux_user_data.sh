# Amazon linux needs stack size to be increased and for some reason this is not easy in packer.
# This script is a workaround to increase the stack size.
set -e

# Send the log output from this script to user-data.log, syslog, and the console. From: https://alestic.com/2010/12/ec2-user-data-output/
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

echo "SET UP STACK SIZE"
sudo sed -i '/# End of file/i * soft nofile unlimited' /etc/security/limits.conf
sudo -i '/# End of file/i * hard nofile unlimited' /etc/security/limits.conf
sudo -i '/# End of file/i * soft nproc unlimited' /etc/security/limits.conf
sudo sed -i '/# End of file/i * hard nproc unlimited' /etc/security/limits.conf
echo "DONE SETTING UP STACK SIZE"
sudo cat /etc/security/limits.conf
