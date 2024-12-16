# Amazon linux needs stack size to be increased and for some reason this is not easy in packer.
# This script is a workaround to increase the stack size.

sed -i '/# End of file/i * soft nofile unlimited' /etc/security/limits.conf
sed -i '/# End of file/i * hard nofile unlimited' /etc/security/limits.conf
sed -i '/# End of file/i * soft nproc unlimited' /etc/security/limits.conf
sed -i '/# End of file/i * hard nproc unlimited' /etc/security/limits.conf
