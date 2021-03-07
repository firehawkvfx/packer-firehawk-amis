# The base AMI's primary purpose is to produce an anchor point with apt-get/yum updates, and apply bug fixes to incoming AMI's.
# Updates can be unstable on a daily basis so the base ami once successful can be reused, improving build time.
# Avoiding updates altogether is not good for security and some packages and executables depend on updates to function, so the update process is run initially here.
# Some AMI's may require fixes to resolves bugs which are also performed here (Centos 7, Open VPN).
# We also install any packages that will not likely require frequent modification (Python, Git).  If they do require significant/frequent/unreliable modification they do not belong here.

variable "aws_region" {
  type = string
  default = null
}
locals {
  timestamp    = regex_replace(timestamp(), "[- TZ:]", "")
  template_dir = path.root
}

source "amazon-ebs" "amazon-linux-2-ami" {
  ami_description = "An Amazon Linux 2 AMI with basic updates."
  ami_name        = "firehawk-base-amazon-linux-2-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
  source_ami_filter {
    filters = {
      architecture                       = "x86_64"
      "block-device-mapping.volume-type" = "gp2"
      name                               = "*amzn2-ami-hvm-*"
      root-device-type                   = "ebs"
      virtualization-type                = "hvm"
    }
    most_recent = true
    owners      = ["amazon"]
  }
  ssh_username = "ec2-user"
}

source "amazon-ebs" "centos7-ami" {
  ami_description = "A Cent OS 7 AMI with basic updates."
  ami_name        = "firehawk-base-centos7-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
  source_ami_filter {
    filters = {
      name         = "CentOS Linux 7 x86_64 HVM EBS *"
      product-code = "aw0evgkw8e5c1q413zgy5pjce"
    }
    most_recent = true
    owners      = ["679593333241"]
  }
  user_data_file = "${local.template_dir}/cloud-init.yaml" # This is a fix for some instance types with Centos 7 and mounts causing errors.
  ssh_username = "centos"
}

source "amazon-ebs" "ubuntu18-ami" {
  ami_description = "An Ubuntu 18.04 AMI with basic updates."
  ami_name        = "firehawk-base-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
  source_ami_filter {
    filters = {
      architecture                       = "x86_64"
      "block-device-mapping.volume-type" = "gp2"
      name                               = "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"
      root-device-type                   = "ebs"
      virtualization-type                = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"
}

source "amazon-ebs" "openvpn-server-base-ami" {
  ami_description = "An Open VPN Access Server AMI with basic updates"
  ami_name        = "firehawk-openvpn-server-base-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
  user_data = <<EOF
#! /bin/bash
admin_user=openvpnas
admin_pw=''
EOF
  source_ami_filter {
    filters = {
      description  = "OpenVPN Access Server 2.8.3 publisher image from https://www.openvpn.net/."
      product-code = "f2ew2wrz425a1jagnifd02u5t"
    }
    most_recent = true
    owners      = ["679593333241"]
  }
  ssh_username = "openvpnas"
}

build {
  sources = [
    "source.amazon-ebs.ubuntu18-ami",
    "source.amazon-ebs.amazon-linux-2-ami",
    "source.amazon-ebs.centos7-ami",
    "source.amazon-ebs.openvpn-server-base-ami",
    ]

### Wait for cloud init ###

  provisioner "shell" {
    inline         = [
      "echo 'Init success.'",
      "sudo echo 'Sudo test success.'",
      "unset HISTFILE",
      "history -cw",
      "echo === Waiting for Cloud-Init ===",
      "timeout 180 /bin/bash -c 'until stat /var/lib/cloud/instance/boot-finished &>/dev/null; do echo waiting...; sleep 6; done'",
      ]
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline_shebang = "/bin/bash -e"
  }

### Wait for apt daily update ###

  provisioner "shell" {
    inline         = [
      "echo === System Packages ===",
      "echo 'Connected success. Wait for updates to finish...'", # Open VPN AMI runs apt daily update which must end before we continue.
      "sudo systemd-run --property='After=apt-daily.service apt-daily-upgrade.service' --wait /bin/true; echo \"exit $?\""
      ]
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline_shebang = "/bin/bash -e"
    only = ["amazon-ebs.ubuntu18-ami","amazon-ebs.openvpn-server-base-ami"]
  }

### Ensure openvpnas user is owner of their home dir to firx Open VPN AMI bug

  provisioner "shell" {
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline         = [
      "export SHOWCOMMANDS=true; set -x",
      "sudo cat /etc/systemd/system.conf",
      "sudo chown openvpnas:openvpnas /home/openvpnas; echo \"exit $?\"",
      "echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections; echo \"exit $?\"",
    ]
    inline_shebang = "/bin/bash -e"
    only = ["amazon-ebs.openvpn-server-base-ami"]
  }

### Ensure Dialog is installed to fix open vpn image issues ###

  provisioner "shell" {
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    valid_exit_codes = [0,1] # ignore exit code.  this requirement is a bug in the open vpn ami.
    inline         = [
      "sudo apt-get -y install dialog; echo \"exit $?\"", # supressing exit code - until dialog is installed, apt-get may produce non zero exit codes. In open vpn ami
      "sudo apt-get install -y -q; echo \"exit $?\""
    ]
    inline_shebang = "/bin/bash -e"
    only = ["amazon-ebs.openvpn-server-base-ami"]
  }

### Update ###

  provisioner "shell" {
    inline_shebang = "/bin/bash -e"
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline         = [
      "sudo apt-get -y update",
      "sudo apt-get install dpkg -y",
      "sudo apt-get --yes --force-yes -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\" upgrade", # These args are required to fix a dpkg bug in the openvpn ami.

    ]
    only = ["amazon-ebs.ubuntu18-ami","amazon-ebs.openvpn-server-base-ami"]
  }
  provisioner "shell" {
    inline_shebang = "/bin/bash -e"
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline         = [
      "sudo yum update -y"
    ]
    only = ["amazon-ebs.amazon-linux-2-ami", "amazon-ebs.centos7-ami"]
  }

### GIT ###

  provisioner "shell" {
    inline = [
      "sudo yum update -y",
      "sleep 5",
      "export CENTOS_MAIN_VERSION=$(cat /etc/centos-release | awk -F 'release[ ]*' '{print $2}' | awk -F '.' '{print $1}')",
      "echo $CENTOS_MAIN_VERSION", # output should be "6" or "7"
      "sudo yum install -y https://repo.ius.io/ius-release-el$${CENTOS_MAIN_VERSION}.rpm", # Install IUS Repo and Epel-Release:
      "sudo yum install -y epel-release",
      "sudo yum erase -y git*",       # re-install git:
      "sudo yum install -y git-core",
      "git --version"
    ]
    only = ["amazon-ebs.centos7-ami"]
  }
  provisioner "shell" {
    inline = [
      "sudo yum install -y git",
      "git --version"
    ]
    only = ["amazon-ebs.amazon-linux-2-ami"]
  }

### Python 3 & PIP ###

  provisioner "shell" {
    inline_shebang = "/bin/bash -e"
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline         = [ 
      "sudo apt-get -y install python3",
      "sudo apt-get -y install python-apt",
      "sudo apt install -y python3-pip",
      "python3 -m pip install --upgrade pip",
      "python3 -m pip install boto3",
      "python3 -m pip --version",
      "sudo apt-get install -y git",
      "echo '...Finished bootstrapping'"
    ]
    only = ["amazon-ebs.ubuntu18-ami","amazon-ebs.openvpn-server-base-ami"]
  }
  provisioner "shell" {
    inline = [
      "sudo yum install -y python python3.7 python3-pip",
      "python3 -m pip install --user --upgrade pip",
      "python3 -m pip install --user boto3"
    ]
    only = ["amazon-ebs.amazon-linux-2-ami", "amazon-ebs.centos7-ami"]
  }
  
  post-processor "manifest" {
      output = "${local.template_dir}/manifest.json"
      strip_path = true
      custom_data = {
        timestamp = "${local.timestamp}"
      }
  }
}