# Ensure you first build the ./firehawk-base-ami first to produce a manifest.
# The firehawk-base-ami is used to build this ami.

variable "aws_region" {
  type = string
}
variable "account_id" {
  type = string
}
variable "ami_role" {
  description = "A descriptive name for the purpose of the image."
  type        = string
}
variable "commit_hash" {
  description = "The hash of the commit in the current git repository contining this file."
  type        = string
}
variable "commit_hash_short" {
  description = "The hash of the commit in the current git repository contining this file."
  type        = string
}
variable "ingress_commit_hash" {
  description = "The hash of the commit in the git repository contining the source file."
  type        = string
}
variable "ingress_commit_hash_short" {
  description = "The hash of the commit in the git repository contining the source file."
  type        = string
}
variable "resourcetier" {
  description = "The current environment ( dev / green / blue / main )"
  type        = string
}
variable "terraform_version" {
  description = "The current environment ( dev / green / blue / main )"
  type        = string
  default     = "1.5.6"
}
variable "terragrunt_version" {
  description = "The current environment ( dev / green / blue / main )"
  type        = string
  default     = "0.36.0"
}
variable "firehawk_deadline_installer_version" {
  description = "The firehawk repo aws-thinkbox-deadline version to install/configure Deadline"
  type        = string
  default     = "v0.0.23" # This should always be a semantic version for a release, not main.
}
variable "ca_public_key_path" {
  type = string
  # default = "/home/ec2-user/.ssh/tls/ca.crt.pem"
}
variable "consul_download_url" {
  type    = string
  default = ""
}
variable "install_auth_signing_script" {
  type    = string
  default = "true"
}
variable "tls_private_key_path" {
  type = string
  # default = "/home/ec2-user/.ssh/tls/vault.key.pem"
}
variable "tls_public_key_path" {
  type = string
  # default = "/home/ec2-user/.ssh/tls/vault.crt.pem"
}
variable "vault_download_url" {
  type    = string
  default = ""
}
variable "consul_version" {
  type    = string
  default = "1.9.2"
}

### Only required if testing consul during build

variable "consul_cluster_tag_key" {
  type    = string
  default = ""
}
variable "consul_cluster_tag_value" {
  type    = string
  default = ""
}
variable "packer_iam_profile_name" { # Required for some builds requiring S3 Installers
  type = string
}
variable "test_consul" { # If a consul cluster is running, attempt to join the cluster. This can be useful for debugging, but will prevent inital builds if you have no infrastructure running yet.  This test may not also work unless the appropriate role is assigned.
  type    = bool
  default = false
}
variable "deadlineuser_name" {
  description = "The deadline user name for render nodes and deadline DB"
  type        = string
  default     = "deadlineuser"
}

variable "db_host_name" {
  description = "The hostname for deadline DB"
  type        = string
  default     = "deadlinedb.service.consul"
}
variable "installers_bucket" {
  description = "The installer bucket to persist installations to"
  type        = string
}
# Required for render node AMI
variable "sesi_client_id" {
  description = "The client ID generated from your Side FX Account to automatically download Houdini."
  type        = string
}
variable "sesi_client_secret_key" {
  description = "The secret key generated from your Side FX Account to automatically download Houdini."
  type        = string
}
variable "houdini_license_server_address" {
  description = "The IP or host name of your Houdini license server (IP Address is recommended to simplify usage across sites with DNS)."
  type        = string
}
variable "SSL_expiry" {
  description = "The Expiry resulting from the TTL on the SSL Certificates"
  type        = string
}

locals {
  timestamp         = regex_replace(timestamp(), "[- TZ:]", "")
  template_dir      = path.root
  deadline_version  = "10.3.2.1"
  installers_bucket = var.installers_bucket
  common_ami_tags = {
    "packer_template" : "firehawk-ami",
    "commit_hash" : var.commit_hash,
    "commit_hash_short" : var.commit_hash_short,
    "resourcetier" : var.resourcetier,
    "sslexpiry" : var.SSL_expiry,
    "deadline_version" : local.deadline_version
  }
  syscontrol_gid                 = "9003"
  deployuser_uid                 = "9004"
  deadlineuser_uid               = "9001"
  houdini_build                  = "daily"
  sesi_client_id                 = var.sesi_client_id
  sesi_client_secret_key         = var.sesi_client_secret_key
  houdini_license_server_address = var.houdini_license_server_address

  # python_libs_folder will change between 2.7 and 3.7 depending on your installer
  # You may require a different version of houdini for hserver
  houdini_json_vars = {
    "houdini_version_list" = [
      {
        "houdini_major_version"      = "20.0",
        "python_libs_folder"         = "python3.10libs",
        "houdini_auto_version"       = "true",
        "houdini_minor_version"      = "auto",
        "houdini_linux_tar_filename" = "auto",
        "houdini_build"              = "production"
      }
    ]
  }
  # deprecated: this is only needed if installing a license server
  #   "houdini_license_server_version_list" : [
  #   {
  #     "houdini_major_version"      = "20.0",
  #     "houdini_auto_version"       = "true",
  #     "houdini_minor_version"      = "auto",
  #     "houdini_linux_tar_filename" = "auto",
  #     "houdini_build"              = "production"
  #   }
  # ]
}

source "amazon-ebs" "openvpn-server-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.openvpn-server-ami" },
    { "ami_role" : "firehawk_openvpn_server_ami" },
    { "Name" : "firehawk_openvpn_server_ami" },
    local.common_ami_tags
  )
  ami_description = "An Open VPN Access Server AMI configured for Firehawk"
  ami_name        = "firehawk-openvpn-server-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.openvpn_server_base_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "openvpn_server_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  # We generate a random pass for the image build.  It will never need to be reused.  When the ami is started, the password is reset to a vault provided value.
  user_data    = <<EOF
#! /bin/bash
admin_user=openvpnas
admin_pw="$(openssl rand -base64 12)"
EOF
  ssh_username = "openvpnas"

}

source "amazon-ebs" "amazonlinux2-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.amazonlinux2-ami" },
    { "ami_role" : "firehawk_amazonlinux2_ami" },
    { "Name" : "firehawk_amazonlinux2_ami" },
    local.common_ami_tags
  )
  ami_description = "An Amazon Linux 2 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastion-amazonlinux2-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.amazon_linux_2_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "amazonlinux2_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  ssh_username = "ec2-user"
}

source "amazon-ebs" "amazonlinux2-nicedcv-nvidia-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami" },
    { "ami_role" : "firehawk_amazonlinux2_nicedcv_ami" },
    { "Name" : "firehawk_amazonlinux2_nicedcv_ami" },
    local.common_ami_tags
  )
  ami_description = "A Graphical Amazon Linux 2 NICE DCV AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-workstation-amazonlinux2-nicedcv-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.amazon_linux_2_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "amazonlinux2_nicedcv_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  # launch_block_device_mappings {
  #   device_name           = "/dev/xvda1"
  #   volume_size           = 20
  #   volume_type           = "gp2"
  #   delete_on_termination = true
  # }
  # ami_block_device_mappings {
  #   device_name  = "/dev/sdb"
  #   virtual_name = "ephemeral0"
  # }
  # ami_block_device_mappings {
  #   device_name  = "/dev/sdc"
  #   virtual_name = "ephemeral1"
  # }
  ssh_username         = "ec2-user"
  iam_instance_profile = var.packer_iam_profile_name # provide read and write s3 access for updating and retrieving installers

}



#could not parse template for following block: "template: generated:4: function \"clean_resource_name\" not defined"

source "amazon-ebs" "centos7-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.centos7-ami" },
    { "ami_role" : "firehawk_centos7_ami" },
    { "Name" : "firehawk_centos7_ami" },
    local.common_ami_tags
  )
  ami_description = "A Cent OS 7 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastion-centos7-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.centos7_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "centos7_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  ssh_username = "centos"

}

source "amazon-ebs" "centos7-rendernode-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.centos7-rendernode-ami" },
    { "ami_role" : "firehawk_centos7_rendernode_ami" },
    { "Name" : "firehawk_centos7_rendernode_ami" },
    { "firehawk_deadline_installer_version" : "${var.firehawk_deadline_installer_version}" },
    { "houdini_major_version" : local.houdini_json_vars["houdini_version_list"][0]["houdini_major_version"] },
    local.common_ami_tags
  )
  ami_description = "A Cent OS 7 AMI rendernode."
  ami_name        = "firehawk-rendernode-centos7-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.centos7_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "centos7_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  ssh_username = "centos"

  iam_instance_profile = var.packer_iam_profile_name # provide read and write s3 access for updating and retrieving installers

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 17
    volume_type           = "gp2"
    delete_on_termination = true
  }
  # ami_block_device_mappings {
  #   device_name  = "/dev/sdb"
  #   virtual_name = "ephemeral0"
  # }
  # ami_block_device_mappings {
  #   device_name  = "/dev/sdc"
  #   virtual_name = "ephemeral1"
  # }
}

source "amazon-ebs" "ubuntu18-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.ubuntu18-ami" },
    { "ami_role" : "firehawk_ubuntu18_ami" },
    { "Name" : "firehawk_ubuntu18_ami" },
    local.common_ami_tags
  )
  ami_description = "An Ubuntu 18.04 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastion-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.ubuntu18_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "ubuntu18_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  ssh_username = "ubuntu"
}

source "amazon-ebs" "ubuntu18-vault-consul-server-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.ubuntu18-vault-consul-server-ami" },
    { "ami_role" : "firehawk_ubuntu18_vault_consul_server_ami" },
    { "Name" : "firehawk_ubuntu18_vault_consul_server_ami" },
    local.common_ami_tags
  )
  ami_description = "An Ubuntu 18.04 AMI Vault and Consul Server."
  ami_name        = "firehawk-vault-consul-server-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.ubuntu18_ami}"
  source_ami_filter { # Uses firehawk base ami
    filters = {
      "tag:ami_role" : "ubuntu18_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  # source_ami_filter { # uses default ami from hashicorp template
  #   filters = {
  #     architecture                       = "x86_64"
  #     "block-device-mapping.volume-type" = "gp2"
  #     name                               = "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"
  #     root-device-type                   = "ebs"
  #     virtualization-type                = "hvm"
  #   }
  #   most_recent = true
  #   owners      = ["099720109477"]
  # }
  ssh_username = "ubuntu"
}

source "amazon-ebs" "deadline-db-ubuntu18-ami" {
  tags = merge(
    { "packer_source" : "amazon-ebs.deadline-db-ubuntu18-ami" },
    { "ami_role" : "firehawk_deadlinedb_ami" },
    { "Name" : "firehawk_deadlinedb_ami" },
    { "firehawk_deadline_installer_version" : "${var.firehawk_deadline_installer_version}" },
    { "houdini_major_version" : local.houdini_json_vars["houdini_version_list"][0]["houdini_major_version"] },
    local.common_ami_tags
  )
  ami_description = "An Ubuntu 18.04 AMI with Deadline DB ${local.deadline_version} server."
  ami_name        = "firehawk-deadlinedb-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = var.aws_region
  # source_ami      = "${var.ubuntu18_ami}"
  source_ami_filter {
    filters = {
      "tag:ami_role" : "ubuntu18_base_ami",
      "tag:packer_template" : "firehawk-base-ami",
      "tag:commit_hash" : var.ingress_commit_hash,
      "tag:commit_hash_short" : var.ingress_commit_hash_short,
      "tag:resourcetier" : var.resourcetier,
    }
    most_recent = true
    owners      = [var.account_id]
  }
  ssh_username = "ubuntu"

  iam_instance_profile = var.packer_iam_profile_name

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }
  # ami_block_device_mappings {
  #   device_name  = "/dev/sdb"
  #   virtual_name = "ephemeral0"
  # }
  # ami_block_device_mappings {
  #   device_name  = "/dev/sdc"
  #   virtual_name = "ephemeral1"
  # }
  # assume_role { # Since we need to read files from s3, we require a role with read access.
  #     role_arn     = "arn:aws:iam::972620357255:role/provisioner_instance_role_pipeid0" # This needs to be replaced with a terraform output
  #     session_name = "SESSION_NAME"
  #     # external_id  = "EXTERNAL_ID"
  # }
}

build {
  sources = [
    "source.amazon-ebs.amazonlinux2-ami",
    "source.amazon-ebs.amazonlinux2-nicedcv-nvidia-ami",
    "source.amazon-ebs.centos7-ami",
    "source.amazon-ebs.centos7-rendernode-ami",
    "source.amazon-ebs.ubuntu18-ami",
    "source.amazon-ebs.ubuntu18-vault-consul-server-ami",
    "source.amazon-ebs.deadline-db-ubuntu18-ami",
    "source.amazon-ebs.openvpn-server-ami"
  ]

  ### Open VPN - Wait for updates to finish and change daily update timer ###

  provisioner "shell" {
    inline = [
      "echo 'Init success'",
      "unset HISTFILE",
      "history -cw",
      "echo === Waiting for Cloud-Init ===",
      "timeout 180 /bin/bash -c 'until stat /var/lib/cloud/instance/boot-finished &>/dev/null; do echo waiting...; sleep 6; done'",
      "echo === System Packages ===",
      "echo 'Connected success. Wait for updates to finish...'", # Open VPN AMI runs apt daily update which must end before we continue.
      "sudo systemd-run --property='After=apt-daily.service apt-daily-upgrade.service' --wait /bin/true; echo \"exit $?\""
    ]
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline_shebang   = "/bin/bash -e"
    only             = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.deadline-db-ubuntu18-ami", "amazon-ebs.openvpn-server-ami", "amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }

  provisioner "file" { # fix apt upgrades to not hold up boot
    destination = "/tmp/override.conf"
    source      = "${local.template_dir}/override.conf"
  }
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /etc/systemd/system/apt-daily.timer.d",
      "sudo cp /tmp/override.conf /etc/systemd/system/apt-daily.timer.d/override.conf",
      "sudo mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d",
      "sudo cp /tmp/override.conf /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf",
      "sudo rm -f /tmp/override.conf",
      "sudo chmod 0644 /etc/systemd/system/apt-daily.timer.d/override.conf",
      "sudo systemctl daemon-reload",
      "sudo systemctl cat apt-daily{,-upgrade}.timer",
      "sudo systemctl --all list-timers apt-daily{,-upgrade}.timer"
    ]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.deadline-db-ubuntu18-ami", "amazon-ebs.openvpn-server-ami"]
  }

  ### Public cert block to verify other consul agents ###

  # provisioner "shell" {
  #   inline = ["mkdir -p /tmp/terraform-aws-vault/modules"]
  # }
  # provisioner "file" {
  #   destination = "/tmp/terraform-aws-vault/modules"
  #   source      = "${local.template_dir}/../../../terraform-aws-vault/modules/"
  # }

  ### This block will install Vault and Consul Agent for DNS

  # Ensure no more updates are running
  provisioner "shell" {
    inline = [
      "sudo systemd-run --property='After=apt-daily.service apt-daily-upgrade.service' --wait /bin/true; echo \"exit $?\""
    ]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.deadline-db-ubuntu18-ami", "amazon-ebs.openvpn-server-ami"]
  }

  # TODO remove tofu
  # fix pub keys for github centos and deadlineuser ?
  # provisioner "shell" {
  #   inline = [
  #     "echo 'Add github keys to known_hosts'",
  #     "sudo su - centos -c \"mkdir -p /home/centos/.ssh\"",
  #     "sudo su - centos -c \"touch /home/centos/.ssh/known_hosts\"",
  #     "sudo su - centos -c \"chmod 0600 /home/centos/.ssh/known_hosts\"",
  #     "sudo su - centos -c \"ssh-keygen -R 140.82.112.4\"",
  #     "sudo su - centos -c \"ssh-keyscan -t rsa github.com >> /home/centos/.ssh/known_hosts\""
  #   ]
  #   only = [
  #     "amazon-ebs.centos7-rendernode-ami"
  #   ]
  # }

  provisioner "shell" { # Install amazon systems manager for centos intelx86/amd64
    inline = [
      "sudo yum install -y https://s3.${var.aws_region}.amazonaws.com/amazon-ssm-${var.aws_region}/latest/linux_amd64/amazon-ssm-agent.rpm",
      "sudo systemctl enable amazon-ssm-agent",
      "sudo systemctl start amazon-ssm-agent",
      "sudo yum install -y ruby wget", # the following steps are to install codedeploy agent
      # "CODEDEPLOY_BIN=\"/opt/codedeploy-agent/bin/codedeploy-agent\"", # only required if there is an existing version
      # "$CODEDEPLOY_BIN stop",
      # "sudo yum erase codedeploy-agent -y",
      "cd /home/centos; sudo wget https://aws-codedeploy-${var.aws_region}.s3.${var.aws_region}.amazonaws.com/latest/install; sudo chmod +x ./install; sudo ./install auto",
      "sudo service codedeploy-agent start",
      "sudo service codedeploy-agent status",
      "sudo service codedeploy-agent enable",
    ]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.centos7-rendernode-ami"]
  }

  ### Install cloudwatch logs agent
  provisioner "shell" {
    inline = [
      "cd /tmp; sudo wget https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm; sudo rpm -U ./amazon-cloudwatch-agent.rpm",
      "sudo rm -f /tmp/amazon-cloudwatch-agent.rpm",
      "sudo yum install -y jq"
    ]
    only = [
      "amazon-ebs.amazonlinux2-ami",
      "amazon-ebs.centos7-rendernode-ami"
    ]
  }

  # install python 3.8 # this might be affecting the sesi downloader
  # provisioner "shell" {
  #   inline = [
  #     "sudo yum install -y epel-release",
  #     "sudo yum install -y centos-release-scl",
  #     "sudo yum install -y rh-python38" # scl enable rh-python38 bash
  #   ]
  #   only = [
  #     "amazon-ebs.centos7-rendernode-ami" # the binary wont be located in normal location, for that you need to compile it.
  #   ]
  # }

  provisioner "shell" {
    inline = [
      "sudo amazon-linux-extras enable python3.8",
      "sudo yum clean metadata",
      "sudo yum install -y python3.8" # scl enable rh-python38 bash
    ]
    only = [
      "amazon-ebs.amazonlinux2-ami"
    ]
  }


  # Install terraform, terragrunt, packer for Amazon Linux
  provisioner "shell" {
    inline = [
      "sudo python3.8 -m pip install ansible boto3 botocore",                                                                                       #: Install ansible using the same method we use to install it to codebuild
      "wget https://releases.hashicorp.com/terraform/${var.terraform_version}/terraform_${var.terraform_version}_linux_amd64.zip -P /tmp/ --quiet", # Get terraform
      "sudo unzip /tmp/terraform_${var.terraform_version}_linux_amd64.zip -d /tmp/",
      "sudo mv /tmp/terraform /usr/local/bin/.",
      "wget https://github.com/gruntwork-io/terragrunt/releases/download/v${var.terragrunt_version}/terragrunt_linux_386 -P /tmp/ --quiet", # Get Terragrunt
      "sudo mv /tmp/terragrunt_linux_386 /usr/local/bin/terragrunt",
      "sudo chmod +x /usr/local/bin/terragrunt"
    ]
    only = [
      "amazon-ebs.amazonlinux2-ami",
    ]
  }

  ### Init ansible collections for all hosts.

  provisioner "ansible" { # See https://github.com/hashicorp/packer-plugin-ansible/issues/47#issuecomment-852443057
    playbook_file = "./ansible/ansible_init.yaml"
    user          = "centos"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "variable_host=default package_python_interpreter=/usr/bin/python2.7"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.centos7-ami",
      "amazon-ebs.centos7-rendernode-ami",
    ]
  }


  provisioner "ansible" { # See https://github.com/hashicorp/packer-plugin-ansible/issues/47#issuecomment-852443057
    playbook_file = "./ansible/ansible_init.yaml"
    user          = "ec2-user"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "variable_host=default package_python_interpreter=/usr/bin/python2.7"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.amazonlinux2-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami",
      "amazon-ebs.ubuntu18-ami",
      "amazon-ebs.deadline-db-ubuntu18-ami",
      "amazon-ebs.openvpn-server-ami",
      "ubuntu18-vault-consul-server-ami"
    ]
  }


  provisioner "shell" { # Vault client probably wont be installed on bastions in future, but most hosts that will authenticate will require it.
    inline = [
      "git config --global advice.detachedHead false",                                                                    # disable warning about detached head because we dont care, it is a software installation
      "set -x; git clone --branch v0.17.0 https://github.com/hashicorp/terraform-aws-vault.git /tmp/terraform-aws-vault", # This can be replaced with a local copy if required.
      "if test -n '${var.vault_download_url}'; then",
      " set -x; /tmp/terraform-aws-vault/modules/install-vault/install-vault --download-url ${var.vault_download_url} --skip-package-update",
      "else",
      " set -x; /tmp/terraform-aws-vault/modules/install-vault/install-vault --version 1.6.1 --skip-package-update",
      "fi"
      # "if [[ -n \"$(command -v yum)\" ]]; then sudo yum remove awscli -y; fi", # uninstall AWS CLI v1
      # "if [[ -n \"$(command -v apt-get)\" ]]; then sudo apt-get remove awscli -y; fi", # uninstall AWS CLI v1
      # "if sudo test -f /bin/aws; then sudo rm -f /bin/aws; fi" # Ensure AWS CLI v1 doesn't exist
    ]
  }

  ### Install certs for clients and servers

  provisioner "file" {
    destination = "/tmp/sign-request.py"
    source      = "${local.template_dir}/auth/sign-request.py"
  }
  provisioner "file" {
    destination = "/tmp/ca.crt.pem"
    source      = var.ca_public_key_path
  }
  ### Clients only require the CA cert.
  provisioner "shell" {
    inline = [
      "if [[ '${var.install_auth_signing_script}' == 'true' ]]; then",
      "sudo mkdir -p /opt/vault/scripts/",
      "sudo mv /tmp/sign-request.py /opt/vault/scripts/",
      "else",
      "sudo rm /tmp/sign-request.py",
      "fi",
      "sudo mkdir -p /opt/vault/tls/",
      "sudo mv /tmp/ca.crt.pem /opt/vault/tls/",
      "sudo chmod -R 600 /opt/vault/tls",
      "sudo chmod 700 /opt/vault/tls",
      "sudo /tmp/terraform-aws-vault/modules/update-certificate-store/update-certificate-store --cert-file-path /opt/vault/tls/ca.crt.pem"
    ]
    inline_shebang = "/bin/bash -e"
    only = [
      "amazon-ebs.amazonlinux2-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami",
      "amazon-ebs.centos7-ami",
      "amazon-ebs.centos7-rendernode-ami",
      "amazon-ebs.ubuntu18-ami",
      "amazon-ebs.deadline-db-ubuntu18-ami",
      "amazon-ebs.openvpn-server-ami"
    ]
  }
  # ### Only Vault and Consul servers should have the private keys.
  provisioner "file" {
    destination = "/tmp/vault.crt.pem"
    source      = var.tls_public_key_path
    only        = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }
  provisioner "file" {
    destination = "/tmp/vault.key.pem"
    source      = var.tls_private_key_path
    only        = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }

  provisioner "shell" {
    inline = [
      "if [[ '${var.install_auth_signing_script}' == 'true' ]]; then",
      "sudo mv /tmp/sign-request.py /opt/vault/scripts/",
      "else",
      "sudo rm /tmp/sign-request.py",
      "fi",
      "sudo mv /tmp/ca.crt.pem /opt/vault/tls/",
      "sudo mv /tmp/vault.crt.pem /opt/vault/tls/",
      "sudo mv /tmp/vault.key.pem /opt/vault/tls/",
      "sudo chown -R vault:vault /opt/vault/tls/",
      "sudo chmod -R 600 /opt/vault/tls",
      "sudo chmod 700 /opt/vault/tls",
    "sudo /tmp/terraform-aws-vault/modules/update-certificate-store/update-certificate-store --cert-file-path /opt/vault/tls/ca.crt.pem"]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }

  provisioner "shell" {
    inline = [
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y git",
      "if [[ '${var.install_auth_signing_script}' == 'true' ]]; then",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python-pip",
      "LC_ALL=C && sudo pip install boto3",
    "fi"]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }

  provisioner "shell" {
    inline         = ["sudo systemd-run --property='After=apt-daily.service apt-daily-upgrade.service' --wait /bin/true"]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  ### requirements for deadline SSL

  provisioner "shell" {
    inline = [
      "apt-get install python-openssl",
      "cd /home/ubuntu/Downloads",
      "git clone https://github.com/ThinkboxSoftware/SSLGeneration.git" # https://docs.thinkboxsoftware.com/products/deadline/10.1/1_User%20Manual/manual/proxy-sslgen.html?highlight=ssl%20certificate%20generation
    ]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  ### End public cert block to verify other consul agents ###

  provisioner "shell" {
    inline = [
      "sudo setenforce 0",                                                  # Temporarily disable SELinux
      "sudo sed -i 's/^SELINUX=.*$/SELINUX=disabled/' /etc/selinux/config", # Permanently disable SELinux
      # "sudo reboot" # Reboot the system
    ]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.centos7-rendernode-ami"]
  }

  provisioner "ansible" { # Add user deployuser
    playbook_file = "./ansible/newuser.yaml"
    user          = "centos"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "variable_user=deployuser sudo=true passwordless_sudo=true add_to_group_syscontrol=true variable_connect_as_user=centos variable_uid=${local.deployuser_uid} syscontrol_gid=${local.syscontrol_gid} variable_host=default delegate_host=localhost"
      #  package_python_interpreter=/usr/bin/python2.7"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.centos7-rendernode-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  provisioner "ansible" {
    playbook_file = "./ansible/newuser.yaml"
    user          = "centos"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "variable_user=deadlineuser sudo=true passwordless_sudo=true add_to_group_syscontrol=false variable_connect_as_user=centos variable_uid=${local.deadlineuser_uid} syscontrol_gid=${local.syscontrol_gid} variable_host=default delegate_host=localhost"
      #  package_python_interpreter=/usr/bin/python2.7"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.centos7-rendernode-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  # "sudo su - ${var.deadlineuser_name} -c \"mkdir -p /home/${var.deadlineuser_name}/Thinkbox/Deadline10\"",

  provisioner "ansible" {
    playbook_file = "./ansible/newuser.yaml"
    user          = "ubuntu"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "variable_user=deadlineuser sudo=true passwordless_sudo=true add_to_group_syscontrol=false variable_connect_as_user=ubuntu variable_uid=${local.deadlineuser_uid} syscontrol_gid=${local.syscontrol_gid} variable_host=default delegate_host=localhost"
      #  package_python_interpreter=/usr/bin/python2.7"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.deadline-db-ubuntu18-ami"
    ]
  }

  ### Install Mongo / Deadline DB

  provisioner "shell" {
    ### Install Deadline DB Ubuntu Dependencies
    inline = [
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y xdg-utils lsb python-openssl netcat nfs-common",
      "sudo mkdir -p /usr/share/desktop-directories"
    ]
    only = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }
  provisioner "shell" {
    ### Install Deadline Worker Centos Dependencies. nc is also used to ensure a connection can be established with a port.
    inline = [
      "sudo yum install -y redhat-lsb samba-client samba-common cifs-utils nfs-utils tree bzip2 nmap wget nc"
    ]
    only = [
      "amazon-ebs.centos7-rendernode-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }
  # Install Powershell
  provisioner "shell" {
    inline = [
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wget apt-transport-https software-properties-common",
      "wget -q \"https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb\"",
      "sudo dpkg -i packages-microsoft-prod.deb",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update", # this needs to go into the base image.
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y powershell"
    ]
    only = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }
  provisioner "shell" {
    inline = [
      "curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo",
      "sudo yum makecache",
      "sudo yum install powershell -y"
    ]
    only = [
      "amazon-ebs.centos7-rendernode-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }
  provisioner "shell" {
    ### Install Deadline Worker Amazon Linux 2 Dependencies - https://docs.thinkboxsoftware.com/products/deadline/10.1/1_User%20Manual/manual/install-client.html
    inline = [
      "sudo yum install -y lsb"
    ]
    only = [
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  provisioner "ansible" {
    playbook_file = "./ansible/transparent-hugepages-disable.yml"
    user          = "ubuntu"
    extra_arguments = [
      "-v",
      "--extra-vars",
      # "user_deadlineuser_pw=${local.user_deadlineuser_pw} user_deadlineuser_name=deadlineuser variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost"
      "resourcetier=${var.resourcetier} user_deadlineuser_name=ubuntu variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only             = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  provisioner "file" { # fix apt upgrades to not hold up boot
    destination = "/tmp/zip-each-folder"
    source      = "${local.template_dir}/scripts/zip-each-folder"
    only        = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  provisioner "shell" { ### Download Deadline install script
    inline = [
      "set -x; cd /var/tmp; git clone --branch ${var.firehawk_deadline_installer_version} https://github.com/firehawkvfx/aws-thinkbox-deadline.git",
      "set -x; sudo chown -R ${var.deadlineuser_name}:${var.deadlineuser_name} /var/tmp/aws-thinkbox-deadline"
    ]
    only = [
      "amazon-ebs.deadline-db-ubuntu18-ami",
      "amazon-ebs.centos7-rendernode-ami"
    ]
  }

  provisioner "shell" { ### Install Deadline for DB, RCS Client
    inline = [
      "set -x; sudo su - ${var.deadlineuser_name} -c \"/var/tmp/aws-thinkbox-deadline/install-deadline --verbose --deadline-version ${local.deadline_version} --db-host-name ${var.db_host_name} --skip-certgen-during-db-install --skip-certgen-during-rcs-install --skip-install-validation --skip-install-packages --installers-bucket ${local.installers_bucket}\"",
      "sudo rm -frv /var/log/Thinkbox/Deadline10/*", # cleanup logs
      "sudo rm -fv /var/tmp/downloads/AWSPortalLink*",
      "sudo rm /tmp/Deadline-${local.deadline_version}-linux-installers.tar",
      "sudo apt-get install -y zip unzip",
      "sudo su - ${var.deadlineuser_name} -c \"/tmp/zip-each-folder /opt/Thinkbox/DeadlineRepository10/submission\"",
      "sudo su - ${var.deadlineuser_name} -c \"aws s3 sync /opt/Thinkbox/DeadlineRepository10/submission \"s3://${local.installers_bucket}/Deadline-${local.deadline_version}/Thinkbox/DeadlineRepository10/submission\"\""
    ]
    only = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  provisioner "file" { # fix apt upgrades to not hold up boot
    destination = "/tmp/retry"
    source      = "${local.template_dir}/scripts/retry"
    only = [
      "amazon-ebs.centos7-rendernode-ami"
    ]
  }

  provisioner "shell" { ### Install Deadline for Client Worker
    inline = [
      "sudo su - ${var.deadlineuser_name} -c \"mkdir -p /home/${var.deadlineuser_name}/Thinkbox/Deadline10\"",
      "sudo su - ${var.deadlineuser_name} -c \"touch /home/${var.deadlineuser_name}/Thinkbox/Deadline10/secure.ini\"", # to fix a bug introduced by Thinkbox in 10.1.17.x
      "sudo su - ${var.deadlineuser_name} -c \"/var/tmp/aws-thinkbox-deadline/install-deadline --verbose --deadline-version ${local.deadline_version} --db-host-name ${var.db_host_name} --install-worker --skip-install-validation --skip-download-mongo --skip-install-packages --installers-bucket ${local.installers_bucket}\"",
      "sudo rm -fv /tmp/Deadline-${local.deadline_version}-linux-installers.tar",
      "sudo rm -fv $deadline_installer_dir/AWSPortalLink*",
      "sudo rm -fv $deadline_installer_dir/DeadlineRepository*",
      "sudo rm -frv /var/log/Thinkbox/Deadline10/*", # cleanup logs
      "echo '...Wait for Submission/Client plugin from bucket'",
      # The need to wait for this dependency is unfortunate... the deadline repository /submission scripts for the render node are not available until the repostory is installed.  Rather than break the parallel build workflow, we test for existance of the required file in the s3 bucket for a duration limit (15 mins) before failing the render node build.  The deadline DB places those files in the bucket when installing, so if this fails, it should be because the Deadline repository build failed.
      "sudo su - ${var.deadlineuser_name} -c \"/tmp/retry 'aws s3api head-object --bucket ${local.installers_bucket} --key Deadline-${local.deadline_version}/Thinkbox/DeadlineRepository10/submission/Houdini.zip' 'Wait for file to arrive in bucket...'\"",
      "echo '...Retrieve file...'",
      "sudo su - ${var.deadlineuser_name} -c \"aws s3api get-object --bucket ${local.installers_bucket} --key Deadline-${local.deadline_version}/Thinkbox/DeadlineRepository10/submission/Houdini.zip /tmp/Houdini.zip\"",
      "sudo su - ${var.deadlineuser_name} -c \"/tmp/retry 'aws s3api head-object --bucket ${local.installers_bucket} --key Deadline-${local.deadline_version}/Thinkbox/DeadlineRepository10/submission/HServer.zip' 'Wait for file to arrive in bucket...'\"",
      "echo '...Retrieve file...'",
      "sudo su - ${var.deadlineuser_name} -c \"aws s3api get-object --bucket ${local.installers_bucket} --key Deadline-${local.deadline_version}/Thinkbox/DeadlineRepository10/submission/HServer.zip /tmp/HServer.zip\"",
      "echo '...Create /var/tmp/submission'",
      "sudo su - ${var.deadlineuser_name} -c \"mkdir -p /var/tmp/submission\"",
      "sudo su - ${var.deadlineuser_name} -c \"unzip /tmp/Houdini.zip -d /var/tmp/submission\"",
      "sudo su - ${var.deadlineuser_name} -c \"unzip /tmp/HServer.zip -d /var/tmp/submission\"",
      "sudo ls -ltriah /var/tmp/submission/Houdini/Client",
      "sudo systemctl disable deadline10launcher", # Ensure the launcher does not start automatically on first boot.  User data must aquire the certificates first, then the service will be started and enabled for subsequent reboots.
      "sudo systemctl stop deadline10launcher"
    ]
    only = [
      "amazon-ebs.centos7-rendernode-ami"
      # "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  ### Install Houdini Plugin for Deadline DB ###
  provisioner "ansible" {
    playbook_file = "./ansible/deadline_db_houdini_plugin.yml"
    user          = "ubuntu"
    extra_arguments = [
      "-vvv",
      "--extra-vars",
      jsonencode(local.houdini_json_vars),
      "--extra-vars",
      "resourcetier=${var.resourcetier} variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost",
      "--tags",
      "install_houdini,install_deadline_db"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only             = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }


  ### Install FSX fsx_packages.yaml

  provisioner "ansible" {
    playbook_file = "./ansible/fsx_packages.yaml"
    user          = "centos"
    extra_arguments = [
      "-vv",
      "--extra-vars",
      "variable_user=deadlineuser resourcetier=${var.resourcetier} variable_host=default user_deadlineuser_pw='' package_python_interpreter=/usr/bin/python2.7"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.centos7-rendernode-ami",
      # "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  ### Install Houdini ### Requires you create a SESI API Key on the Side FX website to auto download.

  provisioner "ansible" {
    playbook_file = "./ansible/houdini_module.yaml"
    user          = "centos"
    extra_arguments = [
      "-vv",
      "--extra-vars",
      jsonencode(local.houdini_json_vars),
      "--extra-vars",
      "variable_user=deadlineuser resourcetier=${var.resourcetier} installers_bucket=${local.installers_bucket} variable_host=default houdini_build=${local.houdini_build} sesi_client_id=${local.sesi_client_id} sesi_client_secret_key=${local.sesi_client_secret_key} houdini_license_server_address=${var.houdini_license_server_address} user_deadlineuser_pw='' package_python_interpreter=/usr/bin/python2.7 firehawk_houdini_tools=/home/deadlineuser/openfirehawk-houdini-tools",
      "--tags",
      "install_houdini,set_hserver,install_deadline_db"
    ]
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg sesi_client_id=${local.sesi_client_id} sesi_client_secret_key=${local.sesi_client_secret_key}"]
    galaxy_file      = "./requirements.yml"
    only = [
      "amazon-ebs.centos7-rendernode-ami",
      # "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  ### This block will install Consul Agent for DNS

  provisioner "shell" {
    ### Centos 7 - jq required and the dig command is also required
    inline = [
      # "sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm",
      "sudo yum -y install bind-utils jq"
    ]
    only = [
      "amazon-ebs.centos7-ami",
      "amazon-ebs.centos7-rendernode-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"
    ]
  }

  ### Install Consul

  provisioner "shell" {
    inline = [
      "git config --global advice.detachedHead false", # disable warning about detached head because we dont care, it is a software installation
      "git clone --branch v0.8.0 https://github.com/hashicorp/terraform-aws-consul.git /tmp/terraform-aws-consul",
      "if test -n \"${var.consul_download_url}\"; then",
      " /tmp/terraform-aws-consul/modules/install-consul/install-consul --download-url ${var.consul_download_url}",
      "else",
      " /tmp/terraform-aws-consul/modules/install-consul/install-consul --version 1.9.2",
    "fi"]
  }

  ### Consul DNS config.

  provisioner "shell" { # configure systemd-resolved per https://unix.stackexchange.com/questions/442598/how-to-configure-systemd-resolved-and-systemd-networkd-to-use-local-dns-server-f
    inline = [
      "set -x; sudo sed -i \"s/#Domains=/Domains=service.consul ~consul/g\" /etc/systemd/resolved.conf",
      "set -x; /tmp/terraform-aws-consul/modules/setup-systemd-resolved/setup-systemd-resolved",
      "set -x; sudo systemctl daemon-reload",
      "set -x; sudo systemctl restart systemd-resolved",
      "set -x; sudo cat /etc/systemd/resolved.conf",
      "set -x; sudo cat /etc/resolv.conf",
    ]
    only = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.deadline-db-ubuntu18-ami", "amazon-ebs.openvpn-server-ami"]
  }
  # The servers dont require the same config for DNS to function


  provisioner "shell" {
    inline = [
      "/tmp/terraform-aws-consul/modules/install-dnsmasq/install-dnsmasq"
      # "sudo systemctl restart dnsmasq", # if this fixes vault server, but breaks other clients, inspect further.
    ]
    only = [
      "amazon-ebs.ubuntu16-ami",
      "amazon-ebs.amazonlinux2-ami",
      "amazon-ebs.amazonlinux2-nicedcv-nvidia-ami",
      "amazon-ebs.centos7-ami",
      "amazon-ebs.centos7-rendernode-ami"
    ]
  }
  provisioner "shell" {
    inline = ["/tmp/terraform-aws-consul/modules/setup-systemd-resolved/setup-systemd-resolved"]
    only   = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }
  provisioner "shell" {
    inline = [
      "echo 'Reconfigure network interfaces...'",              # the centos 7 base ami has issues with sudo.  These hacks here are unfortunate.
      "sudo rm -fr /etc/sysconfig/network-scripts/ifcfg-eth0", # this may need to be removed from the image. having a leftover network interface file here if the interface is not present can cause dns issues and slowdowns with sudo.
      "sudo sed -i 's/sudo //g' /opt/consul/bin/run-consul"    # strip sudo for when we run consul. sudo on centos takes 25 seconds due to a bad AMI build. https://bugs.centos.org/view.php?id=18066
    ]
    only = ["amazon-ebs.centos7-ami", "amazon-ebs.centos7-rendernode-ami"]
  }
  provisioner "shell" { # Generate certificates with vault.
    inline = [
      "if [[ \"${var.test_consul}\" == true ]]; then",                                                                                                                 # only test the connection if the var is set.
      " set -x; sudo /opt/consul/bin/run-consul --client --cluster-tag-key \"${var.consul_cluster_tag_key}\" --cluster-tag-value \"${var.consul_cluster_tag_value}\"", # this is normally done with user data but dont for convenience here
      " set -x; consul members list",
      " set -x; dig $(hostname) | awk '/^;; ANSWER SECTION:$/ { getline ; print $5 ; exit }'",                      # check localhost resolve's
      " set -x; dig @127.0.0.1 vault.service.consul | awk '/^;; ANSWER SECTION:$/ { getline ; print $5 ; exit }'",  # check consul will resolve vault
      " set -x; dig @localhost vault.service.consul | awk '/^;; ANSWER SECTION:$/ { getline ; print $5 ; exit }'",  # check localhost will resolve vault
      " set -x; vault_ip=$(dig vault.service.consul | awk '/^;; ANSWER SECTION:$/ { getline ; print $5 ; exit }')", # check default lookup will resolve vault
      " echo \"vault_ip=$vault_ip\"",
      " if [[ -n \"$vault_ip\" ]]; then echo 'Build Success'; else echo 'Build Failed' >&2; dig vault.service.consul; exit 1; fi",
      "fi"
    ]
    inline_shebang = "/bin/bash -e"
  }
  provisioner "shell" {
    expect_disconnect = true
    inline            = ["set -x; sudo reboot; sleep 60"]
    environment_vars  = ["DEBIAN_FRONTEND=noninteractive"]
    inline_shebang    = "/bin/bash -e"
    only              = ["amazon-ebs.openvpn-server-ami"]
  }
  provisioner "shell" {
    expect_disconnect = true
    inline            = ["set -x; sleep 120"]
    only              = ["amazon-ebs.openvpn-server-ami"]
  }

  provisioner "ansible" {
    extra_arguments = [
      "-v",
      "--extra-vars",
      "ansible_distribution=Ubuntu ansible_python_interpreter=/usr/bin/python package_python_interpreter=/usr/bin/python variable_host=default variable_connect_as_user=openvpnas variable_user=openvpnas variable_become_user=openvpnas delegate_host=localhost",
      "--skip-tags",
      "user_access"
    ]
    playbook_file    = "./ansible/init-packages.yaml"
    user             = "openvpnas"
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only             = ["amazon-ebs.openvpn-server-ami"]
  }

  ### Configure Centos user and render user

  # provisioner "ansible" {
  #   playbook_file = "./ansible/newuser.yaml"
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "user_deadlineuser_name=ubuntu variable_host=default variable_connect_as_user=centos variable_user=deployuser sudo=true add_to_group_syscontrol=true create_ssh_key=false variable_uid=${local.deployuser_uid} delegate_host=localhost syscontrol_gid=${local.syscontrol_gid}"
  #   ]
  #   collections_path = "./ansible/collections"
  #   roles_path = "./ansible/roles"
  #   ansible_env_vars = [ "ANSIBLE_CONFIG=ansible/ansible.cfg" ]
  #   galaxy_file = "./requirements.yml"
  #   only = ["amazon-ebs.centos7-rendernode-ami"]
  # }

  # provisioner "ansible" {
  #   playbook_file = "./ansible/newuser.yaml"
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "user_deadlineuser_name=ubuntu variable_host=default variable_connect_as_user=centos variable_user=deadlineuser sudo=false add_to_group_syscontrol=false create_ssh_key=false variable_uid=${local.deadlineuser_uid} delegate_host=localhost syscontrol_gid=${local.syscontrol_gid}"
  #   ]
  #   collections_path = "./ansible/collections"
  #   roles_path = "./ansible/roles"
  #   ansible_env_vars = [ "ANSIBLE_CONFIG=ansible/ansible.cfg" ]
  #   galaxy_file = "./requirements.yml"
  #   only = ["amazon-ebs.centos7-rendernode-ami"]
  # }


  ### Configure NICEDCV workstation - Always create session.  Install browser
  provisioner "shell" { # Install Firefox
    inline = [
      "wget -O ~/FirefoxSetup.tar.bz2 \"https://download.mozilla.org/?product=firefox-latest&os=linux64\" --quiet",
      "sudo tar xvjf ~/FirefoxSetup.tar.bz2 -C /opt/",
      "sudo ln -s /opt/firefox/firefox /usr/bin/firefox"
    ]
    only = ["amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"]
  }

  provisioner "file" { # Start a virtual session on each boot.  Do not combine this with the console session above.  Pick one.
    destination = "/tmp/dcv_session.sh"
    source      = "${local.template_dir}/scripts/dcv_session.sh"
    only        = ["amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"]
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/dcv_session.sh /var/lib/cloud/scripts/per-boot/",
      "sudo /var/lib/cloud/scripts/per-boot/dcv_session.sh", # This just tests the script.
      "dcv list-sessions"                                    # A session should be listed here.
    ]
    only = ["amazon-ebs.amazonlinux2-nicedcv-nvidia-ami"]
  }

  post-processor "manifest" {
    output     = "${local.template_dir}/manifest.json"
    strip_path = true
    custom_data = {
      timestamp = "${local.timestamp}"
    }
  }
}
