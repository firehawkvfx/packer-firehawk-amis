# Ensure you first build the ./firehawk-base-ami first to produce a manifest.
# The firehawk-base-ami is used to build this ami.

variable "aws_region" {
  type    = string
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
variable "ca_public_key_path" {
  type    = string
  default = "/home/ec2-user/.ssh/tls/ca.crt.pem"
}
variable "consul_download_url" {
  type    = string
  default = ""
}
variable "consul_module_version" {
  type    = string
  default = "v0.8.0"
}
variable "consul_version" {
  type    = string
  default = "1.8.4"
}
variable "install_auth_signing_script" {
  type    = string
  default = "true"
}
variable "tls_private_key_path" {
  type    = string
  default = "/home/ec2-user/.ssh/tls/vault.key.pem"
}
variable "tls_public_key_path" {
  type    = string
  default = "/home/ec2-user/.ssh/tls/vault.crt.pem"
}
variable "vault_download_url" {
  type    = string
  default = ""
}
variable "vault_version" {
  type    = string
  default = "1.5.5"
}
variable "vault_module_version" { # The hashicorp github module version to clone.
  default = "pull-request-235" # from "v0.13.11", this resolves consul dns issues on start.  This is likely resolved by Hashicorp now.
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
variable "provisioner_iam_profile_name" { # Required for some builds requiring S3 Installers
  type = string
}
variable "test_consul" { # If a consul cluster is running, attempt to join the cluster. This can be useful for debugging, but will prevent inital builds if you have no infrastructure running yet.  This test may not also work unless the appropriate role is assigned.
  type    = bool
  default = false
}
variable "deadline_version" {
  description = "The version of the deadline installer to aquire"
  type        = string
  default     = "10.1.9.2"
}
variable "installers_bucket" {
  description = "The installer bucket to persist installations to"
  type        = string
}
# Required for render node AMI
variable "sesi_client_id" {
  description = "The client ID generated from your Side FX Account to automatically download Houdini."
  type = string
}
variable "sesi_client_secret_key" {
  description = "The secret key generated from your Side FX Account to automatically download Houdini."
  type = string
}
variable "houdini_license_server_address" {
  description = "The IP or host name of your Houdini license server (IP Address is recommended to simplify usage across sites with DNS)."
  type = string
}
variable "SSL_expiry" {
  description = "The Expiry resulting from the TTL on the SSL Certificates"
  type = string
}

locals {
  timestamp         = regex_replace(timestamp(), "[- TZ:]", "")
  template_dir      = path.root
  deadline_version  = var.deadline_version
  installers_bucket = var.installers_bucket
  common_ami_tags = {
    "packer_template" : "firehawk-ami",
    "commit_hash" : var.commit_hash,
    "commit_hash_short" : var.commit_hash_short,
    "resourcetier" : var.resourcetier,
    "sslexpiry": var.SSL_expiry
  }
  syscontrol_gid = "9003"
  deployuser_uid = "9004"
  deadlineuser_uid = "9001"
  houdini_build = "daily"
  sesi_client_id = var.sesi_client_id
  sesi_client_secret_key = var.sesi_client_secret_key
  houdini_license_server_address = var.houdini_license_server_address
}

source "amazon-ebs" "openvpn-server-ami" {
  tags            = merge({ "ami_role" : "firehawk_openvpn_server_ami" }, local.common_ami_tags)
  ami_description = "An Open VPN Access Server AMI configured for Firehawk"
  ami_name        = "firehawk-openvpn-server-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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

source "amazon-ebs" "amazon-linux-2-ami" {
  tags            = merge({ "ami_role" : "firehawk_amazonlinux2_ami" }, local.common_ami_tags)
  ami_description = "An Amazon Linux 2 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastion-amazon-linux-2-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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

#could not parse template for following block: "template: generated:4: function \"clean_resource_name\" not defined"

source "amazon-ebs" "centos7-ami" {
  tags            = merge({ "ami_role" : "firehawk_centos7_ami" }, local.common_ami_tags)
  ami_description = "A Cent OS 7 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastion-centos7-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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
  tags            = merge({ "ami_role" : "firehawk_centos7_rendernode_ami" }, local.common_ami_tags)
  ami_description = "A Cent OS 7 AMI rendernode."
  ami_name        = "firehawk-bastion-centos7-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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

  iam_instance_profile = var.provisioner_iam_profile_name # provide read and write s3 access for updating and retrieving installers

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 16
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
  tags            = merge({ "ami_role" : "firehawk_ubuntu18_ami" }, local.common_ami_tags)
  ami_description = "An Ubuntu 18.04 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastion-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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
  tags            = merge({ "ami_role" : "firehawk_ubuntu18_vault_consul_server_ami" }, local.common_ami_tags)
  ami_description = "An Ubuntu 18.04 AMI Vault and Consul Server."
  ami_name        = "firehawk-vault-consul-server-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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
  tags            = merge({ "ami_role" : "firehawk_deadlinedb_ami" }, local.common_ami_tags)
  ami_description = "An Ubuntu 18.04 AMI with Deadline DB ${var.deadline_version} server."
  ami_name        = "firehawk-deadlinedb-ubuntu18-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
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

  iam_instance_profile = var.provisioner_iam_profile_name

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
    "source.amazon-ebs.amazon-linux-2-ami",
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

  provisioner "shell" { # Vault client probably wont be installed on bastions in future, but most hosts that will authenticate will require it.
    inline = [
      "git config --global advice.detachedHead false", # disable warning about detached head because we dont care, it is a software installation
      "git clone --branch ${var.vault_module_version} https://github.com/queglay/terraform-aws-vault.git /tmp/terraform-aws-vault", # This can be replaced with a local copy if required.
      "if test -n '${var.vault_download_url}'; then",
      " /tmp/terraform-aws-vault/modules/install-vault/install-vault --download-url ${var.vault_download_url} --skip-package-update;",
      "else",
      " /tmp/terraform-aws-vault/modules/install-vault/install-vault --version ${var.vault_version} --skip-package-update;",
      "fi"
    ]
  }

  ### Install certs for clients and servers

  provisioner "file" {
    destination = "/tmp/sign-request.py"
    source      = "${local.template_dir}/auth/sign-request.py"
  }
  provisioner "file" {
    destination = "/tmp/ca.crt.pem"
    source      = "${var.ca_public_key_path}"
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
    only           = [
      "amazon-ebs.amazon-linux-2-ami",
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
    source      = "${var.tls_public_key_path}"
    only           = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }
  provisioner "file" {
    destination = "/tmp/vault.key.pem"
    source      = "${var.tls_private_key_path}"
    only           = ["amazon-ebs.ubuntu18-vault-consul-server-ami"]
  }

  provisioner "shell" {
    inline         = [
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
    inline         = ["sudo apt-get install -y git",
      "if [[ '${var.install_auth_signing_script}' == 'true' ]]; then",
      "sudo apt-get install -y python-pip",
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
    inline         = [
      "apt-get install python-openssl",
      "cd /home/ubuntu/Downloads",
      "git clone https://github.com/ThinkboxSoftware/SSLGeneration.git" # https://docs.thinkboxsoftware.com/products/deadline/10.1/1_User%20Manual/manual/proxy-sslgen.html?highlight=ssl%20certificate%20generation
    ]
    inline_shebang = "/bin/bash -e"
    only           = ["amazon-ebs.amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  ### End public cert block to verify other consul agents ###

  ### Configure deadlineuser for render service ###
  # provisioner "ansible" {
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "set_selinux=disabled", # TODO Enable this and test once all services function.
  #     "variable_host=default variable_connect_as_user=centos variable_user=deadlineuser variable_become_user=centos",
  #     "--skip-tags",
  #     "user_access"
  #   ]
  #   playbook_file    = "./ansible/newuser_deadlineuser.yaml"
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.centos7-rendernode-ami"]
  # }

  provisioner "ansible" {
    playbook_file = "./ansible/newuser_deadlineuser.yaml"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "user_deadlineuser_name=deadlineuser variable_host=default variable_connect_as_user=centos variable_user=deployuser sudo=true add_to_group_syscontrol=true create_ssh_key=false variable_uid=${local.deployuser_uid} delegate_host=localhost syscontrol_gid=${local.syscontrol_gid}"
    ]
    collections_path = "./ansible/collections"
    roles_path = "./ansible/roles"
    ansible_env_vars = [ "ANSIBLE_CONFIG=ansible/ansible.cfg" ]
    galaxy_file = "./requirements.yml"
    only = ["amazon-ebs.centos7-rendernode-ami"]
  }

  provisioner "ansible" {
    playbook_file = "./ansible/newuser_deadlineuser.yaml"
    extra_arguments = [
      "-v",
      "--extra-vars",
      "user_deadlineuser_name=deadlineuser variable_host=default variable_connect_as_user=centos variable_user=deadlineuser sudo=false add_to_group_syscontrol=false create_ssh_key=false variable_uid=${local.deadlineuser_uid} delegate_host=localhost syscontrol_gid=${local.syscontrol_gid}"
    ]
    collections_path = "./ansible/collections"
    roles_path = "./ansible/roles"
    ansible_env_vars = [ "ANSIBLE_CONFIG=ansible/ansible.cfg" ]
    galaxy_file = "./requirements.yml"
    only = ["amazon-ebs.centos7-rendernode-ami"]
  }

  ### Open VPN / Deadline DB / Centos install CLI.  This should be relocated to the base ami, and done purely with bash now instead.
  # provisioner "ansible" {
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "variable_host=default variable_connect_as_user=openvpnas variable_user=openvpnas variable_become_user=openvpnas delegate_host=localhost",
  #     "--skip-tags",
  #     "user_access"
  #   ]
  #   playbook_file    = "./ansible/aws_cli_ec2_install.yaml"
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.openvpn-server-ami"]
  # }
  # provisioner "ansible" {
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "variable_host=default variable_connect_as_user=ubuntu variable_user=ubuntu variable_become_user=ubuntu delegate_host=localhost",
  #     "--skip-tags",
  #     "user_access"
  #   ]
  #   playbook_file    = "./ansible/aws_cli_ec2_install.yaml"
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  # }
  # provisioner "ansible" {
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "variable_host=default variable_connect_as_user=centos variable_user=centos variable_become_user=centos delegate_host=localhost",
  #     "--skip-tags",
  #     "user_access"
  #   ]
  #   playbook_file    = "./ansible/aws_cli_ec2_install.yaml"
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.centos7-rendernode-ami"]
  # }
  # # Install for deadline user and sudo user.
  # provisioner "ansible" {
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     "variable_host=default variable_connect_as_user=centos variable_user=centos variable_become_user=deadlineuser delegate_host=localhost package_python_interpreter=/usr/bin/python2.7", # Centos7 requires Py2.7 for Ansible packages.
  #     "--skip-tags",
  #     "user_access"
  #   ]
  #   playbook_file    = "./ansible/aws_cli_ec2_install.yaml"
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.centos7-rendernode-ami"]
  # }

  provisioner "shell" {
    ### Centos 7 - jq required and the dig command is also required
    inline = [
      # "sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm",
      "python3 -m pip install --user --upgrade awscli",
    ]
    only = ["amazon-ebs.openvpn-server-ami", "amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  provisioner "shell" {
    ### Centos 7 - jq required and the dig command is also required
    inline = [
      # "sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm",
      "python3 -m pip install --user --upgrade awscli",
    ]
    only = ["amazon-ebs.centos7-rendernode-ami"]
  }

  ### Install Houdini ### Requires you create a SESI API Key on the Side FX website to auto download.
  provisioner "ansible" {
    playbook_file = "./ansible/collections/ansible_collections/firehawkvfx/houdini/houdini_module.yaml"
    extra_arguments = [
      "-vvv",
      "--extra-vars",
      "resourcetier=${var.resourcetier} installers_bucket=${local.installers_bucket} variable_host=default houdini_build=${local.houdini_build} sesi_client_id=${local.sesi_client_id} sesi_client_secret_key=${local.sesi_client_secret_key} houdini_license_server_address=${var.houdini_license_server_address} user_deadlineuser_pw='' package_python_interpreter=/usr/bin/python2.7",
      "--tags",
      "install_houdini"
    ]
    collections_path = "./ansible/collections"
    roles_path = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg sesi_client_id=${local.sesi_client_id} sesi_client_secret_key=${local.sesi_client_secret_key}" ]
    galaxy_file = "./requirements.yml"
    only = ["amazon-ebs.centos7-rendernode-ami"]
  }

  # ### Ensure aws works for root user.  This should be relocated to the base ami.

  # provisioner "shell" {
  #   inline = [
  #     "echo '...Correct links for AWS CLI'",
  #     "set -x; which aws",
  #     "sudo ln -s $(which aws) /usr/local/sbin/aws",
  #     "sudo ls -ltriah /usr/local/sbin/aws"
  #   ]
  #   inline_shebang = "/bin/bash -e"
  #   only           = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.deadline-db-ubuntu18-ami"]
  # }

  ### Install Mongo / Deadline DB

  provisioner "shell" {
    ### Install Deadline DB Ubuntu Dependencies
    inline = [
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y xdg-utils lsb",
      "sudo mkdir -p /usr/share/desktop-directories"
    ]
    only = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  provisioner "shell" {
    ### Install Deadline Worker Centos Dependencies
    inline = [
      "sudo yum install -y redhat-lsb samba-client samba-common cifs-utils nfs-utils tree bzip2 nmap wget"
    ]
    only = ["amazon-ebs.centos7-rendernode-ami"]
  }

  provisioner "ansible" {
    playbook_file = "./ansible/transparent-hugepages-disable.yml"
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
    destination = "/var/tmp/download-deadline.sh"
    source      = "${local.template_dir}/scripts/download-deadline.sh"
    only = ["amazon-ebs.deadline-db-ubuntu18-ami", "amazon-ebs.centos7-rendernode-ami"]
  }
  provisioner "shell" {
    ### Download Deadline Installer for DB, RCS Client
    inline = [
      "sudo chmod +x /var/tmp/download-deadline.sh",
      "deadline_version=${var.deadline_version} installers_bucket=${var.installers_bucket} mongo_url=\"https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.19.tgz\" /var/tmp/download-deadline.sh",
      "download_dir=/var/tmp/downloads", # Cleanup unneeded AWSPortalLink
      "deadline_linux_installers_tar=\"$download_dir/Deadline-${var.deadline_version}-linux-installers.tar\"",
      "deadline_linux_installers_filename=\"$(basename $deadline_linux_installers_tar)\"",
      "deadline_linux_installers_basename=\"$${deadline_linux_installers_filename%.*}\"",
      "deadline_installer_dir=\"$download_dir/$deadline_linux_installers_basename\"",
      "sudo rm -fv $deadline_linux_installers_tar",
      "sudo rm -fv $deadline_installer_dir/AWSPortalLink*"
    ]
    only = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  provisioner "shell" {
    ### Download Deadline Installer for Client
    inline = [
      "sudo chmod +x /var/tmp/download-deadline.sh",
      "deadline_version=${var.deadline_version} installers_bucket=${var.installers_bucket} /var/tmp/download-deadline.sh",
      "download_dir=/var/tmp/downloads", 
      "deadline_linux_installers_tar=\"$download_dir/Deadline-${var.deadline_version}-linux-installers.tar\"",
      "deadline_linux_installers_filename=\"$(basename $deadline_linux_installers_tar)\"",
      "deadline_linux_installers_basename=\"$${deadline_linux_installers_filename%.*}\"",
      "deadline_installer_dir=\"$download_dir/$deadline_linux_installers_basename\"",
      "sudo rm -fv $deadline_linux_installers_tar",
      "sudo rm -fv $deadline_installer_dir/AWSPortalLink*",
      "sudo rm -fv $deadline_installer_dir/DeadlineRepository*"
    ]
    only = ["amazon-ebs.centos7-rendernode-ami"]
  }

  # provisioner "ansible" { # Temp disable dealine and rcs install until immutability is achieved.
  #   playbook_file = "./ansible/deadline-db-install.yaml"
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     # "user_deadlineuser_pw=${local.user_deadlineuser_pw} user_deadlineuser_name=deployuser variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost openfirehawkserver=deadlinedb.service.consul deadline_proxy_certificate_password=${local.deadline_proxy_certificate_password} installers_bucket=${local.installers_bucket} deadline_version=${local.deadline_version} reinstallation=false"
  #     "resourcetier=${var.resourcetier} user_deadlineuser_name=ubuntu variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost openfirehawkserver=deadlinedb.service.consul installers_bucket=${local.installers_bucket} deadline_version=${local.deadline_version} reinstallation=false"
  #   ]
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  # }

  # provisioner "ansible" {
  #   playbook_file = "./ansible/deadlinercs.yaml"
  #   extra_arguments = [
  #     "-v",
  #     "--extra-vars",
  #     # "user_deadlineuser_pw=${local.user_deadlineuser_pw} user_deadlineuser_name=deployuser variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost openfirehawkserver=deadlinedb.service.consul deadline_proxy_certificate_password=${local.deadline_proxy_certificate_password} installers_bucket=${local.installers_bucket} deadline_version=${local.deadline_version} reinstallation=false"
  #     "resourcetier=${var.resourcetier} user_deadlineuser_name=ubuntu variable_host=default variable_connect_as_user=ubuntu delegate_host=localhost openfirehawkserver=deadlinedb.service.consul installers_bucket=${local.installers_bucket} deadline_version=${local.deadline_version} reinstallation=false"
  #   ]
  #   collections_path = "./ansible/collections"
  #   roles_path       = "./ansible/roles"
  #   ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
  #   galaxy_file      = "./requirements.yml"
  #   only             = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  # }

  ### Install Houdini Plugin for deadline DB ###
  provisioner "ansible" {
    playbook_file = "./ansible/collections/ansible_collections/firehawkvfx/houdini/deadline_db_houdini_plugin.yml"
    extra_arguments = [
      "-vvv",
      "--extra-vars",
      "resourcetier=${var.resourcetier} variable_host=default houdini_build=${local.houdini_build}",
      "--tags",
      "install_houdini"
    ]
    collections_path = "./ansible/collections"
    roles_path = "./ansible/roles"
    ansible_env_vars = [ "ANSIBLE_CONFIG=ansible/ansible.cfg" ]
    galaxy_file = "./requirements.yml"
    only = ["amazon-ebs.deadline-db-ubuntu18-ami"]
  }

  ### This block will install Consul Agent for DNS

  provisioner "shell" {
    ### Centos 7 - jq required and the dig command is also required
    inline = [
      # "sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm",
      "sudo yum -y install bind-utils jq"
    ]
    only = ["amazon-ebs.centos7-ami", "amazon-ebs.centos7-rendernode-ami"]
  }

  ### Install Consul

  provisioner "shell" {
    inline = [
      "git config --global advice.detachedHead false", # disable warning about detached head because we dont care, it is a software installation
      "git clone --branch ${var.consul_module_version} https://github.com/hashicorp/terraform-aws-consul.git /tmp/terraform-aws-consul",
      "if test -n \"${var.consul_download_url}\"; then",
      " /tmp/terraform-aws-consul/modules/install-consul/install-consul --download-url ${var.consul_download_url};",
      "else",
      " /tmp/terraform-aws-consul/modules/install-consul/install-consul --version ${var.consul_version};",
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
    only = ["amazon-ebs.ubuntu16-ami", "amazon-ebs.amazon-linux-2-ami", "amazon-ebs.centos7-ami", "amazon-ebs.centos7-rendernode-ami"]
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
    collections_path = "./ansible/collections"
    roles_path       = "./ansible/roles"
    ansible_env_vars = ["ANSIBLE_CONFIG=ansible/ansible.cfg"]
    galaxy_file      = "./requirements.yml"
    only             = ["amazon-ebs.openvpn-server-ami"]
  }

### Configure Centos user and render user

  # provisioner "ansible" {
  #   playbook_file = "./ansible/newuser_deadlineuser.yaml"
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
  #   playbook_file = "./ansible/newuser_deadlineuser.yaml"
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

  post-processor "manifest" {
    output     = "${local.template_dir}/manifest.json"
    strip_path = true
    custom_data = {
      timestamp = "${local.timestamp}"
    }
  }
}
