# The base AMI's purpose is to produce an image with apt-get/yum updates 
# Updates can be unstable on a daily basis so the base ami once successful can be reused for further ami configuration also improving build time.
# Avoiding updates altogether is not ideal as some packages and executables depend on updates to function.

variable "aws_region" {
  type = string
  default = null
}

variable "vpc_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "provisioner_iam_profile_name" {
  type = string
}

locals {
  timestamp    = regex_replace(timestamp(), "[- TZ:]", "")
  template_dir = path.root
}

source "amazon-ebs" "amazon-linux-2-ami" {
  ami_description = "An Amazon Linux 2 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastionbase-amazon-linux-2-${local.timestamp}-{{uuid}}"
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

  vpc_id               = "${var.vpc_id}"
  subnet_id            = "${var.subnet_id}"
  security_group_id    = "${var.security_group_id}"
  iam_instance_profile = var.provisioner_iam_profile_name
}

#could not parse template for following block: "template: generated:4: function \"clean_resource_name\" not defined"

source "amazon-ebs" "centos7-ami" {
  ami_description = "A Cent OS 7 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastionbase-centos7-${local.timestamp}-{{uuid}}"
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
  ssh_username = "centos"

  vpc_id               = "${var.vpc_id}"
  subnet_id            = "${var.subnet_id}"
  security_group_id    = "${var.security_group_id}"
  iam_instance_profile = var.provisioner_iam_profile_name
}

#could not parse template for following block: "template: generated:4: function \"clean_resource_name\" not defined"

source "amazon-ebs" "ubuntu16-ami" {
  ami_description = "An Ubuntu 16.04 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastionbase-ubuntu16-${local.timestamp}-{{uuid}}"
  instance_type   = "t2.micro"
  region          = "${var.aws_region}"
  source_ami_filter {
    filters = {
      architecture                       = "x86_64"
      "block-device-mapping.volume-type" = "gp2"
      name                               = "ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"
      root-device-type                   = "ebs"
      virtualization-type                = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"

  vpc_id               = "${var.vpc_id}"
  subnet_id            = "${var.subnet_id}"
  security_group_id    = "${var.security_group_id}"
  iam_instance_profile = var.provisioner_iam_profile_name
}

#could not parse template for following block: "template: generated:4: function \"clean_resource_name\" not defined"

source "amazon-ebs" "ubuntu18-ami" {
  ami_description = "An Ubuntu 18.04 AMI that will accept connections from hosts with TLS Certs."
  ami_name        = "firehawk-bastionbase-ubuntu18-${local.timestamp}-{{uuid}}"
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

  vpc_id               = "${var.vpc_id}"
  subnet_id            = "${var.subnet_id}"
  security_group_id    = "${var.security_group_id}"
  iam_instance_profile = var.provisioner_iam_profile_name
}

build {
  sources = [
    "source.amazon-ebs.ubuntu18-ami",
    "source.amazon-ebs.ubuntu16-ami",
    "source.amazon-ebs.amazon-linux-2-ami",
    "source.amazon-ebs.centos7-ami"
    ]

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

  provisioner "shell" {
    inline         = [
      "echo === System Packages ===",
      "echo 'Connected success. Wait for updates to finish...'", # Open VPN AMI runs apt daily update which must end before we continue.
      "sudo systemd-run --property='After=apt-daily.service apt-daily-upgrade.service' --wait /bin/true; echo \"exit $?\""
      ]
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline_shebang = "/bin/bash -e"
    only = ["amazon-ebs.ubuntu18-ami"]
  }
  
  provisioner "shell" {
    inline_shebang = "/bin/bash -e"
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline         = [
      "sudo apt-get update -y"
    ]
    only = ["amazon-ebs.ubuntu18-ami", "amazon-ebs.ubuntu16-ami"]
  }

  provisioner "shell" {
    inline_shebang = "/bin/bash -e"
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline         = [
      "sudo yum update -y"
    ]
    only = ["amazon-ebs.centos7-ami", "amazon-linux-2-ami"]
  }

  post-processor "manifest" {
      output = "${local.template_dir}/manifest.json"
      strip_path = true
      custom_data = {
        timestamp = "${local.timestamp}"
      }
  }
}