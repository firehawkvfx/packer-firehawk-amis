#!/bin/bash
set -e

EXECDIR="$(pwd)"
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script
cd $SCRIPTDIR

export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/\(.*\)[a-z]/\1/')

manifest="$SCRIPTDIR/base-ami/manifest.json"
if [[ -f "$manifest" ]]; then
    export PKR_VAR_centos7_ami="$(jq -r '.builds[] | select(.name == "centos7-ami") | .artifact_id' "$manifest" | tail -1 | cut -d ":" -f2)"
    echo "Found centos7_ami in manifest: PKR_VAR_centos7_ami=$PKR_VAR_centos7_ami"

    export PKR_VAR_ubuntu18_ami="$(jq -r '.builds[] | select(.name == "ubuntu18-ami") | .artifact_id' "$manifest" | tail -1 | cut -d ":" -f2)"
    echo "Found ubuntu18_ami in manifest: PKR_VAR_ubuntu18_ami=$PKR_VAR_ubuntu18_ami"

    export PKR_VAR_ubuntu16_ami="$(jq -r '.builds[] | select(.name == "ubuntu16-ami") | .artifact_id' "$manifest" | tail -1 | cut -d ":" -f2)"
    echo "Found ubuntu16_ami in manifest: PKR_VAR_ubuntu16_ami=$PKR_VAR_ubuntu16_ami"

    export PKR_VAR_amazon_linux_2_ami="$(jq -r '.builds[] | select(.name == "amazon-linux-2-ami") | .artifact_id' "$manifest" | tail -1 | cut -d ":" -f2)"
    echo "Found amazon_linux_2_ami in manifest: PKR_VAR_amazon_linux_2_ami=$PKR_VAR_amazon_linux_2_ami"
else
    echo "Manifest for base ami does not exist.  Build the base ami and try again."
    exit 1
fi

# Packer Vars
export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
export PACKER_LOG=1
export PACKER_LOG_PATH="$SCRIPTDIR/packerlog.log"

export PKR_VAR_vpc_id="$(cd $SCRIPTDIR/../../../vpc; terraform output -json "vpc_id" | jq -r '.')"
echo "Using VPC: $PKR_VAR_vpc_id"
export PKR_VAR_subnet_id="$(cd $SCRIPTDIR/../../../vpc; terraform output -json "public_subnets" | jq -r '.[0]')"
echo "Using Subnet: $PKR_VAR_subnet_id"
export PKR_VAR_security_group_id="$(cd $SCRIPTDIR/../../../vpc; terraform output -json "consul_client_security_group" | jq -r '.')"
echo "Using Security Group: $PKR_VAR_security_group_id"

export PKR_VAR_manifest_path="$SCRIPTDIR/manifest.json"
rm -f $PKR_VAR_manifest_path
packer build "$@" $SCRIPTDIR/bastion.json.pkr.hcl
cd $EXECDIR