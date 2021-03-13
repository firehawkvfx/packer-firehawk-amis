#!/bin/bash
set -e

EXECDIR="$(pwd)"
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script
cd $SCRIPTDIR
source ../../update_vars.sh
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script


export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/\(.*\)[a-z]/\1/')
# AMI TAGS
# Get the resourcetier from the instance tag.
export TF_VAR_instance_id_main_cloud9=$(curl http://169.254.169.254/latest/meta-data/instance-id)
export TF_VAR_resourcetier="$(aws ec2 describe-tags --filters Name=resource-id,Values=$TF_VAR_instance_id_main_cloud9 --out=json|jq '.Tags[]| select(.Key == "resourcetier")|.Value' --raw-output)" # Can be dev,green,blue,main.  it is pulled from this instance's tags by default
export PKR_VAR_resourcetier="$TF_VAR_resourcetier"
export PKR_VAR_ami_role="$(basename $SCRIPTDIR)"
export PKR_VAR_commit_hash="$(git rev-parse HEAD)"
export PKR_VAR_commit_hash_short="$(git rev-parse --short HEAD)"
export PKR_VAR_account_id=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep -oP '(?<="accountId" : ")[^"]*(?=")')
cd $SCRIPTDIR/../firehawk-base-ami
export PKR_VAR_ingress_commit_hash="$(git rev-parse HEAD)" # the commit hash for incoming amis
export PKR_VAR_ingress_commit_hash_short="$(git rev-parse --short HEAD)"

cd $SCRIPTDIR/terraform-remote-state-inputs
terraform init \
    -input=false
terraform plan -out=tfplan -input=false
terraform apply -input=false tfplan
export PKR_VAR_provisioner_iam_profile_name="$(terraform output instance_profile_name)"
echo "Using profile: $PKR_VAR_provisioner_iam_profile_name"
export PKR_VAR_installers_bucket="$(terraform output installers_bucket)"
echo "Using installers bucket: $PKR_VAR_installers_bucket"

cd $SCRIPTDIR

# Packer Vars
export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
export PACKER_LOG=1
export PACKER_LOG_PATH="$SCRIPTDIR/packerlog.log"

# ansible log path
mkdir -p "$SCRIPTDIR/tmp/log"

# export PKR_VAR_manifest_path="$SCRIPTDIR/manifest.json"
# rm -f $PKR_VAR_manifest_path
packer build "$@" $SCRIPTDIR/firehawk-ami.pkr.hcl
cd $EXECDIR