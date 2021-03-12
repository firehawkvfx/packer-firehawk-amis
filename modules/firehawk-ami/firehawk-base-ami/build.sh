#!/bin/bash

EXECDIR="$(pwd)"
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script
echo "SCRIPTDIR: $SCRIPTDIR"
cd $SCRIPTDIR
# source ../../../update_vars.sh
# echo "SCRIPTDIR: $SCRIPTDIR"

export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/\(.*\)[a-z]/\1/')
# AMI TAGS
# Get the resourcetier from the instance tag.
export TF_VAR_instance_id_main_cloud9=$(curl http://169.254.169.254/latest/meta-data/instance-id)
export TF_VAR_resourcetier="$(aws ec2 describe-tags --filters Name=resource-id,Values=$TF_VAR_instance_id_main_cloud9 --out=json|jq '.Tags[]| select(.Key == "resourcetier")|.Value' --raw-output)" # Can be dev,green,blue,main.  it is pulled from this instance's tags by default
export PKR_VAR_resourcetier="$TF_VAR_resourcetier"
export PKR_VAR_ami_role="$(basename $SCRIPTDIR)"
export PKR_VAR_commit_hash="$(git rev-parse HEAD)"
export PKR_VAR_commit_hash_short="$(git rev-parse --short HEAD)"

# Packer Vars
export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
export PACKER_LOG=1
export PACKER_LOG_PATH="$SCRIPTDIR/packerlog.log"
export PKR_VAR_manifest_path="$SCRIPTDIR/manifest.json"

mkdir -p $SCRIPTDIR/tmp/log
rm -f $PKR_VAR_manifest_path
packer build "$@" $SCRIPTDIR/firehawk-base-ami.pkr.hcl

cd $EXECDIR