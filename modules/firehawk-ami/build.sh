#!/bin/bash
set -e

function log {
  local -r level="$1"
  local -r message="$2"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "${timestamp} [${level}] [$SCRIPT_NAME] ${message}"
}

function log_info {
  local -r message="$1"
  log "INFO" "$message"
}

function log_warn {
  local -r message="$1"
  log "WARN" "$message"
}

function log_error {
  local -r message="$1"
  log "ERROR" "$message"
}

function error_if_empty {
  if [[ -z "$2" ]]; then
    log_error "$1"
  fi
  return
}

EXECDIR="$(pwd)"
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script
cd $SCRIPTDIR
source ../../../../update_vars.sh --sub-script --skip-find-amis
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
terragrunt init \
    -input=false
terragrunt plan -out=tfplan -input=false
terragrunt apply -input=false tfplan
export PKR_VAR_provisioner_iam_profile_name="$(terragrunt output instance_profile_name)"
echo "Using profile: $PKR_VAR_provisioner_iam_profile_name"
export PKR_VAR_installers_bucket="$(terragrunt output installers_bucket)"
echo "Using installers bucket: $PKR_VAR_installers_bucket"

cd $SCRIPTDIR

# Packer Vars
export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
export PACKER_LOG=1
export PACKER_LOG_PATH="$SCRIPTDIR/packerlog.log"

# retrieve secretsmanager secrets
sesi_client_secret_key_path="/firehawk/resourcetier/${TF_VAR_resourcetier}/sesi_client_secret_key"
get_secret_strings=$(aws secretsmanager get-secret-value --secret-id "$sesi_client_secret_key_path")
if [[ $? -eq 0 ]]; then
  export TF_VAR_sesi_client_secret_key=$(echo $get_secret_strings | jq ".SecretString" --raw-output)
  error_if_empty "Secretsmanager secret missing: TF_VAR_sesi_client_secret_key" "$TF_VAR_sesi_client_secret_key"
  export PKR_VAR_sesi_client_secret_key="$TF_VAR_sesi_client_secret_key"
else
  log_error "Error retrieving: $sesi_client_secret_key_path"
  return
fi

# ansible log path
mkdir -p "$SCRIPTDIR/tmp/log"

# If sourced, dont execute
(return 0 2>/dev/null) && sourced=1 || sourced=0
echo "Script sourced: $sourced"
if [[ "$sourced" -eq 0 ]]; then
    packer build "$@" $SCRIPTDIR/firehawk-ami.pkr.hcl -var ca_public_key_path=$HOME/.ssh/tls/ca.crt.pem -var tls_public_key_path=$HOME/.ssh/tls/vault.crt.pem -var tls_private_key_path=$HOME/.ssh/tls/vault.key.pem
fi
cd $EXECDIR

set +e