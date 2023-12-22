#!/bin/bash
set -e
# set -x

# Header to get this script's path
EXECDIR="$(pwd)"
SOURCE=${BASH_SOURCE[0]}   # resolve the script dir even if a symlink is used to this script
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR=$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPTDIR=$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)
cd $SCRIPTDIR

function log {
  local -r level="$1"
  local -r message="$2"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo >&2 -e "${timestamp} [${level}] [$SCRIPT_NAME] ${message}"
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

# Store all arguments in a variable
all_args="$@"

ami_role="$1"

# Store all arguments except the first one in a new variable
shift
args_without_first="$@"

### Vars

# You can build a single AMI to test by modifying this list.
# Deployment will require all items in the list.

if [[ $ami_role == "firehawk-base-ami" ]]; then
  export PKR_VAR_ami_role="firehawk-base-ami"
  # primary amis to build:
  build_list="amazon-ebs.ubuntu18-ami,\
amazon-ebs.amazonlinux2-ami,\
amazon-ebs.centos7-ami"

elif [[ $ami_role == "firehawk-ami" ]]; then
  export PKR_VAR_ami_role="firehawk-ami"
  # secondary amis to build
  build_list="amazon-ebs.amazonlinux2-ami,\
amazon-ebs.centos7-ami,\
amazon-ebs.centos7-rendernode-ami,\
amazon-ebs.ubuntu18-ami,\
amazon-ebs.ubuntu18-vault-consul-server-ami,\
amazon-ebs.deadline-db-ubuntu18-ami"
else
  log_error "Invalid argument: $ami_role"
  exit 1
fi

export PKR_VAR_resourcetier="$TF_VAR_resourcetier"
export PKR_VAR_commit_hash="$(git rev-parse HEAD)"
export PKR_VAR_commit_hash_short="$(git rev-parse --short HEAD)"
export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
export PACKER_LOG=1
export PACKER_LOG_PATH="$SCRIPTDIR/packerlog.log"
export PKR_VAR_manifest_path="$SCRIPTDIR/manifest.json"

cd $SCRIPTDIR/../firehawk-base-ami
export PKR_VAR_ingress_commit_hash="$(git rev-parse HEAD)" # the commit hash for incoming amis
export PKR_VAR_ingress_commit_hash_short="$(git rev-parse --short HEAD)"
cd $SCRIPTDIR

echo "Building AMI's for deployment: $PKR_VAR_ami_role"

### Idempotency logic: exit if all images exist
error_if_empty "Missing: PKR_VAR_commit_hash_short:" "$PKR_VAR_commit_hash_short"
error_if_empty "Missing: build_list:" "$build_list"

ami_query=$(aws ec2 describe-images --owners self --filters "Name=tag:commit_hash_short,Values=[$PKR_VAR_commit_hash_short]" --query "Images[*].{ImageId:ImageId,date:CreationDate,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId,commit_hash_short:[Tags[?Key=='commit_hash_short']][0][0].Value,packer_source:[Tags[?Key=='packer_source']][0][0].Value}")

total_built_images=$(echo $ami_query | jq -r '. | length')

missing_images_for_hash=$(echo $ami_query |
  jq -r '
  .[].packer_source' |
  jq --arg BUILDLIST "$build_list" --slurp --raw-input 'split("\n")[:-1] as $existing_names
| ($existing_names | unique) as $existing_names_set
| ($BUILDLIST | split(",") | unique) as $intended_names_set
| $intended_names_set - $existing_names_set
')

count_missing_images_for_hash=$(jq -n --argjson data "$missing_images_for_hash" '$data | length')

if [[ "$count_missing_images_for_hash" -eq 0 ]]; then
  echo
  echo "All images have already been built for this hash and build list."
  echo "To force a build, ensure at least one image from the build list is missing.  The builder will erase all images for the commit hash and rebuild."
  echo

  cd $EXECDIR
  set +e
  exit 0
fi

### Packer profile
# export PKR_VAR_provisioner_iam_profile_name="$(terragrunt output instance_profile_name)"
echo "Using profile: $PKR_VAR_provisioner_iam_profile_name"
error_if_empty "Missing: PKR_VAR_provisioner_iam_profile_name" "$PKR_VAR_provisioner_iam_profile_name"

if [[ $ami_role == "firehawk-ami" ]]; then
  ### Software Bucket
  # export PKR_VAR_installers_bucket="$(terragrunt output installers_bucket)"
  echo "Using installers bucket: $PKR_VAR_installers_bucket"
  error_if_empty "Missing: PKR_VAR_installers_bucket" "$PKR_VAR_installers_bucket"
  cd $SCRIPTDIR

  # Retrieve secretsmanager secrets
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
fi

# If sourced, dont execute
(return 0 2>/dev/null) && sourced=1 || sourced=0
echo "Script sourced: $sourced"
if [[ ! "$sourced" -eq 0 ]]; then
  cd $EXECDIR
  set +e
  exit 0
fi

echo "The following images have not yet been built:"
echo "$missing_images_for_hash"

echo "total_built_images: $total_built_images"
if [[ $total_built_images -gt 0 ]]; then
  echo "Packer will erase all images for this commit hash and rebuild all images"
  $SCRIPTDIR/delete-all-old-amis.sh --commit-hash-short-list $PKR_VAR_commit_hash_short --auto-approve
fi

if [[ $ami_role == "firehawk-base-ami" ]]; then
  # Validate
  packer validate \
    -only=$build_list \
    $SCRIPTDIR/firehawk-base-ami.pkr.hcl

  # Prepare for build.
  # Ansible log path
  mkdir -p "$SCRIPTDIR/tmp/log"
  # Clear previous manifest
  rm -f $PKR_VAR_manifest_path

  # Build
  packer build \
    -only=$build_list \
    $SCRIPTDIR/firehawk-base-ami.pkr.hcl
elif [[ $1 == "firehawk-ami" ]]; then

  # Prepare for build.
  # Ansible log path
  mkdir -p "$SCRIPTDIR/tmp/log"
  # Clear previous manifest
  rm -f $PKR_VAR_manifest_path

  # Ensure certs exist for Consul and Vault
  $SCRIPTDIR/../../init/init
  if [[ -f "$TF_VAR_ca_public_key_file_path" ]]; then
    export SSL_expiry=$(cat "$TF_VAR_ca_public_key_file_path" | openssl x509 -noout -enddate | awk -F "=" '{print $2}')
    # export PKR_VAR_SSL_expiry="$TF_VAR_SSL_expiry"
    echo "Current SSL Certificates will expire at: $SSL_expiry"
  else
    echo "Warning: No SSL Certifcates exist."
  fi

  # Validate
  packer validate \
    -var "ca_public_key_path=$HOME/.ssh/tls/ca.crt.pem" \
    -var "tls_public_key_path=$HOME/.ssh/tls/vault.crt.pem" \
    -var "tls_private_key_path=$HOME/.ssh/tls/vault.key.pem" \
    -var "SSL_expiry=$SSL_expiry" \
    -only=$build_list \
    $SCRIPTDIR/firehawk-ami.pkr.hcl

  # Build
  packer build \
    -var "ca_public_key_path=$HOME/.ssh/tls/ca.crt.pem" \
    -var "tls_public_key_path=$HOME/.ssh/tls/vault.crt.pem" \
    -var "tls_private_key_path=$HOME/.ssh/tls/vault.key.pem" \
    -var "SSL_expiry=$SSL_expiry" \
    -only=$build_list \
    $SCRIPTDIR/firehawk-ami.pkr.hcl

  # Track the houdini build by adding an extra tag to the AMI.
  # ...Since the build version downloaded cannot always be known until after install.
  if test -f /tmp/houdini_download_result.txt; then
    echo "Get downloadeded versions to tag ami from: /tmp/houdini_download_result.txt"
    cat /tmp/houdini_download_result.txt
    echo "Parse manfiest content: $PKR_VAR_manifest_path"
    jq . $PKR_VAR_manifest_path
    houdini_ami_to_update="$(jq -r '.builds[] | select(.name=="centos7-rendernode-ami").artifact_id | split(":")[-1]' $PKR_VAR_manifest_path)"
    result_houdini_build="$(cat /tmp/houdini_download_result.txt)"
    echo "Add tag: houdini_build=$result_houdini_build to ami: $houdini_ami_to_update"
    aws ec2 create-tags \
      --resources $houdini_ami_to_update --tags Key=houdini_build,Value=$result_houdini_build
  fi

fi

cd $EXECDIR
set +e
