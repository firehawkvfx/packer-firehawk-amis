#!/bin/bash

vpcname="vaultvpc"
to_abs_path() {
  python3 -c "import os; print(os.path.abspath('$1'))"
}

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

local -r SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script

# Region is required for AWS CLI
export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/\(.*\)[a-z]/\1/')
# Get the resourcetier from the instance tag.
export TF_VAR_instance_id_main_cloud9=$(curl http://169.254.169.254/latest/meta-data/instance-id)
export TF_VAR_resourcetier="$(aws ec2 describe-tags --filters Name=resource-id,Values=$TF_VAR_instance_id_main_cloud9 --out=json|jq '.Tags[]| select(.Key == "resourcetier")|.Value' --raw-output)" # Can be dev,green,blue,main.  it is pulled from this instance's tags by default
export TF_VAR_resourcetier_vault="$TF_VAR_resourcetier" # WARNING: if vault is deployed in a seperate tier for use, then this will probably need to become an SSM driven parameter from the template
export TF_VAR_vpcname="${TF_VAR_resourcetier}${vpcname}" # Why no underscores? Because the vpc name is used to label terraform state S3 buckets
export TF_VAR_vpcname_vault="${TF_VAR_resourcetier}vaultvpc" # WARNING: if vault is deployed in a seperate tier for use, then this will probably need to become an SSM driven parameter from the template

# Instance and vpc data
export TF_VAR_deployer_ip_cidr="$(curl http://169.254.169.254/latest/meta-data/public-ipv4)/32" # Initially there will be no remote ip onsite, so we use the cloud 9 ip.
export TF_VAR_remote_cloud_public_ip_cidr="$(curl http://169.254.169.254/latest/meta-data/public-ipv4)/32" # The cloud 9 IP to provision with.
export TF_VAR_remote_cloud_private_ip_cidr="$(curl http://169.254.169.254/latest/meta-data/local-ipv4)/32"
macid=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/)
export TF_VAR_vpc_id_main_cloud9=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/${macid}/vpc-id) # Aquire the cloud 9 instance's VPC ID to peer with Main VPC
export TF_VAR_cloud9_instance_name="$(aws ec2 describe-tags --filters Name=resource-id,Values=$TF_VAR_instance_id_main_cloud9 --out=json|jq '.Tags[]| select(.Key == "Name")|.Value' --raw-output)"
export TF_VAR_account_id=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep -oP '(?<="accountId" : ")[^"]*(?=")')
export TF_VAR_owner="$(aws s3api list-buckets --query Owner.DisplayName --output text)"
# region specific vars
export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
export TF_VAR_aws_internal_domain=$AWS_DEFAULT_REGION.compute.internal # used for FQDN resolution
export PKR_VAR_aws_internal_domain=$AWS_DEFAULT_REGION.compute.internal # used for FQDN resolution
export TF_VAR_aws_external_domain=$AWS_DEFAULT_REGION.compute.amazonaws.com

if [[ -z "$TF_VAR_resourcetier" ]]; then
  log_error "Could not read resourcetier tag from this instance.  Ensure you have set a tag with resourcetier."
  return
fi
export PKR_VAR_resourcetier="$TF_VAR_resourcetier"
export TF_VAR_pipelineid="0" # Uniquely name and tag the resources produced by a CI pipeline
export TF_VAR_conflictkey="${TF_VAR_resourcetier}${TF_VAR_pipelineid}" # The conflict key is a unique identifier for a deployment.
if [[ "$TF_VAR_resourcetier"=="dev" ]]; then
  export TF_VAR_environment="dev"
else
  export TF_VAR_environment="prod"
fi
export TF_VAR_firehawk_path=$SCRIPTDIR

# # Packer Vars
# if [[ -f "$SCRIPTDIR/modules/terraform-aws-vault/examples/vault-consul-ami/manifest.json" ]]; then
#     export PKR_VAR_vault_consul_ami="$(jq -r '.builds[] | select(.name == "ubuntu18-ami") | .artifact_id' $SCRIPTDIR/modules/terraform-aws-vault/examples/vault-consul-ami/manifest.json | tail -1 | cut -d ":" -f2)"
#     echo "Found vault_consul_ami in manifest: PKR_VAR_vault_consul_ami=$PKR_VAR_vault_consul_ami"
#     export TF_VAR_vault_consul_ami_id=$PKR_VAR_vault_consul_ami
# fi
export PACKER_LOG=1
export PACKER_LOG_PATH="packerlog.log"
export TF_VAR_provisioner_iam_profile_name="provisioner_instance_role_$TF_VAR_conflictkey"
export PKR_VAR_provisioner_iam_profile_name="provisioner_instance_role_$TF_VAR_conflictkey"
export TF_VAR_packer_iam_profile_name="packer_instance_role_$TF_VAR_conflictkey"
export PKR_VAR_packer_iam_profile_name="packer_instance_role_$TF_VAR_conflictkey"

# Terraform Vars
export TF_VAR_general_use_ssh_key="$HOME/.ssh/id_rsa" # For debugging deployment of most resources- not for production use.
export TF_VAR_aws_private_key_path="$TF_VAR_general_use_ssh_key"

export TF_VAR_log_dir="$SCRIPTDIR/tmp/log"; mkdir -p $TF_VAR_log_dir

export VAULT_ADDR=https://vault.service.consul:8200 # verify dns before login with: dig vault.service.consul
export consul_cluster_tag_key="consul-servers" # These tags are used when new hosts join a consul cluster. 
export consul_cluster_tag_value="consul-$TF_VAR_resourcetier"
export TF_VAR_consul_cluster_tag_key="$consul_cluster_tag_key"
export PKR_VAR_consul_cluster_tag_key="$consul_cluster_tag_key"
export TF_VAR_consul_cluster_name="$consul_cluster_tag_value"
export PKR_VAR_consul_cluster_tag_value="$consul_cluster_tag_value"

get_parameters=$( aws ssm get-parameters --names \
    "/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_public_ip" \
    "/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_private_subnet_cidr" \
    "/firehawk/resourcetier/${TF_VAR_resourcetier}/global_bucket_extension" \
    "/firehawk/resourcetier/${TF_VAR_resourcetier}/combined_vpcs_cidr" \
    "/firehawk/resourcetier/${TF_VAR_resourcetier}/vpn_cidr" )

num_invalid=$(echo $get_parameters | jq '.InvalidParameters| length')

if [[ num_invalid -eq 0 ]]; then
  export TF_VAR_onsite_public_ip=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_public_ip\")|.Value" --raw-output)
  error_if_empty "SSM Parameter missing: onsite_public_ip" "$TF_VAR_onsite_public_ip"
  export TF_VAR_onsite_private_subnet_cidr=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_private_subnet_cidr\")|.Value" --raw-output)
  error_if_empty "SSM Parameter missing: onsite_private_subnet_cidr" "$TF_VAR_onsite_private_subnet_cidr"
  export TF_VAR_global_bucket_extension=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/global_bucket_extension\")|.Value" --raw-output)
  error_if_empty "SSM Parameter missing: global_bucket_extension" "$TF_VAR_global_bucket_extension"
  export TF_VAR_combined_vpcs_cidr=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/combined_vpcs_cidr\")|.Value" --raw-output)
  error_if_empty "SSM Parameter missing: combined_vpcs_cidr" "$TF_VAR_combined_vpcs_cidr"
  export TF_VAR_vpn_cidr=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/vpn_cidr\")|.Value" --raw-output)
  error_if_empty "SSM Parameter missing: vpn_cidr" "$TF_VAR_vpn_cidr"

  export TF_VAR_bucket_extension="$TF_VAR_resourcetier.$TF_VAR_global_bucket_extension"
  export TF_VAR_installers_bucket="software.$TF_VAR_resourcetier.$TF_VAR_global_bucket_extension" # All installers should be kept in the same bucket.  If a main account is present, packer builds should trigger from the main account.
  export TF_VAR_bucket_extension_vault="$TF_VAR_resourcetier.$TF_VAR_global_bucket_extension" # WARNING: if vault is deployed in a seperate tier for use, then this will probably need to become an SSM driven parameter from the template
  # export PKR_VAR_installers_bucket="$TF_VAR_installers_bucket"
else
  log_error "SSM parameters are not yet initialised.  You can init SSM parameters with the cloudformation template modules/cloudformation-cloud9-vault-iam/cloudformation_ssm_parameters_firehawk.yaml"
  return
fi

export TF_VAR_common_tags=$(jq -n -f "$SCRIPTDIR/common_tags.json" \
  --arg environment "$TF_VAR_environment" \
  --arg resourcetier "$TF_VAR_resourcetier" \
  --arg conflictkey "$TF_VAR_conflictkey" \
  --arg pipelineid "$TF_VAR_pipelineid" \
  --arg region "$AWS_DEFAULT_REGION" \
  --arg vpcname "$TF_VAR_vpcname" \
  --arg accountid "$TF_VAR_account_id" \
  --arg owner "$TF_VAR_owner" )

echo "TF_VAR_common_tags: $TF_VAR_common_tags"

log_info "Done sourcing vars."