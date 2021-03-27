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


SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )" # The directory of this script

# # Region is required for AWS CLI
# export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/\(.*\)[a-z]/\1/')
# # Get the resourcetier from the instance tag.
# export TF_VAR_instance_id_main_cloud9=$(curl http://169.254.169.254/latest/meta-data/instance-id)
# export TF_VAR_resourcetier="$(aws ec2 describe-tags --filters Name=resource-id,Values=$TF_VAR_instance_id_main_cloud9 --out=json|jq '.Tags[]| select(.Key == "resourcetier")|.Value' --raw-output)" # Can be dev,green,blue,main.  it is pulled from this instance's tags by default
# export TF_VAR_resourcetier_vault="$TF_VAR_resourcetier" # WARNING: if vault is deployed in a seperate tier for use, then this will probably need to become an SSM driven parameter from the template

# # Instance and vpc data
# export TF_VAR_deployer_ip_cidr="$(curl http://169.254.169.254/latest/meta-data/public-ipv4)/32" # Initially there will be no remote ip onsite, so we use the cloud 9 ip.
# export TF_VAR_remote_cloud_public_ip_cidr="$(curl http://169.254.169.254/latest/meta-data/public-ipv4)/32" # The cloud 9 IP to provision with.
# export TF_VAR_remote_cloud_private_ip_cidr="$(curl http://169.254.169.254/latest/meta-data/local-ipv4)/32"
# macid=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/)
# export TF_VAR_vpc_id_main_cloud9=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/${macid}/vpc-id) # Aquire the cloud 9 instance's VPC ID to peer with Main VPC
# export TF_VAR_cloud9_instance_name="$(aws ec2 describe-tags --filters Name=resource-id,Values=$TF_VAR_instance_id_main_cloud9 --out=json|jq '.Tags[]| select(.Key == "Name")|.Value' --raw-output)"
# export TF_VAR_account_id=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep -oP '(?<="accountId" : ")[^"]*(?=")')
# export TF_VAR_owner="$(aws s3api list-buckets --query Owner.DisplayName --output text)"
# # region specific vars
# export PKR_VAR_aws_region="$AWS_DEFAULT_REGION"
# export TF_VAR_aws_internal_domain=$AWS_DEFAULT_REGION.compute.internal # used for FQDN resolution
# export PKR_VAR_aws_internal_domain=$AWS_DEFAULT_REGION.compute.internal # used for FQDN resolution
# export TF_VAR_aws_external_domain=$AWS_DEFAULT_REGION.compute.amazonaws.com

# if [[ -z "$TF_VAR_resourcetier" ]]; then
#   log_error "Could not read resourcetier tag from this instance.  Ensure you have set a tag with resourcetier."
#   return
# fi
# export PKR_VAR_resourcetier="$TF_VAR_resourcetier"
# export TF_VAR_pipelineid="0" # Uniquely name and tag the resources produced by a CI pipeline
# export TF_VAR_conflictkey="${TF_VAR_resourcetier}${TF_VAR_pipelineid}" # The conflict key is a unique identifier for a deployment.
# if [[ "$TF_VAR_resourcetier"=="dev" ]]; then
#   export TF_VAR_environment="dev"
# else
#   export TF_VAR_environment="prod"
# fi
# export TF_VAR_firehawk_path="$SCRIPTDIR/deploy/firehawk-main"

# # Packer Vars

# export PACKER_LOG=1
# export PACKER_LOG_PATH="packerlog.log"
# export TF_VAR_provisioner_iam_profile_name="provisioner_instance_role_$TF_VAR_conflictkey"
# export PKR_VAR_provisioner_iam_profile_name="provisioner_instance_role_$TF_VAR_conflictkey"
# export TF_VAR_packer_iam_profile_name="packer_instance_role_$TF_VAR_conflictkey"
# export PKR_VAR_packer_iam_profile_name="packer_instance_role_$TF_VAR_conflictkey"

# # Terraform Vars
# export TF_VAR_general_use_ssh_key="$HOME/.ssh/id_rsa" # For debugging deployment of most resources- not for production use.
# export TF_VAR_aws_private_key_path="$TF_VAR_general_use_ssh_key"

# # SSH Public Key is used for debugging instances only.  Not for general use.  Use SSH Certificates instead.
# export TF_VAR_aws_key_name="cloud9_$TF_VAR_cloud9_instance_name"
# public_key_path="$HOME/.ssh/id_rsa.pub"
# if [[ ! -f $public_key_path ]] ; then
#     echo "File $public_key_path is not there, aborting. Ensure you have initialised a keypair with ssh-keygen.  This should occur automatically when you deploy init/"
#     return
# fi
# export TF_VAR_vault_public_key=$(cat $public_key_path)

# export TF_VAR_log_dir="$SCRIPTDIR/tmp/log"; mkdir -p $TF_VAR_log_dir

# export VAULT_ADDR=https://vault.service.consul:8200 # verify dns before login with: dig vault.service.consul
# export consul_cluster_tag_key="consul-servers" # These tags are used when new hosts join a consul cluster. 
# export consul_cluster_tag_value="consul-$TF_VAR_resourcetier"
# export TF_VAR_consul_cluster_tag_key="$consul_cluster_tag_key"
# export PKR_VAR_consul_cluster_tag_key="$consul_cluster_tag_key"
# export TF_VAR_consul_cluster_name="$consul_cluster_tag_value"
# export PKR_VAR_consul_cluster_tag_value="$consul_cluster_tag_value"

# # Retrieve SSM parameters set by cloudformation
# get_parameters=$( aws ssm get-parameters --names \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_public_ip" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/organization_name" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/validity_period_hours" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_private_subnet_cidr" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/global_bucket_extension" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/combined_vpcs_cidr" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/vpn_cidr" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/houdini_license_server_address" \
#     "/firehawk/resourcetier/${TF_VAR_resourcetier}/sesi_client_id" )

# num_invalid=$(echo $get_parameters | jq '.InvalidParameters| length')
# if [[ $num_invalid -eq 0 ]]; then
#   export TF_VAR_onsite_public_ip=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_public_ip\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: onsite_public_ip" "$TF_VAR_onsite_public_ip"
#   export TF_VAR_organization_name=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/organization_name\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: organization_name" "$TF_VAR_organization_name"
#   export TF_VAR_validity_period_hours=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/validity_period_hours\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: validity_period_hours" "$TF_VAR_validity_period_hours"
#   export TF_VAR_onsite_private_subnet_cidr=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/onsite_private_subnet_cidr\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: onsite_private_subnet_cidr" "$TF_VAR_onsite_private_subnet_cidr"
#   export TF_VAR_global_bucket_extension=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/global_bucket_extension\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: global_bucket_extension" "$TF_VAR_global_bucket_extension"
#   export TF_VAR_combined_vpcs_cidr=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/combined_vpcs_cidr\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: combined_vpcs_cidr" "$TF_VAR_combined_vpcs_cidr"
#   export TF_VAR_vpn_cidr=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/vpn_cidr\")|.Value" --raw-output)
#   error_if_empty "SSM Parameter missing: vpn_cidr" "$TF_VAR_vpn_cidr"

#   export TF_VAR_ca_common_name="$TF_VAR_organization_name CA Cert"
#   export TF_VAR_common_name="$TF_VAR_organization_name Cert"

#   export TF_VAR_houdini_license_server_address=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/houdini_license_server_address\")|.Value" --raw-output)
#   export PKR_VAR_houdini_license_server_address="$TF_VAR_houdini_license_server_address"
#   error_if_empty "SSM Parameter missing: houdini_license_server_address" "$TF_VAR_houdini_license_server_address"
#   export TF_VAR_sesi_client_id=$(echo $get_parameters | jq ".Parameters[]| select(.Name == \"/firehawk/resourcetier/${TF_VAR_resourcetier}/sesi_client_id\")|.Value" --raw-output)
#   export PKR_VAR_sesi_client_id="$TF_VAR_sesi_client_id"
#   error_if_empty "SSM Parameter missing: sesi_client_id" "$TF_VAR_sesi_client_id"
  
#   export TF_VAR_bucket_extension="$TF_VAR_resourcetier.$TF_VAR_global_bucket_extension"
#   export TF_VAR_installers_bucket="software.$TF_VAR_resourcetier.$TF_VAR_global_bucket_extension" # All installers should be kept in the same bucket.  If a main account is present, packer builds should trigger from the main account.
#   export TF_VAR_bucket_extension_vault="$TF_VAR_resourcetier.$TF_VAR_global_bucket_extension" # WARNING: if vault is deployed in a seperate tier for use, then this will probably need to become an SSM driven parameter from the template 
#   # export PKR_VAR_installers_bucket="$TF_VAR_installers_bucket"
# else
#   log_error "SSM parameters are not yet initialised.  You can init SSM parameters with the cloudformation template modules/cloudformation-cloud9-vault-iam/cloudformation_ssm_parameters_firehawk.yaml"
#   return
# fi


# export TF_VAR_ca_public_key_file_path="/home/ec2-user/.ssh/tls/ca.crt.pem"
# if [[ -f "$TF_VAR_ca_public_key_file_path" ]]; then
#   export TF_VAR_SSL_expiry=$(cat "$TF_VAR_ca_public_key_file_path" | openssl x509 -noout -enddate | awk -F "=" '{print $2}')
#   export PKR_VAR_SSL_expiry="$TF_VAR_SSL_expiry"
#   echo "Current SSL Certificates will expire at: $TF_VAR_SSL_expiry"
# else
#   echo "Warning: No SSL Certifcates exist."
# fi

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

common_tags_path="$SCRIPTDIR/common_tags.json"
echo "read: $common_tags_path"
export TF_VAR_common_tags=$(jq -n -f "$common_tags_path" \
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