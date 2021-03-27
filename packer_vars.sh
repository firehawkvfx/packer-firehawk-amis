#!/bin/bash

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

# common_tags_path="$SCRIPTDIR/common_tags.json"
# echo "read: $common_tags_path"
# export TF_VAR_common_tags=$(jq -n -f "$common_tags_path" \
#   --arg environment "$TF_VAR_environment" \
#   --arg resourcetier "$TF_VAR_resourcetier" \
#   --arg conflictkey "$TF_VAR_conflictkey" \
#   --arg pipelineid "$TF_VAR_pipelineid" \
#   --arg region "$AWS_DEFAULT_REGION" \
#   --arg vpcname "$TF_VAR_vpcname" \
#   --arg accountid "$TF_VAR_account_id" \
#   --arg owner "$TF_VAR_owner" \
#   --arg sslexpiry "$TF_VAR_SSL_expiry" )

# echo "TF_VAR_common_tags: $TF_VAR_common_tags"

# log_info "Done sourcing vars."