#!/bin/bash

function print_usage {
  echo
  echo "Usage: ./delete-all-old-amis.sh [OPTIONS]"
  echo
  echo "This script can be used to delete old AMI's and snapshots. This script has been tested with AWS Cloudshell."
  echo
  echo "Options:"
  echo
  echo -e "  --days-old\t\t\tThis sets the minimum age in days to delete AMI's."
  echo -e "  --commit-hash-short-list\tThe AMI's with matching tags for commit_hash_short that are in this list."
  echo
  echo "Example:"
  echo
  echo "  ./delete-all-old-amis.sh"
  echo
  echo "Example:"
  echo
  echo "  ./delete-all-old-amis.sh --days-old 14"
  echo
  echo "Example:"
  echo
  echo "  ./delete-all-old-amis.sh --commit-hash-short-list 5d6447e,a0236d9,8f8bedc"  
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

function main {
    local -r days_old="$1"
    local -r commit_hash_short_list="$2"

    if [[ ! -z "$commit_hash_short_list" ]]; then
      aws ec2 describe-images --owners self --filters "Name=tag:commit_hash_short,Values=[$commit_hash_short_list]" --query "Images[*].{ImageId:ImageId,date:CreationDate,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId,commit_hash_short:[Tags[?Key=='commit_hash_short']][0][0].Value}" > /tmp/ami-delete.txt
      ami_delete=$(cat /tmp/ami-delete.txt)
      echo "ami_delete: $ami_delete"
      echo "WARNING: This script will delete ALL images in your account with tags matching commit_hash_short: $commit_hash_short_list"
    else
      latest_date=$(date  --date="$days_old days ago" +"%Y-%m-%d")
      aws ec2 describe-images --owners self --filters "Name=tag:packer_template,Values=[firehawk-ami,firehawk-base-ami]" --query "Images[?CreationDate<\`${latest_date}\`].{ImageId:ImageId,date:CreationDate,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId,commit_hash_short:[Tags[?Key=='commit_hash_short']][0][0].Value}" > /tmp/ami-delete.txt
      # # example to exclude based on data
      # aws ec2 describe-images --owners self --filters "Name=tag:packer_template,Values=[firehawk-ami,firehawk-base-ami]" --query "Images[*].{ImageId:ImageId,date:CreationDate,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId,commit_hash_short:[Tags[?Key=='commit_hash_short']][0][0].Value}" | jq 'del(.[] | select(.commit_hash_short == "MYCOMMITHASH"))'
      # aws ec2 describe-images --owners self --filters "Name=tag:packer_template,Values=[firehawk-ami,firehawk-base-ami]" --query "Images[*].{ImageId:ImageId,date:CreationDate,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId,commit_hash_short:[Tags[?Key=='commit_hash_short']][0][0].Value}" | jq 'del(.[] | ["MYCOMMITHASH","MYCOMMITHASH2"] as $in | select(.commit_hash_short == $in ))'
      # aws ec2 describe-images --owners self --filters "Name=tag:packer_template,Values=[firehawk-ami,firehawk-base-ami]" --query "Images[*].{ImageId:ImageId,date:CreationDate,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId,commit_hash_short:[Tags[?Key=='commit_hash_short']][0][0].Value}" | jq -c '.commit_hash_short - ["MYCOMMITHASH","71555a9"]'
      # -c '. - ["MYCOMMITHASH","71555a9"]'
      # jq 'del(.[] | select(.commit_hash_short == "MYCOMMITHASH"))'
      ami_delete=$(cat /tmp/ami-delete.txt)
      echo "ami_delete: $ami_delete"
      echo "WARNING: This script will delete ALL images in your account older than $days_old days"
    fi

    ami_delete_list=$(echo $ami_delete | jq -r '.[] | "\(.ImageId)"')
    # echo "ami_delete_list: $ami_delete_list"
    snap_delete_list=$(echo $ami_delete | jq -r '.[] | "\(.SnapshotId)"')
    # echo "snap_delete_list: $snap_delete_list"

    read -r -p "Are you sure you want to delete the above images?: [Y/n] " input

    echo "Selected: $input"

    case $input in
        [yY][eE][sS]|[yY])
        echo "Yes"
        ;;
        [nN][oO]|[nN])
        echo "No"
        exit 1
        ;;
        *)
        echo "Invalid input: $input"
        exit 1
        ;;
    esac

    echo "...Deleting images"
    # aws ec2 deregister-image --image-id $ami_delete_list
    for i in $ami_delete_list; do
        echo "Delete: $i"
        aws ec2 deregister-image --image-id $i
    done

    echo "...Deleting snapshots"
    for i in $snap_delete_list; do
        echo "Delete: $i"
        aws ec2 delete-snapshot --snapshot-id $i
    done
}

function options { # Not all defaults are available as args, however the script has been built to easily alter this.
  local days_old="7"
  local run="true"
  local commit_hash_short_list=""

  while [[ $# > 0 ]]; do
    local key="$1"
    case "$key" in
      --days-old)
        days_old="$2"
        shift
        ;;
      --commit-hash-short-list)
        commit_hash_short_list="$2"
        days_old="0"
        shift
        ;;
      --help)
        print_usage
        run="false"
        ;;
      *)
        log_error "Unrecognized argument: $key"
        print_usage
        run="false"
        ;;
    esac
    shift
  done
  if [[ "$run" == "true" ]]; then
    main "$days_old" "$commit_hash_short_list"
  fi
}

options "$@"