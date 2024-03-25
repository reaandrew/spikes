#!/bin/bash
export AWS_PAGER=""

# Define variables
LT_NAME="$1"  # Launch template name from the first script argument
LT_VERSION='$Latest'  # Example: use specific version number, or adjust as needed

# Find the latest AWS Linux 2 AMI ID
AMI_ID=$(aws ec2 describe-images --owners amazon --filters \
    "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
    "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)

# Retrieve the full configuration of the specified source version of the launch template
LT_DATA=$(aws ec2 describe-launch-template-versions --launch-template-name "$LT_NAME" --versions "$LT_VERSION" --query "LaunchTemplateVersions[0].LaunchTemplateData" --output json)

# Update the AMI ID in the retrieved launch template data
UPDATED_LT_DATA=$(echo $LT_DATA | jq --arg AMI_ID "$AMI_ID" '. + {ImageId: $AMI_ID}')

# Create a new launch template version with the updated AMI ID, preserving other configurations
aws ec2 create-launch-template-version --launch-template-name "$LT_NAME" --source-version "$LT_VERSION" --version-description "Update with latest AWS Linux 2 AMI" --launch-template-data "$UPDATED_LT_DATA"

# Optional: Update the default version to the new version
# Get the latest version number of the launch template
NEW_VERSION=$(aws ec2 describe-launch-templates --launch-template-names "$LT_NAME" --query "LaunchTemplates[0].LatestVersionNumber" --output text)

# Update the default version
aws ec2 modify-launch-template --launch-template-name "$LT_NAME" --default-version "$NEW_VERSION"
