#!/bin/bash

# List all launch templates
launch_templates=$(aws ec2 describe-launch-templates --query 'LaunchTemplates[*].LaunchTemplateId' --output text)

# Iterate over each launch template to get details
for lt_id in $launch_templates; do
    # Retrieve the default version of the launch template
    lt_info=$(aws ec2 describe-launch-template-versions --launch-template-id $lt_id --versions '$Default' --query 'LaunchTemplateVersions[*].LaunchTemplateData' --output text)

    # Extract AMI ID and Launch Template Name
    ami_id=$(echo "$lt_info" | grep 'ImageId' | cut -f2)
    lt_name=$(aws ec2 describe-launch-templates --launch-template-ids $lt_id --query 'LaunchTemplates[*].LaunchTemplateName' --output text)

    # Print the Launch Template ID, AMI ID, and Launch Template Name
    echo "Launch Template ID: $lt_id, AMI ID: $ami_id, Launch Template Name: $lt_name"
done
