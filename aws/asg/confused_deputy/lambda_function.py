import logging
from dataclasses import dataclass

import boto3
import json


@dataclass
class EventDetails:
    timestamp: str
    instance_id: str
    image_id: str
    account_id: str
    region: str
    auto_scaling_group_name: str


def send_invalid_ami_event_to_security_hub(event_details: EventDetails):
    securityhub = boto3.client('securityhub')
    finding = {
        'SchemaVersion': '2018-10-08',
        'Id': event_details.instance_id + '/compliance-check',
        'ProductArn': f'arn:aws:securityhub:{event_details.region}:{event_details.account_id}:product/{event_details.account_id}/default',
        'GeneratorId': 'custom-compliance-check',
        'AwsAccountId': f'{event_details.account_id}',
        'Types': ['Software and Configuration Checks/Industry and Regulatory Standards'],
        'CreatedAt': f'{event_details.timestamp}',
        'UpdatedAt': f'{event_details.timestamp}',
        'Severity': {'Label': 'HIGH'},  # Adjusted from 'WARNING' to a valid value
        'Title': 'EC2 Instance Non-Compliance with Company Standards',
        'Description': f'EC2 instance {event_details.instance_id} with AMI {event_details.image_id} is non-compliant and was terminated.',
        'Resources': [
            {
                'Type': 'AwsEc2Instance',
                'Id': event_details.instance_id,
                'Partition': 'aws',
                'Region': f'{event_details.region}',
                'Details': {
                    'AwsEc2Instance': {
                        'ImageId': event_details.image_id
                    },
                    'Other': {  # Add ASG information in the Other field
                        'AutoScalingGroupName': event_details.auto_scaling_group_name if event_details.auto_scaling_group_name else 'Not part of an ASG'
                    }
                }
            }
        ],
        'Compliance': {'Status': 'FAILED'},  # This was correct
        'RecordState': 'ACTIVE'
    }

    response = securityhub.batch_import_findings(Findings=[finding])
    print(response)
    return response


def lambda_handler(event, context):
    # Initialize EC2 client
    ec2_client = boto3.client('ec2')
    autoscaling_client = boto3.client('autoscaling')

    event_time = event['detail']['eventTime']
    account = event['account']
    region = event['region']

    # # Extract the invoking resource details from the AWS Config event
    for item in event['detail']['responseElements']['instancesSet']['items']:
        instance_id = item['instanceId']
        ami_id = item['imageId']
        tags = item['tagSet']['items']

        asg_name = None
        for tag in tags:
            if tag['key'] == 'aws:autoscaling:groupName':
                asg_name = tag['value']
                break

        # Check if the AMI is private
        ami_info = ec2_client.describe_images(ImageIds=[ami_id])
        ami_public = ami_info['Images'][0]['Public']

        if ami_public:
            if asg_name:
                try:
                    autoscaling_client.suspend_processes(
                        AutoScalingGroupName=asg_name
                    )
                    print(f"Suspended ASG: {asg_name}")
                except Exception as e:
                    print(f"Error suspending ASG {asg_name}: {str(e)}")

            try:
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                print(f"Terminating instance: {instance_id}")
            except Exception as e:
                print(f"Error terminating instance {instance_id}: {str(e)}")

            send_invalid_ami_event_to_security_hub(EventDetails(
                    timestamp=event_time,
                    instance_id=instance_id,
                    image_id=ami_id,
                    account_id=account,
                    region=region,
                    auto_scaling_group_name=asg_name
                ))

    return {
        'statusCode': 200,
        'body': json.dumps('Evaluation complete.')
    }
