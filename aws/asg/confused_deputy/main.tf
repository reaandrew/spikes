provider "aws" {
  region = "eu-west-2" # You can change this to your preferred AWS region
}

resource "aws_vpc" "example_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = "exampleVPC"
  }
}

resource "aws_subnet" "example_subnet" {
  vpc_id            = aws_vpc.example_vpc.id
  cidr_block        = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-west-2a" # Adjust the availability zone as needed

  tags = {
    Name = "exampleSubnet"
  }
}

resource "aws_internet_gateway" "example_igw" {
  vpc_id = aws_vpc.example_vpc.id

  tags = {
    Name = "exampleIGW"
  }
}

resource "aws_route_table" "example_rt" {
  vpc_id = aws_vpc.example_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.example_igw.id
  }

  tags = {
    Name = "exampleRouteTable"
  }
}

resource "aws_route_table_association" "example_rta" {
  subnet_id      = aws_subnet.example_subnet.id
  route_table_id = aws_route_table.example_rt.id
}

resource "aws_launch_template" "ubuntu_launch_template" {
  name_prefix   = "ubuntu-launch-template-"
  image_id      = "ami-0c8dea2b7a3adf9c8"
  instance_type = "t2.micro" # You can adjust the instance type based on your requirements

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "UbuntuInstance"
    }
  }
}

resource "aws_autoscaling_group" "ubuntu_asg" {
  launch_template {
    id      = aws_launch_template.ubuntu_launch_template.id
    version = "$Latest"
  }

  min_size         = 1
  max_size         = 3
  desired_capacity = 1

  vpc_zone_identifier = [aws_subnet.example_subnet.id]

  tag {
    key                 = "Name"
    value               = "UbuntuASGInstance"
    propagate_at_launch = true
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Effect = "Allow"
        Sid = ""
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "config_service_role" {
  name = "AWSConfigServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Effect = "Allow"
        Sid = ""
      },
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "LambdaEC2ConfigPermissions"
  description = "Allow Lambda to call ec2:DescribeImages and config:PutEvaluations"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "ec2:DescribeImages",
          "securityhub:BatchImportFindings",
          "autoscaling:SuspendProcesses",
          "ec2:TerminateInstances"
        ],
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

resource "aws_lambda_function" "compliance_lambda" {
  function_name = "ConfigRuleCheckAMI"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.8"
  role          = aws_iam_role.lambda_exec_role.arn
  filename      = data.archive_file.lambda_zip.output_path
  timeout = 30

  tags = {
    Name = "ConfigRuleCheckAMI"
  }

  # Add this line to include the source code hash
  source_code_hash = filebase64sha256(data.archive_file.lambda_zip.output_path)


  depends_on = [data.archive_file.lambda_zip]
}

resource "aws_cloudwatch_event_rule" "ec2_launch_rule" {
  name        = "ec2-instance-launch-rule"
  description = "Triggers on EC2 instance launch"

  event_pattern = jsonencode({
    "source" : ["aws.ec2"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["ec2.amazonaws.com"],
      "eventName" : ["RunInstances"]
    }
  })
}

resource "aws_cloudwatch_event_target" "invoke_lambda" {
  rule      = aws_cloudwatch_event_rule.ec2_launch_rule.name
  target_id = "InvokeLambdaFunction"
  arn       = aws_lambda_function.compliance_lambda.arn
}

resource "aws_lambda_permission" "allow_eventbridge_to_invoke" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_launch_rule.arn
}