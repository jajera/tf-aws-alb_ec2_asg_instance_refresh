variable "use_case" {
  default = "tf-aws-alb_ec2_asg_instance_refresh"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_resourcegroups_group" "example" {
  name        = "tf-rg-example-${random_string.suffix.result}"
  description = "Resource group for example resources"

  resource_query {
    query = <<JSON
    {
      "ResourceTypeFilters": [
        "AWS::AllSupported"
      ],
      "TagFilters": [
        {
          "Key": "Owner",
          "Values": ["John Ajera"]
        },
        {
          "Key": "UseCase",
          "Values": ["${var.use_case}"]
        }
      ]
    }
    JSON
  }

  tags = {
    Name    = "tf-rg-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_vpc" "example" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "tf-vpc-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "public1" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-southeast-1a"

  tags = {
    Name    = "tf-subnet-public1-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "public2" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = "10.0.3.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-southeast-1b"

  tags = {
    Name    = "tf-subnet-public2-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "public3" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = "10.0.5.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-southeast-1c"

  tags = {
    Name    = "tf-subnet-public3-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "private1" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "ap-southeast-1a"

  tags = {
    Name    = "tf-subnet-private1-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "private2" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = "10.0.4.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "ap-southeast-1b"

  tags = {
    Name    = "tf-subnet-private2-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "private3" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = "10.0.6.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "ap-southeast-1c"

  tags = {
    Name    = "tf-subnet-private3-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_internet_gateway" "example" {
  vpc_id = aws_vpc.example.id

  tags = {
    Name    = "tf-ig-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_eip" "example" {
  domain = "vpc"

  tags = {
    Name    = "tf-eip-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_nat_gateway" "example" {
  allocation_id = aws_eip.example.id
  subnet_id     = aws_subnet.public1.id

  depends_on = [
    aws_internet_gateway.example
  ]

  tags = {
    Name    = "tf-ngw-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.example.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.example.id
  }

  tags = {
    Name    = "tf-rt-public"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table" "private1" {
  vpc_id = aws_vpc.example.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.example.id
  }

  tags = {
    Name    = "tf-rt-private1"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table" "private2" {
  vpc_id = aws_vpc.example.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.example.id
  }

  tags = {
    Name    = "tf-rt-private2"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table" "private3" {
  vpc_id = aws_vpc.example.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.example.id
  }

  tags = {
    Name    = "tf-rt-private3"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table_association" "public1" {
  subnet_id      = aws_subnet.public1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.private1.id
  route_table_id = aws_route_table.private1.id
}

resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.private2.id
  route_table_id = aws_route_table.private2.id
}

resource "aws_route_table_association" "private3" {
  subnet_id      = aws_subnet.private3.id
  route_table_id = aws_route_table.private3.id
}

resource "aws_security_group" "http_alb" {
  name        = "tf-sg-example_http_alb-${random_string.suffix.result}"
  description = "Security group for example resources to allow alb access to http"
  vpc_id      = aws_vpc.example.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "tf-sg-example_http_alb-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_security_group" "http_ec2" {
  name        = "tf-sg-example_http_ec2-${random_string.suffix.result}"
  description = "Security group for example resources to allow access to http hosted in ec2"
  vpc_id      = aws_vpc.example.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.http_alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "tf-sg-example_http_ec2-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_lb" "example" {
  name                       = "tf-alb-example-${random_string.suffix.result}"
  internal                   = false
  load_balancer_type         = "application"
  enable_deletion_protection = false
  drop_invalid_header_fields = true
  idle_timeout               = 600

  security_groups = [
    aws_security_group.http_alb.id
  ]

  subnets = [
    aws_subnet.public1.id,
    aws_subnet.public2.id,
    aws_subnet.public3.id
  ]

  tags = {
    Name    = "tf-alb-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_lb_target_group" "example" {
  name        = "tf-alb-tg-example-${random_string.suffix.result}"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.example.id

  health_check {
    enabled             = true
    healthy_threshold   = 5
    unhealthy_threshold = 2
    path                = "/"
  }

  tags = {
    Name    = "tf-alb-tg-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }

  tags = {
    Name    = "tf-alb-listener-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

data "aws_ami" "amazon-linux-2" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }
}

resource "aws_launch_template" "example" {
  name_prefix   = "lt-example-"
  ebs_optimized = true
  image_id      = data.aws_ami.amazon-linux-2.image_id
  instance_type = "t3.micro"

  vpc_security_group_ids = [
    aws_security_group.http_ec2.id
  ]

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name    = "tf-lt-example-${random_string.suffix.result}"
      Owner   = "John Ajera"
      UseCase = var.use_case
    }
  }

  user_data = filebase64("${path.module}/external/webserver.sh")
}

resource "aws_autoscaling_group" "example" {
  desired_capacity = 3
  max_size         = 6
  min_size         = 1

  vpc_zone_identifier = [
    aws_subnet.private1.id,
    aws_subnet.private2.id,
    aws_subnet.private3.id
  ]

  target_group_arns = [
    aws_lb_target_group.example.arn
  ]

  launch_template {
    id      = aws_launch_template.example.id
    version = aws_launch_template.example.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 100
    }
  }

  tag {
    key                 = "AutoPatching"
    value               = "enable"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "tf-asg-example"
    propagate_at_launch = true
  }

  tag {
    key                 = "Owner"
    value               = "John Ajera"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "example" {
  name                   = "tf-autoscale-policy-example-${random_string.suffix.result}"
  scaling_adjustment     = 4
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.example.name
}

resource "aws_iam_role" "sfn" {
  name = "tf-iam-role-sfn-example-${random_string.suffix.result}"
  path = "/service-role/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Name    = "tf-iam-role-sfn-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_policy" "ssm_put" {
  name = "tf-iam-policy-ssm-put-example-${random_string.suffix.result}"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "ssm:PutParameter"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/*"
      }
    ]
  })

  tags = {
    Name    = "tf-iam-policy-ssm-put-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "ssm_put" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ssm_put.arn
}

# SSM_GetParameter
resource "aws_iam_policy" "ssm_get" {
  name = "tf-iam-policy-ssm-get-example-${random_string.suffix.result}"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "ssm:GetParameter"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:ssm:${data.aws_region.current.name}::parameter${data.aws_ssm_parameters_by_path.example.path}"
      }
    ]
  })

  tags = {
    Name    = "tf-iam-policy-ssm-get-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

# Cloudwatch Logs
resource "aws_iam_policy" "cw_log_grp" {
  name = "tf-iam-policy-cw-log-grp-example-${random_string.suffix.result}"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/tf-iam-role-sfn-example-${random_string.suffix.result}/*"
      }
    ]
  })

  tags = {
    Name    = "tf-iam-policy-cw-log-grp-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "cw_log_grp" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.cw_log_grp.arn
}

resource "aws_iam_policy" "ec2_get_launch_template_data" {
  name = "tf-iam-policy-ec2-get-launch-template-data-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action   = "ec2:GetLaunchTemplateData",
      Effect   = "Allow",
      Resource = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
    }]
  })

  tags = {
    Name    = "tf-iam-policy-ec2-get-launch-template-data-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "ec2_get_launch_template_data" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ec2_get_launch_template_data.arn
}

# EC2DescribeAutoScalingGroups
resource "aws_iam_policy" "autoscaling_describe_groups" {
  name = "tf-iam-policy-autoscaling-describe-groups-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "autoscaling:DescribeAutoScalingGroups",
      ],
      Effect   = "Allow",
      Resource = "*"
    }]
  })

  tags = {
    Name    = "tf-iam-policy-autoscaling-describe-groups-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "autoscaling_describe_groups" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.autoscaling_describe_groups.arn
}

# EC2DescribeLaunchTemplateVersions
resource "aws_iam_policy" "ec2_describe_launch_template_versions" {
  name = "tf-iam-policy-ec2-describe-launch-template-versions-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "ec2:DescribeLaunchTemplateVersions",
      ],
      Effect   = "Allow",
      Resource = "*"
    }]
  })

  tags = {
    Name    = "tf-iam-policy-ec2-describe-launch-template-versions-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "ec2_describe_launch_template_versions" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ec2_describe_launch_template_versions.arn
}

# EC2CreateLaunchTemplateVersion
resource "aws_iam_policy" "ec2_create_launch_template_version" {
  name = "tf-iam-policy-ec2-create-launch-template-version-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "ec2:CreateLaunchTemplateVersion",
      ],
      Effect   = "Allow",
      Resource = "*"
    }]
  })

  tags = {
    Name    = "tf-iam-policy-ec2-create-launch-template-version-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "ec2_create_launch_template_version" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ec2_create_launch_template_version.arn
}

# EC2ModifyLaunchTemplate
resource "aws_iam_policy" "ec2_modify_launch_template" {
  name = "tf-iam-policy-ec2-modify-launch-template-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "ec2:ModifyLaunchTemplate",
      ],
      Effect   = "Allow",
      Resource = "*"
    }]
  })

  tags = {
    Name    = "tf-iam-policy-ec2-modify-launch-template-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "ec2_modify_launch_template" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ec2_modify_launch_template.arn
}

# EC2DescribeTags
resource "aws_iam_policy" "ec2_describe_tags" {
  name = "tf-iam-policy-ec2-describe-tags-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "ec2:DescribeTags",
      ],
      Effect   = "Allow",
      Resource = "*"
    }]
  })

  tags = {
    Name    = "tf-iam-policy-ec2-describe-tags-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "ec2_describe_tags" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ec2_describe_tags.arn
}

# SNSPublish
resource "aws_iam_policy" "sns_publish" {
  name = "tf-sns-publish-example-${random_string.suffix.result}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "SNS:Publish",
      ],
      Effect   = "Allow",
      Resource = "*"
    }]
  })

  tags = {
    Name    = "tf-sns-publish-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "sns_publish" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.sns_publish.arn
}

resource "aws_sfn_state_machine" "example" {
  name     = "tf-sfn-state-machine-example-${random_string.suffix.result}"
  role_arn = aws_iam_role.sfn.arn
  type     = "EXPRESS"
  definition = jsonencode({
    "Comment" : "An AWS Step Functions state machine that includes the Launch Template creation",
    "StartAt" : "DescribeAutoScalingGroup",
    "States" : {
      "DescribeAutoScalingGroup" : {
        "Next" : "ExtractPatchingTag",
        "Parameters" : {
          "AutoScalingGroupNames" : [
            aws_autoscaling_group.example.id
          ]
        },
        "Resource" : "arn:aws:states:::aws-sdk:autoscaling:describeAutoScalingGroups",
        "ResultPath" : "$.AutoScalingGroupResult",
        "Type" : "Task"
      },
      "ExtractPatchingTag" : {
        "Next" : "IsAutoPatching"
        "Parameters" : {
          "ExtractPatchingTagResult.$" : "$.AutoScalingGroupResult.AutoScalingGroups[0].Tags[?(@.Key == 'AutoPatching')].Value"
        },
        "ResultPath" : "$.ExtractPatchingTag",
        "Type" : "Pass"
      },
      "IsAutoPatching" : {
        "Type" : "Choice",
        "Choices" : [
          {
            "Variable" : "$.ExtractPatchingTag.ExtractPatchingTagResult[0]",
            "StringEquals" : "disable",
            "Next" : "SkipPatching"
          }
        ],
        "Default" : "ReadAmiImageId"
      },
      "SkipPatching" : {
        "Type" : "Succeed",
        "Comment" : "The autoscaling group AutoPatching tag is set to disable."
      },
      "ReadAmiImageId" : {
        "Next" : "DescribeLaunchTemplateVersion",
        "Parameters" : {
          "Name" : "arn:aws:ssm:ap-southeast-1::parameter${data.aws_ssm_parameters_by_path.example.path}"
        },
        "Resource" : "arn:aws:states:::aws-sdk:ssm:getParameter",
        "ResultPath" : "$.ParameterResult",
        "Type" : "Task"
      },
      "DescribeLaunchTemplateVersion" : {
        "Next" : "IsLatestAmi",
        "Parameters" : {
          "LaunchTemplateId.$" : "$.AutoScalingGroupResult.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId",
          "Versions" : [
            "$Latest"
          ]
        },
        "Resource" : "arn:aws:states:::aws-sdk:ec2:describeLaunchTemplateVersions",
        "ResultPath" : "$.LaunchTemplateResult",
        "Type" : "Task"
      },
      "IsLatestAmi" : {
        "Type" : "Choice",
        "Choices" : [
          {
            "Variable" : "$.ParameterResult.Parameter.Value",
            "StringEqualsPath" : "$.LaunchTemplateResult.LaunchTemplateVersions[0].LaunchTemplateData.ImageId",
            "Next" : "SkipUpdate"
          }
        ],
        "Default" : "SendEmail"
      },
      "SendEmail" : {
        "Next" : "CreateLaunchTemplateVersion",
        "Parameters" : {
          "Message" : "your detailed message goes here.",
          "Subject" : "Updating $.AutoScalingGroupResult.AutoScalingGroups.AutoScalingGroupName EC2 Autoscaling Group with new release AMI ID $.ParameterResult.Parameter.Value",
          "TopicArn" : "${aws_sns_topic.example.arn}"
        },
        "Resource" : "arn:aws:states:::sns:publish",
        "ResultPath" : "$.SdkHttpMetadata",
        "Type" : "Task"
      },
      "CreateLaunchTemplateVersion" : {
        "Next" : "ModifyLaunchTemplate",
        "Parameters" : {
          "LaunchTemplateData" : {
            "ImageId.$" : "$.ParameterResult.Parameter.Value"
          },
          "LaunchTemplateId.$" : "$.AutoScalingGroupResult.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId",
          "SourceVersion.$" : "$.AutoScalingGroupResult.AutoScalingGroups[0].LaunchTemplate.Version"
        },
        "Resource" : "arn:aws:states:::aws-sdk:ec2:createLaunchTemplateVersion",
        "ResultPath" : "$.NewLaunchTemplateVersion",
        "Type" : "Task"
      },
      "ModifyLaunchTemplate" : {
        "End" : true,
        "Parameters" : {
          "DefaultVersion.$" : "States.Format('{}', $.NewLaunchTemplateVersion.LaunchTemplateVersion.VersionNumber)",
          "LaunchTemplateId.$" : "$.NewLaunchTemplateVersion.LaunchTemplateVersion.LaunchTemplateId"
        },
        "Resource" : "arn:aws:states:::aws-sdk:ec2:modifyLaunchTemplate",
        "ResultPath" : "$",
        "Type" : "Task"
      },
      "SkipUpdate" : {
        "Type" : "Succeed",
        "Comment" : "The autoscaling group is already using the latest image id."
      }
    }
  })

  logging_configuration {
    include_execution_data = true
    level                  = "ALL"
    log_destination        = "${aws_cloudwatch_log_group.sfn_logs.arn}:*"
  }

  tracing_configuration {
    enabled = false
  }

  depends_on = [
    aws_iam_role_policy_attachment.cw_log_grp
  ]

  tags = {
    Name    = "tf-sfn-state-machine-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_cloudwatch_log_group" "sfn_logs" {
  name              = "/aws/vendedlogs/states/example-${random_string.suffix.result}"
  retention_in_days = 30

  tags = {
    Name    = "tf-log-group-sfn-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role" "eventbridge_rule" {
  name = "tf-iam-role-eventbridge-rule-example-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Action : "sts:AssumeRole",
        Effect : "Allow",
        Principal : {
          Service : "events.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name    = "tf-iam-role-eventbridge-rule-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy" "eventbridge_rule" {
  name = "tf-iam-role-policy-eventbridge-rule-example-${random_string.suffix.result}"
  role = aws_iam_role.eventbridge_rule.id
  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Action : [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:GetParametersByPath"
        ],
        Effect : "Allow",
        Resource : "*"
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "example" {
  name     = "tf-cw-event-rule-example-${random_string.suffix.result}"
  role_arn = aws_iam_role.eventbridge_rule.arn

  event_pattern = jsonencode({
    source : ["aws.ssm"],
    "detail-type" : ["Parameter Store Change"],
    detail : {
      operation : ["Update"],
      name : ["/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"],
    }
  })

  tags = {
    Name    = "tf-cw-event-rule-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_cloudwatch_event_target" "example" {
  rule      = aws_cloudwatch_event_rule.example.name
  target_id = "SendToStepFunction"
  arn       = aws_sfn_state_machine.example.arn
  role_arn  = aws_iam_role.eventbridge.arn
}

data "aws_ssm_parameters_by_path" "example" {
  path = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
}

resource "aws_iam_role" "eventbridge" {
  name = "tf-iam-role-eventbridge-example-${random_string.suffix.result}"
  path = "/service-role/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Name    = "tf-iam-role-eventbridge-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

# StateMachine_StartExecution
data "aws_iam_policy_document" "eventbridge_invoke" {
  statement {
    effect = "Allow"
    actions = [
      "states:StartExecution"
    ]
    resources = [
      "arn:aws:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stateMachine:tf-sfn-state-machine-example-${random_string.suffix.result}"
    ]
  }
}

resource "aws_iam_policy" "eventbridge_invoke" {
  name   = "tf-iam-policy-eventbridge-invoke-example-${random_string.suffix.result}"
  policy = data.aws_iam_policy_document.eventbridge_invoke.json

  tags = {
    Name    = "tf-iam-policy-eventbridge-invoke-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "eventbridge_invoke" {
  role       = aws_iam_role.eventbridge.name
  policy_arn = aws_iam_policy.eventbridge_invoke.arn
}

resource "aws_iam_role_policy_attachment" "ssm_get" {
  role       = aws_iam_role.sfn.name
  policy_arn = aws_iam_policy.ssm_get.arn
}

resource "aws_sns_topic" "example" {
  name = "tf-topic-example-${random_string.suffix.result}"

  tags = {
    Name    = "tf-topic-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_sns_topic_subscription" "example" {
  topic_arn = aws_sns_topic.example.arn
  protocol  = "email"
  endpoint  = "jdcajera@gmail.com"

  confirmation_timeout_in_minutes = 0
}

output "config" {
  value = {
    lb_url = "http://${aws_lb.example.dns_name}"
    eip    = aws_eip.example.public_ip
  }
}
