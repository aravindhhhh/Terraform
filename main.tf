### @note GITHUB ROLE ###
resource "aws_iam_openid_connect_provider" "github" {
  url  = "https://github.com/.well-known/openid-configuration"  # Replace with your IdP's discovery URL
client_id_list = ["682584168980-k71l505ej3lu832gra6e6ubrk618isqg.apps.googleusercontent.com"] 
thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

resource "aws_iam_role" "github_actions" {
  name               = "${var.project}-${terraform.workspace}-github-actions"
  assume_role_policy = data.aws_iam_policy_document.github_grant.json
  description        = "${var.project} Github Actions Role"
}

resource "aws_iam_role_policy" "github_actions" {
  name   = "${var.project}-${terraform.workspace}-ecs-execution-policy"
  role   = aws_iam_role.github_actions.id
  policy = data.aws_iam_policy_document.github_actions.json
}

# @RichardOrnelas: todo - Tighten this up
data "aws_iam_policy_document" "github_actions" {
  statement {
    actions = [
      "*"
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "github_grant" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"

      values = [
        "sts.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "lambda_edge_role" {
  name               = "${terraform.workspace}-lambda-edge-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_edge_grant.json
  description        = "${var.project} Lambda Edge Role"
}

resource "aws_iam_role_policy" "lambda_edge_policy" {
  name   = "${terraform.workspace}-lambda-edge-policy"
  role   = aws_iam_role.lambda_edge_role.name
  policy = data.aws_iam_policy_document.lambda_edge_policy.json
}

# TODO: do the actual tighter policy
data "aws_iam_policy_document" "lambda_edge_policy" {
  statement {
    actions = [
      "*"
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "lambda_edge_grant" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com",
        "edgelambda.amazonaws.com"
      ]
    }
  }
}


### @note S3 Buckets ###
resource "aws_s3_bucket" "bucket" {
  bucket = "tf-${var.project}-${terraform.workspace}-app"
}

resource "aws_s3_bucket" "logs" {
  bucket = "${var.project}-logs-${terraform.workspace}"
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json
}

data "aws_iam_policy_document" "logs" {
  statement {

    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.project}-logs-${terraform.workspace}/*",
      "arn:aws:s3:::${var.project}-logs-${terraform.workspace}"
    ]
    principals {
      type = "Service"
      identifiers = [
        "delivery.logs.amazonaws.com",
        "logdelivery.elasticloadbalancing.amazonaws.com"
      ]
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  depends_on = [aws_s3_bucket_ownership_controls.logs]

  bucket = aws_s3_bucket.logs.id
  acl    = "private"
}

### @note VPC ###
resource "aws_vpc" "primary" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project}-${terraform.workspace}"
  }
}

### @note PUBLIC NETWORK ###

resource "aws_internet_gateway" "primary" {
  vpc_id = aws_vpc.primary.id

  tags = {
    Name    = "${var.project}"
    Network = "public"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.primary.id
  cidr_block              = cidrsubnet(aws_vpc.primary.cidr_block, 6, count.index + 40)
  availability_zone       = local.availability_zones[count.index]
  count                   = local.az_count
  map_public_ip_on_launch = true

  tags = {
    Name             = "public-${local.availability_zones[count.index]}"
    Network          = "public"
    Access           = "public"
    AvailabilityZone = local.availability_zones[count.index]
  }
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = aws_route_table.primary-public.id
}

resource "aws_route_table" "primary-public" {
  vpc_id = aws_vpc.primary.id

  tags = {
    Name    = "primary-public"
    Network = "public"
    Access  = "public"
  }
}

resource "aws_route" "primary_internet_public" {
  depends_on             = [aws_route_table.primary-public]
  route_table_id         = aws_route_table.primary-public.id
  gateway_id             = aws_internet_gateway.primary.id
  destination_cidr_block = "0.0.0.0/0"
}

### @note PRIVATE NETWORK ###

resource "aws_nat_gateway" "primary" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name    = "nat-${var.project}"
    Network = "public"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name    = "nat-${var.project}"
    Network = "public"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.primary.id
  cidr_block        = cidrsubnet(aws_vpc.primary.cidr_block, 6, count.index + 20)
  availability_zone = local.availability_zones[count.index]
  count             = local.az_count
  # map_private_ip_on_launch = true

  tags = {
    Name             = "private-${local.availability_zones[count.index]}"
    Network          = "private"
    Access           = "private"
    AvailabilityZone = local.availability_zones[count.index]
  }
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = element(aws_subnet.private.*.id, count.index)
  route_table_id = aws_route_table.primary-private.id
}

resource "aws_route_table" "primary-private" {
  vpc_id = aws_vpc.primary.id

  tags = {
    Name    = "private"
    Network = "private"
    Access  = "private"
  }
}

resource "aws_route" "primary_nat_private" {
  depends_on             = [aws_route_table.primary-private]
  route_table_id         = aws_route_table.primary-private.id
  nat_gateway_id         = aws_nat_gateway.primary.id
  destination_cidr_block = "0.0.0.0/0"
}

### @note VPC Endpoints ###
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.primary.id
  service_name = "com.amazonaws.${var.region}.s3"
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = aws_vpc.primary.id
  service_name = "com.amazonaws.${var.region}.dynamodb"
}

### @note Security Groups ###
resource "aws_security_group" "vpn" {
  name        = "vpn-${terraform.workspace}"
  description = "Incoming VPN Traffic"
  vpc_id      = aws_vpc.primary.id
}

resource "aws_security_group_rule" "vpn" {
  security_group_id = aws_security_group.vpn.id
  type              = "ingress"
  from_port         = 0
  to_port           = 65000
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow public network traffic over HTTPS"
}

resource "aws_security_group" "alb_public" {
  name        = "alb-public-${terraform.workspace}"
  description = "Allow public internet traffic to load balancer"
  vpc_id      = aws_vpc.primary.id
}

resource "aws_security_group_rule" "alb_public_80_platform" {
  security_group_id = aws_security_group.alb_public.id
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = var.whitelist_enabled ? local.ip_whitelist : ["0.0.0.0/0"]
  description       = "Allow public network traffic over HTTP"
}

resource "aws_security_group_rule" "alb_public_443_platform" {
  security_group_id = aws_security_group.alb_public.id
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.whitelist_enabled ? local.ip_whitelist : ["0.0.0.0/0"]
  description       = "Allow public network traffic over HTTP"
}

resource "aws_security_group_rule" "lb_ingress_cloudfront" {
  description       = "HTTPS from CloudFront"
  security_group_id = aws_security_group.alb_public.id
  type              = "ingress"
  from_port         = 80
  to_port           = 443
  protocol          = "tcp"
  prefix_list_ids   = [data.aws_ec2_managed_prefix_list.cloudfront.id]
}

resource "aws_security_group" "ecs" {
  name        = "ecs-access-${terraform.workspace}"
  description = "ecs and ec2 sg"
  vpc_id      = aws_vpc.primary.id
}

resource "aws_security_group_rule" "ecs_self" {
  security_group_id = aws_security_group.ecs.id
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  self              = true
  description       = "Allow private network traffic from itself over all ports"
}

resource "aws_security_group_rule" "ecs_sg_https" {

  security_group_id        = aws_security_group.ecs.id
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb_public.id
  description              = "Allow private network traffic from JMJ security groups over HTTPS"
}

resource "aws_security_group_rule" "ecs_sg_http" {

  security_group_id        = aws_security_group.ecs.id
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb_public.id
  description              = "Allow private network traffic from JMJ security groups over HTTP"
}

resource "aws_security_group_rule" "ecs_sg_http2" {

  security_group_id        = aws_security_group.ecs.id
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb_public.id
  description              = "Allow private network traffic from JMJ security groups over HTTP"
}

resource "aws_security_group" "rds" {
  name        = "rds-access-${terraform.workspace}"
  description = "ECS RDS Instance Access"
  vpc_id      = aws_vpc.primary.id
}

resource "aws_security_group_rule" "rds_postgres_ecs" {
  security_group_id        = aws_security_group.rds.id
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  description              = "Allow postgres traffic from ECS cluster"
}

resource "aws_security_group_rule" "rds_postgres_vpn" {
  security_group_id        = aws_security_group.rds.id
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpn.id
  description              = "Allow postgres traffic from ECS cluster"
}

locals {
  security_groups = [
    aws_security_group.alb_public.id,
    aws_security_group.ecs.id,
    aws_security_group.rds.id,
    aws_security_group.vpn.id
  ]
}

resource "aws_security_group_rule" "egress" {
  count = length(local.security_groups)

  security_group_id = element(local.security_groups, count.index)
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow outbound internet"
}

### @note RDS PostGres DB ###

### RDS ###
resource "aws_db_subnet_group" "ecs" {
  name        = "db-subnets-${terraform.workspace}"
  subnet_ids  = aws_subnet.private[*].id
  description = "RDS Subnets - ${terraform.workspace}"
}

resource "random_password" "rds_password" {
  length  = 32
  special = false
  lower   = true
  numeric = true
  upper   = true
  keepers = {
    # If you want to rotate the password, then just change this value
    "last-updated" = "2023-06-10"
  }
}

resource "aws_db_instance" "primary" {

  allocated_storage                     = 20
  storage_type                          = "gp2"
  engine                                = "postgres"
  engine_version                        = var.db_postgres_version
  instance_class                        = var.db_instance_class
  db_name                               = var.project
  identifier                            = "${var.project}-${terraform.workspace}"
  username                              = var.project
  password                              = random_password.rds_password.result
  port                                  = 5432
  parameter_group_name                  = var.db_parameter_group
  vpc_security_group_ids                = [aws_security_group.rds.id]
  db_subnet_group_name                  = aws_db_subnet_group.ecs.name
  backup_retention_period               = 7
  auto_minor_version_upgrade            = true
  apply_immediately                     = true
  copy_tags_to_snapshot                 = true
  skip_final_snapshot                   = terraform.workspace == "production" ? false : true
  final_snapshot_identifier             = "${var.project}-${terraform.workspace}-final"
  storage_encrypted                     = true
  multi_az                              = terraform.workspace == "production" ? true : false
  performance_insights_enabled          = terraform.workspace == "production" ? true : false
  deletion_protection                   = terraform.workspace == "production" ? false : false
  performance_insights_retention_period = terraform.workspace == "production" ? 7 : 0
}
### RDS ###

# Burst Balance (Percent)
# The percent of General Purpose SSD (gp2) burst-bucket I/O credits available.
resource "aws_cloudwatch_metric_alarm" "rds_burst_balance" {
  depends_on = [aws_db_instance.primary]

  alarm_name                = "${terraform.workspace}-rds-burst-balance"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "BurstBalance"
  namespace                 = "AWS/RDS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 50
  alarm_description         = "RDS percent of General Purpose SSD (gp2) burst-bucket I/O credits available"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Database = aws_db_instance.primary.identifier
  }
}

# Queue Depth (Count)
# The number of outstanding I/Os (read/write requests) waiting to access the disk.
resource "aws_cloudwatch_metric_alarm" "rds_queue_depth" {
  depends_on = [aws_db_instance.primary]

  alarm_name                = "${terraform.workspace}-rds-queue-depth"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "QueueDepth"
  namespace                 = "AWS/RDS"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 4
  alarm_description         = "The number of outstanding I/Os (read/write requests) waiting to access the disk"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Database = aws_db_instance.primary.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_utilization" {
  depends_on = [aws_db_instance.primary]

  alarm_name                = "${terraform.workspace}-rds-cpu-utilization"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/RDS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 50
  alarm_description         = "RDS CPU Utilization threshold"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Database = aws_db_instance.primary.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_free_storage_space" {
  depends_on = [aws_db_instance.primary]

  alarm_name                = "${terraform.workspace}-rds-free-storage-space"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "FreeStorageSpace"
  namespace                 = "AWS/RDS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = aws_db_instance.primary.allocated_storage * 0.20
  alarm_description         = "Free storage space left on the instance"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Database = aws_db_instance.primary.identifier
  }
}

# The average amount of time taken per disk I/O operation in seconds.
resource "aws_cloudwatch_metric_alarm" "rds_read_latency" {
  depends_on = [aws_db_instance.primary]

  alarm_name                = "${terraform.workspace}-rds-read-latency"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "ReadLatency"
  namespace                 = "AWS/RDS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 1
  alarm_description         = "Read latency in seconds"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Database = aws_db_instance.primary.identifier
  }
}

# The average amount of time taken per disk I/O operation in seconds.
resource "aws_cloudwatch_metric_alarm" "rds_write_latency" {
  depends_on = [aws_db_instance.primary]

  alarm_name                = "${terraform.workspace}-rds-write-latency"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "WriteLatency"
  namespace                 = "AWS/RDS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 1
  alarm_description         = "Write latency in seconds"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Database = aws_db_instance.primary.identifier
  }
}

### SQS ###

resource "aws_sqs_queue" "queue" {
  count                     = length(var.queues)
  name                      = "${var.project}_${terraform.workspace}_${element(var.queues, count.index)}"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 605000
  receive_wait_time_seconds = 20
  sqs_managed_sse_enabled   = true
  redrive_policy            = "{\"deadLetterTargetArn\":\"${element(aws_sqs_queue.queue_dead.*.arn, count.index)}\",\"maxReceiveCount\":2}"
}

resource "aws_sqs_queue" "queue_dead" {
  count                     = length(var.queues)
  name                      = "${var.project}_${terraform.workspace}_${element(var.queues, count.index)}_dead"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 345600
  receive_wait_time_seconds = 20
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue_policy" "queue" {
  lifecycle {
    ignore_changes = [
      policy
    ]
  }

  count     = length(var.queues)
  queue_url = element(aws_sqs_queue.queue.*.id, count.index)

  policy = element(data.aws_iam_policy_document.queue_policy.*.json, count.index)
}

data "aws_iam_policy_document" "queue_policy" {
  count = length(var.queues)
  statement {
    actions = [
      "sqs:SendMessage"
    ]
    resources = [element(aws_sqs_queue.queue.*.id, count.index)]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [element(aws_sqs_queue.queue.*.arn, count.index)]
    }
  }
}

# ### SNS Topics ###
resource "aws_sns_topic" "cloudwatch_alerts" {
  name = "${terraform.workspace}-alerts"
}

### @note: IAM ###

# ECS Execution
resource "aws_iam_role" "ecs_execution" {
  name               = "${var.project}-${terraform.workspace}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_execution_grant.json
  description        = "${var.project} ECS Task Execution Role"
}

resource "aws_iam_role_policy" "ecs_execution_policy" {
  name   = "${var.project}-${terraform.workspace}-ecs-execution-policy"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_policy.json
}

data "aws_iam_policy_document" "ecs_execution_policy" {
  statement {
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:Create*",
      "logs:Put*"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ssm:GetParameters",
      # "secretsmanager:GetSecretValue",
      "kms:Decrypt"
    ]
    resources = ["*"]
  }
}


data "aws_iam_policy_document" "ecs_execution_grant" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "ecs-tasks.amazonaws.com"
      ]
    }
  }
}

# ECS Service Role
resource "aws_iam_role" "ecs_service" {
  name               = "${var.project}-${terraform.workspace}-ecs-service"
  assume_role_policy = data.aws_iam_policy_document.ecs_service_grant.json

  description = "${var.project} ECS Service Role"
}

resource "aws_iam_role_policy" "ecs_service" {
  name   = "${var.project}-${terraform.workspace}-ecs-service-policy"
  role   = aws_iam_role.ecs_service.id
  policy = data.aws_iam_policy_document.ecs_service_policy.json
}

data "aws_iam_policy_document" "ecs_service_grant" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ecs_service_policy" {

  statement {
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:Describe*"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:RegisterTargets"
    ]
    resources = ["*"]
  }

  statement {
    sid = "ECSTaskManagement"
    actions = [
      "ec2:AttachNetworkInterface",
      "ec2:CreateNetworkInterface",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
      "ec2:DeleteNetworkInterfacePermission",
      "ec2:Describe*",
      "ec2:DetachNetworkInterface",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:RegisterTargets",
      "route53:ChangeResourceRecordSets",
      "route53:CreateHealthCheck",
      "route53:DeleteHealthCheck",
      "route53:Get*",
      "route53:List*",
      "route53:UpdateHealthCheck",
      "servicediscovery:DeregisterInstance",
      "servicediscovery:Get*",
      "servicediscovery:List*",
      "servicediscovery:RegisterInstance",
      "servicediscovery:UpdateInstanceCustomHealthStatus"
    ]
    resources = ["*"]
  }

  statement {
    sid = "ECSTagging"
    actions = [
      "ec2:CreateTags",
    ]
    resources = ["arn:aws:ec2:*:*:network-interface/*"]
  }
}


### Task Role ###
# @RichardOrnelas: todo - Tighten this up
resource "aws_iam_role" "platform_service" {
  name               = "tf-${var.project}-${terraform.workspace}"
  assume_role_policy = data.aws_iam_policy_document.grant.json
}

resource "aws_iam_role_policy" "platform_service_policy" {
  name   = "${var.project}-${terraform.workspace}-service-policy"
  role   = aws_iam_role.platform_service.id
  policy = data.aws_iam_policy_document.platform_service.json
}

data "aws_iam_policy_document" "platform_service" {

  statement {
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:ChangeMessageVisibilityBatch",
      "sqs:DeleteMessage",
      "sqs:DeleteMessageBatch",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
      "sqs:SendMessage",
      "sqs:SendMessageBatch",
      "sqs:ListQueues"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecs:*",
    ]
    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "iam:PassRole",
    ]
    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "ec2:Describe*"
    ]
    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "sns:*",
      "cognito-identity:*",
      "cognito-idp:*"
    ]
    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "*"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "s3:Put*",
      "s3:Get*",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.bucket.arn,
      "${aws_s3_bucket.bucket.arn}/*"
    ]
  }
}

data "aws_iam_policy_document" "grant" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "ecs-tasks.amazonaws.com"
      ]
    }
  }
}

### @note ECR ###
resource "aws_ecr_repository" "primary" {
  count                = terraform.workspace == "staging" ? 1 : 0
  name                 = var.project
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

data "aws_iam_policy_document" "ecr_policy" {
  statement {
    sid    = "new policy"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    actions = [
      "ecr:*",
    ]
  }
}

resource "aws_ecr_repository_policy" "ecr_policy" {
  depends_on = [aws_ecr_repository.primary]

  count      = terraform.workspace == "staging" ? 1 : 0
  repository = aws_ecr_repository.primary[0].name
  policy     = data.aws_iam_policy_document.ecr_policy.json
}

# @RichardOrnelas: todo - Fix this so that it works
# resource "aws_ecr_lifecycle_policy" "ecr_lifecycle" {
#   depends_on = [aws_ecr_repository.primary]

#   count      = terraform.workspace == "production" ? 1 : 0
#   repository = aws_ecr_repository.primary[0].name

#   policy = <<EOF
# {
#     "rules": [
#         {
#             "rulePriority": 1,
#             "description": "Keep last 25 images",
#             "selection": {
#                 "tagStatus": "tagged",
#                 "tagPrefixList": ["v"],
#                 "countType": "imageCountMoreThan",
#                 "countNumber": 25
#             },
#             "action": {
#                 "type": "expire"
#             }
#         },
#         {
#             "rulePriority": 5,
#             "description": "Delete after 45 days",
#             "selection": {
#                 "tagStatus": "any",
#                 "countType": "sinceImagePushed",
#                 "countNumber": 45
#             },
#             "action": {
#                 "type": "expire"
#             }
#         }
#     ]
# }
# EOF
# }


### @note: ECS ###
resource "aws_ecs_cluster" "primary" {
  name = terraform.workspace
}

resource "aws_ecs_cluster_capacity_providers" "primary" {
  cluster_name = aws_ecs_cluster.primary.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

### Application Load Balancer ###

resource "aws_alb" "web" {
  name                       = "${var.project}-${terraform.workspace}"
  internal                   = false
  security_groups            = [aws_security_group.alb_public.id]
  subnets                    = aws_subnet.public[*].id
  enable_deletion_protection = terraform.workspace == "production" ? true : false

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "load_balancer"
    enabled = true
  }
}

resource "aws_alb_target_group" "api" {
  name        = "${var.project}-api-${terraform.workspace}-http"
  port        = "8080"
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.primary.id

  health_check {
    healthy_threshold   = 2
    path                = "/healthcheck"
    timeout             = 5
    unhealthy_threshold = 3
    interval            = 10
    matcher             = "200-399"
  }

  deregistration_delay = 30
}

# @RichardOrnelas: todo - Uncomment if want to run admin portal separate
# resource "aws_alb_target_group" "admin" {
#   name        = "${var.project}-admin-${terraform.workspace}-http"
#   port        = "8080"
#   protocol    = "HTTP"
#   target_type = "ip"
#   vpc_id      = aws_vpc.primary.id

#   health_check {
#     healthy_threshold   = 2
#     path                = "/healthcheck"
#     timeout             = 5
#     unhealthy_threshold = 3
#     interval            = 10
#     matcher             = "200-399"
#   }

#   deregistration_delay = 30
# }

resource "aws_alb_listener" "https" {
  load_balancer_arn = aws_alb.web.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.ssl.arn
  ssl_policy        = "ELBSecurityPolicy-2016-08"

  default_action {
    target_group_arn = aws_alb_target_group.api.arn
    type             = "forward"
  }

  lifecycle {
    ignore_changes = [
      # Ignore changes to tags, e.g. because a management agent
      # updates these based on some ruleset managed elsewhere.
      default_action
    ]
  }
}

resource "aws_lb_listener_rule" "api_rule" {
  listener_arn = aws_alb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.api.arn
  }

  condition {
    host_header {
      values = ["api.${local.domain}", "*.api.${local.domain}", "hive.${local.domain}", "*.hive.${local.domain}"]
    }
  }
}

# @RichardOrnelas: todo - Uncomment if want to run admin portal separate
# resource "aws_lb_listener_rule" "admin_rule" {
#   listener_arn = aws_alb_listener.https.arn
#   priority     = 5

#   action {
#     type             = "forward"
#     target_group_arn = aws_alb_target_group.admin.arn
#   }

#   condition {
#     host_header {
#       values = ["admin.${local.domain}", "*.admin.${local.domain}", "hive.${local.domain}", "*.hive.${local.domain}"]
#     }
#   }
# }

resource "aws_alb_listener" "http" {
  load_balancer_arn = aws_alb.web.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  lifecycle {
    ignore_changes = [
      # Ignore changes to tags, e.g. because a management agent
      # updates these based on some ruleset managed elsewhere.
      default_action
    ]
  }
}

# HealthyHostCount
resource "aws_cloudwatch_metric_alarm" "alb_healthy_host_count" {
  depends_on = [aws_alb.web, aws_alb_target_group.api]

  alarm_name                = "${terraform.workspace}-alb-healthy-host-count"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "HealthyHostCount"
  namespace                 = "AWS/ApplicationELB"
  period                    = 120
  statistic                 = "Minimum"
  threshold                 = terraform.workspace == "production" ? 1 : 0
  alarm_description         = "Healthy host count"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    LoadBalancer = aws_alb.web.id
    TargetGroup  = aws_alb_target_group.api.id
  }
}

# TargetResponseTime
resource "aws_cloudwatch_metric_alarm" "alb_target_response_time" {
  depends_on = [aws_alb.web, aws_alb_target_group.api]

  alarm_name                = "${terraform.workspace}-alb-target-response-time"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "TargetResponseTime"
  namespace                 = "AWS/ApplicationELB"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 2
  alarm_description         = "ALB target response time"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    LoadBalancer = aws_alb.web.id
    TargetGroup  = aws_alb_target_group.api.id
  }
}


resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  depends_on = [aws_ecs_cluster.primary]

  alarm_name                = "${terraform.workspace}-ecs-cpu-utilization"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/ECS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 95
  alarm_description         = "ECS CPU Utilization"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Cluster = aws_ecs_cluster.primary.name
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory" {
  depends_on = [aws_ecs_cluster.primary]

  alarm_name                = "${terraform.workspace}-ecs-memory-utilization"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "MemoryUtilization"
  namespace                 = "AWS/ECS"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 95
  alarm_description         = "ECS Memory Utilization"
  insufficient_data_actions = []
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions                = [aws_sns_topic.cloudwatch_alerts.arn]
  dimensions = {
    Cluster = aws_ecs_cluster.primary.name
  }
}

resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = join(".", compact(["api", local.domain]))
  type    = "A"

  alias {
    name                   = aws_alb.web.dns_name
    zone_id                = aws_alb.web.zone_id
    evaluate_target_health = false
  }
}

# @RichardOrnelas: todo - Uncomment if want to run admin portal separate
# resource "aws_route53_record" "admin" {
#   zone_id = data.aws_route53_zone.primary.zone_id
#   name    = join(".", compact(["admin", local.domain]))
#   type    = "A"

#   alias {
#     name                   = aws_alb.web.dns_name
#     zone_id                = aws_alb.web.zone_id
#     evaluate_target_health = false
#   }
# }

# @RichardOrnelas: todo - Uncomment when old infrastructure is deprecated
# resource "aws_route53_record" "hive" {
#   zone_id = data.aws_route53_zone.primary.zone_id
#   name    = join(".", compact(["hive", local.domain]))
#   type    = "A"

#   alias {
#     name                   = aws_alb.web.dns_name
#     zone_id                = aws_alb.web.zone_id
#     evaluate_target_health = false
#   }
# }

resource "aws_acm_certificate" "ssl" {
  domain_name               = "master.${local.domain}"
  subject_alternative_names = ["*.${local.domain}", "*.app.${local.domain}", "*.portal.${local.domain}", "*.hive.${local.domain}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "ssl" {
  certificate_arn         = aws_acm_certificate.ssl.arn
  validation_record_fqdns = [for record in aws_route53_record.cert : record.fqdn]
}

resource "aws_route53_record" "cert" {
  for_each = {
    for dvo in aws_acm_certificate.ssl.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.primary.zone_id
}

