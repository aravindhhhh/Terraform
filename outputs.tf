output "log_bucket_id" {
  description = "AWS S3 bucket for all AWS logs for this environment"
  value       = aws_s3_bucket.logs.id
}

output "vpc_id" {
  description = "Primary VPC ID"
  value       = aws_vpc.primary.id
}

output "nat_gateway_ips" {
  description = "NAT Gateway IP address(es)"
  value       = aws_nat_gateway.primary.public_ip
}

output "private_subnets" {
  description = "AWS Private Subnet IDs"
  value       = [aws_subnet.private.*.id]
}

output "private_route_tables" {
  description = "AWS Private Route Table IDs"
  value       = [aws_route_table.primary-private.*.id]
}

output "public_subnets" {
  description = "AWS Public Subnet IDs"
  value       = [aws_subnet.public.*.id]
}

output "public_route_tables" {
  description = "AWS Public Route Table IDs"
  value       = [aws_route_table.primary-public.*.id]
}

output "sg_alb_public" {
  description = "Security Group assigned to public-facing Application Load Balancers"
  value       = aws_security_group.alb_public.id
}

output "sg_ecs" {
  description = "Security Group assigned to ECS Services"
  value       = aws_security_group.ecs.id
}

output "sg_rds" {
  description = "Security Group assigned to RDS instances"
  value       = aws_security_group.rds.id
}

output "database_url" {
  description = "Postgres Database URL"
  # sensitive   = true
  value = format("postgres://%s:%s@%s/%s", aws_db_instance.primary.username, "password", aws_db_instance.primary.endpoint, aws_db_instance.primary.db_name)
}

output "app_bucket_name" {
  description = "Application S3 bucket name"
  value       = aws_s3_bucket.bucket.id
}

output "api_target_group_arn" {
  description = "ARN for the Target Group belonging to the ECS Web Service API"
  value       = aws_alb_target_group.api.arn
}

# output "admin_target_group_arn" {
#   description = "ARN for the Target Group belonging to the ECS Web Service Admin"
#   value       = aws_alb_target_group.admin.arn
# }

output "ecs_cluster_name" {
  description = "AWS ECS Cluster Name"
  value       = aws_ecs_cluster.primary.name
}

output "spa_bucket" {
  description = "AWS S3 bucket hosting the web application's files"
  value       = aws_s3_bucket.spa.id
}

output "cloudfront_distro_id" {
  description = "AWS Cloudfront Distribution ID that fronts the web application S3 bucket"
  value       = aws_cloudfront_distribution.spa.id
}

output "github_role_name" {
  description = "AWS IAM Role for Github Actions"
  value       = aws_iam_role.github_actions.name
}

output "github_role_arn" {
  description = "AWS IAM Role ARN for Github Actions"
  value       = aws_iam_role.github_actions.arn
}

output "ecs_execution_role_name" {
  description = "AWS IAM Role for ECS executions"
  value       = aws_iam_role.ecs_execution.name
}

output "ecs_execution_role_arn" {
  description = "AWS IAM Role for ECS executions"
  value       = aws_iam_role.ecs_execution.arn
}

output "ecs_service_role_name" {
  description = "AWS IAM Role for ECS services"
  value       = aws_iam_role.ecs_service.name
}

output "ecs_service_role_arn" {
  description = "AWS IAM Role for ECS executions"
  value       = aws_iam_role.ecs_service.arn
}

output "plaform_service_role_name" {
  description = "AWS IAM Role for ECS services"
  value       = aws_iam_role.platform_service.name
}

output "plaform_service_role_arn" {
  description = "AWS IAM Role for ECS executions"
  value       = aws_iam_role.platform_service.arn
}

output "api_fqdn" {
  description = "API GraphQL Domain Name"
  value       = aws_route53_record.api.fqdn
}

output "app_fqdn" {
  description = "App Domain Name"
  value       = aws_route53_record.app["A"].fqdn
}

output "vpn_endpoint_id" {
  value = aws_ec2_client_vpn_endpoint.main.id
}

output "vpn_endpoint_dns" {
  value = aws_ec2_client_vpn_endpoint.main.dns_name
}
