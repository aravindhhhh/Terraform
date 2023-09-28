variable "project" {
  type        = string
  description = "Name of the project"
  default     = "hive"
}

variable "domain" {
  type        = string
  description = "Root Domain"
  default     = "jmjdev.me"
}

variable "region" {
  type        = string
  description = "AWS Region to deploy resources in"
  default     = "us-east-1"
}

variable "vpc_cidr_block" {
  type        = string
  description = "CIDR block for the created VPC."
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  type        = map(string)
  description = "List of availability zones in the region"
  default = {
    "us-east-1" = "us-east-1a,us-east-1b,us-east-1c"
  }
}

variable "whitelist_enabled" {
  type        = bool
  description = "Is the environment whitelist only access?"
  default     = false
}

variable "ip_whitelist" {
  type        = list(string)
  description = "IP Whitelist"
  default     = []
}

variable "db_postgres_version" {
  type        = string
  description = "Postgres database version"
  default     = "15.3"
}

variable "db_parameter_group" {
  type        = string
  description = "Postgres database parameter group name"
  default     = "default.postgres15"
}

variable "db_instance_class" {
  type        = string
  description = "Size and Class for the RDS Postgres instance"
  default     = "db.t3.micro"
}

variable "slack_webhook_url" {
  type        = string
  description = "Slack webhook URL for Cloudwatch Alert Notifications"
  default     = ""
}

variable "vpn_cidr" {
  type        = string
  description = "CIDR for the VPN Client"
  default     = "10.0.0.0/22"
}

variable "vpn_split_tunnel" {
  type        = bool
  description = "Whether VPN tunnel traffic is split or not"
  default     = false
}

variable "queues" {
  type        = list(string)
  description = "List of SQS Queue Names"

  default = [
    "main",
    "encompass",
  ]
}

variable "users" {

  description = "User list for VPN, Database Access, etc etc"
  default = {
    rr = {
      first_name = "ryan"
      last_name  = "robertson"
      email      = "rr@jmj.me"
    }

    vk = {
      first_name = "virgil"
      last_name  = "kyle"
      email      = "vk@jmj.me"
    }

    rich = {
      first_name = "rich"
      last_name  = "ornelas"
      email      = "rich@deepseas.dev"
    }

    travis = {
      first_name = "travis"
      last_name  = "tincher"
      email      = "trtincher12@gmail.com"
    }

    clayton = {
      first_name = "clayton"
      last_name  = "noyes"
      phone      = "claytonRnoyes@gmail.com"
    }

    chim = {
      first_name = "chim"
      last_name  = "k"
      email      = "chim@thebitcrew.dev"
    }

    arun = {
      first_name = "arun"
      last_name  = "shan"
      email      = "arun@thebitcrew.dev"
    }

    amandeep = {
      first_name = "amandeep"
      last_name  = "singh"
      phone      = "amandeep@thebitcrew.dev"
    }
  }
}

variable "auth_net_api_login_id" {
  type        = string
  description = "Application environment secret"
  default     = "4dAP2s9d"
}

variable "auth_net_transaction_key" {
  type        = string
  description = "Application environment secret"
  default     = "3un64YQB655mSkW5"
}

variable "encompass_client_password" {
  type        = string
  description = "Application environment secret"
  default     = "sdfhaod"
}

variable "encompass_client_secret" {
  type        = string
  description = "Application environment secret"
  default     = "0w3OQf*^80sNFbmUHai7@^wnAHbaKAb1K2I!wz1ElxsNwADkciuBtUvn4o6dEo^G"
}

variable "equifax_password" {
  type        = string
  description = "Application environment secret"
  default     = "nUAhHqisDVCI3Gws"
}

variable "equifax_username" {
  type        = string
  description = "Application environment secret"
  default     = "Eha48rWTez22c9MGnmRx65gSXd6jfWjG"
}

variable "google_client_id" {
  type        = string
  description = "Application environment secret"
  default     = "682584168980-k71l505ej3lu832gra6e6ubrk618isqg.apps.googleusercontent.com"
}

variable "google_client_secret" {
  type        = string
  description = "Application environment secret"
  default     = "npf2tV7h2QGq-S0R1FJE0dq8"
}

variable "hello_sign_api_key" {
  type        = string
  description = "Application environment secret"
  default     = "dad2c30984f8eeb0e140dd6dea41faf7597353a3ec3d661e86d2402feeef9cb7"
}

variable "hello_sign_client_id" {
  type        = string
  description = "Application environment secret"
  default     = "3b4a369da5a979a35fec9a12c6811e03"
}

variable "smtp_password" {
  type        = string
  description = "Application environment secret"
  default     = "BBuORtdrmrlMFij5F7Xo23pH0O03GoSU5xXPP2nq4G+X"
}

locals {
  availability_zones        = split(",", var.availability_zones[var.region])
  az_count                  = length(local.availability_zones)
  domain                    = join(".", compact([terraform.workspace == "production" ? "" : terraform.workspace, var.domain]))
  s3_cors_request_policy_id = data.aws_cloudfront_origin_request_policy.s3_origin.id
  hsts_max_age              = 365 * 24 * 3600
  build_cache_ttl           = 3600
  usernames                 = toset(keys(var.users))
  ip_whitelist              = setunion(var.ip_whitelist, ["${aws_nat_gateway.primary.public_ip}/32"])
}

data "aws_route53_zone" "primary" {
  name         = local.domain
  private_zone = false
}

data "aws_caller_identity" "current" {}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}
data "aws_cloudfront_origin_request_policy" "s3_origin" {
  name = "Managed-CORS-S3Origin"
}

data "aws_cloudfront_origin_request_policy" "all_cf" {
  name = "Managed-AllViewerAndCloudFrontHeaders-2022-06"
}

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}
