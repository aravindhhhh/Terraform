resource "aws_ssm_parameter" "AWS_REGION" {

  name        = "/${terraform.workspace}/${var.project}/AWS_REGION"
  description = "Application Bucket for the Application"
  type        = "SecureString"
  value       = var.region
}

resource "aws_ssm_parameter" "APP_BUCKET" {

  name        = "/${terraform.workspace}/${var.project}/APP_BUCKET"
  description = "Application Bucket for the Application"
  type        = "SecureString"
  value       = aws_s3_bucket.bucket.id
}

resource "aws_ssm_parameter" "DATABASE_URL" {

  name        = "/${terraform.workspace}/${var.project}/DATABASE_URL"
  description = "Database URL for the application"
  type        = "SecureString"
  value       = format("postgres://%s:%s@%s/%s", aws_db_instance.primary.username, random_password.rds_password.result, aws_db_instance.primary.endpoint, aws_db_instance.primary.db_name)
}

resource "aws_ssm_parameter" "CLOUDFRONT_DISTRO_ID" {

  name        = "/${terraform.workspace}/${var.project}/CLOUDFRONT_DISTRO_ID"
  description = "Portal Cloudfront Distribution ID"
  type        = "SecureString"
  value       = aws_cloudfront_distribution.spa.id
}

resource "aws_ssm_parameter" "DEFAULT_QUEUE" {

  name        = "/${terraform.workspace}/${var.project}/DEFAULT_QUEUE"
  description = "Hive API Default Queue"
  type        = "SecureString"
  value       = aws_sqs_queue.queue[0].name
}

resource "aws_ssm_parameter" "ENCOMPASS_QUEUE" {

  name        = "/${terraform.workspace}/${var.project}/ENCOMPASS_QUEUE"
  description = "Hive API Encompass Queue"
  type        = "SecureString"
  value       = aws_sqs_queue.queue[1].name
}

resource "aws_ssm_parameter" "HIVE_URL" {

  name        = "/${terraform.workspace}/${var.project}/HIVE_URL"
  description = "Hive URL"
  type        = "SecureString"
  value       = aws_route53_record.api.fqdn
}



################# CALCULATED ######################
locals {
  hash_keys = [
    "ENCRYPTION_PRIMARY_KEY",
    "ENCRYPTION_DETERMINISTIC_KEY",
    "ENCRYPTION_KEY_DERIVATION_SALT",
    "HMAC_SECRET",
    "LOCKBOX_MASTER_KEY",
    "SECRET_KEY_BASE"
  ]
}

resource "random_id" "rails_key" {
  for_each    = toset(local.hash_keys)
  byte_length = 32
}

resource "aws_ssm_parameter" "rails_key" {
  for_each = toset(local.hash_keys)

  # lifecycle {
  #   ignore_changes = [value]
  # }

  name        = "/${terraform.workspace}/${var.project}/${each.key}"
  type        = "SecureString"
  description = "Generated Rails encryption key"
  value       = random_id.rails_key[each.key].b64_std
}

####### Actual Secrets ########

resource "aws_ssm_parameter" "AUTH_NET_API_LOGIN_ID" {
  name        = "/${terraform.workspace}/${var.project}/AUTH_NET_API_LOGIN_ID"
  type        = "SecureString"
  description = ""
  value       = var.auth_net_api_login_id
}

resource "aws_ssm_parameter" "AUTH_NET_TRANSACTION_KEY" {
  name        = "/${terraform.workspace}/${var.project}/AUTH_NET_TRANSACTION_KEY"
  type        = "SecureString"
  description = ""
  value       = var.auth_net_transaction_key
}

resource "aws_ssm_parameter" "ENCOMPASS_CLIENT_PASSWORD" {
  name        = "/${terraform.workspace}/${var.project}/ENCOMPASS_CLIENT_PASSWORD"
  type        = "SecureString"
  description = ""
  value       = var.encompass_client_password
}

resource "aws_ssm_parameter" "ENCOMPASS_CLIENT_SECRET" {
  name        = "/${terraform.workspace}/${var.project}/ENCOMPASS_CLIENT_SECRET"
  type        = "SecureString"
  description = ""
  value       = var.encompass_client_secret
}

resource "aws_ssm_parameter" "EQUIFAX_PASSWORD" {
  name        = "/${terraform.workspace}/${var.project}/EQUIFAX_PASSWORD"
  type        = "SecureString"
  description = ""
  value       = var.equifax_password
}

resource "aws_ssm_parameter" "EQUIFAX_USERNAME" {
  name        = "/${terraform.workspace}/${var.project}/EQUIFAX_USERNAME"
  type        = "SecureString"
  description = ""
  value       = var.equifax_username
}

resource "aws_ssm_parameter" "GOOGLE_CLIENT_ID" {
  name        = "/${terraform.workspace}/${var.project}/GOOGLE_CLIENT_ID"
  type        = "SecureString"
  description = ""
  value       = var.google_client_id
}

resource "aws_ssm_parameter" "GOOGLE_CLIENT_SECRET" {
  name        = "/${terraform.workspace}/${var.project}/GOOGLE_CLIENT_SECRET"
  type        = "SecureString"
  description = ""
  value       = var.google_client_secret
}

resource "aws_ssm_parameter" "HELLO_SIGN_API_KEY" {
  name        = "/${terraform.workspace}/${var.project}/HELLO_SIGN_API_KEY"
  type        = "SecureString"
  description = ""
  value       = var.hello_sign_api_key
}

resource "aws_ssm_parameter" "HELLO_SIGN_CLIENT_ID" {
  name        = "/${terraform.workspace}/${var.project}/HELLO_SIGN_CLIENT_ID"
  type        = "SecureString"
  description = ""
  value       = var.hello_sign_client_id
}

resource "aws_ssm_parameter" "SMTP_PASSWORD" {
  name        = "/${terraform.workspace}/${var.project}/SMTP_PASSWORD"
  type        = "SecureString"
  description = ""
  value       = var.smtp_password
}
resource "aws_ssm_parameter" "RAILS_ENV" {
  name  = "/${terraform.workspace}/${var.project}/RAILS_ENV"
  type  = "SecureString"
  value = "staging"
}

resource "aws_ssm_parameter" "RACK_ENV" {
  name  = "/${terraform.workspace}/${var.project}/RACK_ENV"
  type  = "SecureString"
  value = "staging"
}

resource "aws_ssm_parameter" "RAILS_LOG_TO_STDOUT" {
  name  = "/${terraform.workspace}/${var.project}/RAILS_LOG_TO_STDOUT"
  type  = "SecureString"
  value = "true"
}

resource "aws_ssm_parameter" "STAGE" {
  name  = "/${terraform.workspace}/${var.project}/STAGE"
  type  = "SecureString"
  value = "staging"
}

resource "aws_ssm_parameter" "PORT" {
  name  = "/${terraform.workspace}/${var.project}/PORT"
  type  = "SecureString"
  value = "8080"
}

resource "aws_ssm_parameter" "SENTRY_LOG_LEVEL" {
  name  = "/${terraform.workspace}/${var.project}/SENTRY_LOG_LEVEL"
  type  = "SecureString"
  value = "INFO"
}

resource "aws_ssm_parameter" "LOG_LEVEL" {
  name  = "/${terraform.workspace}/${var.project}/LOG_LEVEL"
  type  = "SecureString"
  value = "INFO"
}

resource "aws_ssm_parameter" "USE_ENCOMPASS_V3" {
  name  = "/${terraform.workspace}/${var.project}/USE_ENCOMPASS_V3"
  type  = "SecureString"
  value = "true"
}

resource "aws_ssm_parameter" "HELLO_SIGN_TEST_MODE" {
  name  = "/${terraform.workspace}/${var.project}/HELLO_SIGN_TEST_MODE"
  type  = "SecureString"
  value = "1"
}

resource "aws_ssm_parameter" "AUTH_NET_GATEWAY" {
  name  = "/${terraform.workspace}/${var.project}/AUTH_NET_GATEWAY"
  type  = "SecureString"
  value = "sandbox"
}

resource "aws_ssm_parameter" "ENCOMPASS_CLIENT_USER" {
  name  = "/${terraform.workspace}/${var.project}/ENCOMPASS_CLIENT_USER"
  type  = "SecureString"
  value = "admin"
}

resource "aws_ssm_parameter" "ENCOMPASS_FOLDER" {
  name  = "/${terraform.workspace}/${var.project}/ENCOMPASS_FOLDER"
  type  = "SecureString"
  value = "Dev"
}

resource "aws_ssm_parameter" "ENCOMPASS_INSTANCE_ID" {
  name  = "/${terraform.workspace}/${var.project}/ENCOMPASS_INSTANCE_ID"
  type  = "SecureString"
  value = "BE11124729"
}

resource "aws_ssm_parameter" "EQUIFAX_BASE_URL" {
  name  = "/${terraform.workspace}/${var.project}/EQUIFAX_BASE_URL"
  type  = "SecureString"
  value = "https://api.sandbox.equifax.com"
}

resource "aws_ssm_parameter" "NOTIFICATION_EMAIL_ADDRESS" {
  name  = "/${terraform.workspace}/${var.project}/NOTIFICATION_EMAIL_ADDRESS"
  type  = "SecureString"
  value = "notifications@dev.jmjdev.me"
}

resource "aws_ssm_parameter" "SMTP_USERNAME" {
  name  = "/${terraform.workspace}/${var.project}/SMTP_USERNAME"
  type  = "SecureString"
  value = "AKIAR75CKF7OKUCIWE43"
}

resource "aws_ssm_parameter" "SENTRY_DSN" {
  name  = "/${terraform.workspace}/${var.project}/SENTRY_DSN"
  type  = "SecureString"
  value = "https://722c514e6cf12b0fab12b84d727824bd@o437804.ingest.sentry.io/4505863317159936"
}
