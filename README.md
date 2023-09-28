# infrastructure
AWS infrastructure for the JMJ applications

<!-- BEGIN_TF_DOCS -->
<p align="center">
<img width="200" height="200" src="docs/terraform-icon.svg"><br>
<h1 align="center">Terraform Infrastructure Documentation</h1>
</p>

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_auth_net_api_login_id"></a> [auth\_net\_api\_login\_id](#input\_auth\_net\_api\_login\_id) | Application environment secret | `string` | `"4dAP2s9d"` | no |
| <a name="input_auth_net_transaction_key"></a> [auth\_net\_transaction\_key](#input\_auth\_net\_transaction\_key) | Application environment secret | `string` | `"3un64YQB655mSkW5"` | no |
| <a name="input_availability_zones"></a> [availability\_zones](#input\_availability\_zones) | List of availability zones in the region | `map(string)` | <pre>{<br>  "us-east-1": "us-east-1a,us-east-1b,us-east-1c"<br>}</pre> | no |
| <a name="input_db_instance_class"></a> [db\_instance\_class](#input\_db\_instance\_class) | Size and Class for the RDS Postgres instance | `string` | `"db.t3.micro"` | no |
| <a name="input_db_parameter_group"></a> [db\_parameter\_group](#input\_db\_parameter\_group) | Postgres database parameter group name | `string` | `"default.postgres15"` | no |
| <a name="input_db_postgres_version"></a> [db\_postgres\_version](#input\_db\_postgres\_version) | Postgres database version | `string` | `"15.3"` | no |
| <a name="input_domain"></a> [domain](#input\_domain) | Root Domain | `string` | `"jmjdev.me"` | no |
| <a name="input_encompass_client_password"></a> [encompass\_client\_password](#input\_encompass\_client\_password) | Application environment secret | `string` | `"sdfhaod"` | no |
| <a name="input_encompass_client_secret"></a> [encompass\_client\_secret](#input\_encompass\_client\_secret) | Application environment secret | `string` | `"0w3OQf*^80sNFbmUHai7@^wnAHbaKAb1K2I!wz1ElxsNwADkciuBtUvn4o6dEo^G"` | no |
| <a name="input_equifax_password"></a> [equifax\_password](#input\_equifax\_password) | Application environment secret | `string` | `"nUAhHqisDVCI3Gws"` | no |
| <a name="input_equifax_username"></a> [equifax\_username](#input\_equifax\_username) | Application environment secret | `string` | `"Eha48rWTez22c9MGnmRx65gSXd6jfWjG"` | no |
| <a name="input_google_client_id"></a> [google\_client\_id](#input\_google\_client\_id) | Application environment secret | `string` | `"682584168980-k71l505ej3lu832gra6e6ubrk618isqg.apps.googleusercontent.com"` | no |
| <a name="input_google_client_secret"></a> [google\_client\_secret](#input\_google\_client\_secret) | Application environment secret | `string` | `"npf2tV7h2QGq-S0R1FJE0dq8"` | no |
| <a name="input_hello_sign_api_key"></a> [hello\_sign\_api\_key](#input\_hello\_sign\_api\_key) | Application environment secret | `string` | `"dad2c30984f8eeb0e140dd6dea41faf7597353a3ec3d661e86d2402feeef9cb7"` | no |
| <a name="input_hello_sign_client_id"></a> [hello\_sign\_client\_id](#input\_hello\_sign\_client\_id) | Application environment secret | `string` | `"3b4a369da5a979a35fec9a12c6811e03"` | no |
| <a name="input_ip_whitelist"></a> [ip\_whitelist](#input\_ip\_whitelist) | IP Whitelist | `list(string)` | `[]` | no |
| <a name="input_project"></a> [project](#input\_project) | Name of the project | `string` | `"hive"` | no |
| <a name="input_queues"></a> [queues](#input\_queues) | List of SQS Queue Names | `list(string)` | <pre>[<br>  "main",<br>  "encompass"<br>]</pre> | no |
| <a name="input_region"></a> [region](#input\_region) | AWS Region to deploy resources in | `string` | `"us-east-1"` | no |
| <a name="input_slack_webhook_url"></a> [slack\_webhook\_url](#input\_slack\_webhook\_url) | Slack webhook URL for Cloudwatch Alert Notifications | `string` | `""` | no |
| <a name="input_smtp_password"></a> [smtp\_password](#input\_smtp\_password) | Application environment secret | `string` | `"BBuORtdrmrlMFij5F7Xo23pH0O03GoSU5xXPP2nq4G+X"` | no |
| <a name="input_users"></a> [users](#input\_users) | User list for VPN, Database Access, etc etc | `map` | <pre>{<br>  "amandeep": {<br>    "first_name": "amandeep",<br>    "last_name": "singh",<br>    "phone": "amandeep@thebitcrew.dev"<br>  },<br>  "arun": {<br>    "email": "arun@thebitcrew.dev",<br>    "first_name": "arun",<br>    "last_name": "shan"<br>  },<br>  "chim": {<br>    "email": "chim@thebitcrew.dev",<br>    "first_name": "chim",<br>    "last_name": "k"<br>  },<br>  "clayton": {<br>    "first_name": "clayton",<br>    "last_name": "noyes",<br>    "phone": "claytonRnoyes@gmail.com"<br>  },<br>  "rich": {<br>    "email": "rich@deepseas.dev",<br>    "first_name": "rich",<br>    "last_name": "ornelas"<br>  },<br>  "rr": {<br>    "email": "rr@jmj.me",<br>    "first_name": "ryan",<br>    "last_name": "robertson"<br>  },<br>  "travis": {<br>    "email": "trtincher12@gmail.com",<br>    "first_name": "travis",<br>    "last_name": "tincher"<br>  },<br>  "vk": {<br>    "email": "vk@jmj.me",<br>    "first_name": "virgil",<br>    "last_name": "kyle"<br>  }<br>}</pre> | no |
| <a name="input_vpc_cidr_block"></a> [vpc\_cidr\_block](#input\_vpc\_cidr\_block) | CIDR block for the created VPC. | `string` | `"10.0.0.0/16"` | no |
| <a name="input_vpn_cidr"></a> [vpn\_cidr](#input\_vpn\_cidr) | CIDR for the VPN Client | `string` | `"10.0.0.0/22"` | no |
| <a name="input_vpn_split_tunnel"></a> [vpn\_split\_tunnel](#input\_vpn\_split\_tunnel) | Whether VPN tunnel traffic is split or not | `bool` | `false` | no |
| <a name="input_whitelist_enabled"></a> [whitelist\_enabled](#input\_whitelist\_enabled) | Is the environment whitelist only access? | `bool` | `false` | no |
## Resources

| Name | Type |
|------|------|
| [aws_acm_certificate.ca](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate) | resource |
| [aws_acm_certificate.server](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate) | resource |
| [aws_acm_certificate.ssl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate) | resource |
| [aws_acm_certificate_validation.ssl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate_validation) | resource |
| [aws_alb.web](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb) | resource |
| [aws_alb_listener.http](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb_listener) | resource |
| [aws_alb_listener.https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb_listener) | resource |
| [aws_alb_target_group.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb_target_group) | resource |
| [aws_cloudfront_cache_policy.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_cache_policy) | resource |
| [aws_cloudfront_distribution.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution) | resource |
| [aws_cloudfront_function.build_viewer_request](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_function) | resource |
| [aws_cloudfront_origin_access_control.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_origin_access_control) | resource |
| [aws_cloudfront_response_headers_policy.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_response_headers_policy) | resource |
| [aws_cloudwatch_log_group.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_stream.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_stream) | resource |
| [aws_cloudwatch_metric_alarm.alb_healthy_host_count](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.alb_target_response_time](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.ecs_cpu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.ecs_memory](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rds_burst_balance](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rds_cpu_utilization](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rds_free_storage_space](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rds_queue_depth](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rds_read_latency](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rds_write_latency](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_db_instance.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance) | resource |
| [aws_db_subnet_group.ecs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_subnet_group) | resource |
| [aws_ec2_client_vpn_authorization_rule.all_groups](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_authorization_rule) | resource |
| [aws_ec2_client_vpn_authorization_rule.all_groups_internet](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_authorization_rule) | resource |
| [aws_ec2_client_vpn_endpoint.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_endpoint) | resource |
| [aws_ec2_client_vpn_network_association.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_network_association) | resource |
| [aws_ec2_client_vpn_route.internet_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_route) | resource |
| [aws_ecr_repository.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository) | resource |
| [aws_ecr_repository_policy.ecr_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy) | resource |
| [aws_ecs_cluster.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster) | resource |
| [aws_ecs_cluster_capacity_providers.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster_capacity_providers) | resource |
| [aws_eip.nat](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_iam_openid_connect_provider.github](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_openid_connect_provider) | resource |
| [aws_iam_role.ecs_execution](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.ecs_service](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.github_actions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.lambda_edge_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.platform_service](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.ecs_execution_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ecs_service](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.github_actions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.lambda_edge_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.platform_service_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_internet_gateway.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/internet_gateway) | resource |
| [aws_lb_listener_rule.api_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_rule) | resource |
| [aws_nat_gateway.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/nat_gateway) | resource |
| [aws_route.primary_internet_public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route.primary_nat_private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route53_record.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route53_record.app](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route53_record.app_wildcard](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route53_record.cert](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route_table.primary-private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table) | resource |
| [aws_route_table.primary-public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table) | resource |
| [aws_route_table_association.private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_route_table_association.public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_s3_bucket.bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_acl.logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_acl.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_cors_configuration.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_cors_configuration) | resource |
| [aws_s3_bucket_lifecycle_configuration.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_logging.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging) | resource |
| [aws_s3_bucket_ownership_controls.logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_ownership_controls.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_policy.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.spa](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_security_group.alb_public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.ecs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.rds](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group_rule.alb_public_443_platform](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.alb_public_80_platform](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ecs_self](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ecs_sg_http](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ecs_sg_http2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ecs_sg_https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.egress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.lb_ingress_cloudfront](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.rds_postgres_ecs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.rds_postgres_vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_sns_topic.cloudwatch_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sqs_queue.queue](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_sqs_queue.queue_dead](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_sqs_queue_policy.queue](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy) | resource |
| [aws_ssm_parameter.APP_BUCKET](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.AUTH_NET_API_LOGIN_ID](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.AUTH_NET_GATEWAY](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.AUTH_NET_TRANSACTION_KEY](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.AWS_REGION](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.CLOUDFRONT_DISTRO_ID](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.DATABASE_URL](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.DEFAULT_QUEUE](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ENCOMPASS_CLIENT_PASSWORD](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ENCOMPASS_CLIENT_SECRET](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ENCOMPASS_CLIENT_USER](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ENCOMPASS_FOLDER](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ENCOMPASS_INSTANCE_ID](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ENCOMPASS_QUEUE](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.EQUIFAX_BASE_URL](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.EQUIFAX_PASSWORD](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.EQUIFAX_USERNAME](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.GOOGLE_CLIENT_ID](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.GOOGLE_CLIENT_SECRET](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.HELLO_SIGN_API_KEY](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.HELLO_SIGN_CLIENT_ID](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.HELLO_SIGN_TEST_MODE](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.HIVE_URL](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.LOG_LEVEL](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.NOTIFICATION_EMAIL_ADDRESS](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.PORT](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.RACK_ENV](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.RAILS_ENV](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.RAILS_LOG_TO_STDOUT](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.SENTRY_DSN](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.SENTRY_LOG_LEVEL](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.SMTP_PASSWORD](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.SMTP_USERNAME](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.STAGE](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.USE_ENCOMPASS_V3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.rails_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_subnet.private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_subnet.public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_vpc.primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc) | resource |
| [aws_vpc_endpoint.dynamodb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint) | resource |
| [aws_vpc_endpoint.s3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint) | resource |
| [aws_wafv2_ip_set.ip_whitelist](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_web_acl.firewall](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [local_sensitive_file.some_user](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/sensitive_file) | resource |
| [random_id.rails_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/id) | resource |
| [random_password.rds_password](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [tls_cert_request.server](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/cert_request) | resource |
| [tls_cert_request.some_user](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/cert_request) | resource |
| [tls_locally_signed_cert.server](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/locally_signed_cert) | resource |
| [tls_locally_signed_cert.some_user](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/locally_signed_cert) | resource |
| [tls_private_key.ca](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key) | resource |
| [tls_private_key.server](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key) | resource |
| [tls_private_key.some_user](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key) | resource |
| [tls_self_signed_cert.ca](https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/self_signed_cert) | resource |
## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_fqdn"></a> [api\_fqdn](#output\_api\_fqdn) | API GraphQL Domain Name |
| <a name="output_api_target_group_arn"></a> [api\_target\_group\_arn](#output\_api\_target\_group\_arn) | ARN for the Target Group belonging to the ECS Web Service API |
| <a name="output_app_bucket_name"></a> [app\_bucket\_name](#output\_app\_bucket\_name) | Application S3 bucket name |
| <a name="output_app_fqdn"></a> [app\_fqdn](#output\_app\_fqdn) | App Domain Name |
| <a name="output_cloudfront_distro_id"></a> [cloudfront\_distro\_id](#output\_cloudfront\_distro\_id) | AWS Cloudfront Distribution ID that fronts the web application S3 bucket |
| <a name="output_database_url"></a> [database\_url](#output\_database\_url) | Postgres Database URL |
| <a name="output_ecs_cluster_name"></a> [ecs\_cluster\_name](#output\_ecs\_cluster\_name) | AWS ECS Cluster Name |
| <a name="output_ecs_execution_role_arn"></a> [ecs\_execution\_role\_arn](#output\_ecs\_execution\_role\_arn) | AWS IAM Role for ECS executions |
| <a name="output_ecs_execution_role_name"></a> [ecs\_execution\_role\_name](#output\_ecs\_execution\_role\_name) | AWS IAM Role for ECS executions |
| <a name="output_ecs_service_role_arn"></a> [ecs\_service\_role\_arn](#output\_ecs\_service\_role\_arn) | AWS IAM Role for ECS executions |
| <a name="output_ecs_service_role_name"></a> [ecs\_service\_role\_name](#output\_ecs\_service\_role\_name) | AWS IAM Role for ECS services |
| <a name="output_github_role_arn"></a> [github\_role\_arn](#output\_github\_role\_arn) | AWS IAM Role ARN for Github Actions |
| <a name="output_github_role_name"></a> [github\_role\_name](#output\_github\_role\_name) | AWS IAM Role for Github Actions |
| <a name="output_log_bucket_id"></a> [log\_bucket\_id](#output\_log\_bucket\_id) | AWS S3 bucket for all AWS logs for this environment |
| <a name="output_nat_gateway_ips"></a> [nat\_gateway\_ips](#output\_nat\_gateway\_ips) | NAT Gateway IP address(es) |
| <a name="output_plaform_service_role_arn"></a> [plaform\_service\_role\_arn](#output\_plaform\_service\_role\_arn) | AWS IAM Role for ECS executions |
| <a name="output_plaform_service_role_name"></a> [plaform\_service\_role\_name](#output\_plaform\_service\_role\_name) | AWS IAM Role for ECS services |
| <a name="output_private_route_tables"></a> [private\_route\_tables](#output\_private\_route\_tables) | AWS Private Route Table IDs |
| <a name="output_private_subnets"></a> [private\_subnets](#output\_private\_subnets) | AWS Private Subnet IDs |
| <a name="output_public_route_tables"></a> [public\_route\_tables](#output\_public\_route\_tables) | AWS Public Route Table IDs |
| <a name="output_public_subnets"></a> [public\_subnets](#output\_public\_subnets) | AWS Public Subnet IDs |
| <a name="output_sg_alb_public"></a> [sg\_alb\_public](#output\_sg\_alb\_public) | Security Group assigned to public-facing Application Load Balancers |
| <a name="output_sg_ecs"></a> [sg\_ecs](#output\_sg\_ecs) | Security Group assigned to ECS Services |
| <a name="output_sg_rds"></a> [sg\_rds](#output\_sg\_rds) | Security Group assigned to RDS instances |
| <a name="output_spa_bucket"></a> [spa\_bucket](#output\_spa\_bucket) | AWS S3 bucket hosting the web application's files |
| <a name="output_vpc_id"></a> [vpc\_id](#output\_vpc\_id) | Primary VPC ID |
| <a name="output_vpn_endpoint_dns"></a> [vpn\_endpoint\_dns](#output\_vpn\_endpoint\_dns) | n/a |
| <a name="output_vpn_endpoint_id"></a> [vpn\_endpoint\_id](#output\_vpn\_endpoint\_id) | n/a |
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.7.0 |
| <a name="provider_local"></a> [local](#provider\_local) | 2.4.0 |
| <a name="provider_random"></a> [random](#provider\_random) | 3.5.1 |
| <a name="provider_tls"></a> [tls](#provider\_tls) | 4.0.4 |
## Modules

No modules.
<!-- END_TF_DOCS -->
