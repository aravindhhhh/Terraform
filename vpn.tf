### SERVER CERTIFICATES ###
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "ca.vpn.${local.domain}"
    organization = var.project
  }

  validity_period_hours = 87600
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

resource "aws_acm_certificate" "ca" {
  private_key      = tls_private_key.ca.private_key_pem
  certificate_body = tls_self_signed_cert.ca.cert_pem
}

resource "tls_private_key" "server" {
  algorithm = "RSA"
}

resource "tls_cert_request" "server" {
  private_key_pem = tls_private_key.server.private_key_pem

  subject {
    common_name  = "server.vpn.${local.domain}"
    organization = var.project
  }
}

resource "tls_locally_signed_cert" "server" {
  cert_request_pem      = tls_cert_request.server.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 87600

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
    "client_auth",
  ]
}

resource "aws_acm_certificate" "server" {
  private_key       = tls_private_key.server.private_key_pem
  certificate_body  = tls_locally_signed_cert.server.cert_pem
  certificate_chain = tls_self_signed_cert.ca.cert_pem
}

### VPN ###

resource "aws_cloudwatch_log_group" "vpn" {
  name              = "/aws/vpn/${local.domain}/logs"
  retention_in_days = 90
}

resource "aws_cloudwatch_log_stream" "vpn" {
  name           = "vpn-usage"
  log_group_name = aws_cloudwatch_log_group.vpn.name
}

resource "aws_ec2_client_vpn_endpoint" "main" {
  tags = {
    name = "${terraform.workspace}-client-vpn"
  }

  description            = "${terraform.workspace}-client-vpn"
  server_certificate_arn = aws_acm_certificate.server.arn
  client_cidr_block      = cidrsubnet(aws_vpc.primary.cidr_block, 6, 1 + 40)
  split_tunnel           = var.vpn_split_tunnel
  transport_protocol     = "tcp"
  dns_servers            = ["8.8.8.8", "8.8.4.4"]
  self_service_portal    = "enabled"
  security_group_ids     = [aws_security_group.vpn.id]
  vpc_id                 = aws_vpc.primary.id
  vpn_port               = 443

  client_connect_options {
    enabled = false
  }

  client_login_banner_options {
    enabled = false
  }

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.server.arn
    # saml_provider_arn          = var.authentication_saml_provider_arn
  }

  connection_log_options {
    enabled               = true
    cloudwatch_log_group  = aws_cloudwatch_log_group.vpn.name
    cloudwatch_log_stream = aws_cloudwatch_log_stream.vpn.name
  }
}

resource "aws_ec2_client_vpn_network_association" "main" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  subnet_id              = aws_subnet.private[0].id
}

resource "aws_ec2_client_vpn_authorization_rule" "all_groups" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  target_network_cidr    = var.vpc_cidr_block
  authorize_all_groups   = true
}

resource "aws_ec2_client_vpn_authorization_rule" "all_groups_internet" {
  count = var.vpn_split_tunnel ? 0 : 1

  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  target_network_cidr    = "0.0.0.0/0"
  authorize_all_groups   = true
}

resource "aws_ec2_client_vpn_route" "internet_access" {
  count = var.vpn_split_tunnel ? 0 : 1

  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  destination_cidr_block = "0.0.0.0/0"
  target_vpc_subnet_id   = aws_subnet.private[0].id
}

### PRIVATE USER KEYS ###

resource "tls_private_key" "some_user" {
  for_each = local.usernames

  algorithm = "RSA"
}

resource "tls_cert_request" "some_user" {
  for_each = local.usernames

  private_key_pem = tls_private_key.some_user[each.value].private_key_pem

  subject {
    common_name  = each.value
    organization = "${var.project} (${local.domain})"
  }
}

resource "tls_locally_signed_cert" "some_user" {
  for_each = local.usernames

  cert_request_pem   = tls_cert_request.some_user[each.value].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 87600

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "client_auth",
    "server_auth",
  ]
}

resource "local_sensitive_file" "some_user" {
  for_each = local.usernames

  content = templatefile("${path.module}/config.tpl", {
    vpn_endpoint   = replace(aws_ec2_client_vpn_endpoint.main.dns_name, "*.", "")
    server_name    = "server.vpn.${local.domain}"
    ca_body        = tls_self_signed_cert.ca.cert_pem
    user_cert_body = tls_locally_signed_cert.some_user[each.value].cert_pem
    user_key_body  = tls_private_key.some_user[each.value].private_key_pem
  })
  filename = "${path.module}/ovpn/${each.key}-${terraform.workspace}.ovpn"
}
