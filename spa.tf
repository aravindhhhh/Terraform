######### NEWWWWWWW
# S3
resource "aws_s3_bucket" "spa" {
  bucket = "${var.project}-spa-${terraform.workspace}"
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_acl" "spa" {
  bucket = aws_s3_bucket.spa.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "spa" {
  bucket = aws_s3_bucket.spa.id
  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "spa" {
  depends_on = [aws_s3_bucket_versioning.spa]

  bucket = aws_s3_bucket.spa.id

  rule {
    id = "ExpireOldThings"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }

    noncurrent_version_expiration {
      noncurrent_days = 180
    }

    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "spa" {
  bucket = aws_s3_bucket.spa.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "spa" {
  bucket = aws_s3_bucket.spa.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_logging" "spa" {
  bucket = aws_s3_bucket.spa.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3/spa-pipeline/"
}

resource "aws_s3_bucket_cors_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET"]
    allowed_origins = [
      "https://${local.domain}",
      "https://*.${local.domain}",
      "https://app.${local.domain}",
      "https://*.app.${local.domain}",
    ]
    expose_headers  = ["Etag"]
    max_age_seconds = 604800
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "spa" {
  bucket = aws_s3_bucket.spa.id
  policy = data.aws_iam_policy_document.spa_bucket_policy.json
}

data "aws_iam_policy_document" "spa_bucket_policy" {
  # statement {
  #   actions = ["s3:GetObject"]
  #   resources = [
  #     "arn:aws:s3:::${aws_s3_bucket.spa.id}/*",
  #   ]
  #   principals {
  #     type = "AWS"
  #     identifiers = data.aws_cloudfront_origin_access_identities.old.iam_arns
  #   }
  # }

  statement {
    sid     = "CloudFrontRead"
    actions = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.spa.id}/*",
    ]
    principals {
      type = "Service"
      identifiers = [
        "cloudfront.amazonaws.com"
      ]
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/*"
      ]
    }
  }

  statement {
    sid     = "AllowSSLRequestsOnly"
    actions = ["s3:*"]
    effect  = "Deny"
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.spa.id}",
      "arn:aws:s3:::${aws_s3_bucket.spa.id}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# CLOUDFRONT
locals {
  cf_origin_id = "s3-spa"
}

resource "aws_cloudfront_distribution" "spa" {

  lifecycle {
    prevent_destroy = false
  }

  origin {
    domain_name              = aws_s3_bucket.spa.bucket_regional_domain_name
    origin_id                = local.cf_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.main.id
  }

  enabled             = true
  is_ipv6_enabled     = false
  comment             = "SPA Build Pipeline"
  default_root_object = "index.html"

  web_acl_id = var.whitelist_enabled ? aws_wafv2_web_acl.firewall[0].arn : null

  aliases = [
    "app.${local.domain}",
    "*.app.${local.domain}",
  ]

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_regional_domain_name
    prefix          = "cloudfront/spa-pipeline/"
  }

  default_cache_behavior {
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.cf_origin_id
    compress         = true

    origin_request_policy_id   = local.s3_cors_request_policy_id
    cache_policy_id            = aws_cloudfront_cache_policy.spa.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.spa.id

    viewer_protocol_policy = "redirect-to-https"

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.build_viewer_request.arn
    }
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.ssl.arn
    minimum_protocol_version = "TLSv1.2_2019"
    ssl_support_method       = "sni-only"
  }

  # I cant be bothered
  wait_for_deployment = false
}

resource "aws_cloudfront_origin_access_control" "main" {
  name                              = "spa-pipeline-${terraform.workspace}-oac"
  description                       = "Access to SPA buckets"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "build_viewer_request" {
  name    = "spa-build-viewer-request-${terraform.workspace}"
  runtime = "cloudfront-js-1.0"
  comment = "SPA Pipeline Build ViewerRequest"
  publish = true
  code = join("\n", [
    file("${path.module}/functions/common.js"),
    file("${path.module}/functions/cf-viewerRequest.js")
  ])
}

resource "aws_cloudfront_cache_policy" "spa" {
  name    = "spa-pipeline-build-cache-${terraform.workspace}"
  comment = "SPA Pipeline: Build"

  default_ttl = local.build_cache_ttl
  max_ttl     = 31536000
  min_ttl     = 1

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    # Whitelisting the host forwards it to S3 which causes
    # AccessDenied errors... leave it as none
    headers_config {
      header_behavior = "none"
    }

    #  headers_config {
    #   header_behavior = "whitelist"
    #   headers {
    #     items = [
    #       "Host"
    #     ]
    #   }
    # }

    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "spa" {
  name    = "spa-pipeline-build-headers-${terraform.workspace}"
  comment = "SPA Pipeline: Builds"

  cors_config {
    access_control_allow_credentials = false

    access_control_allow_headers {
      items = ["*"]
    }

    access_control_allow_methods {
      items = ["GET"]
    }

    access_control_allow_origins {
      items = [
        "https://app.${local.domain}",
        "https://*.app.${local.domain}",
      ]
    }

    access_control_max_age_sec = 86400

    origin_override = true
  }

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "SAMEORIGIN"
      override     = true
    }
    strict_transport_security {
      include_subdomains         = false
      override                   = true
      access_control_max_age_sec = local.hsts_max_age
      preload                    = false
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

### WAF aka Web Access Firewall aka DDOS protection and IP whitelisting
resource "aws_wafv2_ip_set" "ip_whitelist" {
  name               = "ip-whitelist-${terraform.workspace}"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = local.ip_whitelist
}

resource "aws_wafv2_web_acl" "firewall" {
  count = var.whitelist_enabled ? 1 : 0
  name  = "${var.project}-firewall-${terraform.workspace}"
  scope = "CLOUDFRONT"

  default_action {
    block {}
  }

  rule {
    name     = "allow-whitelist"
    priority = 10

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.ip_whitelist.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Allowed"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "Blocked"
    sampled_requests_enabled   = true
  }
}

### DNS ###

resource "aws_route53_record" "app" {
  for_each = toset(["A", "AAAA"])

  zone_id = data.aws_route53_zone.primary.zone_id
  name    = join(".", compact(["app", local.domain]))
  type    = each.value

  alias {
    name                   = aws_cloudfront_distribution.spa.domain_name
    zone_id                = aws_cloudfront_distribution.spa.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "app_wildcard" {
  count = terraform.workspace == "production" ? 1 : 0

  zone_id = data.aws_route53_zone.primary.zone_id
  name    = join(".", compact(["*", "app", local.domain]))
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.spa.domain_name
    zone_id                = aws_cloudfront_distribution.spa.hosted_zone_id
    evaluate_target_health = false
  }
}

