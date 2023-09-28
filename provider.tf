terraform {
  required_version = ">= 1.4"
  backend "s3" {
    bucket  = "jmj-terraformm"
    key     = "infrastructure/aws.tfstate"
    region  = "us-west-1"
    profile = "jmj"
  }
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = var.region

  assume_role {
    role_arn = "arn:aws:iam::225827365710:user/Terraform"
  }

  default_tags {
    tags = {
      Application = "hive"
      Environment = terraform.workspace
      IAC         = "Terraform"
    }
  }
}

