# bootstrap/main.tf
#
# Bootstrap module — creates the S3 bucket that holds the main Terraform's
# remote state. Runs once, separately from the main capstone Terraform,
# with its own LOCAL state.
#
# Why this exists: the main Terraform's `backend "s3"` block needs a
# bucket that already exists. This module creates that bucket. It is the
# only piece of Terraform in this repo with local state, by design.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Random suffix so the bucket name is globally unique on first apply.
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "tfstate" {
  bucket = "acme-health-intake-tfstate-${random_id.suffix.hex}"
}

# Versioning - recover from a bad state write by rolling back to the
# previous version object.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Block all public access. State files contain ARNs, IDs, and sometimes
# sensitive values - they are never public.
resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encryption with SSE-S3 (AWS-managed). Deliberate scoping choice:
# state files contain resource references but no patient data; the CUI
# CMK isn't required here. The CMK lives in the main Terraform.
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

output "tfstate_bucket" {
  description = "Name of the bucket holding the main Terraform's remote state"
  value       = aws_s3_bucket.tfstate.id
}
