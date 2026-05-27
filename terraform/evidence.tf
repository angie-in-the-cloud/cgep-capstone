# evidence.tf
# Layer 1 baseline — the evidence vault.
# Every pipeline run lands a signed, timestamped bundle here. Object Lock
# in COMPLIANCE mode makes those bundles immutable: once written, they
# cannot be altered or deleted by anyone, including the account root,
# until retention expires.

resource "aws_s3_bucket" "evidence" {
  bucket = "${local.name_prefix}-evidence-${local.suffix}"

  # Object Lock must be enabled at bucket creation - it cannot be added later.
  object_lock_enabled = true
}

# Versioning - required for Object Lock to function.
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock retention - COMPLIANCE mode, 1-day default.
# COMPLIANCE: immutable to all principals, no override. 1 day: long
# enough to demonstrate enforced immutability, short enough not to lock
# objects beyond the capstone's lifespan.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 1
    }
  }

  # Object Lock config depends on versioning being enabled first.
  depends_on = [aws_s3_bucket_versioning.evidence]
}

# Encrypt the vault with the same customer CMK as the other data stores.
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cui.arn
    }
    bucket_key_enabled = true
  }
}

# Block all public access - an evidence vault is never public.
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
