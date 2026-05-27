# kms.tf
# Customer-managed KMS key for CUI at rest.
# Closes GAP-01 (S3 uploads) and GAP-02 (DynamoDB) — one shared CMK.

resource "aws_kms_key" "cui" {
  description             = "Acme Health - CMK for CUI data stores (S3 uploads, DynamoDB)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "cui" {
  name          = "alias/${local.name_prefix}-cui"
  target_key_id = aws_kms_key.cui.key_id
}
