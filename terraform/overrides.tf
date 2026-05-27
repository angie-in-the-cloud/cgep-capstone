# overrides.tf
# Gap-closing overrides on the starter's resources.
# These are NEW sibling resources that reference the starter by ID.
# main.tf is not edited.

# GAP-01 DELIBERATELY REINTRODUCED for red-PR demonstration.
# This downgrade from SSE-KMS (customer CMK) to SSE-S3 (AWS-managed)
# violates SC.L2-3.13.11. The policy gate must block this PR.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# GAP-04 — enable versioning on the uploads bucket.
# Without versioning, an overwrite or delete of a CUI object is unrecoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-03 — deny any non-TLS request to the uploads bucket.
# Without this, the bucket accepts plaintext HTTP requests carrying CUI.
resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GAP-05 support: the Lambda service needs EC2 network-interface
# permissions (via the execution role) to create ENIs when the function
# runs in a VPC. AWS-managed policy, scoped to exactly those actions.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# GAP-06 support: X-Ray active tracing needs the role to be allowed to
# publish trace data. AWS-managed policy, minimal X-Ray write actions.
resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}
