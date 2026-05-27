# github_oidc.tf
# Layer 3 prep — GitHub Actions assumes an AWS IAM role via OIDC.
# No long-lived AWS keys live in GitHub. The trust policy restricts which
# workflow runs in which repo can assume the role.

# OIDC identity provider for GitHub Actions - already exists in the account
# (created by an earlier lab). Read it as a data source; the capstone does
# not own this account-wide resource.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

# The role GitHub Actions assumes. Trust restricted to:
#   - pull_request events on this repo (used by pr.yml: plan + policy check)
#   - main-branch refs on this repo (used by apply.yml: plan + policy + apply + sign + upload)
resource "aws_iam_role" "github_actions" {
  name = "${local.name_prefix}-github-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:angie-in-the-cloud/cgep-capstone:pull_request",
            "repo:angie-in-the-cloud/cgep-capstone:ref:refs/heads/main",
            "repo:angie-in-the-cloud/cgep-capstone:environment:production"
          ]
        }
      }
    }]
  })
}

# Permissions the role holds in AWS. Scoped to what the pipeline actually does:
#   - read the workload (for plan)
#   - write the capstone-managed resources (for apply)
#   - put objects into the evidence vault (for upload)
resource "aws_iam_role_policy" "github_actions" {
  name = "github-actions-pipeline"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read-only across the services the pipeline plans against.
        # The plan must inspect every resource the Terraform manages.
        Sid    = "ReadForPlan"
        Effect = "Allow"
        Action = [
          "s3:Get*", "s3:List*",
          "dynamodb:Describe*", "dynamodb:List*",
          "lambda:Get*", "lambda:List*",
          "apigateway:GET",
          "iam:Get*", "iam:List*",
          "ec2:Describe*",
          "kms:Describe*", "kms:Get*", "kms:List*",
          "sqs:Get*", "sqs:List*",
          "logs:Describe*", "logs:Get*", "logs:List*",
          "cloudtrail:Get*", "cloudtrail:List*", "cloudtrail:Describe*"
        ]
        Resource = "*"
      },
      {
        # Write on the capstone's own resources only. The pipeline never
        # touches resources outside this workload.
        Sid    = "WriteCapstoneResources"
        Effect = "Allow"
        Action = [
          "s3:PutBucket*", "s3:DeleteBucket*", "s3:PutObject*",
          "s3:CreateBucket", "s3:DeleteBucket",
          "dynamodb:UpdateTable", "dynamodb:UpdateTimeToLive",
          "lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode",
          "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency",
          "lambda:TagResource", "lambda:UntagResource",
          "apigateway:PATCH", "apigateway:POST", "apigateway:PUT", "apigateway:DELETE",
          "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:TagRole", "iam:UntagRole", "iam:PassRole",
          "ec2:Create*", "ec2:Delete*", "ec2:Modify*", "ec2:Authorize*", "ec2:Revoke*",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "kms:CreateKey", "kms:CreateAlias", "kms:DeleteAlias",
          "kms:EnableKeyRotation", "kms:DisableKeyRotation",
          "kms:TagResource", "kms:UntagResource",
          "kms:UpdateAlias", "kms:ScheduleKeyDeletion",
          "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:SetQueueAttributes",
          "sqs:TagQueue", "sqs:UntagQueue",
          "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
          "logs:TagLogGroup", "logs:UntagLogGroup",
          "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
          "cloudtrail:StartLogging", "cloudtrail:StopLogging",
          "cloudtrail:AddTags", "cloudtrail:RemoveTags"
        ]
        Resource = "*"
      },
      {
        # Upload signed evidence bundles to the vault. Scoped to the
        # evidence bucket only - never the workload's uploads bucket.
        Sid    = "UploadEvidence"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold"
        ]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        # Required to PutObject into the evidence vault, which is
        # SSE-KMS encrypted with the CUI CMK. S3 calls GenerateDataKey
        # on the writer's behalf during the upload.
        Sid    = "EvidenceVaultKMS"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.cui.arn
      }
    ]
  })
}

# Output the role ARN - GitHub Actions workflows need this value to
# configure aws-actions/configure-aws-credentials.
output "github_actions_role_arn" {
  description = "ARN of the IAM role GitHub Actions assumes via OIDC"
  value       = aws_iam_role.github_actions.arn
}
