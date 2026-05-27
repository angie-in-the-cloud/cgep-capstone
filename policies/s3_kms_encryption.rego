# s3_kms_encryption.rego
# GAP-01 - S3 buckets storing CUI must use SSE-KMS with a customer-managed
# CMK, not SSE-S3 (the AWS-managed default).
#
# CMMC: SC.L2-3.13.11 - employ FIPS-validated cryptography to protect CUI.
# Severity: high
# Remediation: set sse_algorithm to "aws:kms" with a customer CMK ARN in
#   the aws_s3_bucket_server_side_encryption_configuration resource.

package terraform.s3_kms_encryption

import rego.v1

# Collect S3 SSE configuration resources from the plan.
sse_configs contains rc if {
	rc := input.resource_changes[_]
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
}

# Deny any SSE config whose algorithm is not aws:kms.
deny contains msg if {
	rc := sse_configs[_]
	rule := rc.change.after.rule[_]
	default_enc := rule.apply_server_side_encryption_by_default[_]
	default_enc.sse_algorithm != "aws:kms"

	msg := sprintf(
		"[SC.L2-3.13.11] %s uses sse_algorithm '%s'; CUI buckets must use 'aws:kms' with a customer CMK.",
		[rc.address, default_enc.sse_algorithm],
	)
}