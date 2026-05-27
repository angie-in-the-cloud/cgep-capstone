# s3_kms_encryption_test.rego
# Tests for the GAP-01 S3 SSE-KMS policy.

package terraform.s3_kms_encryption_test

import rego.v1

import data.terraform.s3_kms_encryption

# Compliant fixture: SSE config using aws:kms. Policy should NOT deny.
compliant_input := {"resource_changes": [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{
		"sse_algorithm": "aws:kms",
		"kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/abcd",
	}]}]}},
}]}

# Non-compliant fixture: SSE config using AES256 (SSE-S3). Policy SHOULD deny.
violating_input := {"resource_changes": [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{
		"sse_algorithm": "AES256",
	}]}]}},
}]}

# A compliant plan produces no denials.
test_compliant_passes if {
	count(s3_kms_encryption.deny) == 0 with input as compliant_input
}

# A non-compliant plan produces exactly one denial.
test_violation_denied if {
	count(s3_kms_encryption.deny) == 1 with input as violating_input
}

# The denial message cites the CMMC control ID.
test_denial_cites_control if {
	some msg in s3_kms_encryption.deny with input as violating_input
	contains(msg, "SC.L2-3.13.11")
}