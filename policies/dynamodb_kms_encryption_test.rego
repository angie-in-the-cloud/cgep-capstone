# dynamodb_kms_encryption_test.rego
# Tests for the GAP-02 DynamoDB CMK policy.

package terraform.dynamodb_kms_encryption_test

import rego.v1

import data.terraform.dynamodb_kms_encryption

# Compliant: table with a real CMK ARN. Policy should NOT deny.
compliant_input := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {"after": {"server_side_encryption": [{
		"enabled": true,
		"kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/abcd",
	}]}},
}]}

# Non-compliant: SSE block present but empty - the AWS-owned default key.
empty_block_input := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {"after": {"server_side_encryption": [{}]}},
}]}

# Non-compliant: no SSE block at all.
missing_block_input := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {"after": {"server_side_encryption": []}},
}]}

# A compliant plan produces no denials.
test_compliant_passes if {
	count(dynamodb_kms_encryption.deny) == 0 with input as compliant_input
}

# An empty SSE block (AWS-owned key) is denied.
test_empty_block_denied if {
	count(dynamodb_kms_encryption.deny) == 1 with input as empty_block_input
}

# A missing SSE block is denied.
test_missing_block_denied if {
	count(dynamodb_kms_encryption.deny) == 1 with input as missing_block_input
}

# The denial message cites the CMMC control ID.
test_denial_cites_control if {
	some msg in dynamodb_kms_encryption.deny with input as empty_block_input
	contains(msg, "SC.L2-3.13.11")
}