# dynamodb_kms_encryption.rego
# GAP-02 - DynamoDB tables storing CUI must use a customer-managed CMK,
# not the AWS-owned default key.
#
# CMMC: SC.L2-3.13.11 - employ FIPS-validated cryptography to protect CUI.
# Severity: high
# Remediation: add a server_side_encryption block with enabled = true and
#   kms_key_arn set to a customer CMK ARN on the aws_dynamodb_table.

package terraform.dynamodb_kms_encryption

import rego.v1

# Collect DynamoDB table resources from the plan.
tables contains rc if {
	rc := input.resource_changes[_]
	rc.type == "aws_dynamodb_table"
}

# A table is CMK-encrypted only if it has an SSE entry with a
# non-empty kms_key_arn.
cmk_encrypted(rc) if {
	sse := rc.change.after.server_side_encryption[_]
	sse.kms_key_arn != ""
	sse.kms_key_arn != null
}

# Deny any table that is not CMK-encrypted.
deny contains msg if {
	rc := tables[_]
	not cmk_encrypted(rc)

	msg := sprintf(
		"[SC.L2-3.13.11] %s is not encrypted with a customer-managed CMK; CUI tables must set server_side_encryption.kms_key_arn.",
		[rc.address],
	)
}