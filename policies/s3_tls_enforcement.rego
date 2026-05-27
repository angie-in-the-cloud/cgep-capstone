# s3_tls_enforcement.rego
# GAP-03 - S3 buckets storing CUI must have a bucket policy that denies
# non-TLS (plaintext HTTP) requests.
#
# CMMC: SC.L2-3.13.8 - protect the confidentiality of CUI in transmission.
# Severity: medium
# Remediation: add an aws_s3_bucket_policy with a Deny statement on
#   aws:SecureTransport = false.

package terraform.s3_tls_enforcement

import rego.v1

# Collect S3 bucket policy resources from the plan.
bucket_policies contains rc if {
	rc := input.resource_changes[_]
	rc.type == "aws_s3_bucket_policy"
}

# A bucket policy enforces TLS if it has a Deny statement conditioned on
# aws:SecureTransport = false.
enforces_tls(rc) if {
	doc := json.unmarshal(rc.change.after.policy)
	stmt := doc.Statement[_]
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

# Deny any bucket policy that does not enforce TLS.
deny contains msg if {
	rc := bucket_policies[_]
	not enforces_tls(rc)

	msg := sprintf(
		"[SC.L2-3.13.8] %s does not deny non-TLS requests; CUI buckets must Deny on aws:SecureTransport = false.",
		[rc.address],
	)
}