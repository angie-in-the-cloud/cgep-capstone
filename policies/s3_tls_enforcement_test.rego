# s3_tls_enforcement_test.rego
# Tests for the GAP-03 S3 TLS-enforcement policy.

package terraform.s3_tls_enforcement_test

import rego.v1

import data.terraform.s3_tls_enforcement

# Helper: wrap a policy document (as a JSON string) in a resource_changes input.
bucket_policy_input(policy_json) := {"resource_changes": [{
	"address": "aws_s3_bucket_policy.uploads_tls",
	"type": "aws_s3_bucket_policy",
	"change": {"after": {"policy": policy_json}},
}]}

# Compliant: a Deny statement conditioned on aws:SecureTransport = false.
compliant_input := bucket_policy_input(json.marshal({"Statement": [{
	"Sid": "DenyNonTLSRequests",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}]}))

# Non-compliant: a Deny statement with no SecureTransport condition.
no_condition_input := bucket_policy_input(json.marshal({"Statement": [{
	"Sid": "SomeOtherDeny",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:DeleteBucket",
}]}))

# Non-compliant: the SecureTransport condition sits on an Allow, not a Deny.
condition_on_allow_input := bucket_policy_input(json.marshal({"Statement": [{
	"Sid": "WrongEffect",
	"Effect": "Allow",
	"Principal": "*",
	"Action": "s3:GetObject",
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}]}))

# A compliant policy produces no denials.
test_compliant_passes if {
	count(s3_tls_enforcement.deny) == 0 with input as compliant_input
}

# A Deny with no SecureTransport condition is denied.
test_no_condition_denied if {
	count(s3_tls_enforcement.deny) == 1 with input as no_condition_input
}

# The SecureTransport condition on an Allow does not count - denied.
test_condition_on_allow_denied if {
	count(s3_tls_enforcement.deny) == 1 with input as condition_on_allow_input
}

# The denial message cites the CMMC control ID.
test_denial_cites_control if {
	some msg in s3_tls_enforcement.deny with input as no_condition_input
	contains(msg, "SC.L2-3.13.8")
}