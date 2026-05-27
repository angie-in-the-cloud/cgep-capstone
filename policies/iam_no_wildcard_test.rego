# iam_no_wildcard_test.rego
# Tests for the GAP-07 IAM wildcard policy.

package terraform.iam_no_wildcard_test

import rego.v1

import data.terraform.iam_no_wildcard

# Helper: wrap an IAM policy document (JSON string) in a resource_changes input.
role_policy_input(policy_json) := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": policy_json}},
}]}

# Compliant: explicit actions only. Includes a string Action and a list
# Action, so normalization is exercised.
compliant_input := role_policy_input(json.marshal({"Statement": [
	{
		"Sid": "DynamoDBWrite",
		"Effect": "Allow",
		"Action": "dynamodb:PutItem",
		"Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/x",
	},
	{
		"Sid": "KMSDataKeys",
		"Effect": "Allow",
		"Action": ["kms:Decrypt", "kms:GenerateDataKey"],
		"Resource": "arn:aws:kms:us-east-1:111122223333:key/x",
	},
]}))

# Non-compliant: a service-wide wildcard (dynamodb:*).
service_wildcard_input := role_policy_input(json.marshal({"Statement": [{
	"Sid": "OverBroadDynamo",
	"Effect": "Allow",
	"Action": "dynamodb:*",
	"Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/x",
}]}))

# Non-compliant: a full wildcard (*).
full_wildcard_input := role_policy_input(json.marshal({"Statement": [{
	"Sid": "FullAdmin",
	"Effect": "Allow",
	"Action": "*",
	"Resource": "*",
}]}))

# Exempt: the pipeline role has wildcards by design. Not denied.
pipeline_role_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.github_actions",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": json.marshal({"Statement": [{
		"Sid": "ReadForPlan",
		"Effect": "Allow",
		"Action": ["s3:Get*", "ec2:Describe*"],
		"Resource": "*",
	}]})}},
}]}

# A compliant policy produces no denials.
test_compliant_passes if {
	count(iam_no_wildcard.deny) == 0 with input as compliant_input
}

# A service-wide wildcard is denied.
test_service_wildcard_denied if {
	count(iam_no_wildcard.deny) == 1 with input as service_wildcard_input
}

# A full wildcard is denied.
test_full_wildcard_denied if {
	count(iam_no_wildcard.deny) == 1 with input as full_wildcard_input
}

# The denial message cites the CMMC control ID.
test_denial_cites_control if {
	some msg in iam_no_wildcard.deny with input as service_wildcard_input
	contains(msg, "AC.L2-3.1.5")
}

# The pipeline role is exempt - wildcards on github_actions are not denied.
test_pipeline_role_exempt if {
	count(iam_no_wildcard.deny) == 0 with input as pipeline_role_input
}