# lambda_vpc_test.rego
# Tests for the GAP-05 Lambda VPC policy.

package terraform.lambda_vpc_test

import rego.v1

import data.terraform.lambda_vpc

# Compliant: a vpc_config with subnets and a security group.
compliant_input := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"after": {"vpc_config": [{
		"subnet_ids": ["subnet-aaa", "subnet-bbb"],
		"security_group_ids": ["sg-aaa"],
	}]}},
}]}

# Non-compliant: no vpc_config at all.
no_vpc_input := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"after": {"vpc_config": []}},
}]}

# Non-compliant: a vpc_config block present but with no subnets.
empty_vpc_input := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"after": {"vpc_config": [{"subnet_ids": []}]}},
}]}

# A compliant plan produces no denials.
test_compliant_passes if {
	count(lambda_vpc.deny) == 0 with input as compliant_input
}

# A Lambda with no vpc_config is denied.
test_no_vpc_denied if {
	count(lambda_vpc.deny) == 1 with input as no_vpc_input
}

# A Lambda with an empty vpc_config is denied.
test_empty_vpc_denied if {
	count(lambda_vpc.deny) == 1 with input as empty_vpc_input
}

# The denial message cites the CMMC control ID.
test_denial_cites_control if {
	some msg in lambda_vpc.deny with input as no_vpc_input
	contains(msg, "SC.L2-3.13.1")
}