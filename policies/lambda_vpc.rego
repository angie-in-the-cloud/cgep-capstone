# lambda_vpc.rego
# GAP-05 - Lambda functions handling CUI must run inside a VPC, not the
# default Lambda environment, so their network path sits on a defined
# boundary.
#
# CMMC: SC.L2-3.13.1 - monitor and control communications at system
#   boundaries.
# Severity: medium
# Remediation: add a vpc_config block referencing private subnets and a
#   security group on the aws_lambda_function.

package terraform.lambda_vpc

import rego.v1

# Collect Lambda function resources from the plan.
functions contains rc if {
	rc := input.resource_changes[_]
	rc.type == "aws_lambda_function"
}

# A function is in a VPC if it has a vpc_config entry with at least
# one subnet.
in_vpc(rc) if {
	vpc := rc.change.after.vpc_config[_]
	count(vpc.subnet_ids) > 0
}

# Deny any Lambda function not deployed inside a VPC.
deny contains msg if {
	rc := functions[_]
	not in_vpc(rc)

	msg := sprintf(
		"[SC.L2-3.13.1] %s is not deployed inside a VPC; CUI-handling Lambdas must set vpc_config with private subnets.",
		[rc.address],
	)
}