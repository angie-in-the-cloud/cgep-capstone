# iam_no_wildcard.rego
# GAP-07 - IAM role policies must not grant wildcard actions. A role's
# permissions must match the actions its workload actually uses.
#
# Scope: aws_iam_role_policy (inline role permission policies). Resource
#   policies and KMS key default policies are governed separately and
#   legitimately use broader grants.
#
# CMMC: AC.L2-3.1.5 - employ the principle of least privilege.
# Severity: high
# Remediation: replace wildcard actions (* or service:*) with the
#   explicit actions the workload calls.

package terraform.iam_no_wildcard

import rego.v1

# Collect inline IAM role policy resources from the plan.
#
# Scope note: this policy targets workload role permissions only. Pipeline
# roles (e.g., the GitHub Actions OIDC role) are excluded - they inherently
# require broad enumerated actions to plan and apply Terraform, and their
# permissions are reviewed as part of pipeline design, not GAP-07.
pipeline_role_addresses := {
	"aws_iam_role_policy.github_actions",
}

role_policies contains rc if {
	rc := input.resource_changes[_]
	rc.type == "aws_iam_role_policy"
	not pipeline_role_addresses[rc.address]
}

# Normalize Action into a list, whether it arrives as a string or a list.
action_list(stmt) := stmt.Action if {
	is_array(stmt.Action)
}

action_list(stmt) := [stmt.Action] if {
	is_string(stmt.Action)
}

# An action is a wildcard if it is "*" or ends in ":*".
is_wildcard(action) if action == "*"

is_wildcard(action) if endswith(action, ":*")

# Deny any role policy statement containing a wildcard action.
deny contains msg if {
	rc := role_policies[_]
	doc := json.unmarshal(rc.change.after.policy)
	stmt := doc.Statement[_]
	action := action_list(stmt)[_]
	is_wildcard(action)

	msg := sprintf(
		"[AC.L2-3.1.5] %s grants wildcard action '%s' in statement '%s'; least privilege requires explicit actions.",
		[rc.address, action, stmt.Sid],
	)
}