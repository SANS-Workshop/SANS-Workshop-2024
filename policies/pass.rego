package aws.validation

import rego.v1

# The name of the policy. Rego uses the prefix before the _ to determine if the policy is:
# * warn - print a warning but don't fail
# * deny - fail the policy
# * violation - logs a policy violation but don't fail
deny_alwayspass contains {
	"msg": "i should always pass", # The error message if the policy fails evaluation
	"details": {"pass": "pass"}, # The additional details that can be provided during failure
} if {
	# The evaluation evaluation of the policy. false passes, true fails.
	false
}
