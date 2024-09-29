package aws.validation

import rego.v1

deny_alwayspass contains {
	"msg": "i should always pass",
	"details": {"pass": "pass"},
} if {
	false
}
