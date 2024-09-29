package aws.validation

import rego.v1

deny_rdspassword contains {
	# Our error message specific to the policy
	"msg": "RDS should not specify passwords",
	"details": {"rds_with_password": rds_with_password}, # If the policy fails, output which resources caused the violation
} if {
	# this takes the values returned from the block and assigns it to data_resources
	data_resources := [resource |
		# this loops over the resources in input.planned_values.root_module
		some resource in input.planned_values.root_module.resources

		# this is a conditional on if the resource should be returned. in this case it checks
		# if it is type aws_db_instance
		resource.type in {"aws_db_instance"}
	]

	# this takes the values returned from the block and assigns it to rds_with_password
	# -> these are our failing resources
	rds_with_password := [rds.name |
		# loop over the data_resources that were set above
		some rds in data_resources

		# return values whose password field is not null
		rds.values.password != null
	]

	# this is a print statement for debugging
	print("hello debugging")

	# If the count of resources with a password is not zero we fail
	# Remember: In rego 'true' is a failure
	count(rds_with_password) != 0
}
