package aws.validation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import input

# we are "cheating" here on handling the null refence with the 
# ```else := false```. We could also properly handle the 
# error with ```is_object(resource)``` and  
# ```contains_element(object.keys(resource), "KEY")```
is_tagged_public(resource) if {
    resource.values.tags.data_classification == "public"
} else := false

check_tagged_as_public_and_unencrypted(tagged_as_public, encrypted) if {
    tagged_as_public == true
    encrypted == false
} else := false

deny_rdsencryption contains {
    "msg": "RDS database must be encrypted",
    "details": {
        "rds_with_out_encryption": rds_with_out_encryption
    }
} if {
    data_resources := [resource |
        some resource in input.planned_values.root_module.resources
        resource.type in {"aws_db_instance"}
    ]

    rds_with_out_encryption := [ rds.name | 
        some rds in data_resources

        encrypted := rds.values.storage_encrypted == true
        tagged_public := is_tagged_public(rds)

        pass_check = encrypted == true
        pass_check = check_tagged_as_public_and_unencrypted(tagged_public, encrypted)

        pass_check != true
    ]

    count(rds_with_out_encryption) != 0
}