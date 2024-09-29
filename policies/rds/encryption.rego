package aws.validation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import input

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
        rds.values.storage_encrypted != true
    ]

    count(rds_with_out_encryption) != 0
}