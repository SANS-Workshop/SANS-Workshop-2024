package aws.validation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import input

deny_improper_tagging contains {
    "msg": "Resources must be tagged with data_classification and owner_email",
    "details": {
        "resource_no_tag_failure" : resource_no_tag_failure,
        "resource_data_classification_tag_failure": resource_data_classification_tag_failure,
        "resource_owner_email_tag_failure": resource_owner_email_tag_failure
    }
} if {
    data_resources := [resource |
        some resource in input.planned_values.root_module.resources
        resource.type in {"aws_db_instance", "aws_s3_bucket"}
    ]

    resource_no_tag_failure := [ resource.name | 
        some resource in data_resources
        resource.values.tags == null
    ]

    resource_owner_email_tag_failure := [ resource.name | 
        some resource in data_resources
        not regex.match(`^[^@]+@[^@]+\.[^@]+$`, resource.values.tags.owner_email)
    ]

    resource_data_classification_tag_failure := [ resource.name | 
        some resource in data_resources
        not resource.values.tags.data_classification in {"private", "public"}
    ]

    count(resource_owner_email_tag_failure) + count(resource_data_classification_tag_failure) + count(resource_no_tag_failure) != 0

}