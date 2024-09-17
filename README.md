# SANS CloudSecNext Summit 2024 - Workshop.

## Prerequisites 
**Required**
* Github.com Account
* Installed locally: git
* IDE / Code Editor

**Optional**
* Installed locally: Docker/Docker Compose OR Podman/Podman Compose
* Installed locally: Conftest
* Installed locally: Terraform


## Local Debugging

### Conftest and Terraform
_This will require a AWS account to test against or localstack running._

### Containerized Environment

#### Starting the debugging Environment 
1. Open a command prompt or terminal in the demo-env directory.
2. Run ```docker-compose up``` or ```podman compose up```. If this is the first time you are starting the containers it may take a little time for it to download everything and start. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
This starts 2 containers: 
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  a) confest/terraform debugging environment <br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; b) a localstack environment that simulates an AWS account.

3. In a new terminal type ```docker exec -it demo-env-runtime-1 bash``` or ```podman exec -it demo-env-runtime-1 bash```. This will open a shell in our debugging environment.
   
NOTE : _The working directory in the container is workspace_

#### Creating terraform output files

1. Enter the terraform directory containing the terraform you are working with, for example run: ```cd /workspace/terraform/rds``` or ```cd /workspace/terraform/s3```
2. Run ```tflocal init``` to initialize terraform. _If you are familar with terraform you will notice we are using tflocal instead of terraform. This is to leverage localstack to simulate our AWS account_
3. Run ```tflocal plan --out tfplan.binary``` to create a plan for the terraform file and output it as a binary.
4. Run ```tflocal show -json tfplan.binary > tfplan.json``` to generate the json terraform output the we will evaluate with OPA.


#### Options to formatting the json output:
The output of the tflocal show will not have whitepace formatting, making it hard to read, you can use one of the following options to format the code:
- IDEs like VSCode you can right click and select Format and the document will be formatted
- If you have jq installed you can run: ```jq . tfplan.json > tfplan-pretty.json```
- You can paste the JSON into this website and have it formatted for you (in a real world scenario the terraform output could have sensitive data in it and this is not recommended): https://jsonformatter.org/

#### Evaluating our terraform plan output
We use conftest to evaluate our terraform output against our policies.

From the folder where the terraform output was created, run: ```conftest test --all-namespaces -p /workspace/policies tfplan.json --output json```

It will output if the policies that are written are successful or fail.

Example:
```json
[
        {
                "filename": "tfplan.json",
                "namespace": "aws.validation",
                "successes": 1,
                "failures": [
                        {
                                "msg": "RDS should not specify passwords",
                                "metadata": {
                                        "details": {
                                                "rds_with_password": [
                                                        "my_db"
                                                ]
                                        }
                                }
                        }
                ]
        }
]
```

##  Debugging with GitHub Actions
In our simulated scenario, GitHub actions is our CI tool and also provides the gating for our OPA rules. It runs a containerized environment that executes the terraform plans and OPA validations. Using this we can both gate our work flow as well as test our changes without the need for specific tooling on our local machine.

We will walkthrough this process in the [Setup](#setup) and [Exercise 1 - Github Actions and a Failing Pipeline](#exercise-1---github-actions-and-a-failing-pipeline)

## Reference Materials
- [OPA Overview](https://www.openpolicyagent.org/docs/latest/#rego)
- [OPA Language Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [OPA Cheat Sheet](https://docs.styra.com/opa/rego-cheat-sheet)

## Workshop

We will do the [Setup](#setup), [Review the Pipeline](#review-the-pipeline), [Review an OPA Policy](#review-an-opa-policy) and [Exercise 1](#exercise-1---github-actions-and-a-failing-pipeline) as a group. The remainder will be done independently.

### Setup
1. Fork the repo into your own account (this will allow you to use the github runners)
2. Checkout the repo to your local machine
3. Create a branch work from
4. Open your code in you preferred IDE

### Review the pipeline
Github actions defines it's pipeline in .github/workflows/ci.yml. Lets take a look at the steps it performs to do validation of the planned Terraform.

### Review an OPA Policy
There is already two OPA Policy created in:
* policies/pass.rego - this is a stripped down policy that always passes
* policies/rds/password.rego - this policy ensures a plaintext password is not set for the database


### Exercise 1 - Github Actions and a Failing Pipeline
In this exercise we want to trigger Github Actions to run our OPA checks, see them pass and also see them fail. Then we want to correct our code to get the pipeline to pass.
1. Add a line to the bottom of this README.md
2. Commit and Push the change.
3. Create a pull request for the branch
4. Open the repo in a browser and browse to your PR
5. Open the link to the failing action _Run OPA Tests - rds_
6. Under the failing Validate OPA step expand the Testing 'tfplan.json' against 2 policies in namespace 'aws.validation' section. What is the error?
7. Open the terraform for the RDS in terraform/rds/main.tf and fix the problem (hint there is a comment that )
8. Commit and push the code
9. The OPA checks should succeed now.

### Exercise 2 - Enforce Encryption of RDS
In this exercise we want to ensure our databases are encrypted.
1. Open the terraform/rds/main.tf files. You should see that storage encryption (```storage_encrypted```) is disabled
2. If you have your local environment setup you can run the steps to generate the plan outputs with ```storage_encrypted``` set to true and false. Otherwise the plan files are in testfiles/aws/rds/encryption
3. Evaluate the difference in the plan outputs. 
4. Write a policy in the policies/rds folder

_Bonus_ - In terraform if a parameter is not required, it will have a default value if it is not specified. In the case of ```storage_encrypted``` encryption the default value is false. Remove the ```storage_encrypted``` parameter and redo the plan (or look in testfiles/aws/rds/encryption/not-set). How does this compare to the other plan outputs? Will your policy need to be updated to cover this case?

### Exercise 3 - Enforce Tagging Resources
In this exercise we want to ensure all our resources have proper tags.
1. Open the terraform/rds/main.tf and the terraform/s3/main.tf files. You should see the lines commented out to enable tagging.
2. If you have your local environment setup you can run the steps to generate the plan outputs with and without tagging enabled. Otherwise the plan files are in testfiles/aws/s3/tagging and testfiles/aws/rds/tagging
3. Evaluate the difference in the plan outputs. 
4. Write a policy in the policies folder that requires a data_classification and owner_email tag.

Hint:

>! Undefined or null references will cause the expression block to halt and ext immediately. If you have checks for null, break them up into multiple expressions, wrap in functions, or use a combination of ```is_object(resource)``` and  ```contains_element(object.keys(resource), "KEY")```


_Bonus_ - Have you validated the tagging values? Making sure people are providing good data is important for resource tagging. Ensure that the values are constrained to:
* data_classification is either public or private
* owner_email is a valid email address. 

Hint: 
>! Rego supports regex expressions to do the email validation: https://docs.styra.com/opa/rego-by-example/builtins/regex



_Bonus_ - Some AWS resources do not support tags, for example [Security Hub](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_account). What will happen when your policy evaluates the terraform plan for Security Hub? You can uncomment out the terraform for Security Hub in terraform/securityhub and run an plan (or look in testfiles/aws/securityhub). Will your policy need to be updated to cover this case?

### Exercise 4 - Put in Exception Case Encryption of Databases
In the exercise 2 we ensured our RDS instances were encrypted, but that may not always be required, for example if we are storing public data. We will put in an exception to the encryption requirement if someone has tagged their RDS instance as public.
1. Open the terraform/rds/main.tf files.
2. Locate the data_classification tag.
2. If you have your local environment setup you can run the steps to generate the plan outputs with data_classification set to public and private. Otherwise the plan files are in testfiles/aws/rds/exception_for_encryption
3. Evaluate the difference in the plan outputs. 
4. Update the policy in the policies/rds folder that you wrote in Exercise 3

Hint:

>! You can chain multiple checks together on multiple lines (in a rule body), and they evaluate with and.

Hint 2:

>! There is no intrinsic or in rego, but if you have 2 boolean expressions that are assigned to the same value they will use an or for the assignment. [How to express OR in Rego](https://www.styra.com/blog/how-to-express-or-in-rego/)

Hint 3: 
>! If you need to nest an and within an or, try putting use a function to wrap the and statement [Functions](https://www.openpolicyagent.org/docs/latest/policy-language/#functions)

Hint 4
>! If you want a function to have a default value if the evaluation fails, you can add a default value, like  ``` funcName(args) if { LOGIC} else := false```

### Bonus
By default new buckets don't allow public access. We can use the terraform resource [s3_bucket_public_access_block](https://registry.terraform.io/providers/hashicorp/aws/3.24.1/docs/resources/s3_bucket_public_access_block) to allow a bucket to be public (also plan is in testfiles/aws/s3/allow-public).

Can you put a restriction in that enforces that a bucket being made public, is also tagged as public? Update the terraform, run some plans and see.

## From Here

Repository Setup:
* This is just a sample project. Typically the OPA Policies and the terraform would live in separate repositories so the policies can be shared across multiple terraform repos.

Things to think about:
* Warn vs deny
* Better messaging for errors

Links: 

## Questions
* Why do we do we evaluate the plan vs the terraform directly? Although our examples are very simple, terraform can get complex with levels of indirection through the use of multiple files and modules. The plan is the evaluation of all that combine and gives us a single file for evaluation.
* My trace statements are not printing, why? Make sure you are not specifying an output, like ```--output json```, since this will suppress printed messages or trace statements.
* My tests are passing when they should fail, why? OPA evaluation will silently fail if it gets a null reference. Try using a print statement (```print(<VARIABLE>```)) of what you are evaluating to see what is being checked.




---- 

# Previous readme

This Repository contains Open Agent Policy(OPA) which is an open source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire environment.
Ths repository will enable fine-grained, logic-based policy decisions that can be extended to source external information to make decisions. This repository will be use for training purposes, it 
contain the creation of the OPA Policy as Code for the participants at the SANS CloudSecNext Summit 2024. 

OPA ensures the first time a Terraform code is deployed its in the best possible security state and allows track teams and development pipelines to work quickly without delay and ensure the code is as secure as possible the first time.

# Using Conftest
[Conftest](https://www.conftest.dev/) is a utility to help you write tests against structured configuration data. Here are some of the commands to use conftest.

> **Conftest will be used to verify the input json (for e.g. terraform plan) to validate the configuration against the rules. All rules must be starting with warn_<rule_name> (for advisory policy) and deny_<rule_name> for the mandatory policy.**

*Always add metadata to the rules before pushing to this repo ([example](https://github.com/terraform-opa-governance/blob/main/aws/kms/kms_key_deletion_window_30_days/kms_key_deletion_window_30_days.rego#L9-L29))*

Below are some of the reference commands:-

To [install conftest](https://www.conftest.dev/install/):-
```bash
brew install conftest
```

To format the files:-
```bash
conftest fmt <PATH>
```

To verify the policy:-
```bash
conftest test --all-namespaces <PATH_TO_PASS_OR_FAIL_JSON_File>
```

To run the policy tests (this will check all the *_test.rego files for tests):-
```bash
conftest verify <path-to-root-directory> --report notes
```

## Generating Terraform JSON Output

```bash
terraform init
terraform plan --out tfplan.binary
terraform show -json tfplan.binary > tfplan.json
```

## OPA Policy Folder Structure

The file and directory structure within this repository has been designed to have
a ROOT directory and then it goes to the basic level of Policy, Cloud Provider Name
category and then finally policy and the name of the policy.
OPA Policies are configured to the two enforcement levels of deny and warn which gives the
flexibility to ensure we can remove and update policies in real-time with no
interruption of services or deployments within the CX Organization.

```ruby
.
└── ROOT - DIR
    └── aws - DIR
        └── service_name - DIR
            └── policy_name - DIR
                └── policy.rego - file
                └── policy_test.rego - file
    └── cloud_agnostics - DIR
        └── policy_name - DIR
                └── policy.rego - file
                └── policy_test.rego - file
    └── common-functions - DIR
        └── function_name - DIR
                └── policy.rego - file
                └── policy_test.rego - file
    └── runon - DIR
    └── tfc - DIR        
```

## OPA Policy Package Structure
Package name follows the folder path, for example AWS KMS key policy "enable_kms_key_rotation.rego" package would be--> package aws.kms.enable_kms_key_rotation  (similar to folder structure aws->kms->enable_kms_key_rotation) and for test it would be package aws.kms.enable_kms_key_rotation_test

Policy package name for AWS:
```rego
package aws.SERVICE_NAME.POLICY_NAME

e.g. for AWS KMS key policy "enable_kms_key_rotation.rego" package would be--> package aws.kms.enable_kms_key_rotation
```

Test package name for AWS:
```rego
package aws.SERVICE_NAME.POLICY_NAME_test

e.g. for AWS KMS key policy test "enable_kms_key_rotation_test.rego" package would be--> package aws.kms.enable_kms_key_rotation_test
```
### Pre-commit hooks

Install the pre-commit hooks, this gives you quick feedback about the quality of your code. More information [here](https://pre-commit.com/#quick-start), and the `.pre-commit-config.yaml` in the repository root contains information about the specific checks that are enabled.

You can see the configuration for the module pre-commit hooks [here](./.pre-commit-config.yaml)

### Dependabot

Dependabot configuration can be found [here](./.github/dependabot.yml), you **MUST** define each directory that has code you wish to scan e.g. each terraform directory or if you have multiple other directories with say Python or Node, these will need configuring too.

## External Resources

