# SANS CloudSecNext Summit 2024 - Security Configuration Management in the Cloud: Policy as Code for CI/CD Gating

Welcome to our hands-on workshop, we are excited to have you join us for an engaging and informative session where you'll learn how to integrate Open Policy Agent (OPA) with GitHub Actions to enforce policy-as-code using Terraform as an example.

As organizations increasingly adopt Infrastructure as Code (IaC) practices, ensuring that infrastructure configurations are compliant with security and governance policies becomes crucial. Open Policy Agent (OPA) is a powerful, open-source policy engine that allows you to define and enforce policies across your infrastructure. 

During this workshop we will complete the [Setup](#setup), [Working with code locally](#working-with-code-locally), [Review the Pipeline](#review-the-pipeline), [Review an OPA Policy](#review-an-opa-policy) and [Exercise 1](#exercise-1---github-actions-and-a-failing-pipeline) as a group. The remainder will be done independently.

## Table of Contents
1. [Prerequisites](#prerequisites)
1. [Reference Materials](#reference-materials)
1. [Setup](#setup)
1. [Working with code locally](#working-with-code-locally)
    1. [Using the Command Line](#using-the-command-line)
1. [Development with GitHub Actions](#development-with-github-actions)
1. [Development with Rego Playground](#development-with-rego-playground)
1. [Local Development - Optiona](#local-development---optiona)
    1. [Creating terraform output files](#creating-terraform-output-files)
    1. [Options for formatting the json output](#options-for-formatting-the-json-output)
    1. [Evaluating our terraform plan output](#evaluating-our-terraform-plan-output)
1. [Exercises](#exercises)
    1. [Review the pipeline](#review-the-pipeline)
    1. [Review an OPA Policy](#review-an-opa-policy)
    1. [Exercise 1 - Github Actions and a Failing Pipeline](#exercise-1---github-actions-and-a-failing-Pipeline)
    1. [Exercise 2 - Enforce Encryption of RDS](#exercise-2---enforce-encryption-of-rds)
    1. [Exercise 3 - Enforce Tagging Resource](#exercise-3---enforce-tagging-resource)
    1. [Exercise 4 - Encryption Exception Case for Databases with Public Data](#exercise-4---encryption-exception-case-for-databases-with-public-data)
    1. [Bonus Exercise](#bonus-exercise)
1. [Next Steps](#next-steps)
1. [Questions you may have](#questions-you-may-have)

## Prerequisites 
**Required**
* Github.com Account
* Installed locally: git
* IDE / Code Editor

**Optional**
* Installed locally: Docker/Docker Compose OR Podman/Podman Compose
* Installed locally: Conftest
* Installed locally: Terraform

## Reference Materials
- [OPA Overview](https://www.openpolicyagent.org/docs/latest/#rego)
- [OPA Language Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [OPA Cheat Sheet](https://docs.styra.com/opa/rego-cheat-sheet)

## Setup
**Fork the repository and first Github Action**

1. Fork the repo into your own account, allowing you to use the github runners. This can be done using the fork button at the top of the repository page.<br>
    <img src="https://i.imgur.com/I2P0oyh.png" alt="Fork repo" height="30"/>
1. Click "Create a new fork"<br>
    <img src="https://i.imgur.com/SLJaHeH.png" alt="Create fork" height="60"/>
1. On the "Create a new fork" page, at the bottom click "Create fork"<br>
    <img src="https://i.imgur.com/kpsYZI7.png" alt="Create fork button" height="30"/>
1. Open up the browser to your forked version of the code (https://github.com/<YOUR_GITHUB_ID>/SANS-Workshop-2024).
1. Select the "Actions" Tab <br>
    <img src="https://i.imgur.com/t7aVNod.png" alt="Actions Tab" height="30"/>
1. Click "Enable Action on this repository" <br>
    <img src="https://i.imgur.com/GGyUQkH.png" alt="Enable Actions" height="30"/>
1. Click back to the "Code" tab.<br>
    <img src="https://i.imgur.com/6giwVXG.png" alt="Code tab" height="30"/>
1. Create a branch by clicking the branch button that will say "main", then enter the branch name "workshop", and click "Create branch workshop from main"<br>
    <img src="https://i.imgur.com/RHgXbvC.png" alt="branch menu" width="200"/>
1. Where the README is being display click the pencil button to edit the read me.<br>
    <img src="https://i.imgur.com/3pYMjin.png" alt="readme-edit" width="200"/>
1. Add a minor change to the file (like a period at the end on the title). Then click the "Commit changes..." button.<br>
    <img src="https://i.imgur.com/kiDWRQ5.png" alt="Commit changes button" height="30"/>
1. On the "Commit Changes" dialog, click the "Commit changes" button (you can also update the commit message).<br>
    <img src="https://i.imgur.com/iuTZUGp.png" alt="Commit changes button" height="200"/>
1. Click "Pull Requests" tab. <br>
    <img src="https://i.imgur.com/xHnQzoT.png" alt="PR tab" height="30"/>
1. There should be a message at the top indicating your new branch has changed, click the "Compare & pull request" button".<br>
    <img src="https://i.imgur.com/Gh1iZL5.png" alt="PR message" height="30"/>
1. On the Open a pull request page, select the destination to be your version of the repository and the main branch, and your version of the repository and your new branch.<br>
    <img src="https://i.imgur.com/OOdEc4X.png" alt="PR message" height="70"/>
1. Click the "Create pull request" button.<br>
    <img src="https://i.imgur.com/oj6KTjI.png" alt="Create pull request button" height="30"/>
1. Give the actions about 30 seconds to start and you should see them begin to run.<br>
    <img src="https://i.imgur.com/ESTJOie.png" alt="PR action decorator" height="70"/>
1. Clicking one of the "Detail links will take you to the action (alternatively you can click the Actions tab at the top and select the running action).<br>
    <img src="https://i.imgur.com/ezoPaJ6.png" alt="Action page" height="150"/>

:fireworks: _Congrats, you have successfully run your first pipeline action with Policy as Code gating._ :fireworks: 


## Working with code locally
There are many ways to pull the source code to your local machine. We will detail using the command line, but you can choose your preferred method.

### Using the Command Line

**Download the code to your local machine**

Clone the repo to your local machine using your preferred method. From a command prompt run: ```git clone https://github.com/<YOUR_GITHUB_ID>/SANS-Workshop-2024.git```

**Upload the code back to the repository**

When you are ready to commit code back to the repository:
* cd into the directory you want the code checked out.
* Run: ```git add .``` stage the code for committing
* Run: ```git commit -m'updates to workshop'``` to commit the code the change
* Run ```git push``` to push the code up to the remote repository

Here is what the output will look like:
```console
SANS-Workshop-2024$ git add .
SANS-Workshop-2024$ git commit -m'updates to workshop'
[main 41a7ade] updates to workshop
 1 file changed, 65 insertions(+), 20 deletions(-)
SANS-Workshop-2024$ git push
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 1.69 KiB | 1.69 MiB/s, done.
Total 3 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
To github.com:SANS-Workshop/SANS-Workshop-2024.git
   1109cbc..41a7ade  main -> main
```

If you committed to a branch with an active PR, you can navigate back to your repository in github.com and see the action executing.

Now you can open the code you just checked out in your preferred IDE.

##  Development with GitHub Actions
In our simulated scenario, GitHub actions is our CI tool and also provides the gating for our OPA rules. It runs a containerized environment that executes the terraform plans and OPA validations. Using this we can both gate our work flow as well as test our changes without the need for specific tooling on our local machine.

We walked through initiating an action in the [Setup](#setup) section. We will further want through it in [Exercise 1 - Github Actions and a Failing Pipeline](#exercise-1---github-actions-and-a-failing-pipeline)

## Development with Rego Playground
We can use the [Rego Playground](https://play.openpolicyagent.org/) to do virtual development. We can copy the terraform plan outputs into the input section and work on the policy in the coding section. The rego output is displayed in the outputs and any print statements have display in the browser's developer console.

## Local Development - Optional
If you want to debug on your local machine, instead of just leveraging github actions, there are two options:
* (_Recommended_) [Use the simulated containerized environment](demo-env/README.md)
* [Setup the each of the tools on your machine and connect to an AWS account](local-debugginf.md)

### Creating terraform output files
_Note: If you are running locally against a real AWS account replace tflocal with terraform_
1. Enter the terraform directory containing the terraform with which you are working. For example run: ```cd /workspace/terraform/rds``` or ```cd /workspace/terraform/s3```
2. Run: ```tflocal init``` to initialize terraform. _If you are familiar with terraform you will notice we are using tflocal instead of terraform. Which is intended to leverage localstack to simulate our AWS account_.
3. Run: ```tflocal plan --out tfplan.binary``` to create a plan for the terraform file and output it as a binary.
4. Run: ```tflocal show -json tfplan.binary > tfplan.json``` to generate the json terraform output the we will evaluate with OPA.


### Options for formatting the json output
The output of the ```tflocal/terraform show``` will not have whitespace formatting, making it hard to read, consider using one of the following options to format the code:
- Use IDEs like VSCode, for example to formant a document right click and select Format and the document will be formatted
- With jq installed, run: ```jq . tfplan.json > tfplan-pretty.json```
- Paste the JSON into the following website and have it formatted for you (Note this is not recommend if the terraform output could have sensitive data in it): https://jsonformatter.org/

### Evaluating our terraform plan output
We use conftest to evaluate the terraform output against our policies.

From the folder where the terraform output was created, run: 
* For JSON output: ```conftest test --all-namespaces -p /workspace/policies tfplan.json --output json```

The output will state whether the policies written were successful or failed.

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


## Exercises

### Review the pipeline
Github Actions defines a workflow pipeline in [.github/workflows/ci.yml](.github/workflows/ci.yml). Lets take a look at the steps it performs to do validation of the planned Terraform.

### Review an OPA Policy
There are already two OPA Policy created in:
* policies/pass.rego - this is a stripped down policy that always passes.
* policies/rds/password.rego - this policy ensures a plaintext password is not set for the database.


### Exercise 1 - Github Actions and a Failing Pipeline
In this exercise we want to trigger Github Actions to test our OPA checks, and observe both a pass and fail output. For the later scenario, we will then to correct our code to get the pipeline to pass.
1. Add a line to the bottom of this README.md
2. Commit and Push the change.
3. Create a pull request for the branch
4. Open the repo in a browser and browse to your PR
5. Open the link to the failing action _Run OPA Tests - rds_
6. Under the failing Validate OPA step expand the Testing 'tfplan.json' against 2 policies in namespace 'aws.validation' section. What is the error?
7. Open the terraform for the RDS in terraform/rds/main.tf and fix the problem
8. Commit and push the code
9. The OPA checks should succeed now.

<details>
<summary>Hint</summary>
The fix is commented out in terraform/rds/main.tf.
</details>

### Exercise 2 - Enforce Encryption of RDS
In this exercise we want to ensure our databases are encrypted.
1. Open the [terraform/rds/main.tf](terraform/rds/main.tf) files. You should see that storage encryption (```storage_encrypted```) is disabled.
2. If your local environment setup you can [run the steps to generate the plan outputs](#creating-terraform-output-files) with ```storage_encrypted``` set to true and false. Otherwise the plan files are in [testfiles/aws/rds/encryption](testfiles/aws/rds/encryption).
3. Evaluate the difference in the plan outputs. 
4. Write a policy in the policies/rds folder.

_Bonus_ - In terraform, if a parameter is not required it will have a default value assignment if it is not specified. In the case of ```storage_encrypted```, the default value is false. Remove the ```storage_encrypted``` parameter and redo the plan (or look in [testfiles/aws/rds/encryption/not-set](testfiles/aws/rds/encryption/not-set)). How does this compare to the other plan outputs? Will your policy need to be updated to cover this case?

### Exercise 3 - Enforce Tagging Resources
In this exercise we want to ensure all our resources have proper tags.
1. Open the [terraform/rds/main.tf](terraform/rds/main.tf) and the [terraform/s3/main.tf](terraform/s3/main.tf) files. You should see the lines commented out to enable tagging.
2. If your local environment setup you can [run the steps to generate the plan outputs](#creating-terraform-output-files) with and without tagging enabled. Otherwise the plan files are in [testfiles/aws/s3/tagging](testfiles/aws/s3/tagging) and [testfiles/aws/rds/tagging](testfiles/aws/rds/tagging)
3. Evaluate the difference in the plan outputs. 
4. Write a policy in the policies folder that requires a ```data_classification``` and ```owner_email tag```.

<details>
<summary>Hint</summary>

Undefined or null references will cause the expression block to halt and exit immediately. If you have checks for null, break them up into multiple expressions, wrap in functions, or use a combination of ```is_object(resource)``` and  ```contains_element(object.keys(resource), "KEY")```
</details>
<p>

_Bonus_ - Have you validated the tagging values? Making sure people are providing good data is important for resource tagging. Ensure that the values are constrained to:
* ```data_classification``` is either public or private.
* ```owner_email``` is a valid email address. 

<details>
<summary>Hint</summary>
Rego supports regex expressions to do the email validation: https://docs.styra.com/opa/rego-by-example/builtins/regex
</details>
<p>

_Bonus_ - Some AWS resources do not support tags, for example [Security Hub](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_account). What will happen when your policy evaluates the terraform plan for Security Hub? You can uncomment out the terraform for Security Hub in terraform/securityhub and run an plan (or look in [testfiles/aws/securityhub](testfiles/aws/securityhub) ). Will your policy need to be updated to cover this case?

### Exercise 4 - Encryption Exception Case for Databases with Public Data
In the exercise 2 we ensured our RDS instances were encrypted, but that may not always be required, for example if we are storing public data. We will put in an exception to the encryption requirement if someone has tagged their RDS instance as public.
1. Open the [terraform/rds/main.tf](terraform/rds/main.tf) files.
2. Locate the data_classification tag.
2. If your local environment setup you can [run the steps to generate the plan outputs](#creating-terraform-output-files) with ```data_classification``` set to public and private. Otherwise the plan files are in [testfiles/aws/rds/exception_for_encryption](testfiles/aws/rds/exception_for_encryption).
3. Evaluate the difference in the plan outputs. 
4. Update the policy in the policies/rds folder that you wrote in Exercise 3

<details>
<summary>Hint</summary>

You can chain multiple checks together on multiple lines (in a rule body), and they evaluate with and.
</details>
<p>
<details>
<summary>Hint 2</summary>

There is no intrinsic or in rego, but if you have 2 boolean expressions that are assigned to the same value they will use an or for the assignment. [How to express OR in Rego](https://www.styra.com/blog/how-to-express-or-in-rego/)
</details>
<p>
<details>
<summary>Hint 3</summary>

If you need to nest an and within an or, try putting use a function to wrap the and statement [Functions](https://www.openpolicyagent.org/docs/latest/policy-language/#functions)
</details>
<p>
<details>
<summary>Hint 4</summary>

If you want a function to have a default value if the evaluation fails, you can add a default value, like  ``` funcName(args) if { LOGIC} else := false```
</details>

### Bonus Exercise  
By default new buckets don't allow public access. We can use the terraform resource [s3_bucket_public_access_block](https://registry.terraform.io/providers/hashicorp/aws/3.24.1/docs/resources/s3_bucket_public_access_block) to allow a bucket to be public (also plan is in testfiles/aws/s3/allow-public).

Can you add a restriction that enforces that a bucket that is made public and is also tagged as public? Update the terraform, run some plans and see.

## Next Steps

Repository Setup:
* This is just a sample project. Typically the OPA Policies and the terraform would live in separate repositories so the policies can be shared across multiple terraform repos.

Things to think about:
* When to use Warn vs Deny vs Violation - You can prefix your policy names based on how you want conftest to handle failures. Think about the behavior you want when you are writing the policies. [Read more here](https://www.conftest.dev/)
* Better messaging for errors - Make your error messages as descriptive as possible to help developers understand why the policy is failing.


## Questions you may have
* Why do we do we evaluate the plan vs the terraform directly? Although our examples are very simple, terraform can get complex with levels of indirection through the use of multiple files and modules. The plan is an output of all that combined and gives us a single file for evaluation.
* Why are my trace statements are not printing. Make sure you are not specifying an output, like ```--output json```, as this will suppress printed messages or trace statements.
* My tests are passing when they should fail, why? OPA evaluation will silently fail if it gets a null reference. Try using a print statement (```print(<VARIABLE>```) of what you are evaluating to see what is being checked.
