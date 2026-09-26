# Running the suite against AWS

[`template.yaml`](template.yaml) creates what the integration suite and the
KMS tests need in a real AWS account, and nothing more:

- **a bucket of its own**, `blindbucket-test-<account id>`, with public access
  blocked and a lifecycle rule that expires every object and aborts every
  incomplete upload after a day. Each test run sweeps what it wrote; the rule
  is for the run that crashes first.
- **a KMS key**, `alias/blindbucket-test`, for sealing a keyring (ADR-013).
- **a role for GitHub Actions**, assumed through OIDC, so no access key is ever
  stored anywhere. Only workflows in this repository's `aws` environment can
  assume it, and it may touch only that bucket and that key — the key only for
  `Encrypt` and `Decrypt`, and only with the encryption context blindbucket
  sends or with none.

It costs about a dollar a month for the key, and fractions of a cent per run.

## Setting it up

With the AWS CLI logged in to the account (`aws login` is enough for a
personal one):

```sh
aws cloudformation deploy \
  --region eu-central-1 \
  --stack-name blindbucket-test \
  --template-file deploy/aws-test/template.yaml \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation describe-stacks --region eu-central-1 \
  --stack-name blindbucket-test --query 'Stacks[0].Outputs' --output table
```

The role trusts one repository, named by the prefix of the OIDC token's `sub`
claim. The default is this repository's. For a fork, read yours and pass it:

```sh
gh api repos/<owner>/<repo>/actions/oidc/customization/sub --jq .sub_claim_prefix
#   → --parameter-overrides SubjectPrefix=<that>
```

A repository with immutable subjects has numeric ids in it
(`repo:owner@123/repo@456`), which is why it cannot be derived from the name.
If the account already has a GitHub OIDC provider, add
`CreateOIDCProvider=false` to the overrides.

Then give the repository an `aws` environment carrying the three outputs as
variables — not secrets, none of them is one:

```sh
gh api -X PUT repos/<owner>/<repo>/environments/aws --input - <<JSON
{"reviewers": [{"type": "User", "id": $(gh api users/<owner> --jq .id)}],
 "prevent_self_review": false,
 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
gh api -X POST repos/<owner>/<repo>/environments/aws/deployment-branch-policies -f name=main -f type=branch
gh variable set AWS_ROLE_ARN --env aws --body <RoleArn>
gh variable set AWS_BUCKET   --env aws --body <Bucket>
gh variable set AWS_KMS_KEY  --env aws --body <KeyArn>
```

That environment is the whole of the protection on the GitHub side, so it gets
two rules. **Only `main`** may deploy to it, so a branch cannot run changed
workflow code under the role. **Every run waits for the owner's approval**, so
that neither a compromised account's token nor a merged workflow change that
starts using the environment can spend money unseen. Self-review stays allowed:
every run is started by the owner, and without it none could be approved.

## Running it

```sh
gh workflow run aws.yml
```

The run then waits in *Review deployments* on its page until it is approved.

The run is manual on purpose: it is billed, and it measures a provider rather
than a change.

## Removing it

```sh
aws s3 rm s3://blindbucket-test-<account id> --recursive --region eu-central-1
aws cloudformation delete-stack --region eu-central-1 --stack-name blindbucket-test
```

The key is scheduled for deletion, not deleted: KMS keeps it for seven days,
during which it can be restored. A key pending deletion is not charged for
([KMS pricing](https://aws.amazon.com/kms/pricing/)).
