# The network benchmark on AWS (M9)

Every throughput figure before this measured the gateway against a MinIO in a VM
on the same laptop, so the provider was microseconds away and the gateway's
added round trip was the only one. [`template.yaml`](template.yaml) puts the
gateway where a deployment would: on an EC2 instance in the same region as the
bucket, with S3 a real network hop away. [`bench/aws-run.sh`](../../bench/aws-run.sh)
then runs the same matrix as [`bench/warp.sh`](../../bench/warp.sh), direct and
through the gateway, alternating which goes first.

The stack is separate from [`deploy/aws-test`](../aws-test/), because it costs by
the hour and should exist only while a run does:

- **an instance**, `c7g.2xlarge` by default (Graviton, 8 vCPUs, up to 15 Gbit/s),
  running the release named by `Version` from its published archive, checked
  against the release's `checksums.txt`. It has no key pair and no inbound
  port; a run is started through Systems Manager. It **terminates itself after
  `MaxHours`** (default 5), whatever else happens.
- **a bucket of its own**, `blindbucket-bench-<account id>`, which warp clears
  at every run. Results are written under `results/` once the last run is done.
  Objects expire after three days.
- **a role for the instance**, allowed that bucket and nothing else, plus
  Session Manager. warp's direct path and the gateway's upstream both take
  their credentials from it through IMDSv2. For the gateway that is
  `credential_source: imds` ([ADR-024](../../docs/adr/ADR-024-aws-credentials-without-the-sdk.md)),
  which until now was tested only against a stub.

## Cost

An estimate, not a measurement, for the default matrix (3 sizes × 3
concurrencies × PUT and GET × 3 repetitions × 2 paths = 108 runs of 30 s), which
takes about two to two and a half hours:

| | |
|---|---|
| Instance, ~2.5 h at roughly $0.35/h | ~$1 |
| PUT requests, dominated by 1 KiB at 64 clients: several hundred thousand at $0.0054 per 1000 | ~$3–5 |
| GET, LIST, storage for minutes, traffic within the region | cents |
| **Total** | **~$4–6** |

That can cross the account's $5 budget alert. `BENCH_REPEAT=2` or
`BENCH_CONCURRENCY="1 16"` roughly halves the request cost, at the price of the
statistics or of the most loaded cell.

## Running it

From a machine with the AWS CLI logged in to the account:

```sh
aws cloudformation deploy --region eu-central-1 \
  --stack-name blindbucket-bench \
  --template-file deploy/aws-bench/template.yaml \
  --capabilities CAPABILITY_IAM

id=$(aws cloudformation describe-stacks --region eu-central-1 \
  --stack-name blindbucket-bench \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text)

# A few minutes after the stack completes, the instance registers with SSM:
aws ssm describe-instance-information --region eu-central-1 \
  --query "InstanceInformationList[?InstanceId=='$id'].PingStatus" --output text
```

Start the run. `send-command` needs no Session Manager plugin, and its time limit
has to cover the whole matrix:

```sh
cmd=$(aws ssm send-command --region eu-central-1 --instance-ids "$id" \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["/opt/blindbucket/bench/aws-run.sh"],executionTimeout=["16200"]' \
  --query Command.CommandId --output text)

aws ssm get-command-invocation --region eu-central-1 \
  --command-id "$cmd" --instance-id "$id" --query Status --output text
```

When it reports `Success`, fetch the results, then empty the bucket (a stack
cannot delete a bucket that still holds objects) and delete the stack:

```sh
bucket=blindbucket-bench-$(aws sts get-caller-identity --query Account --output text)
aws s3 cp --recursive "s3://$bucket/results/" bench/results-aws/
aws s3 rm --recursive "s3://$bucket"
aws cloudformation delete-stack --region eu-central-1 --stack-name blindbucket-bench
```

A shorter matrix for a first try, passed to the script as environment:

```sh
--parameters 'commands=["BENCH_SIZES=1KiB BENCH_CONCURRENCY=16 BENCH_REPEAT=1 /opt/blindbucket/bench/aws-run.sh"],executionTimeout=["3600"]'
```

## What a result does and does not say

The ratio between the two paths, and the latency the gateway adds per request,
measured against a real provider from where a gateway would sit. It is one
instance type, one region and one time of day; S3's own variance across runs is
part of what the repetitions are for, and the summary reports the spread next
to the median for that reason. It says nothing about a gateway in a different
region from its bucket, where the provider's round trip dominates both paths.
