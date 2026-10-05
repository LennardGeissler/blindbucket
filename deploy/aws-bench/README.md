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
  at every run. Objects expire after three days.
- **a results bucket**, `blindbucket-bench-results-<account id>`, written once
  the last run is done and never touched by warp. Results expire after thirty
  days. (They once sat under `results/` in the first bucket, and the next run on
  the same stack deleted them before it began.)
- **a role for the instance**, allowed those two buckets and nothing else, plus
  Session Manager. warp's direct path and the gateway's upstream both take
  their credentials from it through IMDSv2. For the gateway that is
  `credential_source: imds` ([ADR-024](../../docs/adr/ADR-024-aws-credentials-without-the-sdk.md)),
  which until now was tested only against a stub.

## Cost

Prices are eu-central-1's, read from AWS's price list on 2026-10-05: $0.0054 per
1000 PUT or LIST requests, $0.00043 per 1000 GET requests, $0.33 an hour for a
c7g.2xlarge. Traffic between the instance and a bucket in its region is free.

What a run costs is decided by how many requests S3 answers, and that is not
known before a run: at 1 KiB, every client keeps one request in flight, so the
request rate is the number of clients over S3's latency. The default matrix (3
sizes × 3 concurrencies × PUT and GET × 3 repetitions × 2 paths = 108 runs of
30 s, about two and a half hours) under three assumptions for that latency:

| S3 latency, PUT / GET | PUT requests | GET requests | PUT | GET | Instance | **Total** |
|---|---:|---:|---:|---:|---:|---:|
| 15 / 8 ms | ~1.1 M | ~1.8 M | $5.84 | $0.78 | $0.91 | **~$7.50** |
| 25 / 12 ms | ~0.7 M | ~1.2 M | $3.74 | $0.52 | $0.91 | **~$5.20** |
| 40 / 20 ms | ~0.5 M | ~0.7 M | $2.56 | $0.31 | $0.91 | **~$3.80** |

Almost all of it is 1 KiB at 64 clients. The instance cannot cost more than
`MaxHours` of itself, $1.65 at the default of five; nothing else in the stack
costs by the hour beyond fractions of a cent.

**Calibrate before the full run.** The short run below takes minutes and costs
cents, and its results give the real request rate at 1 KiB and 16 clients
(`obj/s` in `results.md`). Multiplied by 4 for 64 clients, by 6 runs of 30 s and
by $0.0054 per 1000, that is the largest line of the bill. The upper case
crosses the account's $5 budget alert. `BENCH_REPEAT=2` cuts a third,
`BENCH_DURATION=20s` another third, `BENCH_CONCURRENCY="1 16"` removes most of
it, each at the price of statistics or of the most loaded cell.

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

When it reports `Success`, fetch the results, then empty both buckets (a stack
cannot delete a bucket that still holds objects) and delete the stack:

```sh
account=$(aws sts get-caller-identity --query Account --output text)
aws s3 cp --recursive "s3://blindbucket-bench-results-$account/" bench/results-aws/
aws s3 rm --recursive "s3://blindbucket-bench-$account"
aws s3 rm --recursive "s3://blindbucket-bench-results-$account"
aws cloudformation delete-stack --region eu-central-1 --stack-name blindbucket-bench
```

A shorter matrix for a first try, passed to the script as environment:

```sh
--parameters 'commands=["BENCH_SIZES=1KiB BENCH_CONCURRENCY=16 BENCH_REPEAT=1 /opt/blindbucket/bench/aws-run.sh"],executionTimeout=["3600"]'
```

## Runs so far

**2026-10-05**, `1.1.0`, the default matrix. Results, raw output and method:
[bench/figures/aws/](../../bench/figures/aws/). The 1 KiB and 10 MiB cells took
one pass of about 80 minutes; the 1 GiB cells were measured again in a second
pass of about 35 minutes, after the first refused them all (warp's multipart
uploads need `allow_unsigned_payload`, now set by `bench/aws-run.sh`). The
instance ran for about 2 h 20 min. Cost: estimated at about $5 from the request
counts; the billed figure replaces this once AWS has posted it.

## What a result does and does not say

The ratio between the two paths, and the latency the gateway adds per request,
measured against a real provider from where a gateway would sit. It is one
instance type, one region and one time of day; S3's own variance across runs is
part of what the repetitions are for, and the summary reports the spread next
to the median for that reason. It says nothing about a gateway in a different
region from its bucket, where the provider's round trip dominates both paths.
