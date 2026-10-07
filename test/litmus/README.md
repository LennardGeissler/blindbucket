# Litmus tests for S3-compatible stores

`S3-compatible` fixes the API. It does not fix what a store does with a
conditional write it does not support, or which of two overlapping writes it
keeps. The gateway's correctness depends on both ([ADR-020](../../docs/adr/ADR-020-conditional-writes-measured.md),
[ADR-025](../../docs/adr/ADR-025-writes-rank-by-when-they-began.md)), and so
does any other design that coordinates through S3. These tests measure them.

Each test is a fixed sequence of requests against a scratch key. The verdict
depends on what the store answers *and* on what it holds afterwards, because a
store can answer 200 and still not have done what was asked.

| Test | Requests | Verdicts |
|---|---|---|
| `cond-put-inm` | PUT original; PUT with `If-None-Match: *` | **enforced** (412, original kept), **ignored** (2xx, overwritten), refused (other error) |
| `cond-put-im` | PUT original; PUT with a wrong `If-Match` | the same |
| `cond-complete-im` | PUT original; multipart upload completed with a wrong `If-Match` | the same |
| `cond-complete-inm` | PUT original; multipart upload completed with `If-None-Match: *` | the same |
| `copy-source-im` | `UploadPartCopy` with a wrong `x-amz-copy-source-if-match` | the same |
| `overlap-mpu-mpu` | upload A created, then B a second later; B completes, then A | which one the key holds; whether A's completion was acknowledged or refused |
| `overlap-mpu-put` | upload A created; a PUT a second later; A completes | the same |
| `read-after-write` | 20 × PUT, then at once HEAD and a listing | how many were missed |

Every response is also checked for an `<Error>` body inside a `200`, which AWS
documents for `CompleteMultipartUpload` and which an SDK would hide.

`litmus.py` uses only the Python standard library, with its own SigV4 signer
and path-style addressing, so that no SDK retries, parses or smooths over a
response. It writes under `litmus/<run>/` and deletes what it wrote.

## Running it

```sh
docker compose up -d                 # MinIO on :9002
test/providers/garage.sh             # Garage on :3900
test/providers/seaweedfs.sh          # SeaweedFS on :8333

python3 test/litmus/litmus.py --provider garage --repeat 5 \
  --endpoint http://localhost:3900 --region garage --bucket blindbucket-test \
  --access-key GK0123456789abcdef01234567 \
  --secret-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --out results/garage.jsonl

python3 test/litmus/summarise.py results/*.jsonl
```

## Results, 2026-10-07

Five repetitions per test. MinIO, Garage and SeaweedFS ran in Docker on one M4;
AWS S3 in eu-central-1 was reached from the same laptop over the internet, in a
bucket created for the run and deleted after it
([`results/2026-10-07/`](results/2026-10-07/): raw JSON lines and versions).

| Test | MinIO RELEASE.2026-09-22 | Garage v2.4.1 | SeaweedFS 4.48 | AWS S3 |
|---|---|---|---|---|
| `cond-put-inm` | enforced 5/5 | **ignored** 5/5 | enforced 5/5 | enforced 5/5 |
| `cond-put-im` | enforced 5/5 | **ignored** 5/5 | enforced 5/5 | enforced 5/5 |
| `cond-complete-im` | enforced 5/5 | **ignored** 5/5 | enforced 5/5 | enforced 5/5 |
| `cond-complete-inm` | enforced 5/5 | **ignored** 5/5 | enforced 5/5 | enforced 5/5 |
| `copy-source-im` | enforced 5/5 | enforced 5/5 | enforced 5/5 | enforced 5/5 |
| `overlap-mpu-mpu` | last completed 5/5 | **last created**; loser refused (`NoSuchUpload`) 5/5 | last completed 5/5 | **last created; loser acknowledged** (`200`) 5/5 |
| `overlap-mpu-put` | last completed 5/5 | **last begun**; loser refused (`NoSuchUpload`) 5/5 | last completed 5/5 | **last begun; loser acknowledged** (`200`) 5/5 |
| `read-after-write` | consistent 5/5 | consistent 5/5 | consistent 5/5 | consistent 5/5 |
| error inside a `200` | none | none | none | none |

Garage accepts every conditional write it does not implement, and answers it
as a success. Its documentation says it has no conditional writes; nothing in
the protocol does. A design that coordinates through `If-None-Match` therefore
works on MinIO and SeaweedFS and silently does nothing on Garage.

Overlapping writes split the four stores three ways. MinIO and SeaweedFS keep
the write that completed last. Garage and AWS keep the one that began last, but
Garage tells the loser, and AWS answers it `200` and drops it. A design that
treats a successful completion as "my object is the one the key holds" is
correct on two of the four and wrong on AWS (ADR-025).

No error inside a `200` showed up in these runs. AWS sent one for a failed
`If-None-Match` completion during the integration suite on 2026-10-03 (#62), so
it happens; five repetitions here did not provoke it.

**Python and TLS.** The python.org installer for macOS ships without CA
certificates until its `Install Certificates.command` is run; against AWS the
run used Homebrew's Python, which has them. `--session-token` takes the token of
temporary credentials (`aws configure export-credentials`).

Ceph RGW was planned as the fourth store. Its demo image exists for amd64
only, and under emulation on an arm64 Mac its OSD fails to create its object
store, so it is not here.
