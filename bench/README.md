# Benchmarks

Reproducible measurements for the claims the README makes. Hardware and versions
are recorded alongside every result, because a throughput number without them is
decoration.

Published figures and the macro comparison table live in
[figures/](figures/); `results/` is where a run writes and is not committed.

## What is here

| Script | Measures | Benchmark plan row |
|---|---|---|
| `rss-sample.sh` | Resident set of a command over time, separating the one-time Argon2id spike from the steady state while data streams | memory (CLI) |
| `gateway-memory.sh` | Resident set of a **running gateway** while a large object streams through it, end to end over HTTP | memory (gateway) |
| `warp.sh` | MinIO `warp` against the provider directly and through the gateway: throughput and p50/p90/p99 per object size and concurrency | macro, small-object overhead |
| `aws-run.sh` | The same matrix on an EC2 instance against AWS S3 in its region, so the provider is a network hop away; runs on the instance [`deploy/aws-bench/`](../deploy/aws-bench/) creates | macro over a real network (M9) |
| `plot/summarise.py` | Parses `warp` output into `results.csv` and a Markdown comparison table | — |
| `plot/charts.py` | Renders the figures as SVG, light and dark, standard library only | — |

Micro-benchmarks live with the code and run through `make bench`:

```sh
make bench                                   # all packages
go test ./internal/crypto/stream -bench . -benchmem
```

They cover the chunk sizes section 12.5 asks for — 16, 64 and 256 KiB — and run
in CI on every pull request, where `benchstat` compares them against the base
commit and writes the result into the job summary. The comparison reports rather
than fails: a shared runner varies by more than most real regressions, so a
threshold would either fire every week or catch nothing.

## The macro benchmark

The number that matters is not absolute throughput — that is whatever the machine
and the provider can do — but the **ratio** between the two paths, and the extra
latency per request. Both runs hit the same provider on the same machine within
minutes of each other, which is the only thing that makes the ratio mean
anything.

```sh
docker compose up -d
./bin/blindbucket serve --config blindbucket.yaml &

# Docker Desktop: containers reach the host through host.docker.internal.
WARP_DIRECT=host.docker.internal:9002 \
WARP_PROXY=host.docker.internal:9000 \
WARP_PROXY_KEY=... WARP_PROXY_SECRET=... \
  bench/warp.sh results/

# Linux: --network=host and plain loopback.
WARP_DOCKER_ARGS=--network=host \
WARP_PROXY_KEY=... WARP_PROXY_SECRET=... \
  bench/warp.sh results/

python3 bench/plot/summarise.py results/    # results.csv + results.md
python3 bench/plot/charts.py    results/    # the SVGs
```

**Budget the disk.** Each run writes at roughly (throughput × duration) and the
provider frees that space asynchronously, so runs are spaced by `WARP_SETTLE`
seconds. The first version of this script kept objects between runs to save the
upload phase, and filled a 20 GB disk in eleven minutes; the symptom is
`minimum free drive threshold` in the warp output, on the direct path as much as
through the gateway.

**Against a real provider** `warp.sh` takes the bucket names, TLS, the region and
credentials from the EC2 instance role through environment variables listed at
the top of the script; [`deploy/aws-bench/README.md`](../deploy/aws-bench/README.md)
has the instance, the commands and what a run costs.

## Measuring the gateway

Micro-benchmarks live with the code and run through `make bench`:

```sh
make bench                                   # all packages
go test ./internal/crypto/stream -bench . -benchmem
```

```sh
BENCH_BUCKET=blindbucket-dev AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  bench/gateway-memory.sh results/ 10GiB
```

It samples the gateway process while `aws s3 cp` pushes the object through it and
pulls it back, checks the round trip is byte-identical, and reports the median
and peak per phase. `charts.py` turns the samples into the memory figure.

## Measuring the CLI

```sh
BLINDBUCKET_PASSPHRASE=... bench/rss-sample.sh out.csv \
  ./bin/blindbucket encrypt --keyring keyring.json -i big.bin -o big.bb
```

**Read the platform note the script prints.** On macOS, RSS as reported by `ps`
does not fall when Go releases pages: the runtime uses `MADV_FREE_REUSABLE`,
which marks pages reclaimable without lowering RSS until the system is under
pressure. Go's own `HeapReleased` shows the memory was handed back. On Linux the
figure is meaningful.

The portable evidence for constant memory is `TestLargeStreamRoundTrip`, which
samples the Go heap directly rather than asking the operating system:

```sh
BLINDBUCKET_STREAM_SIZE=10GiB go test ./internal/crypto/stream \
  -run TestLargeStreamRoundTrip -v -timeout 30m
```

## A caution the scripts now encode

The first macro run reported the gateway at 72 MiB/s against the provider's 214
for one cell, and the obvious next step -- find the bottleneck -- produced a
plausible culprit and a build that measured 221 MiB/s without it. A controlled
repeat of that same comparison then put the *unmodified* build at 157 MiB/s and
the "fixed" one at 33.9. All of those were single measurements of a cell whose
run-to-run range turned out to be wider than the effect being chased.

Hence `WARP_REPEAT`, the alternating path order, and the spread column: a cell
whose repetitions disagree by more than a quarter is marked in the table rather
than quoted as a number. The effect in that cell is real and survives the stricter
method -- see [figures/results.md](figures/results.md) -- but the first
explanation for it did not.
