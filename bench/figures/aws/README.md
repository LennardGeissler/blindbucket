# The network benchmark, 2026-10-05

`bench/warp.sh`'s matrix against AWS S3 in eu-central-1, from a c7g.2xlarge
(Graviton, 8 vCPUs, up to 15 Gbit/s) in the same region, running the published
`1.1.0` archive. Instance and buckets came from
[`deploy/aws-bench/`](../../../deploy/aws-bench/); the runs were started with
[`bench/aws-run.sh`](../../aws-run.sh). Every cell is three repetitions of 30 s
per path, direct and through the gateway, alternating which goes first.

| File | What it is |
|---|---|
| [`results.md`](results.md) | The comparison table: median of three, with p50 and p99 per path |
| [`results.csv`](results.csv) | The same, with the spread across repetitions |
| [`results-raw.csv`](results-raw.csv) | One row per run |
| [`raw/`](raw/) | warp's own output for each of the 108 runs, and the environment of both passes |
| [`blindbucket.yaml`](blindbucket.yaml) | The gateway's configuration, client secret redacted |
| [`expect-100-continue.txt`](expect-100-continue.txt) | The control measurement below |
| `throughput-{light,dark}.svg` | The figure in the README |

## Two passes, and why

The 1 KiB and 10 MiB cells come from the first pass (13:29 UTC). Its 1 GiB cells
through the gateway were refused, every one: at that size warp uploads in
parts, and minio-go, which warp is built on, sends `UNSIGNED-PAYLOAD` for a
multipart upload exactly as `mc` does, which the gateway refuses unless
`server.allow_unsigned_payload` is set ([COMPATIBILITY.md](../../../docs/COMPATIBILITY.md)).
The configuration had left it out. The pass was stopped, the setting added, and
all 1 GiB cells, both paths, measured again in a second pass (14:50 UTC). The
setting changes nothing for the first pass's cells: warp signs a single PUT
chunk by chunk and never sends `UNSIGNED-PAYLOAD` there. The refused runs are not
in `raw/`; they measured nothing but the refusal.

The gateway logs (91 MB and 12 MB) are not committed either. Almost all of the
first is that refusal, a million times.

## The cells where the gateway is faster

At 10 MiB with 1 and 16 clients, and at 1 GiB with one, uploads through the
gateway beat the direct path by 5–14 %, in every repetition. Encryption does
not do that. The two paths differ in more than the gateway: directly, warp's own
client talks TLS to S3; through the gateway, warp talks plain HTTP on loopback
and the gateway's client talks to S3. Signing is not the difference (both send
`UNSIGNED-PAYLOAD` upstream, neither adds a checksum). `Expect: 100-continue`
is: the gateway's client sends it, warp's does not.

Measured on its own, with curl and nothing else changed — twenty 10 MiB uploads
each way, alternating:

| | median | range |
|---|---:|---:|
| with `Expect: 100-continue` | **127.6 ms** | 122.9–139.1 ms |
| without | **142.6 ms** | 135.4–151.4 ms |

That is the gateway's margin at 10 MiB almost exactly (p50 128.8 → 112.5 ms).
Why S3 takes a body faster once it has accepted the request is not something
this measures. What it does say: a benchmark of anything in front of S3 has to
hold the client's HTTP behaviour constant, or part of what it reports is the
client.

## What the numbers do not say

One instance type, one region, one afternoon. S3's own variance is what the
repetitions are for; `results.csv` has the spread. From 16 clients on, large
objects saturate the instance's network on both paths, so those cells show that
the gateway keeps pace, not how far it could go. Latency at saturation is mostly
queueing: the p99 and the 1 GiB p50 at 64 clients move in both directions and
should be read as such. Nothing here covers a gateway in a different region from
its bucket.
