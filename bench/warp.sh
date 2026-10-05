#!/usr/bin/env bash
#
# Macro benchmark: MinIO `warp` against the storage provider directly, and the
# same load through the gateway. See bench/README.md.
#
# The number that matters is not the absolute throughput -- that is whatever the
# hardware and the provider can do -- but the *ratio* between the two paths, and
# the extra latency the proxy adds per request. Both runs hit the same provider
# on the same machine within minutes of each other, which is the only way that
# ratio means anything.
#
# Usage:
#   bench/warp.sh <results-dir>
#
# Environment:
#   WARP_DIRECT        host:port of the provider          (default 127.0.0.1:9002)
#   WARP_PROXY         host:port of the gateway           (default 127.0.0.1:9000)
#   WARP_DIRECT_KEY    provider access key                (default minioadmin)
#   WARP_DIRECT_SECRET provider secret key                (default minioadmin)
#   WARP_PROXY_KEY     gateway access key                 (required)
#   WARP_PROXY_SECRET  gateway secret key                 (required)
#   WARP_SIZES         object sizes                       (default "1KiB 10MiB")
#   WARP_CONCURRENCY   concurrent clients                 (default "1 16 64")
#   WARP_DURATION      per-run duration                   (default 30s)
#   WARP_OPS           operations                         (default "put get")
#   WARP_IMAGE         warp container image               (default minio/warp:latest)
#   WARP_DOCKER_ARGS   extra docker args, e.g. --network=host on Linux
#   WARP_DIRECT_BUCKET bucket for the direct path      (default warp-benchmark-bucket)
#   WARP_PROXY_BUCKET  bucket for the gateway path     (default warp-proxy-bucket)
#   WARP_DIRECT_TLS    1 to reach the provider over TLS (default 0)
#   WARP_REGION        region for the direct path      (default: warp's own)
#   WARP_DIRECT_CREDENTIALS
#                      "imds" to take the provider's credentials from the EC2
#                      instance role before every direct run, instead of
#                      WARP_DIRECT_KEY and WARP_DIRECT_SECRET (default unset)
#   WARP_PROVIDER      what to record as the provider  (default: the local MinIO
#                      container's image)
#
# Against a real provider -- AWS S3 from an EC2 instance in the same region --
# bench/aws-run.sh sets these; deploy/aws-bench/ has the instance.
#
# On Linux, reach host services with WARP_DOCKER_ARGS=--network=host and
# 127.0.0.1 endpoints. On Docker Desktop, use host.docker.internal endpoints and
# leave WARP_DOCKER_ARGS empty.
#
# Each run clears its bucket before and after, which is warp's default. Keeping
# the objects between runs is tempting -- a GET run could skip its upload phase --
# and it is how the first version of this script filled a 20 GB disk in eleven
# minutes: at a few hundred MiB/s, twenty seconds of PUT is several gigabytes,
# and there are two dozen runs. Budget roughly
# (throughput x duration) of free space, not (throughput x duration x runs) --
# plus WARP_SETTLE seconds between runs, because the provider frees that space
# asynchronously and the next run starts before it has.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <results-dir>" >&2
    exit 2
fi
out=$1
mkdir -p "$out"

WARP_DIRECT=${WARP_DIRECT:-127.0.0.1:9002}
WARP_PROXY=${WARP_PROXY:-127.0.0.1:9000}
WARP_DIRECT_KEY=${WARP_DIRECT_KEY:-minioadmin}
WARP_DIRECT_SECRET=${WARP_DIRECT_SECRET:-minioadmin}
WARP_SIZES=${WARP_SIZES:-"1KiB 10MiB"}
WARP_CONCURRENCY=${WARP_CONCURRENCY:-"1 16 64"}
WARP_DURATION=${WARP_DURATION:-30s}
WARP_OPS=${WARP_OPS:-"put get"}
WARP_IMAGE=${WARP_IMAGE:-minio/warp:latest}
WARP_DOCKER_ARGS=${WARP_DOCKER_ARGS:-}
WARP_DIRECT_BUCKET=${WARP_DIRECT_BUCKET:-warp-benchmark-bucket}
WARP_PROXY_BUCKET=${WARP_PROXY_BUCKET:-warp-proxy-bucket}
WARP_DIRECT_TLS=${WARP_DIRECT_TLS:-0}
WARP_REGION=${WARP_REGION:-}
WARP_DIRECT_CREDENTIALS=${WARP_DIRECT_CREDENTIALS:-}
# Seconds to wait between runs. Providers free deleted space asynchronously, and
# a run that starts while the previous one is still being reclaimed pays for that
# work. Because the two paths of a pair run in a fixed order, the cost lands
# entirely on the second one and reads as "the gateway is three times slower" --
# see the note above run_one. Thirty seconds was enough on the machine this was
# written on; a slower disk wants more.
WARP_SETTLE=${WARP_SETTLE:-30}
# Repetitions per cell. A single measurement of a loaded cell is not a
# measurement: on the machine this was written on, one cell varied between 34 and
# 221 MiB/s across runs of identical code, which is wide enough to invent a
# regression that is not there. The summary reports the median and the spread, so
# a cell whose spread swamps the effect is visible as such rather than quoted.
WARP_REPEAT=${WARP_REPEAT:-3}

: "${WARP_PROXY_KEY:?set WARP_PROXY_KEY to the gateway access key}"
: "${WARP_PROXY_SECRET:?set WARP_PROXY_SECRET to the gateway secret key}"

# How many objects to preload for a GET run. A GET benchmark reads from a fixed
# set, so the set has to be large enough that it is not served entirely from the
# provider's page cache, and small enough to fit on the disk.
objects_for() {
    case $1 in
        1KiB)  echo 2000 ;;
        10MiB) echo 100 ;;
        1GiB)  echo 4 ;;
        *)     echo 100 ;;
    esac
}

record_environment() {
    {
        echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "host:        $(uname -srm)"
        if [[ $(uname -s) == Darwin ]]; then
            echo "cpu:         $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
            echo "cores:       $(sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
            echo "memory:      $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 )) MiB"
        else
            echo "cpu:         $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || echo unknown)"
            echo "cores:       $(nproc 2>/dev/null || echo unknown)"
            echo "memory:      $(( $(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0) / 1024 )) MiB"
        fi
        echo "go:          $(go version 2>/dev/null || echo 'not installed')"
        echo "warp:        $(docker run --rm "$WARP_IMAGE" --version 2>&1 | head -1)"
        echo "provider:    ${WARP_PROVIDER:-$(docker inspect --format '{{.Config.Image}}' blindbucket-minio-1 2>/dev/null || echo unknown)}"
        echo "duration:    $WARP_DURATION per run"
        echo "sizes:       $WARP_SIZES"
        echo "concurrency: $WARP_CONCURRENCY"
    } | tee "$out/environment.txt"
    echo
}

# imds_credentials sets key, secret and token from the EC2 instance role, through
# IMDSv2. It is called before every direct run rather than once: a full matrix
# takes hours, and the role's credentials are replaced well within that.
imds_credentials() {
    local imds=http://169.254.169.254 itoken role json
    itoken=$(curl -fsS -X PUT "$imds/latest/api/token" \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
    role=$(curl -fsS -H "X-aws-ec2-metadata-token: $itoken" \
        "$imds/latest/meta-data/iam/security-credentials/")
    json=$(curl -fsS -H "X-aws-ec2-metadata-token: $itoken" \
        "$imds/latest/meta-data/iam/security-credentials/$role")
    key=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["AccessKeyId"])' <<<"$json")
    secret=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["SecretAccessKey"])' <<<"$json")
    token=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Token"])' <<<"$json")
}

# run_one runs one cell of the matrix.
#
# A measurement caution, learned the hard way: at 10 MiB and 64 concurrent
# clients this reported the gateway at 72 MiB/s against the provider's 214, with
# the gateway process sitting at near-zero CPU the whole time. It was not the
# gateway. The direct run immediately before it had just deleted several
# gigabytes, the provider was still reclaiming them, and the proxy run -- which
# always runs second -- absorbed all of it. Run alone on a settled disk, the same
# cell reports 211 MiB/s, within noise of the direct path.
#
# The general shape of that mistake is worth keeping in mind: when a benchmark
# says a component is slow, check whether that component is actually busy.
run_one() {
    local path=$1 op=$2 size=$3 concurrent=$4 repeat=$5
    local host key secret token='' bucket file
    local conn=()

    case $path in
        direct) host=$WARP_DIRECT; key=$WARP_DIRECT_KEY; secret=$WARP_DIRECT_SECRET
                bucket=$WARP_DIRECT_BUCKET
                if [[ $WARP_DIRECT_CREDENTIALS == imds ]]; then
                    imds_credentials
                fi
                if [[ $WARP_DIRECT_TLS == 1 ]]; then
                    conn+=(--tls)
                fi
                if [[ -n $WARP_REGION ]]; then
                    conn+=(--region="$WARP_REGION")
                fi ;;
        proxy)  host=$WARP_PROXY;  key=$WARP_PROXY_KEY;  secret=$WARP_PROXY_SECRET
                bucket=$WARP_PROXY_BUCKET ;;
        *)      echo "unknown path $path" >&2; return 1 ;;
    esac
    if [[ -n $token ]]; then
        conn+=(--session-token="$token")
    fi

    file="$out/${path}-${op}-${size}-c${concurrent}-r${repeat}.txt"
    printf '  %-6s %-4s %-6s c=%-3s r%-2s ... ' "$path" "$op" "$size" "$concurrent" "$repeat"

    # Only `get` preloads a fixed object set; `put` generates as it goes and has
    # no --objects flag at all. The expansion is written the long way because an
    # empty array under `set -u` is an error in bash 3.2, which is what macOS
    # ships.
    local extra=()
    if [[ $op == get ]]; then
        extra=(--objects "$(objects_for "$size")")
    fi

    # shellcheck disable=SC2086 # WARP_DOCKER_ARGS is deliberately word-split.
    if docker run --rm $WARP_DOCKER_ARGS "$WARP_IMAGE" "$op" \
        --host="$host" --access-key="$key" --secret-key="$secret" \
        --bucket="$bucket" --obj.size="$size" --concurrent="$concurrent" \
        --duration="$WARP_DURATION" \
        ${conn[@]+"${conn[@]}"} ${extra[@]+"${extra[@]}"} > "$file" 2>&1
    then
        grep -m1 'Average:' "$file" | sed 's/^ *\* Average: //' || echo "ok"
    else
        echo "FAILED (see $file)"
        return 1
    fi
}

record_environment

failures=0
for size in $WARP_SIZES; do
    for concurrent in $WARP_CONCURRENCY; do
        for op in $WARP_OPS; do
            for repeat in $(seq 1 "$WARP_REPEAT"); do
                # The two paths alternate order between repetitions, so that the
                # cost of the provider still reclaiming the previous run cannot
                # land on the same path every time and read as a difference
                # between them.
                if (( repeat % 2 )); then
                    order="direct proxy"
                else
                    order="proxy direct"
                fi
                for path in $order; do
                    run_one "$path" "$op" "$size" "$concurrent" "$repeat" \
                        || failures=$((failures + 1))
                    sleep "$WARP_SETTLE"
                done
            done
        done
    done
done

echo
if (( failures )); then
    echo "$failures run(s) failed; the rest are in $out"
    exit 1
fi
echo "results in $out -- summarise with: python3 bench/plot/summarise.py $out"
