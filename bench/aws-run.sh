#!/usr/bin/env bash
#
# The network benchmark (M9), run on the instance deploy/aws-bench/ creates:
# warp against AWS S3 directly and through a gateway on the same instance, the
# bucket in the same region. Everything bench/warp.sh measures locally, with the
# provider a real network hop away instead of a VM on the same laptop.
#
# Started through Session Manager, as root, from the checkout the instance made:
#
#   aws ssm start-session --target <InstanceId>
#   sudo /opt/blindbucket/bench/aws-run.sh
#
# Results land in s3://<results bucket>/<timestamp>/ when the last run is done.
# Not in the bucket warp runs against: warp clears that one at every run, the
# next run included. The results bucket expires objects after thirty days.
#
# Environment (defaults in brackets):
#   BENCH_SIZES        object sizes        ["1KiB 10MiB 1GiB"]
#   BENCH_CONCURRENCY  concurrent clients  ["1 16 64"]
#   BENCH_REPEAT       repetitions         [3]
#   BENCH_DURATION     per-run duration    [30s]
#   BENCH_SETTLE       seconds between runs [10] -- S3 frees nothing on this
#                      instance's disk, unlike the local MinIO bench/warp.sh
#                      was written against, so the wait is shorter
set -euo pipefail

until [[ -e /var/run/blindbucket-bench-ready ]]; do
    echo "waiting for the instance's setup to finish ..."
    sleep 10
done
# shellcheck source=/dev/null
source /etc/blindbucket-bench.env

here=$(cd "$(dirname "$0")" && pwd)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
work=/opt/bench-runs/$stamp
mkdir -p "$work"
cd "$work"

imds=http://169.254.169.254
itoken=$(curl -fsS -X PUT "$imds/latest/api/token" -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
instance_type=$(curl -fsS -H "X-aws-ec2-metadata-token: $itoken" "$imds/latest/meta-data/instance-type")

# Throwaway secrets: the keyring, the passphrase and the client credential exist
# for this run only, and the objects they protect are deleted by warp.
umask 077
openssl rand -hex 32 > passphrase
client_key=bench$(openssl rand -hex 6)
client_secret=$(openssl rand -hex 24)
blindbucket keygen --out keyring.json --passphrase-file passphrase

# allow_unsigned_payload: warp is built on minio-go, which signs a single PUT per
# chunk but sends UNSIGNED-PAYLOAD for a multipart upload -- every 1 GiB object --
# exactly as mc does (docs/COMPATIBILITY.md). Without it every multipart request
# is refused at CreateMultipartUpload. The listener is loopback, the case the
# setting is meant for.
cat > blindbucket.yaml <<EOF
server:
  listen: "127.0.0.1:9000"
  allow_unsigned_payload: true
admin:
  listen: "127.0.0.1:9100"
upstream:
  endpoint: https://s3.${BENCH_REGION}.amazonaws.com
  region: ${BENCH_REGION}
  path_style: false
  credential_source: imds
keys:
  provider: file
  keyring: ${work}/keyring.json
  passphrase_file: ${work}/passphrase
crypto:
  log2_chunk_size: 16
clients:
  - name: bench
    access_key_id: ${client_key}
    secret_access_key: ${client_secret}
    buckets: ["${BENCH_BUCKET}"]
EOF

blindbucket version > version.txt 2>&1 || true
blindbucket serve --config blindbucket.yaml > gateway.log 2>&1 &
gateway=$!
trap 'kill "$gateway" 2>/dev/null || true' EXIT

# /readyz asks the upstream, so a pass here means the instance role's
# credentials reached S3 through credential_source: imds.
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:9100/readyz > /dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS http://127.0.0.1:9100/readyz > /dev/null \
    || { echo "gateway not ready; see $work/gateway.log" >&2; exit 1; }

WARP_DIRECT=s3.${BENCH_REGION}.amazonaws.com \
WARP_DIRECT_TLS=1 \
WARP_REGION=$BENCH_REGION \
WARP_DIRECT_CREDENTIALS=imds \
WARP_DIRECT_BUCKET=$BENCH_BUCKET \
WARP_PROXY=127.0.0.1:9000 \
WARP_PROXY_BUCKET=$BENCH_BUCKET \
WARP_PROXY_KEY=$client_key \
WARP_PROXY_SECRET=$client_secret \
WARP_DOCKER_ARGS=--network=host \
WARP_PROVIDER="AWS S3 ${BENCH_REGION}, from ${instance_type} in the same region; gateway ${BENCH_VERSION}" \
WARP_SIZES=${BENCH_SIZES:-"1KiB 10MiB 1GiB"} \
WARP_CONCURRENCY=${BENCH_CONCURRENCY:-"1 16 64"} \
WARP_REPEAT=${BENCH_REPEAT:-3} \
WARP_DURATION=${BENCH_DURATION:-30s} \
WARP_SETTLE=${BENCH_SETTLE:-10} \
    "$here/warp.sh" "$work/results" || status=$?

python3 "$here/plot/summarise.py" "$work/results" || true

# Everything but the secrets.
rm -f passphrase keyring.json
sed -i "s/${client_secret}/<redacted>/" blindbucket.yaml
aws s3 cp --recursive --region "$BENCH_REGION" --quiet \
    "$work" "s3://${BENCH_RESULTS_BUCKET}/${stamp}/"
echo "results: s3://${BENCH_RESULTS_BUCKET}/${stamp}/"
exit "${status:-0}"
