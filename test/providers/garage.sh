#!/usr/bin/env bash
# Start a single-node Garage and give it the bucket and key the integration
# tests expect.
#
#   test/providers/garage.sh            # start, configure, print the variables
#   test/providers/garage.sh stop       # remove the container
#
# Garage is the second provider the suite runs against, next to MinIO, because
# it is an independent S3 implementation: whatever the gateway has quietly come
# to rely on in MinIO shows up here first. Nothing in this file is a secret --
# the RPC secret and the key are fixed so that a run is reproducible.
set -euo pipefail

IMAGE=${GARAGE_IMAGE:-dxflrs/garage:v2.4.1}
NAME=${GARAGE_CONTAINER:-blindbucket-garage}
PORT=${GARAGE_PORT:-3900}
BUCKET=blindbucket-test
# Garage key ids are "GK" and 24 hex digits, secrets 64 hex digits.
KEY_ID=GK0123456789abcdef01234567
SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# Not us-east-1 on purpose: a region the code has never seen is part of the test.
REGION=garage

if [[ ${1:-} == stop ]]; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  exit 0
fi

conf=$(mktemp)
cat >"$conf" <<TOML
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$(printf 'b%.0s' {1..64})"

[s3_api]
s3_region = "$REGION"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"
TOML

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Copied in rather than bind-mounted: Docker Desktop does not share the
# temporary directory on macOS, and the image has no shell to write one with.
docker create --name "$NAME" -p "$PORT:3900" -e RUST_LOG=garage=warn "$IMAGE" >/dev/null
docker cp "$conf" "$NAME:/etc/garage.toml" >/dev/null
docker start "$NAME" >/dev/null

garage() { docker exec "$NAME" /garage "$@"; }

node=
for _ in $(seq 1 30); do
  node=$(garage node id -q 2>/dev/null | cut -d@ -f1) && [[ -n $node ]] && break
  sleep 1
done
[[ -n $node ]] || { echo "garage did not come up" >&2; docker logs "$NAME" >&2; exit 1; }

garage layout assign -z dc1 -c 1G "$node" >/dev/null
garage layout apply --version 1 >/dev/null
garage key import --yes -n blindbucket-test "$KEY_ID" "$SECRET" >/dev/null
garage bucket create "$BUCKET" >/dev/null
garage bucket allow --read --write --owner "$BUCKET" --key "$KEY_ID" >/dev/null

cat <<ENV
export BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:$PORT
export BLINDBUCKET_TEST_S3_REGION=$REGION
export BLINDBUCKET_TEST_S3_ACCESS_KEY=$KEY_ID
export BLINDBUCKET_TEST_S3_SECRET_KEY=$SECRET
export BLINDBUCKET_TEST_S3_BUCKET=$BUCKET
# Measured on v2.4.1: If-Match on CompleteMultipartUpload completes regardless.
export BLINDBUCKET_TEST_S3_COMPLETE_IF_MATCH=ignored
ENV
