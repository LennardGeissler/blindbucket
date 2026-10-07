#!/usr/bin/env bash
# Start a single SeaweedFS server with its S3 gateway, for the litmus tests in
# test/litmus/. A third independent S3 implementation next to MinIO and Garage.
#
#   test/providers/seaweedfs.sh            # start, create the bucket, print the variables
#   test/providers/seaweedfs.sh stop       # remove the container
#
# Nothing here is a secret: the key is fixed so that a run is reproducible.
set -euo pipefail

IMAGE=${SEAWEEDFS_IMAGE:-chrislusf/seaweedfs:latest}
NAME=${SEAWEEDFS_CONTAINER:-blindbucket-seaweedfs}
PORT=${SEAWEEDFS_PORT:-8333}
BUCKET=litmus
KEY_ID=litmusaccesskey
SECRET=litmussecretkey

if [[ ${1:-} == stop ]]; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  exit 0
fi

conf=$(mktemp)
cat >"$conf" <<JSON
{"identities":[{"name":"litmus","credentials":[{"accessKey":"$KEY_ID","secretKey":"$SECRET"}],
 "actions":["Admin","Read","Write","List","Tagging"]}]}
JSON
# mktemp makes the file 0600, and the server in the image does not run as root.
chmod 0644 "$conf"

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Copied in rather than bind-mounted: Docker Desktop does not share the
# temporary directory on macOS.
docker create --name "$NAME" -p "$PORT:8333" "$IMAGE" \
  server -s3 -s3.config=/etc/s3.json -dir=/data >/dev/null
docker cp "$conf" "$NAME:/etc/s3.json" >/dev/null
docker start "$NAME" >/dev/null

for _ in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:$PORT/" && break
  sleep 2
done
sleep 3
AWS_ACCESS_KEY_ID=$KEY_ID AWS_SECRET_ACCESS_KEY=$SECRET AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://localhost:$PORT" s3 mb "s3://$BUCKET" >/dev/null 2>&1 || true

cat <<EOF
# SeaweedFS $(docker run --rm "$IMAGE" version 2>/dev/null | head -1)
--endpoint http://localhost:$PORT --region us-east-1 --bucket $BUCKET \\
--access-key $KEY_ID --secret-key $SECRET
EOF
