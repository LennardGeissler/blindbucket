#!/usr/bin/env bash
# Starts Dex for the dashboard's sign-in test (ADR-039), as CI runs it, and
# waits until it serves its discovery document.
#
#   test/services/dex.sh         # start
#   test/services/dex.sh stop    # remove the container
set -euo pipefail

IMAGE=${DEX_IMAGE:-ghcr.io/dexidp/dex:v2.41.1}
NAME=${DEX_CONTAINER:-blindbucket-dex}
here=$(cd "$(dirname "$0")" && pwd)

if [[ ${1:-} == stop ]]; then
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	exit 0
fi

docker run -d --name "$NAME" -p 5556:5556 \
	-v "$here/dex.yaml:/etc/dex/config.yaml:ro" \
	"$IMAGE" dex serve /etc/dex/config.yaml >/dev/null

for _ in $(seq 1 60); do
	if curl -sf http://127.0.0.1:5556/dex/.well-known/openid-configuration >/dev/null; then
		echo "export BLINDBUCKET_TEST_DEX_ISSUER=http://127.0.0.1:5556/dex"
		exit 0
	fi
	sleep 1
done
echo "Dex did not start" >&2
docker logs "$NAME" >&2 || true
exit 1
