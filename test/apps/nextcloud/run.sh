#!/usr/bin/env bash
# Nextcloud with S3 as primary storage, through the gateway (#125).
#
# Brings up compose.yaml, waits for both Nextcloud instances to install
# themselves -- which already writes some sixty objects through the gateway --
# runs ops.sh against each, and then asks the provider and the gateway what
# happened:
#
#   - every object in both buckets is a blindbucket segment or manifest, never
#     plaintext;
#   - with names.encrypt, no stored key is Nextcloud's urn:oid:<n>;
#   - neither gateway logged an ERROR. Nextcloud closes many downloads early,
#     which the gateway logged as integrity failures until #150.
#
#   test/apps/nextcloud/run.sh          run, then tear everything down
#   KEEP=1 test/apps/nextcloud/run.sh   leave it running, to look around
#
# Needs Docker with compose, Go, curl and python3. test/apps/lib.sh does what
# every scenario does; this file is what is particular to Nextcloud.
set -euo pipefail
cd "$(dirname "$0")"
. ../lib.sh

app_setup "Nextcloud on :8081 (names in clear) and :8082 (names encrypted)"
app_up

echo "==> waiting for both Nextcloud instances to install through the gateway"
for port in 8081 8082; do
	for _ in $(seq 1 120); do
		if curl -sf "http://127.0.0.1:$port/status.php" | grep -q '"installed":true'; then
			break
		fi
		app_gateways_running || { echo "a gateway is not running" >&2; exit 1; }
		sleep 3
	done
	curl -sf "http://127.0.0.1:$port/status.php" | grep -q '"installed":true' ||
		{ echo "Nextcloud on :$port did not finish installing" >&2; exit 1; }
done
compose exec -T nextcloud-plain sh -c 'grep -m1 OC_VersionString version.php'

echo "==> operations"
OCC="docker compose exec -T -u www-data nextcloud-plain php occ" \
	./ops.sh 8081 scenario-admin-plain "names in clear "
OCC="docker compose exec -T -u www-data nextcloud-names php occ" \
	./ops.sh 8082 scenario-admin-names "names encrypted"

# Installing Nextcloud alone writes some sixty objects.
app_check_provider nc 50 urn:oid:

echo "==> what the gateways saw"
# Proof that the multipart path ran, not only that a large file round-tripped:
# below Nextcloud's threshold the same file goes as one PutObject, and every
# content check above would pass all the same.
for gw in gateway-plain gateway-names; do
	n=$(compose logs --no-color "$gw" | grep -c '"msg":"multipart upload completed"' || true)
	if ((n < 1)); then
		echo "$gw completed no multipart upload: the multipart check did not exercise multipart" >&2
		exit 1
	fi
	echo "$gw: $n multipart uploads completed"
done

app_check_gateway_logs

echo "PASS"
