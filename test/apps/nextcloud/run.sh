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
#   - neither gateway logged an ERROR, apart from the client-closed downloads
#     of #150, which Nextcloud causes on every partial read.
#
#   test/apps/nextcloud/run.sh          run, then tear everything down
#   KEEP=1 test/apps/nextcloud/run.sh   leave it running, to look around
#
# Needs Docker with compose, Go, curl and python3.
set -euo pipefail
cd "$(dirname "$0")"
repo=$(cd ../../.. && pwd)

# Beside the scenario rather than in $TMPDIR: Docker Desktop shares the home
# directory with its VM but not macOS's temporary directory, and a bind
# mount whose source it cannot see becomes an empty directory, silently.
work="$PWD/.work"
rm -rf "$work"
mkdir -p "$work"
# Exported, because ops.sh runs occ through `docker compose exec` too, and
# compose refuses every command while a variable the file needs is unset.
export KEYRING="$work/keyring.json"
compose() { docker compose "$@"; }
finish() {
	status=$?
	if ((status != 0)); then
		echo "--- failed; gateway logs" >&2
		compose logs --no-color --tail 40 gateway-plain gateway-names >&2 || true
	fi
	if [[ -z ${KEEP:-} ]]; then
		compose down -v --remove-orphans >/dev/null 2>&1 || true
		rm -rf "$work"
	else
		echo "left running: Nextcloud on :8081 (names in clear) and :8082 (names encrypted)"
	fi
	exit "$status"
}
trap finish EXIT

# The gateway runs as an unprivileged user in its container and has to read
# the keyring through a bind mount, so the file is world-readable here. That
# is only acceptable because the keyring and its passphrase are the
# scenario's own and protect nothing.
echo "==> keyring"
BLINDBUCKET_PASSPHRASE=nextcloud-scenario-not-a-secret \
	go run -C "$repo" ./cmd/blindbucket keygen --out "$work/keyring.json" --kid scenario >/dev/null
chmod 644 "$work/keyring.json"

echo "==> the gateway image, from this checkout"
docker build -q -t blindbucket-nextcloud-gateway -f "$repo/deploy/Dockerfile" "$repo" >/dev/null

echo "==> up"
compose up -d --quiet-pull >"$work/up.log" 2>&1 || { cat "$work/up.log" >&2; exit 1; }

echo "==> waiting for both Nextcloud instances to install through the gateway"
for port in 8081 8082; do
	for _ in $(seq 1 120); do
		if curl -sf "http://127.0.0.1:$port/status.php" | grep -q '"installed":true'; then
			break
		fi
		# A gateway that refused to start, or never did, is not waited out.
		if [[ $(compose ps --status running -q gateway-plain gateway-names | wc -l) -ne 2 ]]; then
			echo "a gateway is not running" >&2
			exit 1
		fi
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

echo "==> what the provider holds"
# Plain sh in MinIO's image, which has no grep, cut, sed or awk: a pipeline
# through any of them yields nothing, and a loop over nothing checks nothing.
# Hence the floor on the count as well -- installing Nextcloud alone writes
# some sixty objects.
compose run --rm -T --entrypoint sh buckets -c '
	set -e
	mc alias set m http://minio:9000 minioadmin minioadmin >/dev/null
	for b in nc-plain nc-names; do
		mc ls --recursive "m/$b" > /tmp/list
		n=0 clear=0
		while read -r line; do
			k=${line##* }
			magic=$(mc cat "m/$b/$k" | head -c 4)
			case $magic in
			BLBK | BBM2 | BBM1) ;;
			*) echo "$b/$k starts with \"$magic\": not a blindbucket object"; exit 1 ;;
			esac
			case $k in urn:oid:*) clear=$((clear + 1)) ;; esac
			n=$((n + 1))
		done < /tmp/list
		if [ "$n" -lt 50 ]; then
			echo "$b: only $n objects listed; the check would prove nothing"
			exit 1
		fi
		echo "$b: $n objects, every one a segment or a manifest; $clear keys are urn:oid:<n>"
		if [ "$b" = nc-names ] && [ "$clear" -ne 0 ]; then
			echo "nc-names holds $clear keys in clear"
			exit 1
		fi
	done
'

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

errors=$(compose logs --no-color gateway-plain gateway-names | grep '"level":"ERROR"' |
	grep -v -e 'aborting response.*context canceled' -e 'aborting response.*broken pipe' \
		-e 'aborting response.*connection reset' || true)
if [[ -n $errors ]]; then
	echo "unexpected ERROR lines:" >&2
	echo "$errors" >&2
	exit 1
fi
echo "no ERROR beyond client-closed downloads (#150)"

echo "PASS"
