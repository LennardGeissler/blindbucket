# What every scenario under test/apps does, sourced by its run.sh from the
# scenario's own directory. A scenario runs its application twice, against
# buckets <prefix>-plain and <prefix>-names behind gateways gateway-plain and
# gateway-names, with object names in clear and encrypted.
#
#   app_setup <label>         work directory, keyring, gateway image, teardown
#   app_up                    compose down, then up; failing to start is an error
#   app_gateways_running      true while both gateways are up
#   app_check_provider <prefix> <floor> <clear key prefixes...>
#                             every stored object is a blindbucket segment or
#                             manifest, there are at least <floor> of them,
#                             and the names bucket holds no key in clear
#   app_check_gateway_logs    neither gateway logged an ERROR
#
# Needs Docker with compose, Go and curl.

repo=$(cd ../../.. && pwd)

# Beside the scenario rather than in $TMPDIR: Docker Desktop shares the home
# directory with its VM but not macOS's temporary directory, and a bind mount
# whose source it cannot see becomes an empty directory, silently.
work="$PWD/.work"

# Exported, because a scenario may run `docker compose exec` from its own
# scripts too, and compose refuses every command while a variable the file
# needs is unset.
export KEYRING="$work/keyring.json"

compose() { docker compose "$@"; }

app_setup() {
	app_label=$1
	rm -rf "$work"
	mkdir -p "$work"
	trap app_finish EXIT

	# The gateway runs as an unprivileged user in its container and has to
	# read the keyring through a bind mount, so the file is world-readable
	# here. That is only acceptable because the keyring and its passphrase are
	# the scenario's own and protect nothing.
	echo "==> keyring"
	BLINDBUCKET_PASSPHRASE=apps-scenario-not-a-secret \
		go run -C "$repo" ./cmd/blindbucket keygen --out "$KEYRING" --kid scenario >/dev/null
	chmod 644 "$KEYRING"

	# Built once, before compose: two services building one tag at the same
	# time race.
	echo "==> the gateway image, from this checkout"
	docker build -q -t blindbucket-apps-gateway -f "$repo/deploy/Dockerfile" "$repo" >/dev/null
}

app_finish() {
	local status=$?
	if ((status != 0)); then
		echo "--- failed; gateway logs" >&2
		compose logs --no-color --tail 40 gateway-plain gateway-names >&2 || true
	fi
	if [[ -z ${KEEP:-} ]]; then
		compose down -v --remove-orphans >/dev/null 2>&1 || true
		rm -rf "$work"
	else
		echo "left running: $app_label"
	fi
	exit "$status"
}

# Down first: a run left up with KEEP=1 would otherwise be reused, buckets
# and all, and its data would be counted as this run's.
app_up() {
	echo "==> up"
	compose down -v --remove-orphans >/dev/null 2>&1 || true
	compose up -d --quiet-pull >"$work/up.log" 2>&1 || { cat "$work/up.log" >&2; exit 1; }
}

# A gateway that refused to start, or never did, is not waited out.
app_gateways_running() {
	[[ $(compose ps --status running -q gateway-plain gateway-names | wc -l) -eq 2 ]]
}

app_check_provider() {
	local prefix=$1 floor=$2
	shift 2
	echo "==> what the provider holds"
	# Plain sh in MinIO's image, which has no grep, cut, sed or awk: a
	# pipeline through any of them yields nothing, and a loop over nothing
	# checks nothing. Hence the floor on the count as well.
	compose run --rm -T -e PREFIX="$prefix" -e FLOOR="$floor" -e CLEAR="$*" \
		--entrypoint sh buckets -c '
		set -e
		mc alias set m http://minio:9000 minioadmin minioadmin >/dev/null
		for b in "$PREFIX-plain" "$PREFIX-names"; do
			mc ls --recursive "m/$b" > /tmp/list
			n=0 clear=0
			while read -r line; do
				k=${line##* }
				magic=$(mc cat "m/$b/$k" | head -c 4)
				case $magic in
				BLBK | BBM2 | BBM1) ;;
				*) echo "$b/$k starts with \"$magic\": not a blindbucket object"; exit 1 ;;
				esac
				for p in $CLEAR; do
					case $k in "$p"*) clear=$((clear + 1)) ;; esac
				done
				n=$((n + 1))
			done < /tmp/list
			if [ "$n" -lt "$FLOOR" ]; then
				echo "$b: only $n objects listed, fewer than $FLOOR; the check would prove nothing"
				exit 1
			fi
			echo "$b: $n objects, every one a segment or a manifest; $clear keys in clear"
			if [ "$b" = "$PREFIX-names" ] && [ "$clear" -ne 0 ]; then
				echo "$b holds $clear keys in clear"
				exit 1
			fi
		done
	'
}

app_check_gateway_logs() {
	local errors closed
	errors=$(compose logs --no-color gateway-plain gateway-names | grep '"level":"ERROR"' || true)
	if [[ -n $errors ]]; then
		echo "ERROR lines:" >&2
		echo "$errors" >&2
		exit 1
	fi
	closed=$(compose logs --no-color gateway-plain gateway-names | grep -c 'client closed the connection' || true)
	echo "no ERROR; $closed downloads closed early by the application, logged at INFO"
}
