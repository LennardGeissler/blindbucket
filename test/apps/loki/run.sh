#!/usr/bin/env bash
# Grafana Loki storing through the gateway (#128).
#
# For each of the two Lokis -- object names in clear, and encrypted:
#
#   1. push log lines in three streams, and flush them to storage;
#   2. restart Loki, which has no WAL, so that what it answers afterwards can
#      only have come back from the bucket;
#   3. query every line back and compare it with what was pushed;
#   4. ask Loki to delete one stream and wait until its compactor has --
#      rewriting the index and deleting a chunk through the gateway -- then
#      restart Loki once more: the deleted stream is gone, the other two are
#      intact.
#
# Then the provider holds only blindbucket objects, the names bucket no key
# in clear, and neither gateway logged an ERROR.
#
#   test/apps/loki/run.sh          run, then tear everything down
#   KEEP=1 test/apps/loki/run.sh   leave it running, to look around
#
# Needs Docker with compose, Go, curl and python3. test/apps/lib.sh does what
# every scenario does; this file is what is particular to Loki.
set -euo pipefail
cd "$(dirname "$0")"
. ../lib.sh

app_setup "Loki on :3101 (names in clear) and :3102 (names encrypted)"
app_up

wait_ready() {
	local port=$1
	for _ in $(seq 1 100); do
		[[ $(curl -s "http://127.0.0.1:$port/ready" || true) == ready ]] && return 0
		app_gateways_running || { echo "a gateway is not running" >&2; exit 1; }
		sleep 3
	done
	echo "Loki on :$port did not become ready" >&2
	exit 1
}

# The scenario's lines: three streams of 200 lines each, a nanosecond
# timestamp apiece, written to a file so that what comes back can be
# compared with exactly what went in.
push() {
	local port=$1 out=$2
	python3 - "$out" <<'PY' >"$work/push.json"
import json, sys, time, random
now = time.time_ns()
streams, expected = [], []
for name in ("alpha", "beta", "gamma"):
    values = []
    for i in range(200):
        ts = now - (600 - i) * 1_000_000_000 + hash(name) % 1000
        line = f"{name} line {i} user=alice@example.com token={random.getrandbits(64):016x}"
        values.append([str(ts), line])
        expected.append((name, line))
    streams.append({"stream": {"app": "scenario", "stream": name}, "values": values})
json.dump({"streams": streams}, sys.stdout)
with open(sys.argv[1], "w") as f:
    json.dump(sorted(expected), f)
PY
	local c
	c=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
		--data-binary "@$work/push.json" "http://127.0.0.1:$port/loki/api/v1/push")
	[[ $c == 204 ]] || { echo "push to :$port answered $c" >&2; exit 1; }
}

# Every line in the scenario's streams, as (stream, line) pairs, sorted.
query() {
	local port=$1
	local start=$(( $(date +%s) - 3600 ))000000000 end=$(( $(date +%s) + 60 ))000000000
	curl -s -G "http://127.0.0.1:$port/loki/api/v1/query_range" \
		--data-urlencode 'query={app="scenario"}' --data-urlencode "start=$start" \
		--data-urlencode "end=$end" --data-urlencode limit=5000 --data-urlencode direction=forward |
		python3 -c '
import json, sys
d = json.load(sys.stdin)
got = sorted((r["stream"]["stream"], v[1]) for r in d["data"]["result"] for v in r["values"])
json.dump(got, sys.stdout)'
}

pass=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
fail() { echo "FAIL  $1" >&2; exit 1; }

scenario() {
	local port=$1 service=$2 label=$3
	local pushed="$work/pushed-$port.json"
	wait_ready "$port"

	push "$port" "$pushed"
	[[ $(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/flush") == 204 ]] ||
		fail "$label: flush"
	# A graceful stop ships what the flush did not: the TSDB index of the
	# head, which a restart without a WAL would otherwise lose.
	compose restart -t 60 "$service" >/dev/null 2>&1
	wait_ready "$port"
	ok "$label: 600 lines pushed, flushed, Loki restarted without a WAL"

	local got
	for _ in $(seq 1 40); do
		got=$(query "$port")
		[[ $got == "$(cat "$pushed")" ]] && break
		sleep 3
	done
	[[ $got == "$(cat "$pushed")" ]] ||
		fail "$label: after the restart, $(echo "$got" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))') of 600 lines came back"
	ok "$label: all 600 lines read back from the bucket, identical"

	# A deletion request for one stream. The compactor acts on it at its next
	# run and rewrites what holds the stream's lines. Its window may not reach
	# into the future: Loki refuses that with a 400.
	local start=$(( $(date +%s) - 3600 )) end=$(date +%s)
	local c
	c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -G "http://127.0.0.1:$port/loki/api/v1/delete" \
		--data-urlencode 'query={app="scenario",stream="beta"}' \
		--data-urlencode "start=$start" --data-urlencode "end=$end")
	[[ $c == 204 ]] || fail "$label: the deletion request answered $c"
	# Loki marks the request processed once its compactor has rewritten the
	# index and deleted the stream's chunk -- through the gateway, which has to
	# serve the compactor's listing of index/ and its deletes for that. Queries
	# keep answering from Loki's caches until a restart, with or without a
	# gateway in front of the bucket (measured against MinIO directly, too).
	local status=""
	for _ in $(seq 1 60); do
		status=$(curl -s "http://127.0.0.1:$port/loki/api/v1/delete" |
			python3 -c 'import json,sys; print(" ".join(d["status"] for d in json.load(sys.stdin)))')
		[[ $status == processed ]] && break
		sleep 3
	done
	[[ $status == processed ]] || fail "$label: the deletion request is '$status', not processed"
	compose restart -t 60 "$service" >/dev/null 2>&1
	wait_ready "$port"
	local want
	want=$(python3 -c 'import json,sys; json.dump([p for p in json.load(open(sys.argv[1])) if p[0] != "beta"], sys.stdout)' "$pushed")
	for _ in $(seq 1 20); do
		got=$(query "$port")
		[[ $got == "$want" ]] && break
		sleep 3
	done
	[[ $got == "$want" ]] ||
		fail "$label: after the compactor ran, $(echo "$got" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))') lines came back; want the 400 of the two streams kept"
	ok "$label: the compactor deleted one stream; the other 400 lines are intact"
}

echo "==> operations"
scenario 3101 loki-plain "names in clear "
scenario 3102 loki-names "names encrypted"
compose exec -T loki-plain /usr/bin/loki -version | head -1

app_check_provider loki 5 fake/ index/ loki_cluster_seed.json

echo "==> what the gateways saw"
app_check_gateway_logs

echo "PASS ($pass checks)"
