#!/usr/bin/env bash
# Everything a released version wrote must stay readable by the current build.
#
#   test/upgrade/upgrade.sh                  # every v* tag against the working tree
#   test/upgrade/upgrade.sh v0.2.0 v0.4.0    # just these
#
# SECURITY.md and the CHANGELOG both say so; this is what checks it. For each
# released version, that version -- built from its tag -- creates its own
# keyring, serves a gateway, and stores objects through it with the AWS CLI:
# empty, small, one chunk boundary off, and multipart. It also encrypts a file
# with the CLI. Then the current build, given each old keyring unchanged, reads
# every object back through its own gateway, compares SHA-256 and the size a
# listing reports, and decrypts the file.
#
# That covers what an upgrade actually has to carry: the keyring file, the
# object metadata, the manifests, the segment format and the listing size
# arithmetic. It needs the compose file's MinIO (docker compose up -d), Go, git
# and the AWS CLI.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
endpoint=${UPGRADE_S3_ENDPOINT:-http://localhost:9002}
bucket=${UPGRADE_S3_BUCKET:-blindbucket-test}
work=$(mktemp -d)
prefix="bbtest/upgrade-$(date -u +%Y%m%dT%H%M%S)-$$"
pids=()

cleanup() {
  for pid in "${pids[@]:-}"; do [[ -n $pid ]] && kill "$pid" 2>/dev/null || true; done
  for dir in "$work"/src-*; do
    [[ -d $dir ]] && git -C "$repo" worktree remove --force "$dir" >/dev/null 2>&1 || true
  done
  AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    aws --endpoint-url "$endpoint" s3 rm "s3://$bucket/$prefix/" --recursive >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

if [[ $# -gt 0 ]]; then
  versions=("$@")
else
  # shellcheck disable=SC2207 # one tag per line, no spaces in a tag
  versions=($(git -C "$repo" tag --list 'v*' --sort=version:refname))
fi

export BLINDBUCKET_PASSPHRASE=upgrade-test-passphrase-not-a-secret
export UPSTREAM_ACCESS_KEY_ID=minioadmin UPSTREAM_SECRET_ACCESS_KEY=minioadmin
export BB_ACCESS_KEY_ID=UPGRADETESTKEY BB_SECRET_ACCESS_KEY=upgrade-test-secret-key
client_env() { AWS_ACCESS_KEY_ID=$BB_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY=$BB_SECRET_ACCESS_KEY AWS_DEFAULT_REGION=us-east-1 "$@"; }

# config PORT KEYRING writes a configuration every released version accepts:
# the format has not changed since v0.1.0, and that is part of what is tested.
config() {
  cat <<YAML
server:
  listen: "127.0.0.1:$1"
admin:
  listen: "127.0.0.1:$(($1 + 100))"
upstream:
  endpoint: $endpoint
  region: us-east-1
  path_style: true
  access_key_id: \${UPSTREAM_ACCESS_KEY_ID}
  secret_access_key: \${UPSTREAM_SECRET_ACCESS_KEY}
keys:
  provider: file
  keyring: $2
clients:
  - name: upgrade
    access_key_id: \${BB_ACCESS_KEY_ID}
    secret_access_key: \${BB_SECRET_ACCESS_KEY}
    buckets: ["$bucket"]
YAML
}

# serve BINARY CONFIG PORT starts a gateway and waits until it answers.
serve() {
  "$1" serve --config "$2" >"$2.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 50); do
    curl -s -o /dev/null "http://127.0.0.1:$3/" && return 0
    sleep 0.2
  done
  echo "gateway on :$3 did not start:" >&2
  cat "$2.log" >&2
  return 1
}

stop_last() {
  local last=$((${#pids[@]} - 1))
  kill "${pids[$last]}" 2>/dev/null || true
  wait "${pids[$last]}" 2>/dev/null || true
  pids[last]=
}

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# The payloads. 65535 and 65537 sit either side of the default 64 KiB chunk;
# 20 MiB is above the AWS CLI's 8 MiB multipart threshold.
mkdir -p "$work/payload"
: >"$work/payload/empty.bin"
head -c 1000 /dev/urandom >"$work/payload/small.bin"
head -c 65535 /dev/urandom >"$work/payload/under-chunk.bin"
head -c 65537 /dev/urandom >"$work/payload/over-chunk.bin"
head -c 20971520 /dev/urandom >"$work/payload/multipart.bin"

echo "building the current tree"
(cd "$repo" && go build -o "$work/current" ./cmd/blindbucket)

port=9300
for v in "${versions[@]}"; do
  echo "== $v writes"
  src="$work/src-$v"
  git -C "$repo" worktree add --detach --quiet "$src" "$v"
  (cd "$src" && go build -o "$work/$v" ./cmd/blindbucket)
  git -C "$repo" worktree remove --force "$src"

  "$work/$v" keygen --out "$work/$v.keyring.json" --kid "upgrade-$v" >"$work/$v.keygen.log" 2>&1 ||
    { cat "$work/$v.keygen.log" >&2; exit 1; }
  config $port "$work/$v.keyring.json" >"$work/$v.write.yaml"
  serve "$work/$v" "$work/$v.write.yaml" $port
  for f in "$work"/payload/*.bin; do
    client_env aws --endpoint-url "http://127.0.0.1:$port" s3 cp --only-show-errors \
      "$f" "s3://$bucket/$prefix/$v/$(basename "$f")"
  done
  stop_last
  "$work/$v" encrypt --keyring "$work/$v.keyring.json" \
    <"$work/payload/over-chunk.bin" >"$work/$v.file.bb"
  port=$((port + 1))
done

failures=0
fail() { echo "FAIL $*" >&2; failures=$((failures + 1)); }

for v in "${versions[@]}"; do
  echo "== the current build reads what $v wrote"
  config $port "$work/$v.keyring.json" >"$work/$v.read.yaml"
  serve "$work/current" "$work/$v.read.yaml" $port
  listing=$(client_env aws --endpoint-url "http://127.0.0.1:$port" s3 ls "s3://$bucket/$prefix/$v/")
  for f in "$work"/payload/*.bin; do
    name=$(basename "$f")
    got="$work/$v.$name.back"
    if ! client_env aws --endpoint-url "http://127.0.0.1:$port" s3 cp --only-show-errors \
      "s3://$bucket/$prefix/$v/$name" "$got" 2>"$got.err"; then
      fail "$v $name: $(cat "$got.err")"
      continue
    fi
    [[ $(sha "$got") == "$(sha "$f")" ]] || fail "$v $name: SHA-256 differs"
    want=$(wc -c <"$f" | tr -d ' ')
    listed=$(awk -v n="$name" '$4 == n {print $3}' <<<"$listing")
    [[ $listed == "$want" ]] || fail "$v $name: listed as $listed bytes, want $want"
  done
  stop_last

  if ! "$work/current" decrypt --keyring "$work/$v.keyring.json" \
    <"$work/$v.file.bb" >"$work/$v.file.out" 2>"$work/$v.file.err"; then
    fail "$v encrypted file: $(cat "$work/$v.file.err")"
  elif [[ $(sha "$work/$v.file.out") != "$(sha "$work/payload/over-chunk.bin")" ]]; then
    fail "$v encrypted file: SHA-256 differs"
  fi
  port=$((port + 1))
done

if [[ $failures -gt 0 ]]; then
  echo "$failures failures across ${#versions[@]} versions" >&2
  exit 1
fi
echo "ok: the current build reads everything ${versions[*]} wrote"
