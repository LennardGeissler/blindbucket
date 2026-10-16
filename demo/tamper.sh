#!/usr/bin/env bash
#
# Play the hostile storage provider: flip one bit of a stored object's ciphertext,
# in place, behind the gateway's back -- and preserve the object's metadata, so
# that what the download then hits is the authentication tag and not a missing
# wrapped key.
#
# This exists because "tampering is detected" is the kind of claim a reader should
# be able to check in ten seconds rather than take on trust. The same attack is a
# test (internal/proxy/integration rewrites stored objects and requires an
# error rather than plaintext); this is the hand-operated version, for the demo.
#
# Usage:
#   demo/tamper.sh <key> [byte-offset]
#
# The default offset is 40: past the 32-byte segment header, so the corruption
# lands in the first chunk's ciphertext rather than in the header. Both are
# detected, in different places, which is the point of trying each.
set -euo pipefail

state=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.state
[[ -f "$state/env.sh" ]] || { echo "run demo/setup.sh first" >&2; exit 1; }
# shellcheck disable=SC1091
source "$state/env.sh"

key=${1:?usage: demo/tamper.sh <key> [byte-offset]}
offset=${2:-40}

# Straight at the provider, with the provider's own credentials -- not through the
# gateway. That is the whole premise of the threat model.
upstream=(aws --endpoint-url http://127.0.0.1:9002 s3api)
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

tmp=$(mktemp -t blindbucket-tamper)
trap 'rm -f "$tmp"' EXIT

"${upstream[@]}" get-object --bucket "$DEMO_BUCKET" --key "$key" "$tmp" >/dev/null
meta=$("${upstream[@]}" head-object --bucket "$DEMO_BUCKET" --key "$key" \
  --query Metadata --output json)

size=$(wc -c < "$tmp" | tr -d ' ')
(( offset < size )) || { echo "offset $offset is past the end of the object ($size bytes)" >&2; exit 1; }

before=$(dd if="$tmp" bs=1 skip="$offset" count=1 2>/dev/null | xxd -p)
after=$(printf '%02x' $(( 0x$before ^ 0x01 )))
printf "$(printf '\\x%s' "$after")" | dd of="$tmp" bs=1 seek="$offset" count=1 conv=notrunc 2>/dev/null

"${upstream[@]}" put-object --bucket "$DEMO_BUCKET" --key "$key" \
  --body "$tmp" --metadata "$meta" >/dev/null

printf 'byte %d of %s: 0x%s -> 0x%s, stored, metadata intact\n' "$offset" "$key" "$before" "$after"
