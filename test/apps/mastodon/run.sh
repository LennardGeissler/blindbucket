#!/usr/bin/env bash
# Mastodon storing its media through the gateway (#129).
#
# For each of the two Mastodons -- object names in clear, and encrypted:
#
#   1. upload an image and post it in a direct message; Mastodon processes it
#      and stores an original and a preview through the gateway;
#   2. fetch both the way a browser does, from the URLs Mastodon hands out,
#      through the media proxy: the original's pixels are the uploaded ones;
#   3. ask the gateway for the same URL without the proxy, as a browser would
#      without S3_ALIAS_HOST: it refuses, because the request is not signed;
#   4. upload an image above the multipart threshold, and fetch it back;
#   5. set the account's avatar, and fetch it back;
#   6. delete the large image's record behind Mastodon's back, and let
#      `tootctl media remove-orphans` find its objects by listing the bucket
#      and delete them: they are gone, the others still served.
#
# Then the provider holds only blindbucket objects, the names bucket no key in
# clear, and neither gateway logged an ERROR.
#
#   test/apps/mastodon/run.sh          run, then tear everything down
#   KEEP=1 test/apps/mastodon/run.sh   leave it running, to look around
#
# Needs Docker with compose, Go, curl and python3. test/apps/lib.sh does what
# every scenario does; this file is what is particular to Mastodon.
set -euo pipefail
cd "$(dirname "$0")"
. ../lib.sh

app_setup "Mastodon on :3001 and :3002, media on :8091 and :8092 (names in clear, encrypted)"
app_up

pass=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
fail() { echo "FAIL  $1" >&2; exit 1; }

# Random RGBA pixels, so that PNG cannot compress them and Mastodon keeps the
# format: transparency rules out JPEG.
python3 - "$work" <<'PY'
import random, struct, sys, zlib
def png(path, w, h, seed):
    r = random.Random(seed)
    raw = b"".join(b"\x00" + r.randbytes(w * 4) for _ in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
png(sys.argv[1] + "/small.png", 320, 240, 1)
png(sys.argv[1] + "/large.png", 1400, 1000, 2)  # 5.6 MB, over the 5 MB threshold
PY

# An account, approved and confirmed, and a token for it. Directly in Rails:
# tootctl checks the e-mail domain's MX record, which a scenario has none of.
token_rb='
account = Account.create!(username: "scenario")
user = User.new(email: "scenario@example.com", password: "scenario-password-not-a-secret",
                agreement: true, account: account, confirmed_at: Time.now.utc,
                role: UserRole.find_by(name: "Owner"))
user.save!(validate: false)
user.update_columns(approved: true)
app = Doorkeeper::Application.create!(name: "scenario", redirect_uri: "urn:ietf:wg:oauth:2.0:oob", scopes: "read write")
puts Doorkeeper::AccessToken.create!(application: app, resource_owner_id: user.id, scopes: "read write").token'

# Mastodon runs in production mode and redirects plain HTTP to HTTPS, unless
# a proxy in front says the request came over HTTPS.
api() {
	local port=$1 path=$2
	shift 2
	curl -s -H "Authorization: Bearer $token" -H 'X-Forwarded-Proto: https' -H 'Host: localhost' "$@" \
		-w '\n%{http_code}' "http://127.0.0.1:$port$path"
}
# call <port> <path> [curl arguments]: the body into $body, the status into $code.
call() {
	local out
	out=$(api "$@")
	body=${out%$'\n'*}
	code=${out##*$'\n'}
}
field() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2], {}, {"d": d}))' "$body" "$1"; }

# The pixels of two images, compared by libvips in Mastodon's own container.
same_pixels() {
	local service=$1 a=$2 b=$3
	compose cp "$a" "$service:/tmp/a.png" >/dev/null 2>&1
	compose cp "$b" "$service:/tmp/b.png" >/dev/null 2>&1
	compose exec -T "$service" bundle exec ruby -e '
		require "vips"
		a, b = ARGV.map { |f| Vips::Image.new_from_file(f) }
		[a.width, a.height, a.bands] == [b.width, b.height, b.bands] or abort "#{a.width}x#{a.height} vs #{b.width}x#{b.height}"
		d = (a - b).abs.max
		d == 0 or abort "pixels differ by up to #{d}"' /tmp/a.png /tmp/b.png
}
decodes() {
	local service=$1 f=$2
	compose cp "$f" "$service:/tmp/c.img" >/dev/null 2>&1
	compose exec -T "$service" bundle exec ruby -e 'require "vips"; Vips::Image.new_from_file(ARGV[0]).avg' /tmp/c.img
}
# A media URL, fetched as a browser does, into $2; prints the status.
fetch() { curl -s -o "$2" -w '%{http_code}' "$1"; }

# Whether the gateway has an object, asked past the media proxy, which caches:
# a HEAD signed with Mastodon's credential. Not mc stat, which also lists with
# the whole key as the prefix -- a listing names.encrypt cannot answer.
stored() {
	local v=$1 url=$2 media=$3
	local V c
	V=$(echo "$v" | tr '[:lower:]' '[:upper:]')
	c=$(compose exec -T "media-$v" curl -s -o /dev/null -w '%{http_code}' --head \
		--aws-sigv4 aws:amz:us-east-1:s3 --user "MASTODONSCENARIO$V:mastodon-scenario-secret-$v" \
		"http://gateway-$v:9000/mastodon-$v/${url#http://localhost:$media/}")
	case $c in
	200) return 0 ;;
	404) return 1 ;;
	*) fail "a signed HEAD answered $c" ;;
	esac
}

scenario() {
	local port=$1 media=$2 v=$3 label=$4
	local service=mastodon-$v
	for _ in $(seq 1 100); do
		curl -sf -o /dev/null "http://127.0.0.1:$port/health" && break
		app_gateways_running || { echo "a gateway is not running" >&2; exit 1; }
		sleep 3
	done
	curl -sf -o /dev/null "http://127.0.0.1:$port/health" || fail "$label: Mastodon on :$port did not start"
	token=$(compose exec -T "$service" bin/rails runner "$token_rb" | tail -1)

	# 1. An image, in a direct message.
	call "$port" /api/v2/media -F "file=@$work/small.png" -F description=scenario
	[[ $code == 200 ]] || fail "$label: uploading an image answered $code: $body"
	local id url preview
	id=$(field 'd["id"]') url=$(field 'd["url"]') preview=$(field 'd["preview_url"]')
	call "$port" /api/v1/statuses -F "status=a picture, for the scenario" -F visibility=direct -F "media_ids[]=$id"
	[[ $code == 200 ]] || fail "$label: posting answered $code: $body"
	[[ $(field 'd["media_attachments"][0]["url"]') == "$url" ]] || fail "$label: the status carries another URL"
	ok "$label: an image uploaded, processed and posted in a direct message"

	# 2. As a browser fetches it.
	[[ $url == "http://localhost:$media/"* ]] || fail "$label: Mastodon hands out $url, not the media proxy"
	[[ $(fetch "$url" "$work/got.png") == 200 ]] || fail "$label: the original answered $(fetch "$url" /dev/null)"
	same_pixels "$service" "$work/small.png" "$work/got.png" || fail "$label: the original is not the uploaded image"
	[[ $(fetch "$preview" "$work/preview.img") == 200 ]] || fail "$label: the preview answered $(fetch "$preview" /dev/null)"
	decodes "$service" "$work/preview.img" || fail "$label: the preview is not an image"
	ok "$label: original and preview served through the media proxy, the original's pixels identical"

	# 3. The same object, asked of the gateway without a signature.
	local key=${url#http://localhost:$media/} c
	c=$(compose exec -T "media-$v" curl -s -o /dev/null -w '%{http_code}' "http://gateway-$v:9000/mastodon-$v/$key")
	[[ $c == 403 ]] || fail "$label: an unsigned read answered $c, not 403"
	ok "$label: an unsigned read of the same URL at the gateway is refused, 403"

	# 4. Over the multipart threshold.
	call "$port" /api/v2/media -F "file=@$work/large.png"
	[[ $code == 200 ]] || fail "$label: uploading a large image answered $code: $body"
	local large_id large_url large_preview
	large_id=$(field 'd["id"]') large_url=$(field 'd["url"]') large_preview=$(field 'd["preview_url"]')
	compose logs --no-color "gateway-$v" | grep '"msg":"multipart upload completed"' |
		grep -q "\"key\":\"${large_url#http://localhost:$media/}\"" ||
		fail "$label: the large image was not stored as a multipart upload"
	[[ $(fetch "$large_url" "$work/got-large.png") == 200 ]] || fail "$label: the large image answered $(fetch "$large_url" /dev/null)"
	same_pixels "$service" "$work/large.png" "$work/got-large.png" || fail "$label: the large image is not the uploaded one"
	ok "$label: a 5.6 MB image stored as a multipart upload, its pixels identical"

	# 5. An avatar, which Mastodon crops and resizes.
	call "$port" /api/v1/accounts/update_credentials -X PATCH -F "avatar=@$work/small.png"
	[[ $code == 200 ]] || fail "$label: setting the avatar answered $code: $body"
	local avatar
	avatar=$(field 'd["avatar"]')
	[[ $avatar == "http://localhost:$media/accounts/avatars/"* ]] || fail "$label: the avatar is at $avatar"
	[[ $(fetch "$avatar" "$work/avatar.img") == 200 ]] || fail "$label: the avatar answered $(fetch "$avatar" /dev/null)"
	decodes "$service" "$work/avatar.img" || fail "$label: the avatar is not an image"
	ok "$label: an avatar stored and served"

	# 6. Orphans. The record goes without its files, as when Mastodon loses
	# track of an object; remove-orphans lists media_attachments/ through the
	# gateway, finds the two objects that belong to no record, and deletes
	# them.
	compose exec -T "$service" bin/rails runner "MediaAttachment.find($large_id).delete" >/dev/null
	local out
	out=$(compose exec -T "$service" bin/tootctl media remove-orphans 2>&1)
	[[ $out == *"Removed 2 orphans"* ]] || fail "$label: remove-orphans: $(echo "$out" | tail -3)"
	# Asked of the gateway: the media proxy keeps serving what it cached, for
	# an hour by default, whatever happened to it.
	! stored "$v" "$large_url" "$media" && ! stored "$v" "$large_preview" "$media" ||
		fail "$label: the orphan's objects are still in the bucket"
	stored "$v" "$url" "$media" && stored "$v" "$preview" "$media" && stored "$v" "$avatar" "$media" ||
		fail "$label: remove-orphans deleted more than the orphan"
	ok "$label: remove-orphans listed the bucket and deleted exactly the orphan's 2 objects"
}

echo "==> operations"
scenario 3001 8091 plain "names in clear "
scenario 3002 8092 names "names encrypted"
compose exec -T mastodon-plain bin/tootctl version

# The image's original and preview, and the avatar; the large image's two are
# gone.
app_check_provider mastodon 3 media_attachments/ accounts/

echo "==> what the gateways saw"
app_check_gateway_logs

echo "PASS ($pass checks)"
