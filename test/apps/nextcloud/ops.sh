#!/usr/bin/env bash
# Exercises one Nextcloud instance the way its clients do, over WebDAV and the
# OCS API, and reports each operation as PASS or FAIL with the evidence.
#
#   ops.sh <port> <admin password> <label>
#
# With $OCC set to a command that runs Nextcloud's occ, it also lowers
# Nextcloud's multipart threshold, so that an upload goes through
# CreateMultipartUpload, UploadPart and CompleteMultipartUpload: by default
# Nextcloud uses multipart only above 100 MiB.
#
# Exits non-zero when any operation failed.
set -uo pipefail
port=$1 pw=$2 label=$3
base="http://127.0.0.1:$port"
dav="$base/remote.php/dav/files/admin"
auth=(-u "admin:$pw")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pass=0 fail=0

ok() { echo "PASS  $label  $1"; pass=$((pass + 1)); }
bad() { echo "FAIL  $label  $1"; fail=$((fail + 1)); }
code() { curl -s -o "${OUT:-/dev/null}" -w '%{http_code}' "${auth[@]}" "$@"; }
sum() { shasum -a 256 "$1" | cut -d' ' -f1; }

# 1. A small file, written and read back.
printf 'hello through the gateway\n' > "$work/small.txt"
c=$(code -T "$work/small.txt" "$dav/small.txt")
OUT="$work/small.back" c2=$(code "$dav/small.txt")
if [[ $c =~ ^20[14]$ && $c2 == 200 ]] && cmp -s "$work/small.txt" "$work/small.back"; then
	ok "small file PUT ($c) and GET round trip"
else
	bad "small file: PUT $c, GET $c2"
fi

# 2. A 25 MB file in one PUT: below Nextcloud's multipart threshold.
head -c 25000000 /dev/urandom > "$work/big.bin"
c=$(code -T "$work/big.bin" "$dav/big.bin")
OUT="$work/big.back" c2=$(code "$dav/big.bin")
if [[ $c =~ ^20[14]$ && $c2 == 200 && $(sum "$work/big.bin") == $(sum "$work/big.back") ]]; then
	ok "25 MB single PUT and GET, identical SHA-256"
else
	bad "25 MB single PUT: PUT $c, GET $c2"
fi

# 3. A range read, as a preview or a media player makes.
OUT="$work/range" c=$(code -r 1000-1999 "$dav/big.bin")
if [[ $c == 206 ]] && cmp -s "$work/range" <(tail -c +1001 "$work/big.bin" | head -c 1000); then
	ok "range GET bytes 1000-1999 (206), bytes match"
else
	bad "range GET: $c"
fi

# 4. Rename (MOVE): in primary-storage mode only the database changes.
c=$(code -X MOVE -H "Destination: $dav/renamed.bin" "$dav/big.bin")
OUT="$work/renamed.back" c2=$(code "$dav/renamed.bin")
if [[ $c =~ ^20[14]$ && $c2 == 200 && $(sum "$work/big.bin") == $(sum "$work/renamed.back") ]]; then
	ok "MOVE (rename) $c, renamed file reads back"
else
	bad "MOVE: $c, GET after $c2"
fi

# 5. Copy (COPY): a new object from an existing one.
c=$(code -X COPY -H "Destination: $dav/copy.bin" "$dav/renamed.bin")
OUT="$work/copy.back" c2=$(code "$dav/copy.bin")
if [[ $c =~ ^20[14]$ && $c2 == 200 && $(sum "$work/big.bin") == $(sum "$work/copy.back") ]]; then
	ok "COPY $c, copy reads back identical"
else
	bad "COPY: $c, GET after $c2"
fi

# 6. Overwrite, which makes a version of the old content.
printf 'second version\n' > "$work/small2.txt"
c=$(code -T "$work/small2.txt" "$dav/small.txt")
OUT="$work/small2.back" c2=$(code "$dav/small.txt")
fileid=$(curl -s "${auth[@]}" -X PROPFIND -H 'Depth: 0' \
	--data '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>' \
	"$dav/small.txt" | python3 -I -c 'import sys,re; m=re.search(r"<oc:fileid>(\d+)</oc:fileid>", sys.stdin.read()); print(m.group(1) if m else "")')
old=$(curl -s "${auth[@]}" -X PROPFIND -H 'Depth: 1' "$base/remote.php/dav/versions/admin/versions/$fileid" |
	python3 -I -c 'import sys,re; [print(h) for h in re.findall(r"<d:href>([^<]*)</d:href>", sys.stdin.read())]' |
	grep -v "/$fileid/\$" | head -1)
oldbody=$(curl -s "${auth[@]}" "$base$old")
if [[ $c =~ ^20[14]$ && $c2 == 200 ]] && cmp -s "$work/small2.txt" "$work/small2.back" && [[ $oldbody == "hello through the gateway" ]]; then
	ok "overwrite $c reads the new content, and the old version reads back"
else
	bad "overwrite: PUT $c, GET $c2, old version '${oldbody:0:40}'"
fi

# 7. Chunked upload v2, as the desktop and mobile clients send large files:
#    chunks of 5,000,000 bytes, which Nextcloud turns into S3 multipart parts.
#    5,000,000 is not a multiple of the gateway's 64 KiB chunk.
head -c 12000000 /dev/urandom > "$work/chunked.bin"
up="$base/remote.php/dav/uploads/admin/pilot-$RANDOM"
dest="$dav/chunked.bin"
c0=$(code -X MKCOL -H "Destination: $dest" "$up")
split -b 5000000 -a 1 "$work/chunked.bin" "$work/part."
i=1 cs=""
for p in "$work"/part.*; do
	cs+=" $(code -T "$p" -H "Destination: $dest" -H "OC-Total-Length: 12000000" "$up/$(printf '%05d' $i)")"
	i=$((i + 1))
done
c=$(code -X MOVE -H "Destination: $dest" -H "OC-Total-Length: 12000000" "$up/.file")
OUT="$work/chunked.back" c2=$(code "$dest")
if [[ $c =~ ^20[14]$ && $c2 == 200 && $(sum "$work/chunked.bin") == $(sum "$work/chunked.back") ]]; then
	ok "chunked upload v2, 5,000,000-byte chunks (MKCOL $c0, chunks$cs, assemble $c), identical"
else
	bad "chunked upload v2: MKCOL $c0, chunks$cs, assemble $c, GET $c2"
fi

# 8. A public link share, downloaded without credentials.
share=$(curl -s "${auth[@]}" -H 'OCS-APIRequest: true' -X POST \
	"$base/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json" \
	-d path=/copy.bin -d shareType=3 | python3 -c 'import sys,json; print(json.load(sys.stdin)["ocs"]["data"]["token"])' 2>/dev/null)
c=$(curl -s -o "$work/share.back" -w '%{http_code}' -L "$base/s/$share/download")
if [[ -n $share && $c == 200 && $(sum "$work/big.bin") == $(sum "$work/share.back") ]]; then
	ok "public link share, downloaded anonymously, identical"
else
	bad "public link share: token '${share:-none}', download $c"
fi

# 9. Delete, then empty the trash, which deletes the object.
c=$(code -X DELETE "$dav/copy.bin")
c2=$(code -X DELETE "$base/remote.php/dav/trashbin/admin/trash")
c3=$(code "$dav/copy.bin")
if [[ $c == 204 && $c2 == 204 && $c3 == 404 ]]; then
	ok "DELETE $c, empty trash $c2, file gone ($c3)"
else
	bad "delete: DELETE $c, empty trash $c2, GET after $c3"
fi

# 10. Multipart, as Nextcloud does it above its threshold: 45 MB in 10 MiB
#     parts, a multiple of the gateway's 64 KiB chunk, as Nextcloud's default
#     of 500 MiB is.
if [[ -n ${OCC:-} ]]; then
	# Without these the upload below is a single PutObject, and the content
	# check passes all the same; run.sh checks the gateway completed a
	# multipart upload.
	$OCC config:system:set objectstore arguments putSizeLimit --value 20971520 --type integer >/dev/null &&
		$OCC config:system:set objectstore arguments uploadPartSize --value 10485760 --type integer >/dev/null ||
		{ echo "FAIL  $label  occ could not lower the multipart threshold"; exit 1; }
	head -c 45000000 /dev/urandom > "$work/mp.bin"
	c=$(code -T "$work/mp.bin" "$dav/mp.bin")
	OUT="$work/mp.back" c2=$(code "$dav/mp.bin")
	if [[ $c =~ ^20[14]$ && $c2 == 200 && $(sum "$work/mp.bin") == $(sum "$work/mp.back") ]]; then
		ok "multipart upload, 45 MB in 10 MiB parts ($c), identical"
	else
		bad "multipart upload: PUT $c, GET $c2"
	fi

	# 11. A part size that is not a multiple of 64 KiB: the gateway refuses
	#     the completion (FORMAT §7.3), and Nextcloud reports a failed upload.
	#     The guide tells an operator who changed the part size what that
	#     looks like.
	$OCC config:system:set objectstore arguments uploadPartSize --value 6000000 --type integer >/dev/null ||
		{ echo "FAIL  $label  occ could not set the part size"; exit 1; }
	c=$(code -T "$work/mp.bin" "$dav/mp-unaligned.bin")
	c2=$(code "$dav/mp-unaligned.bin")
	if [[ $c == 500 && $c2 == 404 ]]; then
		ok "multipart with 6,000,000-byte parts is refused ($c), and nothing is left ($c2)"
	else
		bad "unaligned multipart: PUT $c, GET after $c2"
	fi
	$OCC config:system:set objectstore arguments uploadPartSize --value 10485760 --type integer >/dev/null
fi

echo "$label: $pass passed, $fail failed"
((fail == 0))
