#!/usr/bin/env bash
# GitLab storing in object storage through the gateway (#127).
#
# For each of the two GitLabs -- object names in clear, and encrypted -- one
# after the other, because each wants some 4 GB:
#
#   1. an attachment uploaded to a project, downloaded the way a browser does:
#      GitLab redirects to a presigned URL at the gateway, signed with
#      response-content-disposition (ADR-032);
#   2. a generic package, downloaded by redirect and proxied through GitLab;
#   3. an LFS object, through the batch API git-lfs uses, read back by the
#      presigned URL the batch answer hands out;
#   4. a CI job's artifact archive, uploaded by the runner protocol, read back
#      whole by redirect and one file by Workhorse, and listed by the artifact
#      browser, which needs the index Workhorse builds from the archive;
#   5. a second attachment deleted: gone from the bucket, the first one kept.
#
# Every upload goes through Workhorse's own S3 client and Rails' move from
# tmp/uploads/, and every download through a presigned GET. Then the provider
# holds only blindbucket objects, the names buckets no key in clear, and
# neither gateway logged an ERROR.
#
#   test/apps/gitlab/run.sh          run, then tear everything down
#   KEEP=1 test/apps/gitlab/run.sh   leave it running, to look around
#
# Needs Docker with compose, Go, curl and python3. test/apps/lib.sh does what
# every scenario does; this file is what is particular to GitLab.
set -euo pipefail
cd "$(dirname "$0")"
. ../lib.sh

app_setup "GitLab on :8181 (names in clear) or :8182 (names encrypted)"
app_up
# The GitLabs have a profile each, so that app_up starts neither; with both
# profiles on, what follows -- logs, teardown -- sees them too.
export COMPOSE_PROFILES=plain,names

pass=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
fail() { echo "FAIL  $1" >&2; exit 1; }

token=glpat-scenario-token-not-a-secret-0001
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {"d": d}))' "$1"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

head -c 3000000 /dev/urandom >"$work/attach.bin"
head -c 2000000 /dev/urandom >"$work/second.bin"
head -c 12000000 /dev/urandom >"$work/lfs.bin"
python3 - "$work" <<'PY'
import os, sys, zipfile
work = sys.argv[1]
with open(f"{work}/out.bin", "wb") as f:
    f.write(os.urandom(12_000_000))
with zipfile.ZipFile(f"{work}/artifacts.zip", "w", zipfile.ZIP_STORED) as z:
    z.write(f"{work}/out.bin", "out.bin")
PY
lfs_oid=$(sha "$work/lfs.bin")
lfs_size=$(wc -c <"$work/lfs.bin" | tr -d ' ')

scenario() {
	local port=$1 v=$2 label=$3
	local G="http://127.0.0.1:$port"
	local A=(-H "PRIVATE-TOKEN: $token")

	echo "==> GitLab, $label"
	compose up -d --quiet-pull "gitlab-$v" >"$work/up-$v.log" 2>&1 || { cat "$work/up-$v.log" >&2; exit 1; }
	for _ in $(seq 1 120); do
		[[ $(curl -s -o /dev/null -w '%{http_code}' "$G/users/sign_in") == 200 ]] && break
		app_gateways_running || { echo "a gateway is not running" >&2; exit 1; }
		sleep 10
	done
	[[ $(curl -s -o /dev/null -w '%{http_code}' "$G/users/sign_in") == 200 ]] || fail "$label: GitLab did not start"
	compose exec -T "gitlab-$v" cat /opt/gitlab/version-manifest.txt | head -1

	# A token with a known value, in Rails: the API has no way to make the
	# first one. The second Rails process can cost Puma its place in 4 GB, so
	# the API is waited for again.
	compose exec -T "gitlab-$v" gitlab-rails runner "
		t = User.find_by_username('root').personal_access_tokens.create!(name: 'scenario',
			scopes: %w[api read_repository write_repository], expires_at: 30.days.from_now)
		t.set_token('$token'); t.save!" >/dev/null
	for _ in $(seq 1 60); do
		[[ $(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" "$G/api/v4/user") == 200 ]] && break
		sleep 5
	done

	# fog-aws copies a file over 10 MB from tmp/uploads/ to its place in parts
	# of 10 MiB and one byte, which the gateway refuses (FORMAT section 7.3).
	# With this flag off GitLab copies it in one CopyObject.
	curl -s -o /dev/null "${A[@]}" -X POST "$G/api/v4/features/s3_multithreaded_uploads" -d value=false
	local c
	c=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$G/api/v4/projects" \
		-d name=scenario -d visibility=public -d initialize_with_readme=true)
	[[ $c == 201 ]] || fail "$label: creating the project answered $c"

	# 1. An attachment.
	local up loc
	up=$(curl -s "${A[@]}" -F "file=@$work/attach.bin" "$G/api/v4/projects/1/uploads")
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$G$(echo "$up" | json 'd["full_path"]')")
	[[ $loc == "http://gateway-$v:9000/"*"response-content-disposition="* ]] ||
		fail "$label: the attachment's download is not a presigned URL at the gateway: $loc"
	compose exec -T client curl -s -D /dev/stderr -o - "$loc" 2>"$work/headers" >"$work/got"
	grep -q '^HTTP/1.1 200' "$work/headers" || fail "$label: the attachment answered $(head -1 "$work/headers")"
	[[ $(sha "$work/got") == $(sha "$work/attach.bin") ]] || fail "$label: the attachment came back different"
	grep -qi '^Content-Disposition: attachment; filename="attach.bin"' "$work/headers" ||
		fail "$label: the attachment came back without its file name"
	ok "$label: an attachment, downloaded by GitLab's redirect to the gateway, identical and under its name"

	# 2. A generic package, by redirect and proxied.
	c=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" --upload-file "$work/attach.bin" \
		"$G/api/v4/projects/1/packages/generic/scenario/1.0.0/blob.bin")
	[[ $c == 201 ]] || fail "$label: publishing the package answered $c"
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' "${A[@]}" "$G/api/v4/projects/1/packages/generic/scenario/1.0.0/blob.bin")
	compose exec -T client curl -sf "$loc" >"$work/got" || fail "$label: the package's redirect failed"
	[[ $(sha "$work/got") == $(sha "$work/attach.bin") ]] || fail "$label: the package came back different"
	curl -sf "${A[@]}" -o "$work/got" "$G/api/v4/projects/1/packages/generic/scenario/1.0.0/blob.bin?download_mode=proxy" ||
		fail "$label: the proxied package download failed"
	[[ $(sha "$work/got") == $(sha "$work/attach.bin") ]] || fail "$label: the proxied package came back different"
	ok "$label: a package, downloaded by redirect and proxied through GitLab, identical"

	# 3. LFS, as git-lfs does it.
	local L=(-u "root:$token" -H 'Accept: application/vnd.git-lfs+json' -H 'Content-Type: application/vnd.git-lfs+json')
	local batch="{\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"$lfs_oid\",\"size\":$lfs_size}]"
	local answer href auth
	answer=$(curl -s "${L[@]}" -X POST "$G/root/scenario.git/info/lfs/objects/batch" -d "$batch,\"operation\":\"upload\"}")
	href=$(echo "$answer" | json 'd["objects"][0]["actions"]["upload"]["href"]')
	auth=$(echo "$answer" | json 'd["objects"][0]["actions"]["upload"]["header"]["Authorization"]')
	c=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: $auth" \
		-H 'Content-Type: application/octet-stream' --data-binary "@$work/lfs.bin" "$href")
	[[ $c == 200 ]] || fail "$label: the LFS upload answered $c"
	answer=$(curl -s "${L[@]}" -X POST "$G/root/scenario.git/info/lfs/objects/batch" -d "$batch,\"operation\":\"download\"}")
	href=$(echo "$answer" | json 'd["objects"][0]["actions"]["download"]["href"]')
	[[ $href == "http://gateway-$v:9000/"* ]] || fail "$label: the LFS download is not at the gateway: $href"
	compose exec -T client curl -sf "$href" >"$work/got" || fail "$label: the LFS download failed"
	[[ $(sha "$work/got") == "$lfs_oid" ]] || fail "$label: the LFS object came back different"
	ok "$label: a 12 MB LFS object through the batch API, its SHA-256 the oid it was stored under"

	# 4. A job artifact, by the runner protocol.
	local runner job jt
	runner=$(curl -s "${A[@]}" -X POST "$G/api/v4/user/runners" -d runner_type=instance_type -d run_untagged=true |
		json 'd["token"]')
	c=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$G/api/v4/projects/1/repository/files/.gitlab-ci.yml" \
		-d branch=main -d commit_message=ci --data-urlencode $'content=job:\n  script: [":"]\n  artifacts:\n    paths: [out.bin]\n')
	[[ $c == 201 ]] || fail "$label: committing .gitlab-ci.yml answered $c"
	for _ in $(seq 1 30); do
		c=$(curl -s -o "$work/job.json" -w '%{http_code}' -X POST "$G/api/v4/jobs/request" -H 'Content-Type: application/json' \
			-d "{\"token\":\"$runner\",\"info\":{\"features\":{\"artifacts\":true,\"upload_multiple_artifacts\":true}}}")
		[[ $c == 201 ]] && break
		sleep 3
	done
	[[ $c == 201 ]] || fail "$label: no job was handed to the runner"
	job=$(json 'd["id"]' <"$work/job.json")
	jt=$(json 'd["token"]' <"$work/job.json")
	c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "JOB-TOKEN: $jt" -F "file=@$work/artifacts.zip" \
		"$G/api/v4/jobs/$job/artifacts?artifact_format=zip&artifact_type=archive")
	[[ $c == 201 ]] || fail "$label: the artifact upload answered $c"
	curl -s -o /dev/null -X PUT "$G/api/v4/jobs/$job" -H 'Content-Type: application/json' \
		-d "{\"token\":\"$jt\",\"state\":\"success\"}"
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' "${A[@]}" "$G/api/v4/projects/1/jobs/$job/artifacts")
	compose exec -T client curl -sf "$loc" >"$work/got" || fail "$label: the archive's redirect failed"
	[[ $(sha "$work/got") == $(sha "$work/artifacts.zip") ]] || fail "$label: the archive came back different"
	curl -sfL "${A[@]}" -o "$work/got" "$G/api/v4/projects/1/jobs/$job/artifacts/out.bin" ||
		fail "$label: reading one file from the archive failed"
	[[ $(sha "$work/got") == $(sha "$work/out.bin") ]] || fail "$label: the file read from the archive is different"
	curl -s "$G/root/scenario/-/jobs/$job/artifacts/browse" | grep -q 'out.bin' ||
		fail "$label: the artifact browser does not list out.bin: Workhorse could not index the archive"
	ok "$label: a job artifact, the archive by redirect and one file by Workhorse identical, and browsable"

	# 5. Deleting an attachment, checked at the gateway with GitLab's credential.
	local second key V
	V=$(echo "$v" | tr '[:lower:]' '[:upper:]')
	second=$(curl -s "${A[@]}" -F "file=@$work/second.bin" "$G/api/v4/projects/1/uploads")
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$G$(echo "$second" | json 'd["full_path"]')")
	key=${loc%%\?*}
	head_at_gateway() {
		compose exec -T client curl -s -o /dev/null -w '%{http_code}' --head \
			--aws-sigv4 aws:amz:us-east-1:s3 --user "GITLABSCENARIO$V:gitlab-scenario-secret-$v" "$1"
	}
	[[ $(head_at_gateway "$key") == 200 ]] || fail "$label: the second attachment is not in the bucket"
	c=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE \
		"$G/api/v4/projects/1/uploads/$(echo "$second" | json 'd["id"]')")
	[[ $c == 204 ]] || fail "$label: deleting the attachment answered $c"
	[[ $(head_at_gateway "$key") == 404 ]] || fail "$label: the deleted attachment is still in the bucket"
	local first
	first=$(curl -s -o /dev/null -w '%{redirect_url}' "$G$(echo "$up" | json 'd["full_path"]')")
	[[ $(head_at_gateway "${first%%\?*}") == 200 ]] || fail "$label: deleting one attachment took the other"
	ok "$label: an attachment deleted, gone from the bucket, the other kept"

	compose stop -t 60 "gitlab-$v" >/dev/null 2>&1
}

scenario 8181 plain "names in clear "
scenario 8182 names "names encrypted"

# Each kind of object in its own bucket. The keys in clear: projects by the
# hash of their id (6b/86/... is project 1), uploads under @hashed/, an LFS
# object by its oid, and what Workhorse writes first, under tmp/.
clear="6b/ @hashed/ tmp/ ${lfs_oid:0:2}/"
app_check_provider gl-uploads 1 $clear
app_check_provider gl-packages 1 $clear
app_check_provider gl-lfs 1 $clear
app_check_provider gl-artifacts 2 $clear

echo "==> what the gateways saw"
app_check_gateway_logs

echo "PASS ($pass checks)"
