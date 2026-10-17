#!/usr/bin/env bash
# Velero backing up a Kubernetes namespace through the gateway (#126).
#
# A kind cluster holds the provider (MinIO), the two gateways -- object names
# in clear and encrypted -- and Velero with its AWS plugin, with a backup
# storage location behind each gateway. For each location:
#
#   1. back up the namespace app;
#   2. restore it into a namespace of its own, and compare what came back --
#      the ConfigMap, the Secret, the account, the deployment -- with the
#      original;
#   3. delete Velero's record of the backup, and wait for Velero to find the
#      backup again by listing the bucket: the backup sync;
#   4. delete the backup with Velero, and check at the provider that its
#      objects and its restore's are gone.
#
# Between 3 and 4, the provider holds only blindbucket objects, and the names
# bucket no key in clear. Neither gateway may log an ERROR.
#
#   test/apps/velero/run.sh          run, then delete the cluster
#   KEEP=1 test/apps/velero/run.sh   leave the cluster, to look around
#
# Needs Docker and Go: kind runs through `go run`, and kubectl and velero run
# inside the kind node, so neither has to be installed.
set -euo pipefail
cd "$(dirname "$0")"
. ../lib.sh

KIND_VERSION=v0.33.0
CLUSTER=blindbucket-velero
NODE=$CLUSTER-control-plane
VELERO_IMAGE=velero/velero:v1.18.4@sha256:c89fb5b6d1fd6afd368e0f483e6f5555fd62851a1eada8ac5c72482e674ca17b
PLUGIN_IMAGE=velero/velero-plugin-for-aws:v1.14.4@sha256:c85a7fa803569e3128c33e4f5766f84ab156c8d171c9f1dd2715581d45ce98fa

kind() { go run "sigs.k8s.io/kind@$KIND_VERSION" "$@"; }
k() { docker exec -i "$NODE" kubectl "$@"; }
velero() { docker exec -i "$NODE" velero "$@"; }

rm -rf "$work"
mkdir -p "$work"
finish() {
	local status=$?
	if ((status != 0)); then
		echo "--- failed; gateway and Velero logs" >&2
		k -n storage logs deploy/gateway-plain --tail 30 >&2 || true
		k -n storage logs deploy/gateway-names --tail 30 >&2 || true
		k -n velero logs deploy/velero --tail 40 >&2 || true
	fi
	if [[ -z ${KEEP:-} ]]; then
		kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
		rm -rf "$work"
	else
		echo "left running: kind cluster $CLUSTER (docker exec -it $NODE kubectl ...)"
	fi
	exit "$status"
}
trap finish EXIT

echo "==> keyring"
BLINDBUCKET_PASSPHRASE=apps-scenario-not-a-secret \
	go run -C "$repo" ./cmd/blindbucket keygen --out "$KEYRING" --kid scenario >/dev/null

echo "==> cluster"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s >"$work/kind.log" 2>&1 || { cat "$work/kind.log" >&2; exit 1; }

# The gateway image is built from this checkout and loaded into the node; the
# node pulls MinIO and Velero itself, Velero by digest. kind cannot load an
# image pulled from a registry under Docker Desktop's containerd image store:
# it asks for every platform's layers, and only one platform's were pulled.
echo "==> images: the gateway from this checkout, and the velero CLI"
docker build -q -t blindbucket-apps-gateway:latest -f "$repo/deploy/Dockerfile" "$repo" >/dev/null
kind load docker-image blindbucket-apps-gateway:latest --name "$CLUSTER" >"$work/load.log" 2>&1 ||
	{ cat "$work/load.log" >&2; exit 1; }
docker pull -q "$VELERO_IMAGE" >/dev/null

# Velero pulled by digest and run by tag: `velero install` names the plugin's
# init container after its image reference, and a digest in it makes the name
# invalid. With the tag already on the node, IfNotPresent pulls nothing more.
for image in "$VELERO_IMAGE" "$PLUGIN_IMAGE"; do
	docker exec "$NODE" crictl pull "$image" >/dev/null
	docker exec "$NODE" ctr -n k8s.io images tag --force \
		"docker.io/${image%%:*}@${image#*@}" "docker.io/${image%@*}" >/dev/null
done
container=$(docker create --entrypoint /velero "$VELERO_IMAGE")
docker cp "$container:/velero" "$work/velero"
docker rm "$container" >/dev/null
docker cp "$work/velero" "$NODE:/usr/local/bin/velero"

echo "==> MinIO and the two gateways"
k apply -f - <storage.yaml >/dev/null
k -n storage create secret generic keyring --from-file=keyring.json=/dev/stdin <"$KEYRING" >/dev/null
for v in plain names; do
	k -n storage create configmap "gateway-$v" --from-file=blindbucket.yaml=/dev/stdin <"gateway-$v.yaml" >/dev/null
done
k -n storage rollout status deploy/minio --timeout 120s >/dev/null
k -n storage exec deploy/minio -- sh -c \
	'mc alias set m http://localhost:9000 minioadmin minioadmin >/dev/null && mc mb m/velero-plain m/velero-names' >/dev/null
for v in plain names; do
	k -n storage rollout status "deploy/gateway-$v" --timeout 120s >/dev/null
done

echo "==> Velero, with a backup storage location behind each gateway"
velero install --plugins "${PLUGIN_IMAGE%@*}" \
	--image "${VELERO_IMAGE%@*}" --no-default-backup-location --no-secret \
	--use-volume-snapshots=false --wait >"$work/install.log" 2>&1 || { cat "$work/install.log" >&2; exit 1; }
for v in plain names; do
	V=$(echo "$v" | tr '[:lower:]' '[:upper:]')
	printf '[default]\naws_access_key_id=VELEROSCENARIO%s\naws_secret_access_key=velero-scenario-secret-%s\n' "$V" "$v" |
		k -n velero create secret generic "credentials-$v" --from-file=cloud=/dev/stdin >/dev/null
	velero backup-location create "$v" --provider aws --bucket "velero-$v" \
		--credential "credentials-$v=cloud" \
		--config "region=us-east-1,s3ForcePathStyle=true,s3Url=http://gateway-$v.storage:9000" >/dev/null
done
for v in plain names; do
	phase=""
	for _ in $(seq 1 60); do
		phase=$(k -n velero get backupstoragelocation "$v" -o jsonpath='{.status.phase}')
		[[ $phase == Available ]] && break
		sleep 3
	done
	[[ $phase == Available ]] || { echo "location $v is '$phase', not Available" >&2; exit 1; }
done
echo "both locations Available: Velero has listed both buckets through the gateways"

echo "==> the workload"
k apply -f - <workload.yaml >/dev/null

pass=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
fail() { echo "FAIL  $1" >&2; exit 1; }

# What a namespace holds that a restore has to bring back, without the fields
# Kubernetes fills in itself.
content() {
	local ns=$1
	{
		k -n "$ns" get configmap settings -o jsonpath='{.data}'
		echo
		k -n "$ns" get secret credentials -o jsonpath='{.data}'
		echo
		k -n "$ns" get serviceaccount app -o jsonpath='{.metadata.name}'
		echo
		k -n "$ns" get deployment web -o jsonpath='{.spec.template.spec.containers[0].image} {.spec.replicas}'
		echo
	}
}

phase_of() { k -n velero get "$1" "$2" -o jsonpath='{.status.phase}' 2>/dev/null || true; }

backup_and_restore() {
	local v=$1 label=$2
	velero backup create "bk-$v" --include-namespaces app --storage-location "$v" --wait >/dev/null
	[[ $(phase_of backup "bk-$v") == Completed ]] ||
		fail "$label: backup is '$(phase_of backup "bk-$v")'"
	ok "$label: backup Completed"

	velero restore create "rs-$v" --from-backup "bk-$v" --namespace-mappings "app:app-$v" --wait >/dev/null
	[[ $(phase_of restore "rs-$v") == Completed ]] ||
		fail "$label: restore is '$(phase_of restore "rs-$v")'"
	# A namespace that is not there reads as nothing, and nothing equals
	# nothing: the original has to hold what workload.yaml put in it.
	[[ $(content app) == *checkout-v2=on* ]] || fail "$label: cannot read the namespace app"
	[[ $(content "app-$v") == "$(content app)" ]] ||
		fail "$label: the restored namespace differs from the original"
	ok "$label: restored into app-$v, ConfigMap, Secret, account and deployment identical"

	# Only Velero's record goes; the objects stay, and the backup sync finds
	# them again by listing backups/ in the bucket.
	k -n velero delete backup "bk-$v" --wait >/dev/null
	for _ in $(seq 1 60); do
		[[ $(phase_of backup "bk-$v") == Completed ]] && break
		sleep 3
	done
	[[ $(phase_of backup "bk-$v") == Completed ]] ||
		fail "$label: the backup sync did not find bk-$v in the bucket"
	ok "$label: the backup sync found bk-$v again by listing the bucket"
}

# What the provider holds in a bucket, counted here: MinIO's image has no wc.
stored() {
	k -n storage exec deploy/minio -- env MC_HOST_m=http://minioadmin:minioadmin@localhost:9000 \
		mc ls --recursive "m/velero-$1" | grep -c . || true
}

delete_backup() {
	local v=$1 label=$2 before
	before=$(stored "$v")
	velero backup delete "bk-$v" --confirm >/dev/null
	for _ in $(seq 1 60); do
		[[ -z $(phase_of backup "bk-$v") && $(stored "$v") == 0 ]] && break
		sleep 3
	done
	[[ -z $(phase_of backup "bk-$v") ]] || fail "$label: bk-$v was not deleted"
	# Checked at the provider, past the gateway: Velero deletes a backup's
	# objects, and its restores' too, by listing them under their prefixes --
	# which, with names.encrypt, only the gateway can.
	[[ $(stored "$v") == 0 ]] ||
		fail "$label: bk-$v deleted, but $(stored "$v") objects are still in velero-$v"
	ok "$label: bk-$v deleted with its restore, and all $before objects gone from velero-$v"
}

echo "==> backups and restores"
backup_and_restore plain "names in clear "
backup_and_restore names "names encrypted"
echo "Velero $(velero version --client-only | grep -m1 Version: | tr -d '[:space:]' | cut -d: -f2)"

echo "==> what the provider holds"
k -n storage exec -i deploy/minio -- env PREFIX=velero FLOOR=5 CLEAR="backups/ restores/" \
	MC_HOST_m=http://minioadmin:minioadmin@localhost:9000 sh -c "$(app_provider_script)"

echo "==> deleting the backups"
delete_backup plain "names in clear "
delete_backup names "names encrypted"

echo "==> what the gateways logged"
errors=$({ k -n storage logs deploy/gateway-plain; k -n storage logs deploy/gateway-names; } |
	grep '"level":"ERROR"' || true)
[[ -z $errors ]] || { echo "ERROR lines:" >&2; echo "$errors" >&2; exit 1; }
echo "no ERROR"

echo "PASS ($pass checks)"
