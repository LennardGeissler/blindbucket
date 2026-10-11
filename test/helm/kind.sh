#!/usr/bin/env bash
# The Helm chart, installed and used: a kind cluster, MinIO inside it, the chart
# built from this checkout with TLS, and the AWS CLI in another pod putting an
# object through it and reading it back. Then MinIO is asked directly what it
# holds, which has to be ciphertext.
#
# Needs Docker and Go, nothing else: kind runs through `go run`, and kubectl
# and helm run inside the kind node, so neither has to be installed.
#
#   test/helm/kind.sh            # KEEP_CLUSTER=1 leaves the cluster for a look
set -euo pipefail

cd "$(dirname "$0")/../.."
KIND_VERSION=v0.33.0
HELM_IMAGE=alpine/helm:4.3.0
CLUSTER=blindbucket-chart
NODE=$CLUSTER-control-plane
IMAGE=blindbucket:chart-test
WORK=$(mktemp -d)

kind() { go run "sigs.k8s.io/kind@$KIND_VERSION" "$@"; }
k() { docker exec -i "$NODE" kubectl "$@"; }
helm() { docker exec -i "$NODE" helm "$@"; }

cleanup() {
	status=$?
	if [[ $status -ne 0 ]]; then
		echo "--- failed; gateway logs:" >&2
		k logs -l app.kubernetes.io/name=blindbucket --tail=50 --prefix >&2 || true
	fi
	if [[ -z "${KEEP_CLUSTER:-}" ]]; then
		kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
	exit $status
}
trap cleanup EXIT

echo "==> cluster"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s

echo "==> gateway image, built from this checkout"
docker build -q -f deploy/Dockerfile -t "$IMAGE" . >/dev/null
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "==> helm, into the node"
helm_container=$(docker create "$HELM_IMAGE")
docker cp "$helm_container:/usr/bin/helm" "$WORK/helm"
docker rm "$helm_container" >/dev/null
docker cp "$WORK/helm" "$NODE:/usr/local/bin/helm"
docker exec "$NODE" mkdir -p /chart
docker cp deploy/helm/blindbucket "$NODE:/chart/"

echo "==> MinIO, the provider"
k apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: minio }
spec:
  selector: { matchLabels: { app: minio } }
  template:
    metadata: { labels: { app: minio } }
    spec:
      containers:
        - name: minio
          image: cgr.dev/chainguard/minio:latest
          args: [server, /data]
          env:
            - { name: MINIO_ROOT_USER, value: minioadmin }
            - { name: MINIO_ROOT_PASSWORD, value: minioadmin }
          readinessProbe: { httpGet: { path: /minio/health/ready, port: 9000 } }
---
apiVersion: v1
kind: Service
metadata: { name: minio }
spec:
  selector: { app: minio }
  ports: [{ port: 9000 }]
EOF
k rollout status deployment/minio --timeout=180s

mc() {
	k run "mc-$RANDOM" --rm -i --restart=Never --quiet --image=cgr.dev/chainguard/minio:latest \
		--command -- sh -c "mc alias set m http://minio:9000 minioadmin minioadmin >/dev/null && $1"
}

# Ready is not reachable yet. rollout status returns when the pod passes its
# readiness probe, and the Service starts sending traffic to it a moment later,
# once the endpoint has propagated; a client that asks in between is refused,
# which failed a CI run on 2026-10-10 before the gateway was even installed. So
# the first request is retried, a few times and briefly, instead of preceded by a
# sleep that would be too long on most runs and too short on some.
# --ignore-existing keeps a retry after a creation whose answer was lost from
# failing on the bucket it just made.
for attempt in 1 2 3 4 5 6; do
	mc "mc mb --ignore-existing m/chart-test" && break
	if [[ "$attempt" == 6 ]]; then
		echo "MinIO did not accept a request through its Service" >&2
		exit 1
	fi
	sleep 2
done

echo "==> keyring, TLS and credentials, as Secrets that exist before the chart"
go build -o "$WORK/blindbucket" ./cmd/blindbucket
BLINDBUCKET_PASSPHRASE=chart-test-passphrase \
	"$WORK/blindbucket" keygen --out "$WORK/keyring.json" --kid chart-test >/dev/null
printf 'chart-test-passphrase' >"$WORK/passphrase"

# The release is "bb", so the Service is bb-blindbucket, and the certificate has
# to name that host for the client to accept it.
host=bb-blindbucket.default.svc
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$host" \
	-addext "subjectAltName=DNS:$host" \
	-keyout "$WORK/tls.key" -out "$WORK/tls.crt" 2>/dev/null

docker cp "$WORK/." "$NODE:/work"
k create secret generic bb-keyring --from-file=keyring.json=/work/keyring.json
k create secret generic bb-passphrase --from-file=passphrase=/work/passphrase
k create secret tls bb-tls --cert=/work/tls.crt --key=/work/tls.key
k create secret generic bb-upstream \
	--from-literal=access_key_id=minioadmin --from-literal=secret_access_key=minioadmin
k create secret generic bb-client \
	--from-literal=access_key_id=CHARTTESTCLIENT --from-literal=secret_access_key=chart-test-client-secret
k create configmap bb-ca --from-file=ca.crt=/work/tls.crt

echo "==> the chart"
helm install bb /chart/blindbucket --wait --timeout 3m \
	--set image.repository="${IMAGE%%:*}" --set image.tag="${IMAGE##*:}" \
	--set image.pullPolicy=Never \
	--set tls.existingSecret=bb-tls \
	--set upstream.endpoint=http://minio:9000 --set upstream.pathStyle=true \
	--set upstream.existingSecret=bb-upstream \
	--set keys.keyringSecret=bb-keyring --set keys.passphraseSecret=bb-passphrase \
	--set 'clients[0].name=chart-test' --set 'clients[0].existingSecret=bb-client' \
	--set 'clients[0].buckets={chart-test}'
k get pods -l app.kubernetes.io/name=blindbucket

echo "==> a client in another pod, over TLS"
# 20 MiB: over the CLI's 8 MiB threshold, so a multipart upload whose parts the
# Service spreads over both replicas.
k apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata: { name: client }
spec:
  restartPolicy: Never
  containers:
    - name: aws
      image: amazon/aws-cli:latest
      command: [sh, -c]
      args:
        - |
          set -e
          head -c 20971520 /dev/urandom > /tmp/in
          aws s3 cp /tmp/in s3://chart-test/object
          aws s3 cp s3://chart-test/object /tmp/out
          aws s3 ls s3://chart-test/
          sha256sum /tmp/in /tmp/out
          [ "\$(sha256sum < /tmp/in)" = "\$(sha256sum < /tmp/out)" ] && echo ROUNDTRIP-OK
      env:
        - { name: AWS_ENDPOINT_URL, value: "https://$host" }
        - { name: AWS_CA_BUNDLE, value: /ca/ca.crt }
        - { name: AWS_REGION, value: us-east-1 }
        - { name: AWS_ACCESS_KEY_ID, value: CHARTTESTCLIENT }
        - { name: AWS_SECRET_ACCESS_KEY, value: chart-test-client-secret }
      volumeMounts: [{ name: ca, mountPath: /ca }]
  volumes: [{ name: ca, configMap: { name: bb-ca } }]
EOF
# Waiting on Succeeded alone would sit out the whole timeout on a failure.
phase=
for _ in $(seq 1 150); do
	phase=$(k get pod client -o jsonpath='{.status.phase}')
	[[ "$phase" == Succeeded || "$phase" == Failed ]] && break
	sleep 2
done
k logs client
if [[ "$phase" != Succeeded ]]; then
	echo "the client pod ended in phase '$phase'" >&2
	exit 1
fi
k logs client | grep -q ROUNDTRIP-OK

echo "==> what the provider holds"
header=$(mc "mc cat m/chart-test/object | head -c 4")
if [[ "$header" != "BLBK" ]]; then
	echo "the provider holds something other than a blindbucket segment: '$header'" >&2
	exit 1
fi
echo "stored object starts with $header: ciphertext, as it must"

echo "==> without TLS the chart refuses to render"
if helm template bb /chart/blindbucket >/dev/null 2>&1; then
	echo "the chart rendered without tls.existingSecret" >&2
	exit 1
fi

echo "PASS"
