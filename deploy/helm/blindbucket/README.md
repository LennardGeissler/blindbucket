# blindbucket Helm chart

Runs the gateway as a shared service: a Deployment behind a Service, reached over
the cluster network by clients in other pods.

**Prefer the sidecar where you can.** Between client and gateway the body is
plaintext. [deploy/kubernetes-sidecar.yaml](../../kubernetes-sidecar.yaml) keeps
that hop inside one pod, on loopback, and needs no TLS. This chart puts it on the
network, so it serves S3 over TLS only and **refuses to render without a
certificate**. Everyone who can reach the Service and holds a client credential
gets plaintext; `networkPolicy` narrows the first half of that.

## Before installing

The chart creates no Secret. Anything given as a value is stored in the Helm
release, and usually in version control, so every key and credential is referenced
by the name of a Secret that already exists:

| Value | Secret contents |
|---|---|
| `tls.existingSecret` | `tls.crt`, `tls.key` (type `kubernetes.io/tls`, as cert-manager writes it) |
| `keys.keyringSecret` | `keyring.json`, from `blindbucket keygen` |
| `keys.passphraseSecret` | `passphrase` (with `keys.provider=file`) |
| `keys.vault.tokenSecret` | `token` (with `keys.provider=vault`) |
| `keys.awskms.credentialsSecret` | `access_key_id`, `secret_access_key` (with `keys.provider=awskms` and `credentialSource: static`) |
| `upstream.existingSecret` | `access_key_id`, `secret_access_key` for the provider (with `credentialSource: static`) |
| `clients[].existingSecret` | `access_key_id`, `secret_access_key` a client signs with |

```sh
kubectl create secret generic blindbucket-keyring --from-file=keyring.json
kubectl create secret generic blindbucket-passphrase --from-literal=passphrase='...'
kubectl create secret generic blindbucket-upstream \
  --from-literal=access_key_id=... --from-literal=secret_access_key=...
kubectl create secret generic backup-job-s3 \
  --from-literal=access_key_id=... --from-literal=secret_access_key=...
```

## Installing

```sh
helm install blindbucket deploy/helm/blindbucket \
  --set tls.existingSecret=blindbucket-tls \
  --set upstream.endpoint=https://s3.eu-central-1.amazonaws.com \
  --set upstream.region=eu-central-1 \
  --set upstream.existingSecret=blindbucket-upstream \
  --set keys.keyringSecret=blindbucket-keyring \
  --set keys.passphraseSecret=blindbucket-passphrase \
  --set 'clients[0].name=backup-job' \
  --set 'clients[0].existingSecret=backup-job-s3' \
  --set 'clients[0].buckets={backups}'
```

A client then needs `AWS_ENDPOINT_URL=https://blindbucket-blindbucket.<namespace>.svc`
and a certificate it trusts for that name. [values.yaml](values.yaml) documents
every setting.

## On EKS: IRSA or Pod Identity instead of keys

The gateway's own AWS credentials — for the bucket, and for KMS if it seals the
keyring — need not be keys in a Secret. With `credentialSource` set, the gateway
resolves them itself from what EKS gives the pod, refreshes them before they
expire, and logs at startup where they came from
([ADR-024](../../../docs/adr/ADR-024-aws-credentials-without-the-sdk.md)). The chart
creates a ServiceAccount for the role to attach to.

**IRSA.** Annotate the ServiceAccount with the role, and name the source:

```sh
helm install blindbucket deploy/helm/blindbucket \
  --set 'serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::123456789012:role/blindbucket' \
  --set upstream.credentialSource=web_identity \
  --set keys.provider=awskms --set keys.awskms.credentialSource=web_identity \
  ...
```

The role's trust policy allows `sts:AssumeRoleWithWebIdentity` from the cluster's
OIDC provider for `system:serviceaccount:<namespace>:<release>-blindbucket`.

**Pod Identity.** Create the association for the ServiceAccount's name
(`aws eks create-pod-identity-association --service-account <release>-blindbucket ...`)
and set both sources to `container`.

Either way the Kubernetes API token stays unmounted: the gateway never calls the
API, and the role's token is a projected volume of its own, which the EKS webhook
adds regardless of `automountServiceAccountToken` (as its source shows; this chart
has not been run on EKS). `fsGroup` makes that token readable by the non-root
user the gateway runs as.

**What the gateway does not do** is fall back. With `web_identity` named, a pod
whose token is missing or whose role cannot be assumed does not start, and says
why — rather than running with the node's instance role, which is what the AWS
SDK's default chain does in that case. `imds` would choose the node's role on
purpose, and is rarely what a pod should have.

## What it leaves out, and why

- **The audit log and rollback detection.** Each is a file per instance that has
  to outlive the pod: a StatefulSet with a claim per replica, not a Deployment.
  The audit log's worth also depends on where it is shipped, which a chart cannot
  decide.
- **Certificate reloading.** The gateway reads its certificate at startup. A
  certificate cert-manager renews takes effect with the next rollout, so pair it
  with something that restarts on Secret changes, or roll out before expiry.
- **Secrets.** See above.

## Monitoring

`serviceMonitor.enabled` and `prometheusRule.enabled` create the Prometheus
Operator resources. The rules are [deploy/prometheus/alerts.yaml](../../prometheus/alerts.yaml),
with the job label set to the release's Service; `make chart` fails if the chart's
copy drifts from it.

## Tested

- `make chart`: lint, render with every optional part on, validate against the
  Kubernetes schemas and the Prometheus Operator CRDs, and require that it refuses
  to render without TLS. Then the EKS shape ([ci/eks-values.yaml](ci/eks-values.yaml)):
  rendered and validated, with the role annotation on the ServiceAccount, no AWS key
  taken from any Secret, and the API token still unmounted; and the refusals of a
  static source without a Secret and of a source that does not exist.
- `make chart-e2e` ([test/helm/kind.sh](../../../test/helm/kind.sh)): a kind
  cluster with MinIO, the chart installed from the checkout, and the AWS CLI in
  another pod putting a 20 MiB multipart object through it over TLS and reading it
  back with an identical SHA-256. MinIO is then asked directly, and has to hold a
  blindbucket segment. Both run in CI.
