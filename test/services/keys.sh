#!/usr/bin/env bash
# Starts the two key services the root-key tests run against, as CI runs them:
# Vault in dev mode with a transit key, and an emulator of the KMS protocol.
# Used by the root-key job and by the coverage run, so that both start them the
# same way. Locally, `docker compose --profile keys up -d` does the same.
#
# Vault in dev mode: a fixed root token, no storage, gone with the runner. None
# of this is a secret, and the alternative -- mocking the HTTP API -- would only
# assert what the code already believes about it.
#
# The KMS side is an emulator, not AWS. What it establishes is that the client
# speaks KMS correctly; docs/COMPATIBILITY.md says so rather than claiming the
# service was tested.
#
# VAULT_IMAGE picks what answers on :8200. OpenBao, the open-source fork of
# Vault, serves the same Transit API and is run by CI as well; it reads its dev
# settings from BAO_* rather than VAULT_*, so both are set.
set -euo pipefail

VAULT_IMAGE=${VAULT_IMAGE:-hashicorp/vault:latest}

docker run -d --name vault --cap-add IPC_LOCK -p 8200:8200 \
	-e VAULT_DEV_ROOT_TOKEN_ID=blindbucket-dev-token \
	-e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
	-e BAO_DEV_ROOT_TOKEN_ID=blindbucket-dev-token \
	-e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
	"$VAULT_IMAGE" >/dev/null
docker run -d --name kms -p 4599:8080 \
	-e PORT=8080 -e KMS_REGION=us-east-1 \
	nsmithuk/local-kms:latest >/dev/null

for _ in $(seq 1 60); do
	if curl -sf http://localhost:8200/v1/sys/health >/dev/null; then break; fi
	sleep 1
done
curl -sf -X POST -H "X-Vault-Token: blindbucket-dev-token" \
	-d '{"type":"transit"}' http://localhost:8200/v1/sys/mounts/transit
curl -sf -X POST -H "X-Vault-Token: blindbucket-dev-token" \
	-d '{}' http://localhost:8200/v1/transit/keys/blindbucket

for _ in $(seq 1 30); do
	if curl -sf -o /dev/null -X POST http://localhost:4599/ \
		-H "X-Amz-Target: TrentService.CreateKey" \
		-H "Content-Type: application/x-amz-json-1.1" -d '{}'; then break; fi
	sleep 1
done
