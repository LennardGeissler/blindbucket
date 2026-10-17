# Applications through the gateway (M12)

One directory per application that stores to S3 and cannot be changed. Each
runs the application against MinIO, through a gateway built from this
checkout, and fails when the gateway refuses or corrupts anything the
application does.

| Directory | Application | Guide |
|---|---|---|
| [nextcloud/](nextcloud/) | Nextcloud, S3 as primary storage | [docs/guides/nextcloud.md](../../docs/guides/nextcloud.md) |
| [loki/](loki/) | Grafana Loki, single binary | [docs/guides/loki.md](../../docs/guides/loki.md) |

[lib.sh](lib.sh) does what every scenario does -- the keyring, the gateway
image, starting clean, tearing down, and the checks at the provider and in
the gateway's log -- so that a scenario's run.sh is only what is particular to
its application. The shape every scenario keeps:

- **`run.sh`** brings it up with Docker Compose, waits for the application,
  runs the operations, then asks the provider and the gateway what happened:
  every stored object is a blindbucket segment or manifest, and the gateway
  logged no unexpected ERROR. It tears everything down afterwards unless
  `KEEP=1` is set, and it exits non-zero on any failure.
- **`compose.yaml`** builds the gateway from `deploy/Dockerfile` and pins the
  application's image by digest. The version measured is the one
  [COMPATIBILITY.md](../../docs/COMPATIBILITY.md#applications) names.
- **An operations script** drives the application through its own interfaces
  -- the ones its users and clients use -- and checks every result by content,
  not by status code alone.
- Each runs **with object names in clear and encrypted**, side by side.

[.github/workflows/apps.yml](../../.github/workflows/apps.yml) runs them on
changes that can affect them and weekly. Locally: `make app-nextcloud`,
`make app-loki`.
