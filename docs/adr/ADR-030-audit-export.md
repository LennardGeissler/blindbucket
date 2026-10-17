# ADR-030 — Exporting audit entries over TLS syslog and OTLP logs without blocking

**Status:** Accepted
**Date:** 2026-10-17
**Milestone:** post-1.0
**Implements:** `internal/audit` (`Exporter`, `SyslogExporter`, `OTLPExporter`, `AsyncExporter`, `MultiExporter`), `internal/config` (`audit.export`), `cmd/blindbucket` (`serve`), `deploy/prometheus` alerts, [#135](https://github.com/LennardGeissler/blindbucket/issues/135)

## Context

[ADR-016](ADR-016-audit-log.md) established a local, tamper-evident audit log: each gateway instance writes an append-only, SHA-256 hash-chained log signed periodically with Ed25519. Object and bucket names are encrypted deterministically per [ADR-015](ADR-015-object-name-encryption.md) so the log can be audited without leaking plain names.

While the local file is the authoritative cryptographic proof of what the gateway served, operators require audit entries to be ingested into central SIEMs (Security Information and Event Management) and observability platforms (Splunk, Elastic, Datadog, OpenTelemetry collectors) in near real-time for alerting and incident response ([#135](https://github.com/LennardGeissler/blindbucket/issues/135)).

Exporting audit entries from a live gateway introduces two fundamental design challenges:
1. **Protocol and Format:** How records are represented and transferred across networks without leaking credentials or plain names, and in a format that enterprise SIEMs can consume.
2. **Failure and Backpressure Isolation:** A gateway's primary job is serving S3 traffic. Network partitions, SIEM maintenance, or slow receivers must never compromise request throughput, increase request latency, or cause data corruption in the authoritative audit chain.

## Decision

### 1. Protocols: RFC 5424 over RFC 5425 TLS Syslog, and OTLP/HTTP Logs over HTTPS

We support two standard protocols for audit export:
- **Syslog (RFC 5424 with RFC 5425 TLS framing):** Octet-counting framing over a persistent TLS connection (`<MSG-LEN> <MSG>`). Syslog structured data (`[audit@blindbucket seq="..." chain="..."]`) carries chain identity and sequential position, with SD-PARAM escaping of `"`, `\`, and `]` per RFC 5424 §6.3.3. The syslog message body carries the JSON serialization of the entry. Facility and severity are fully configurable (defaulting to `local4` / `13` and `info` / `6`, but allowing `0` for `kern`/`emerg`).
- **OpenTelemetry Logs (OTLP/HTTP over HTTPS):** JSON payloads sent via HTTP POST to the standard logs endpoint (`/v1/logs`). Required attributes include `audit.seq`, `audit.chain`, `audit.hash`, and `audit.op`, with the entry JSON in the log record body. Headers allow authentication (e.g. `Authorization: "Bearer ${OTLP_TOKEN}"`).

**TLS is mandatory for all network exports.** `insecure_skip_verify` is not supported, and OTLP requires `https://`. Custom private enterprise CAs are supported via `ca_cert`.

### 2. Payload Shape and Name Privacy

Exported entries carry the exact record written to the file:
`seq`, `time`, `chain`, `hash`, `op`, `bucket`, `key`, `status`, `bytes`, `client`, `req_id`, `kid`.
Crucially, **bucket and object names remain encrypted** using the deterministic segment encryption of ADR-015 derived from the audit key. An operator or attacker inspecting the SIEM export cannot learn object names in the clear, just as with the audit log file.

### 3. Decoupled, Non-Blocking Buffered Export with Queue Drops

Network export runs strictly **outside the Writer's mutex lock** and asynchronously via a bounded queue (`AsyncExporter`, default capacity 2,048 entries).
- **The file is written and hashed first.** When `Writer.Append` runs, the entry is hashed, written to the local buffer, and if needed checkpointed. Only after the file operation succeeds and the lock is released is the entry enqueued for export.
- **Drops under backpressure:** If a receiver is down or slow and the in-memory queue fills, subsequent entries are dropped immediately without blocking callers or degrading S3 latency.
- **Bounded drain on shutdown:** During gateway shutdown, `AsyncExporter.Close` drains the queue up to a bounded deadline (`DefaultDrainTimeout`, 2 s). If a receiver hangs or remains unreachable, remaining queued entries are dropped rather than stalling process termination for hours.
- **Observable failure signaling:** Dropped or failed exports increment `blindbucket_audit_export_failures_total{destination}` and trigger state-transition logs (`failing` vs `recovered`) rather than spamming logs on every dropped request. The `BlindbucketAuditExportGap` Prometheus alert alerts operators to gaps.

### 4. Verification and SIEM Gap Detection

**The export stream is not signed.** Ed25519 checkpoint signatures remain in the file. The local file is the authoritative tamper-evident record.

Because exported records carry `seq`, a SIEM or audit job can detect missing or dropped entries simply by scanning for sequence gaps (`seq != prev_seq + 1`). If a gap is detected, the operator compares the SIEM stream against the authoritative local file (`blindbucket audit verify`) to audit the missing records. Under concurrency, exports may arrive slightly out of `seq` order at the receiver because export happens outside the writer lock; sorting by `seq` restores strict chain ordering.

## Alternatives considered

### OTLP/gRPC
Rejected. gRPC requires HTTP/2 framing, protobuf serialization, and heavyweight runtime dependencies. The gateway's design deliberately minimizes external dependencies ([ADR-011](ADR-011-languages-outside-the-go-core.md), [ADR-024](ADR-024-aws-credentials-without-the-sdk.md)). OTLP/HTTP+JSON is supported by all major OpenTelemetry collectors, requires only Go's standard `net/http`, and produces zero added binary bloat or complex code generation.

### Sidecar tailing the file (e.g. FluentBit, Promtail)
A standard pattern is running a sidecar container that reads the audit log file and forwards it to a SIEM. We support file tailing naturally because the audit log is a line-delimited JSON file. However, file tailing alone was rejected as the exclusive solution ([#135](https://github.com/LennardGeissler/blindbucket/issues/135)):
1. In bare-metal, systemd, or appliance environments, deploying and managing an auxiliary log-shipping sidecar daemon is operational overhead.
2. Direct push from the gateway allows immediate delivery without filesystem polling latency.
3. Native direct export gives the gateway ownership of metrics (`blindbucket_audit_export_failures_total`) and secure TLS connection configuration.

### Blocking export on backpressure
If the export queue is full, the gateway could block incoming S3 requests until the receiver catches up.
Rejected. S3 availability is paramount. A temporary network hiccup to a third-party SIEM or a slow collector must not bring down the entire object storage service. The audit log file is the true, tamper-evident source of truth; network export is best-effort for search and alerting.

### Signing the export stream
We considered signing individual exported messages or exporting checkpoints.
Rejected. Signing every entry would impose severe CPU overhead (~3.6 µs per entry without signing vs tens of microseconds with Ed25519 signing per request). Furthermore, individual signatures cannot prove non-truncation or ordering without the chain hash. The file's periodic checkpoint signing ([ADR-016](ADR-016-audit-log.md)) already provides optimal security and performance, and the file can always be audited after the fact.

## Consequences

- Operators can stream audit records to Splunk, Elasticsearch, syslog daemons, and OTLP collectors.
- S3 request throughput and latency remain completely isolated from export receiver performance.
- Names remain encrypted in transit and in the SIEM, preserving [ADR-015](ADR-015-object-name-encryption.md) privacy guarantees.
- Missing entries caused by receiver downtime are visible in Prometheus metrics and alerts, and detectable by SIEM gap analysis against `seq`.
