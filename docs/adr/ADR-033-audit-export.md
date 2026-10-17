# ADR-033 — Exporting audit entries over TLS syslog and OTLP logs without blocking

**Status:** Accepted
**Date:** 2026-10-17
**Milestone:** M15
**Implements:** `internal/audit` (`Exporter`, `SyslogExporter`, `OTLPExporter`, `AsyncExporter`, `MultiExporter`), `internal/config` (`audit.export`), `cmd/blindbucket` (`serve`), `deploy/prometheus` alerts, [#135](https://github.com/LennardGeissler/blindbucket/issues/135)

## Context

[ADR-016](ADR-016-audit-log.md) established a local, tamper-evident audit log: each gateway instance writes an append-only, SHA-256 hash-chained log signed periodically with Ed25519. Object names in it are encrypted per path segment, as [ADR-015](ADR-015-object-name-encryption.md) encrypts them at the provider, so the log can be audited without leaking plain names.

The local file is the authoritative record of what the gateway served. Operators also collect audit events in a SIEM (Splunk, Elastic, Datadog, OpenTelemetry collectors) for search, alerting and incident response, and a file on each gateway host is one more thing to ship there by hand ([#135](https://github.com/LennardGeissler/blindbucket/issues/135)).

Exporting from a live gateway raises two questions:

1. **Protocol and format:** how a record travels, and what it looks like, so that SIEMs can consume it and operators can build parsers against it.
2. **Failure and backpressure:** a gateway's job is serving S3 traffic. A slow or unreachable receiver must not slow requests down, and must not touch the chain in the file.

## Decision

### 1. Protocols: RFC 5424 syslog over TLS, and OTLP/HTTP logs over HTTPS

- **Syslog:** RFC 5424 messages with RFC 5425 octet-counting framing (`MSG-LEN SP SYSLOG-MSG`) over a persistent TLS connection. A message is

  ```
  <PRI>1 TIMESTAMP HOSTNAME APP-NAME - audit - {"chain":"…","seq":…,…}
  ```

  - TIMESTAMP is the entry's time cut to microseconds, because RFC 5424 allows at most six fractional digits and the file records nanoseconds.
  - PROCID and STRUCTURED-DATA are the NILVALUE. The entry, its `chain` and `seq` included, is the JSON message. A structured-data element of our own would need an SD-ID registered to a private enterprise number (RFC 5424 §6.3.2), which this project does not have. The chain, free text in the configuration, therefore never reaches a header field that cannot hold it.
  - APP-NAME is configurable and validated: 1 to 48 printable ASCII characters without spaces. A host name that does not fit HOSTNAME is sent as the NILVALUE.
  - Facility and severity are configurable, defaulting to 13 (log audit) and 6 (informational); 0 (kern, emerg) can be set.
- **OpenTelemetry logs (OTLP/HTTP with JSON over HTTPS):** a POST to the configured logs endpoint. Each entry is one log record, with the entry's JSON as its body and each field as an `audit.*` attribute (`audit.seq`, `audit.chain`, `audit.hash`, `audit.op` and the rest). Headers carry authentication, and a header value may reference the environment inside other text: `Authorization: "Bearer ${OTLP_TOKEN}"`. Every other setting takes a `${VAR}` reference only as its whole value, as before; a header is the one place a credential sits inside other text. A header is expanded in one pass, so a variable's value is not searched for references in turn.

**TLS is mandatory for every export.** There is no `insecure_skip_verify`, OTLP requires `https://`, and syslog runs over TLS only (`network` is `tcp`, `tcp4` or `tcp6`). A private CA is given with `ca_cert`.

### 2. Payload and name privacy

An exported entry carries what the file entry carries, plus the chain it belongs to: `chain`, `seq`, `time`, `op`, `bucket`, `key`, `client`, `principal`, `request_id`, `status`, `code`, `kid`, `bytes`, `hash`.

**Bucket and object names stay encrypted**, exactly as in the file: the export sends the entry the writer built. Whoever reads the SIEM learns no more names than whoever reads the file.

### 3. A queue that drops instead of blocking, sent in batches

Export runs outside the writer's lock, through a bounded queue per destination (`AsyncExporter`, 2,048 entries).

- **The file comes first.** `Writer.Append` hashes the entry and writes it to the file's buffer, checkpointing if one is due. Only after that, and outside the lock, is it queued for export. The file's buffer is flushed at checkpoints, so after a crash a receiver can hold entries the file lost; they verify against nothing, and the file stays the record.
- **Batches.** The worker sends what queued up while its last send was in flight, up to 512 entries at once: one OTLP request with a log record each, or one write of several syslog frames. Sending one entry at a time limited OTLP to the receiver's round trip: about 180 entries a second against a receiver answering in 5 ms, measured, so a busy gateway lost entries to a healthy receiver. With batches, the same receiver took 500 entries a second for twelve seconds without dropping one, in about a third as many requests. When there is little to send, a batch is a single entry and nothing waits.
- **Drops under backpressure.** When the queue is full, an entry is dropped at once rather than making the request wait.
- **Bounded shutdown.** `AsyncExporter.Close` keeps sending what is queued for at most `DefaultDrainTimeout`, 2 s. At the deadline a send still in flight is cancelled, its dial, write or request included, and what is left counts as dropped. A receiver that hangs costs shutdown two seconds, not a timeout per queued entry.
- **What an operator sees.** Every entry that was dropped or not delivered increments `blindbucket_audit_export_failures_total{destination}`, and `BlindbucketAuditExportGap` alerts on it. The log carries one line when an export starts losing entries and one when it has gone a minute without losing any, with the number lost meanwhile. A receiver that keeps up only between drops would otherwise switch the state, and log, many times a second.
- **Duplicates are possible.** A syslog write that fails on a connection the receiver has dropped is retried once on a new one, so a receiver can see an entry twice.

### 4. Verification and gap detection

**The export is not signed.** The Ed25519 checkpoint signatures stay in the file, which remains the tamper-evident record, and `blindbucket audit verify` runs on it.

Because every exported entry carries `chain` and `seq`, a SIEM finds what is missing by looking for gaps in `seq` within a chain, and recovers it from the file. Entries can arrive out of `seq` order, because export runs outside the writer's lock, and twice, as above; sorting by `seq` and dropping repeats restores the chain's order.

## Alternatives considered

### OTLP/gRPC

Rejected. gRPC needs HTTP/2 framing, protobuf and a large dependency, against a gateway that keeps its dependencies few ([ADR-024](ADR-024-aws-credentials-without-the-sdk.md) is the same choice for AWS). OTLP/HTTP with JSON is accepted by the OpenTelemetry collector and the common SIEMs, and needs only `net/http`.

### A sidecar tailing the file

A sidecar (Fluent Bit, Promtail) can read the audit log, which is line-delimited JSON, and forward it, and that keeps working. It was not made the only way:

1. Where the gateway runs under systemd or on an appliance, a log shipper is one more daemon to deploy, configure and keep up.
2. The gateway knows when an export loses entries, and can count and alert on it; a sidecar's view of that is its own.
3. TLS to the receiver is configured where the rest of the gateway's TLS is.

### Blocking on backpressure

When the queue is full, the gateway could make requests wait until the receiver catches up. Rejected: a SIEM outage would become an S3 outage. The file is the record; the export is a copy for search and alerting.

### Signing the export

Rejected. A signature per entry costs tens of microseconds against the 3.6 µs an append costs now ([ADR-016](ADR-016-audit-log.md)), and signatures on single entries prove neither order nor completeness without the chain. The file's checkpoints already do both, and the file can be verified at any time.

### One send per entry

What the export first did, and why batching was added: see section 3.

## Consequences

- Operators can stream audit entries to syslog receivers, SIEMs and OTLP collectors, in addition to the file.
- Request latency does not depend on a receiver: the worst a receiver can do is make the export drop entries, which is counted, alerted on and logged.
- Names stay encrypted in transit and in the SIEM, as they are in the file.
- Entries lost to an outage or a full queue are visible in the metric and the alert, and findable in the SIEM by gaps in `seq`.
- The syslog message format above, and the OTLP attributes, are what operators build parsers against. Changing them is a change operators have to follow.
