# ADR-026 — Empty multipart parts are refused on arrival

**Status:** Accepted
**Date:** 2026-10-05
**Milestone:** post-1.0
**Implements:** `internal/proxy` (`UploadPart`, `UploadPartCopy`)

## Context

[ADR-008](ADR-008-part-sizes.md) and FORMAT §7.3 forbid an empty final part;
the completion validator also rejects an empty non-final part. Nevertheless,
copying an empty object as a part returned success, leaving the client to learn
at completion that the upload could never be assembled. An ordinary empty-body
part upload did the same. Either could replace a previously usable part.

## Decision

Refuse zero plaintext bytes with `InvalidRequest` and the existing completion
message, before encrypting or uploading a segment. For `UploadPart`, use the
decoded length from the authenticated body reader, which handles aws-chunked
requests; the wire content length alone does not describe their plaintext. For
`UploadPartCopy`, check the length after source authorization, preconditions and
range validation, and close the source reader on refusal as on every other exit.

Keep completion's size validation. Part alignment still belongs there because
any nonempty part, including one smaller than a chunk, might be the last part.

## Alternatives considered

**Leave the refusal at completion.** This keeps a success response for a part
that is invalid in every position and allows it to replace usable data.

**Enforce every part-size rule on arrival.** Rejected because the gateway does
not know which part will be last. Refusing short or unaligned nonempty parts
would reject valid uploads.

## Consequences

The error code and explanation stay the same, but the part operation now fails
instead of completion. A refused attempt stores nothing and preserves an
existing part; the client can retry with nonempty data and complete the upload.
Completion assembles only the parts the client lists, using `matchParts`:
uploading an empty part and omitting it from completion used to succeed, but
is now rejected when the part arrives.
Empty `PutObject` and `CopyObject` objects remain supported. Ciphertext and
manifest formats, their versions, and publication ordering do not change.
