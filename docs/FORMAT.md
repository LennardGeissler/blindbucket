# blindbucket Wire Format — Version 1

**Status:** Normative for format version `1`, and implemented as specified.
**Last updated:** 2026-10-29 (section 18, the keyring file, written down with
version 2 for tenants, and sections 3, 14.5 and 15.1 amended for them,
[ADR-038](adr/ADR-038-tenants-and-crypto-shredding.md); before that, 2026-10-21:
section 17, object tags, added with `internal/crypto/tags`,
[ADR-037](adr/ADR-037-encrypted-object-tags.md); before that,
2026-10-03: section 10.7: R3 deletes the observed manifest only once
it has seen the object replaced, [ADR-025](adr/ADR-025-writes-rank-by-when-they-began.md);
before that, format `1` declared stable with `v1.0.0`; section 15, the object name
mapping, added with `internal/crypto/names`; section 14, the audit log, added with
`internal/audit`; clarifications from the independent reference decoder, and the manifest
and upload token of sections 10 and 11 becoming normative with M4)

Every section but the version 2 parts of 18 is implemented. Sections 4 to 9 live in `internal/crypto/stream`,
`internal/crypto/keys` and `internal/crypto/envelope` and are pinned by the
known-answer vectors of section 13; section 10 is `internal/manifest`, section 11
is `internal/upload`, section 14 is `internal/audit`, section 15 is
`internal/crypto/names`, pinned by its own vectors. Section 17 is
`internal/crypto/tags`, pinned by its own vectors as well, and the gateway has
written tag sidecars since `v1.6.0`. Section 18 is `internal/crypto/keys`; its
version 1 is what every release has written, and version 2, tenants, is specified
ahead of the code ([ADR-038](adr/ADR-038-tenants-and-crypto-shredding.md)).

This document is the authoritative specification of the bytes blindbucket writes to
object storage. It is written so that an independent implementation can interoperate
with blindbucket using only this document and the test vectors in
[`testdata/vectors/`](../testdata/vectors/), which every release also carries as
downloads listed in its `checksums.txt`.

That claim has been tested rather than asserted: [`ref/python/`](../ref/python/)
holds a second decoder written from this document, and it agrees with the Go one
on every vector and on 100 000 mutated inputs. The two clarifications in §4.4 and
§5.2 are what writing it turned up — neither changes the format, both state
something that was previously only derivable.

The design rationale lives in [ADR-001](adr/ADR-001-segment-format.md) and
[ADR-002](adr/ADR-002-key-hierarchy.md). Where this document and an ADR
disagree, **this document wins**.

---

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as
described in RFC 2119.

| Notation | Meaning |
|---|---|
| `a \|\| b` | concatenation of byte strings `a` and `b` |
| `uintN_be(x)` | `x` encoded as an unsigned big-endian integer in exactly `N` bits |
| `lp(x)` | length-prefixed byte string: `uint16_be(len(x)) \|\| x` |
| `C` | chunk size in bytes, `C = 2^log2C` |
| `P` | plaintext length in bytes |
| `S` | ciphertext (sealed) length in bytes |
| `N` | number of chunks in a segment |
| `M` | number of parts in a multipart object |

All multi-byte integers are big-endian. All lengths are in bytes. Byte offsets are
zero-based and ranges are inclusive, matching HTTP `Range` semantics.

`lp()` is used wherever two or more variable-length fields are concatenated into an
authenticated input. Its purpose is unambiguity: without length prefixes,
`bucket="ab", key="c"` and `bucket="a", key="bc"` would produce identical associated
data. Implementations MUST reject inputs longer than 65535 bytes to `lp()`.

---

## 2. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Content encryption | AES-256-GCM (NIST SP 800-38D), 12-byte nonce, 16-byte tag |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| DEK wrapping | AES-256-GCM |
| Manifest authentication | HMAC-SHA256 |
| Randomness | operating-system CSPRNG |

All AES-256-GCM invocations in this format use a 96-bit nonce and a 128-bit tag.
No other tag or nonce length is permitted.

---

## 3. Key hierarchy

```
Root key            external: AWS KMS | Vault Transit | Argon2id(passphrase)
 └─ KEK             32 bytes, identified by a key id (kid), several versions per keyring
     ├─ Token key   = HKDF-SHA256(ikm=KEK, salt="", info="blindbucket/v1/upload-token", L=32)
     └─ DEK         32 bytes, uniformly random, one per object or multipart upload
         ├─ Subkey  = HKDF-SHA256(ikm=DEK, salt=Salt, info="blindbucket/v1/segment",  L=32)
         └─ MacKey  = HKDF-SHA256(ikm=DEK, salt="",   info="blindbucket/v1/manifest", L=32)
```

A DEK MUST be generated with a CSPRNG and MUST NOT be derived from any value chosen
by the storage provider (notably not from the upstream `UploadId`; see
[ADR-006](adr/ADR-006-upload-token.md)).

With tenants ([ADR-038](adr/ADR-038-tenants-and-crypto-shredding.md)) a keyring holds
several such trees. The default tenant's KEKs are under the deployment's root key;
each other tenant's are under a root key of its own, or under the deployment's if it
has none:

```
Root key (deployment)     └─ default tenant's KEKs, name key; audit and freshness keys; the directory
Root key (tenant "acme")  └─ acme's KEKs, acme's name key
```

Below the KEK nothing changes: a DEK, its subkeys and an upload token's key are
derived the same way whichever tenant's KEK it is. Which tenant a bucket is in,
and so which KEK and name key apply, is §18.5.

### 3.1 Key identifiers

A `kid` MUST be 1 to 64 bytes long and MUST consist only of the characters
`A-Z a-z 0-9 . _ -`. The upper bound is normative: it is what makes the associated
data encodings in §6 unambiguous with respect to each other.

---

## 4. Segment

A **segment** is the unit that encrypts one plaintext stream under one subkey.
A single-part object consists of exactly one segment. A multipart object consists of
one segment per part, concatenated in part-number order by the storage provider.

```
Segment = Header(32) || Chunk_0 || Chunk_1 || ... || Chunk_(N-1)
```

### 4.1 Header

The header is exactly 32 bytes and is **not** encrypted. It is authenticated: it is
supplied verbatim as the associated data of every chunk in the segment (§4.3).

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 4 | Magic | `"BLBK"` = `0x42 0x4C 0x42 0x4B` |
| 4 | 1 | Version | `0x01` |
| 5 | 1 | `log2C` | `12`..`20`; default `16` (64 KiB) |
| 6 | 1 | Flags | bit 0 (`0x01`): segment belongs to a multipart object. All other bits MUST be `0` |
| 7 | 1 | Reserved | MUST be `0x00` |
| 8 | 4 | Segment index | `uint32_be`; `0` for single-part, otherwise the S3 part number `1`..`10000` |
| 12 | 20 | Salt | 160 uniformly random bits, freshly generated per segment |

Consistency constraints, which a decoder MUST enforce (§5.2):

- If flag bit 0 is clear, the segment index MUST be `0`.
- If flag bit 0 is set, the segment index MUST be in `1..10000`.

The salt MUST be freshly generated for every segment, including for every retried
attempt at the same part number. This is what makes nonce reuse impossible across
retries; see §8.2.

### 4.2 Subkey derivation

```
Subkey = HKDF-SHA256(ikm = DEK, salt = Header[12..32], info = "blindbucket/v1/segment", L = 32)
```

The `info` string is ASCII, 22 bytes, without a trailing NUL.

### 4.3 Chunks

```
C        = 2^log2C
f_i      = 0x01 if i == N-1, else 0x00
Nonce_i  = uint88_be(i) || f_i                                          (12 bytes)
Chunk_i  = AES-256-GCM-Seal(key = Subkey, nonce = Nonce_i,
                            plaintext = Plain_i, aad = Header)          (|Plain_i| + 16 bytes)
```

`i` is the zero-based chunk index within the segment. The counter is 88 bits, so
`i` MUST be less than `2^88`; at the maximum chunk size this bound is far beyond the
5 TiB S3 object limit and can never be reached in practice.

### 4.4 Chunk length rules

1. Every chunk except the last MUST carry exactly `C` bytes of plaintext.
2. The last chunk MUST carry 1 to `C` bytes of plaintext, **except** that a segment
   encrypting zero bytes of plaintext consists of exactly one chunk carrying zero
   bytes of plaintext (a bare 16-byte tag).
3. No bytes MUST follow the chunk whose nonce carries `f = 1`.

Consequently `N = max(1, ceil(P / C))` and a segment always contains at least one
chunk.

On the wire this fixes every length a decoder needs:

| | Ciphertext bytes |
|---|---|
| A chunk that is not the last | exactly `C + 16` |
| The last chunk of a non-empty segment | `17` to `C + 16` |
| The single chunk of an empty segment | exactly `16` |
| The smallest possible segment | `32 + 16 = 48` |

A decoder therefore never has to guess where a chunk ends: it consumes `C + 16`
bytes at a time until at most `C + 16` remain, and that remainder is the last
chunk.

---

## 5. Encoder and decoder requirements

### 5.1 Encoder

An encoder MUST NOT emit a chunk with `f = 1` until it knows the plaintext stream has
ended. Because a writer cannot distinguish "buffer full" from "stream finished", the
encoder MUST hold back the most recently completed chunk until either more plaintext
arrives or the stream is explicitly closed.

This means **`Close` is the commit point of a segment.** A segment whose encoder was
never closed is truncated and MUST fail to decrypt. blindbucket relies on this
property in the proxy: the final chunk is withheld until the client's end-to-end
checksum has been verified ([ADR-005](adr/ADR-005-checksums.md)), so a failed
checksum can abort the upstream request before a complete body is ever written.

### 5.2 Decoder

A decoder MUST, in this order:

1. Read exactly 32 bytes of header.
2. Validate the magic, the version, `12 <= log2C <= 20`, that the reserved byte is
   `0x00`, that no undefined flag bits are set, and the flag/index consistency
   constraints of §4.1 — **before allocating any buffer whose size derives from
   `log2C`.** The header is attacker-controlled and is not yet authenticated at this
   point. Without this check, a header claiming `log2C = 30` would coerce a 1 GiB
   allocation from a single 32-byte read.
3. Compare the header's flag and index fields against what the caller expected for
   this segment (part number, multipart flag). A mismatch MUST be an error.
4. Derive the subkey and decrypt chunk 0. Only after chunk 0 verifies is the header
   authentic.
5. For each chunk, determine `f` by looking ahead exactly one byte past the chunk's
   ciphertext: if any byte follows, `f` MUST be `0`; if the stream ends, `f` MUST
   be `1`.

A decoder that holds the whole segment in memory rather than streaming it applies
rule 5 by length instead of by lookahead, and the boundary is easy to get wrong in
a way that ordinary testing does not catch. Chunk `i` is the last one exactly when
**at most** `C + 16` bytes of it and everything after it remain — `<=`, not `<`.
Reading it as `<` produces a decoder that works on every input whose plaintext is
*not* an exact multiple of `C`, and rejects every input whose plaintext is: with
that reading the final full chunk is opened under `f = 0` and fails its tag. The
`exactly one chunk` known-answer vector of §13 exists to catch this, and it is the
only one of the ten that does.

A decoder MUST NOT release the plaintext of a chunk to its caller before that chunk's
authentication tag has been fully verified. A decoder MUST treat every deviation —
bad tag, bad header field, truncation, trailing bytes, wrong key — as a hard error,
and MUST NOT return partial or unauthenticated plaintext for the failing chunk.

Truncation at a chunk boundary is detected by rule 5: the chunk that becomes last
was sealed with `f = 0` but must now verify under `f = 1`, which fails. Appending
bytes after the final chunk is detected the same way, in reverse.

---

## 6. DEK wrapping

A DEK is stored next to the data it protects, wrapped under a KEK.

```
WrappedDEK = Nonce(12) || AES-256-GCM-Seal(key = KEK[kid], nonce = Nonce,
                                           plaintext = DEK, aad = AAD)
```

The result is exactly `12 + 32 + 16 = 60` bytes, which is 80 characters of
unpadded base64url.

### 6.1 Associated data for objects

```
AAD = "blindbucket/v1/dek" || lp(kid) || lp(bucket) || lp(key)
```

Binding bucket and key into the AAD means unwrapping fails if the storage provider
swaps two objects together with their metadata.

### 6.2 Associated data for the local file format

```
AAD = "blindbucket/v1/dek-file" || lp(kid)
```

The two encodings cannot be confused: they share the 18-byte prefix
`"blindbucket/v1/dek"`, after which the object form has `uint16_be(len(kid))` while
the file form has the ASCII bytes `-fi` (`0x2D 0x66 0x69`). A collision would require
`len(kid) == 0x2D66 == 11622`, which §3.1 forbids.

### 6.3 Object metadata

| Header | Content | Size |
|---|---|---|
| `x-amz-meta-bb-v` | format version, decimal ASCII | `1` |
| `x-amz-meta-bb-kid` | KEK id | 1..64 bytes |
| `x-amz-meta-bb-dek` | wrapped DEK, unpadded base64url | 80 chars |
| `x-amz-meta-bb-c` | `log2C`, decimal ASCII | 2 chars |
| `x-amz-meta-bb-mid` | manifest id, 16 bytes unpadded base64url (multipart only) | 22 chars |

`bb-c` repeats the chunk size that the segment header already carries. The
duplication is deliberate: `HeadObject` and `ListObjectsV2` convert a ciphertext
size to a plaintext size (§7.2) without ever reading the body, so without a
recorded chunk size they would have to assume the reading deployment's configured
one — and report wrong sizes for any object written under a different setting.

This value is **not** authenticated. It is a hint for operations that never open
the object. Any operation that does read the body takes the chunk size from the
segment header, which is authenticated, and MUST reject an object whose recorded
`bb-c` disagrees with it: they can only differ if the metadata was altered. An
object with no `bb-c` at all is read with the configured chunk size as a
fallback.

A proxy MUST strip all `bb-`-prefixed metadata from responses to clients, and MUST
reject client requests that attempt to set metadata with the `bb-` prefix.

---

## 7. Size arithmetic

The format is deterministic in length: the ciphertext size is a function of the
plaintext size alone. This is what lets the proxy compute an exact upstream
`Content-Length` before reading a single byte, and report plaintext sizes in
`HEAD` and `ListObjectsV2` without extra requests. It also means the exact plaintext
size is visible to the storage provider; this is a deliberate trade-off recorded in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

### 7.1 Forward: plaintext to ciphertext

For a single segment:

```
N(P) = max(1, ceil(P / C))
S(P) = 32 + P + 16 * N(P)
```

For a multipart object of `M` parts whose per-part plaintext sizes are `P_1..P_M`,
with `P = sum(P_i)`:

```
S = 32*M + P + 16 * ceil(P / C)
```

This identity holds **only if every part except the last is an exact multiple of
`C`**, which is why §7.3 makes that a requirement.

### 7.2 Inverse: ciphertext to plaintext

Given `S` and the number of segments `M` (`M = 1` for single-part objects; for
multipart objects `M` is read from the `-M` suffix of the S3 ETag):

```
D = S - 32*M
N = ceil(D / (C + 16))
P = D - 16*N
```

`D` is valid if and only if:

- `D >= 16`, and
- `D == 16` (the empty object, `P = 0`), or
- `D mod (C + 16)` is **not** in the range `1..16`.

The excluded remainders are exactly those no encoder can produce: a plaintext of
`q*C + r` bytes yields `D mod (C+16) = r + 16` for `1 <= r <= C-1`, and `D mod (C+16) = 0`
for `r = 0, q >= 1`. A remainder of `1..16` therefore indicates a corrupted or
forged size and MUST be reported as an error rather than decoded.

**Worked example.** `P = 100 MiB = 104857600`, `C = 65536`, `M = 1`:
`N = 1600`, `S = 32 + 104857600 + 25600 = 104883232`. Inverting:
`D = 104883200`, `D / 65552 = 1600` exactly, so `N = 1600` and
`P = 104883200 - 25600 = 104857600`. ✓

### 7.3 Part size rules for multipart objects

- Every part except the last MUST have a plaintext size that is an exact multiple
  of `C`. The default part sizes of the AWS CLI, boto3, rclone and `mc` (5, 8 and
  16 MiB) all satisfy this for every permitted `C`, since `C <= 1 MiB`.
- The last part MUST NOT be empty.
- The ciphertext of a single part MUST NOT exceed 5 GiB, which caps the plaintext of
  a part at roughly `5 GiB - 1.25 MiB`.

A proxy MUST reject a `CompleteMultipartUpload` that violates these rules rather
than storing an object whose size cannot be recovered.

---

## 8. Range mapping

For a single segment, a plaintext range `a..b` (inclusive, `0 <= a <= b < P`) maps to
ciphertext as:

```
i       = floor(a / C)                              first chunk touched
j       = floor(b / C)                              last chunk touched
c_start = 32 + i * (C + 16)
c_end   = min(32 + (j + 1) * (C + 16), S) - 1
skip    = a - i * C                                 bytes to discard from chunk i
```

The reader decrypts chunks `i..j`, discards `skip` leading bytes and emits exactly
`b - a + 1` bytes. Chunk `j` is decrypted with `f = 1` if and only if `j == N - 1`,
where `N` is derived from the object's total size `S`.

Because `f` is part of the nonce, a storage provider that misreports `S` causes the
final chunk's authentication to fail in both directions: understating `S` makes a
non-final chunk be opened as final, and overstating it makes the final chunk be
opened as non-final. Neither verifies.

For multipart objects the prefix sums of the per-part plaintext sizes from the
manifest locate the part containing offset `a`; within that part the mapping above
applies with `32` replaced by that part's ciphertext start offset.

---

## 9. Local file format (`BBF1`)

`blindbucket encrypt` and `blindbucket decrypt` produce and consume a self-contained
file consisting of a small envelope followed by exactly one segment.

```
File = "BBF1" || uint8(version = 1) || lp(kid) || WrappedDEK(60) || Segment
```

The wrapped DEK uses the associated data of §6.2. The segment MUST have the multipart
flag clear and segment index `0`.

---

## 10. Multipart manifest (`BBM2`)

A multipart object is the concatenation of one segment per part. Each segment is
authenticated on its own, but nothing in the segments states how many there are, so
a provider could serve an object with parts missing and every remaining tag would
still verify. The manifest is what binds the parts into one object.

```
Manifest = "BBM2" || lp(bucket) || lp(key) || ManifestID(16) || uint16_be(M)
           || { uint16_be(part number) || uint64_be(plaintext size) || Salt(20) } × M
           || HMAC-SHA256(ManifestKey, all preceding bytes)
```

`ManifestKey = HKDF-SHA256(ikm=DEK, salt="", info="blindbucket/v1/manifest", L=32)`.

The `Salt` of each entry is the salt in that part's segment header (§4.1). It
names **which attempt** at that part number the object was completed from. A
client that retries a part leaves two segments under one number, both authentic
and both the same size, and without this a provider could serve either — see
§10.6.

`"BBM1"` is the same structure with the `Salt` field absent. A decoder MUST
accept it, MUST treat its parts as carrying no salt, and MUST NOT compare an
absent salt against anything. Objects written under it keep the residual risk
of §10.6; copying or rotating such an object rewrites its manifest as `BBM2`,
recovering the salts from the stored segment headers.

### 10.1 Placement

A manifest is stored as its own object at:

```
.blindbucket/m/<hex(SHA-256(key))>/<ManifestID>
```

`ManifestID` is 16 random bytes rendered as 22 characters of unpadded base64url —
the same spelling as in `x-amz-meta-bb-mid`. The object key is hashed rather than
embedded so that the manifest's own key stays a fixed width: object keys may be
1024 bytes, which is the same limit the manifest path is subject to.

A proxy MUST refuse client access to the `.blindbucket/` prefix for every
operation, and MUST omit it from listings. A client that could delete a manifest
could make its own object unreadable.

### 10.2 Structural rules

- `M` MUST be at least 1 and at most 10000.
- Part numbers MUST be in 1..10000 and **strictly ascending**. Gaps are permitted:
  S3 allows parts 1, 5, 9, and the manifest records what was assembled.
- Part sizes are plaintext sizes and MUST satisfy §7.3.
- A decoder MUST reject a manifest with trailing bytes.
- In a `BBM2` manifest every entry carries exactly 20 salt bytes. They are not
  required to differ from one another: two parts of one object may legitimately
  share a salt, because each segment's subkey is also separated by its part
  number in the nonce.

### 10.3 Verification

A reader MUST check the HMAC **before** interpreting any length prefix inside the
manifest, so that parsing never runs on bytes an attacker chose.

It MUST then check the bucket, the key and the manifest id against what it
expected — the bucket and key of the request, and the id from the object's
`x-amz-meta-bb-mid` — and MUST NOT take any of them from the manifest itself. A
manifest that is authentic but describes a different object version MUST be
rejected.

Because the MAC key is derived from the DEK, and every upload draws a fresh DEK, a
manifest from an earlier upload of the same key does not verify.

### 10.4 Reading a multipart object

1. Read the object metadata, unwrap the DEK, load the manifest named by `bb-mid`.
2. Verify it as in §10.3.
3. Compute each part's ciphertext size with §7.1 and check that the sizes sum to
   the object's stored size. A mismatch MUST be an error.
4. Decrypt the segments in order. Each segment MUST carry the multipart flag and a
   segment index equal to its part number in the manifest, and — for a `BBM2`
   manifest — a salt equal to that entry's `Salt`.

Step 4 is what catches reordering, substitution of another attempt (§10.6), and
step 3 what catches a dropped part.

The salt MUST be checked when the part's header is read, before any plaintext of
that part is released. It is not a check that can be deferred to the end of the
part: by then the plaintext is already out.

A provider that removes `bb-mid` to present a multipart object as a single-part one
is caught at the first segment header: the multipart flag is set and it is
authenticated.

### 10.5 Learning the salts at completion

A part of an open multipart upload cannot be read back — it is not an object
until the upload completes — and the manifest must exist before the object does
(§10.7). An implementation therefore cannot obtain the salts by reading the
parts it is about to assemble.

The salt is instead carried by the ETag the implementation answers an
`UploadPart` with, which the client echoes back at completion exactly as S3
requires. This document does not prescribe the encoding; blindbucket appends
`"." || base64url(AEAD(salt))` to the provider's own ETag, keyed off the KEK and
bound to the part number, so that a tag returned for the wrong part is refused
rather than recorded.

An implementation that cannot do this MAY write `BBM1` manifests, accepting
§10.6.

### 10.6 Retry substitution

Within one upload, a provider may hold several attempts at the same part number.
Every one of them is a valid segment: the part number is authenticated and
equal, the sizes are equal, and each chunk tag verifies under the object's DEK.
Nothing but the salt tells them apart.

A `BBM2` manifest names the attempt, so serving another one is detected at that
part's header. A `BBM1` manifest does not, and for objects written under it this
remains an accepted risk.

### 10.7 Lifecycle

Which manifests may be written and deleted, and in what order, is normative and is
specified as rules R1–R4 in
[ADR-010](adr/ADR-010-manifest-lifecycle-under-concurrency.md), and model-checked
in [`spec/tla/`](../spec/tla/). In short: every
operation that makes a multipart object visible mints a fresh manifest id and
writes its own manifest before the object becomes visible, and deletes at most the
manifest id it observed beforehand -- and that only once it has seen the object
carrying it replaced, because a provider may acknowledge a write and keep an
older-initiated one ([ADR-025](adr/ADR-025-writes-rank-by-when-they-began.md)).

Orphaned manifests are expected rather than exceptional. They contain no plaintext.

---

## 11. Upload token

A proxy MUST NOT return the storage provider's `UploadId` to a client. It returns a
sealed token carrying the whole state of the upload, so that any instance can serve
any part of it:

```
Token = base64url( 0x01 || lp(kid) || Nonce(12)
                   || AES-256-GCM.Seal(TokenKey[kid], Nonce, Body, AAD) )
Body  = lp(UpstreamUploadId) || WrappedDEK(60) || ManifestID(16)
AAD   = "blindbucket/v1/upload-token" || lp(bucket) || lp(key)
```

`TokenKey[kid] = HKDF-SHA256(ikm=KEK, salt="", info="blindbucket/v1/upload-token", L=32)`.

- The `kid` is outside the sealed part so that a token issued before a KEK rotation
  can still be opened after it.
- Bucket and key are authenticated but not stored: a token MUST NOT open against
  any other object.
- The base64url encoding MUST be unpadded, and a decoder SHOULD reject non-canonical
  encodings, so that one token has one spelling.
- Every failure — forged, truncated, wrong object, unknown or retired `kid` — MUST
  be reported identically. `NoSuchUpload` is what a client sees.

The DEK MUST NOT be derived from the `UploadId`: that value is chosen by the storage
provider, and a provider that repeated one would force two uploads to share a key
and reuse a (key, nonce) pair. See [ADR-006](adr/ADR-006-upload-token.md).

---

## 12. Security notes (informative)

**Why the nonce construction is safe.** Within a segment, `i` is unique by
construction. Across segments the subkey differs, because each segment draws a fresh
160-bit salt; by the birthday bound a salt collision requires on the order of `2^80`
segments. A (key, nonce) pair is therefore never reused. Fresh per-segment subkeys
additionally keep the amount of data under any single GCM key small.

**Why retries are safe.** A client that retries `UploadPart` for part `n` produces a
second, independent segment with a fresh salt and therefore a fresh subkey. Had the
nonce depended only on the part number and the chunk counter, a retry carrying
different bytes would have reused a (key, nonce) pair, which for GCM leaks the XOR of
the plaintexts and allows recovery of the authentication subkey.

**What the header in the AAD buys.** Chunk size, multipart flag and segment index are
authenticated with every single chunk. A storage provider can therefore not
reinterpret the chunk size, present a multipart object as a single-part object, or
reorder parts, without authentication failing.

**What this format does not protect.** Object names, sizes, timestamps, access
patterns and part counts remain visible. Rollback to an older but genuine version of
the same key is not detectable at the format level. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 13. Test vectors

Known-answer test vectors live in
[`testdata/vectors/segment_v1.json`](../testdata/vectors/segment_v1.json) and are a
normative part of this specification. Each vector fixes the DEK, the salt and every
header field, so the expected ciphertext is fully determined. An independent
implementation that reproduces every vector byte for byte is format-compatible.

Each entry is hex-encoded and carries:

| Field | Meaning |
|---|---|
| `dek` | the 32-byte data encryption key |
| `salt` | the 20-byte segment salt, which goes into the header at offset 12 |
| `log2_chunk_size`, `multipart`, `index` | the remaining header fields |
| `plaintext` | the input |
| `ciphertext` | the complete segment, header included |

The ten vectors cover the sizes where an encoder's final-chunk handling either
works or does not -- empty, one byte, one short of a chunk, exactly a chunk, one
past a chunk, and a multi-chunk case -- plus the smallest, default and largest
chunk sizes and both multipart boundaries (part 1 and part 10000).

Regenerate them after a deliberate format change with:

```sh
go test ./internal/crypto/stream -run TestKnownAnswerVectors -update
```

A change that was *not* deliberate shows up as a failure of that same test.

---

## 14. Audit log (`v1`)

This section is not part of the object format. Nothing here is written to object
storage: an audit log is a local file, and it is specified here for the same
reason as the local file format of §9 — it is bytes blindbucket writes that
something else has to be able to read. The design is
[ADR-016](adr/ADR-016-audit-log.md).

### 14.1 File layout

A log is a sequence of newline-terminated JSON objects, one record per line. The
first record MUST be a `head`; every later record is an `entry` or a
`checkpoint`. A decoder MUST reject a record carrying more than one body, a
record whose `type` does not match the body present, and any field not defined
below — an unknown field is data that no hash covers.

```
{"type":"head","head":{…}}
{"type":"entry","entry":{…}}
{"type":"checkpoint","checkpoint":{…}}
```

| Record | Fields |
|---|---|
| `head` | `v`, `chain`, `opened`, `pubkey`, `prev_chain`, `prev_hash`, `hash` |
| `entry` | `seq`, `time`, `op`, `bucket`, `key`, `client`, `principal`, `request_id`, `status`, `code`, `kid`, `bytes`, `hash` |
| `checkpoint` | `seq`, `time`, `hash`, `sig` |

`v` is the log format version and is `1`. `pubkey` and `sig` are standard
base64; `hash`, `prev_hash` and a checkpoint's `hash` are lowercase hex.
Timestamps are RFC 3339 with nanosecond precision, in UTC.

### 14.2 The chain

Hashes are computed over the **fields**, never over the serialised line. JSON has
no canonical form — key order, escaping and whitespace are all free — so a
decoder that hashed the bytes of a line would disagree with the encoder on
re-serialised but unchanged input, and could be made to agree on changed input.
A decoder MUST recompute from the parsed fields and compare.

With `lp()` as defined in §1:

```
h₀ = SHA-256("blindbucket/v1/audit-head"
             || uint32_be(v) || lp(chain) || lp(opened)
             || lp(pubkey) || lp(prev_chain) || lp(prev_hash))

hₙ = SHA-256("blindbucket/v1/audit-entry"
             || uint64_be(seq) || lp(chain) || lp(time) || lp(op)
             || lp(bucket) || lp(key) || lp(client) || lp(principal)
             || lp(request_id) || lp(code) || lp(kid)
             || uint32_be(status) || uint64_be(bytes)
             || lp(hₙ₋₁))
```

`pubkey`, `prev_hash` and `hₙ₋₁` are length-prefixed in their **textual** form —
the base64 and hex strings as they appear in the file — not as decoded bytes. A
decoder MUST NOT decode them before hashing.

The hash of the head is `h₀`; the hash of entry *n* is `hₙ`. A decoder MUST
check that entry *n* has `seq` exactly one greater than the entry before it, and
that its recorded `hash` equals the recomputed `hₙ`.

`bytes` MUST be at least 0 and `status` MUST be in 0..999. Both are hashed as
fixed-width unsigned integers, and a decoder MUST reject a record outside these
bounds rather than convert it: a negative value would wrap consistently and so
would verify, leaving a record that reads as an enormous transfer.

`status` is the status the client was sent, and for an object read `bytes` is
the plaintext it was sent. A response that ends early therefore says why. A
client that left before the end, or stopped reading until the gateway gave
up on it, keeps its 2xx `status` with fewer `bytes` than the object holds and
no `code`. A response cut off because the stored data failed authentication
has the `code` `IntegrityCheckFailed`.

The chain id is inside every entry's hash, so a genuine entry from one chain
cannot be spliced into another.

### 14.3 Checkpoints

A checkpoint asserts that the chain stood at `hash` after `seq` entries. It is
not a link in the chain: it does not advance `hₙ`, and removing one breaks no
hash. A decoder MUST check that a checkpoint's `seq` and `hash` equal the
chain's state at the point the checkpoint appears.

The signature is Ed25519 (RFC 8032) over:

```
SHA-256("blindbucket/v1/audit-checkpoint"
        || uint64_be(seq) || lp(chain) || lp(time) || lp(hash))
```

Note that what is signed is the 32-byte SHA-256 output, not the message itself.

Entries after the last checkpoint are covered by the chain but by no signature.
A verifier MUST be able to report how far the signatures reach, because the
difference is what an attacker holding the file can remove undetectably.

### 14.4 Rotation

When a log is rotated, the new file's head records the previous file's `chain`
in `prev_chain` and its final chain hash in `prev_hash`; both are empty in the
first file of a sequence. A verifier given several files MUST check those links,
so that a file removed from the middle of a sequence is a break rather than a
gap.

Sequence numbers restart at 1 in each file. A chain hash does not.

### 14.5 Names

`bucket` and `key` hold the deterministic per-segment name encryption of
[ADR-015](adr/ADR-015-object-name-encryption.md), implemented in
`internal/crypto/names`, under a key derived from the audit secret. They are
therefore opaque without the keyring, and deterministic with it.

A name whose encrypted form would exceed `names.MaxStoredKey` is recorded
instead as `"h:" || hex(HMAC-SHA256(nameKey, "blindbucket/v1/audit-name-digest" || name))`.
This cannot be confused with an encrypted name: those are base32 over the
uppercase alphabet `A-Z2-7` joined by `/`, in which a lowercase letter cannot
occur. Such a name is not recoverable.

`client`, `principal`, `op`, `code` and `kid` are in clear.

**Entries about a tenant's bucket** (§18.5) use another `nameKey` for both names,
derived from the tenant's name key rather than from the audit secret:

```
nameKey_T = HKDF-SHA256(tenant name key, salt = "", info = "blindbucket/v1/tenant-audit-name", L = 32)
```

The entry records nothing else about the tenant, so the fields, the chain and the
format version stay as they are, and a verifier needs no key at all. A reader
that shows names finds the key by trying the ones it holds: the audit secret's
`nameKey`, then each opened tenant's `nameKey_T`. §15.4's check accepts at most one
of them, since a wrong key fails it with probability 1 − 2⁻¹²⁸ per segment. Once a
tenant is destroyed no key accepts its entries' names, and they stay opaque, while
the entries still verify. A `kid` in clear may name its tenant all the same, if the
operator's key ids do.

### 14.6 Keys

The audit secret is 32 bytes, stored in the keyring wrapped under the root key
with the associated data `"blindbucket/v1/audit-secret"` and no variable part.
Two keys are derived from it:

```
signSeed = HKDF-SHA256(secret, info = "blindbucket/v1/audit-sign",  L = 32)
nameKey  = HKDF-SHA256(secret, info = "blindbucket/v1/audit-name",  L = 32)
```

with an empty salt. `signSeed` is the Ed25519 seed. The corresponding public key
is stored in the keyring **unwrapped**, and an implementation opening a keyring
MUST re-derive it and reject a file where the stored and derived values differ.

---

## 15. Object name mapping (`names v1`)

Everything above describes the bytes of an object. This section describes **where
the object is**: the mapping from the key a client uses to the key the storage
provider is addressed with, when a deployment turns object-name encryption on.

It is optional per deployment and off by default. With it off, the stored key is
the client's key unchanged and nothing in this section applies. With it on, the
mapping is part of the format in the strongest sense — an implementation that
cannot reproduce it cannot find a single object.

Design, alternatives and what the mapping does *not* hide:
[ADR-015](adr/ADR-015-object-name-encryption.md).

### 15.1 Keys

Two keys are derived from a 32-byte name key: the keyring's, or, for a bucket in a
tenant, that tenant's (§18.5):

```
K_prf = HKDF-SHA256(ikm = name_key, salt = "", info = "blindbucket/v1/name-prf", L = 32)
K_enc = HKDF-SHA256(ikm = name_key, salt = "", info = "blindbucket/v1/name-enc", L = 32)
```

`salt = ""` is the empty salt of RFC 5869, which HKDF-Extract replaces with
`HashLen` zero bytes. The two info strings are what keep the PRF key and the
encryption key from ever being the same bytes.

The name key does not rotate with the key-encryption keys. Rotation re-wraps data
keys and MUST leave stored names alone; changing the name key renames every
object at once and is a migration, not a rotation.

### 15.2 Mapping a key

A key is split on `/` into segments. Empty segments are preserved: `a//b` and
`a/b` are different S3 keys and MUST map to different stored keys. An empty key
maps to an empty key.

Each segment is encrypted on its own, and the `/` separators are written through
in the clear:

```
StoredKey = E(s₁) || "/" || E(s₂) || "/" || … || E(sₙ)
```

That is what keeps prefix listing working: `a/b/` remains a prefix of `a/b/c.txt`
after mapping, and a delimiter of `/` groups at the same boundaries it would have
grouped at in plaintext. No other delimiter can be served from this layout.

For the segment at index `i`, let `context` be the plaintext key up to and
**including** the separator before it — so for `a/b/c` the contexts are `""`,
`"a/"` and `"a/b/"`. Then:

```
IV      = HMAC-SHA256(K_prf, lp(context) || lp(segment))[0:16]
C       = AES-256-CTR(K_enc, IV, segment)        // IV is the initial counter block
E(s)    = base32(IV || C)
```

The IV is synthetic — derived from the plaintext rather than from chance — which
is what makes the mapping deterministic, and deterministic is what lets a client
naming one object reach it in one request with no index and no lookup. This is
the SIV paradigm of RFC 5297 with HMAC-SHA256 as the PRF in place of AES-CMAC.

Because `context` covers the path so far, the same segment name under two
different parents encrypts differently. Under the *same* parent it does not:
deterministic encryption never hides equality, which is stated as a property
rather than a defect — [`THREAT_MODEL.md`](THREAT_MODEL.md) section 4 has what
follows from it.

### 15.3 Encoding

`base32` is RFC 4648 base32 with the standard alphabet `A-Z2-7` and **no
padding**.

Base32 rather than the shorter base64url, deliberately: two base64url strings can
differ only in case, and a store that folds case would map two distinct objects
onto one key and lose one of them. Base32's alphabet has no case pairs.

**Canonical encoding is mandatory.** Base32 packs `17` bytes into `28`
characters, which carry 140 bits against the 136 in use, so a decoder that
ignores the four spare bits accepts sixteen spellings of one segment — sixteen
distinct stored keys naming a single object, and a way past any check made
against the canonical one. A decoder MUST re-encode what it decoded and reject
anything that does not match, byte for byte.

### 15.4 Reversing the mapping

For each `/`-separated segment of the stored key, in order:

1. base32-decode it, and reject it if re-encoding does not reproduce the input
   exactly (§15.3).
2. Reject it if the result is shorter than 16 bytes.
3. Split into `IV` (16 bytes) and `C` (the rest).
4. `s = AES-256-CTR(K_enc, IV, C)`.
5. Recompute `IV' = HMAC-SHA256(K_prf, lp(context) || lp(s))[0:16]` over the
   *recovered* plaintext, with `context` built from the segments already
   recovered, and reject unless `IV' == IV`. The comparison MUST be
   constant-time.

Step 5 is what makes the construction authenticated as well as deterministic, and
it is also what binds a segment to its position: a provider that swaps two
encrypted segments produces a key whose segments decrypt to plaintext whose
recomputed IVs do not match.

Object integrity does not depend on any of this. An object's wrapped data key is
bound by its associated data to the bucket and the key **the client named**
(§6.1), not to the stored key — so the envelope is identical whether or not names
are encrypted, and an object does not have to be rewritten to move between the
two. What moves is only where it lives.

### 15.5 Length

A stored key MUST NOT exceed **1024 bytes**, S3's own limit. A plaintext key
whose mapping would exceed it MUST be refused, never truncated.

The 16-byte IV is charged **per segment**, so the expansion is set by how many
segments a key has and not by how long it is. The longest plaintext key that
still maps to a legal stored key, by shape:

| Key shape | Longest plaintext key | Expansion |
|---|---:|---:|
| one long segment | 624 B | 1.64× |
| a path with a long leaf | 560 B | 1.83× |
| segments of 8 | 214 B | 4.79× |
| segments of 4 | 128 B | 8.00× |

Measured by `BenchmarkKeyExpansion` in `internal/crypto/names`.

### 15.6 Test vectors

Known-answer vectors live in
[`testdata/vectors/names_v1.json`](../testdata/vectors/names_v1.json) and are a
normative part of this specification, on the same footing as those of section 13.
Each vector fixes the name key and the plaintext key, so the stored key is fully
determined. An implementation that reproduces every `stored_key` character for
character implements this section.

Regenerate them after a deliberate change with:

```sh
go test ./internal/crypto/names -run TestKnownAnswerVectors -update
```

---

## 16. Version history

| Format version | Status | Change |
|---|---|---|
| `1` | stable since `v1.0.0` | Initial specification. Written by every release since `v0.1.0`; read by every later one ([ADR-021](adr/ADR-021-what-1.0-promises.md)). |

The object name mapping of section 15 is versioned with the object format above:
it decides where an object is, so a reader that cannot reproduce it cannot reach
the bytes the rest of this document describes.

The tag sidecar of section 17 is versioned by its magic, `BBT1`. It adds an object
type next to the segment and the manifest and changes neither, so it needs no new
format version: an object without tags is written exactly as before, and a reader
that does not know section 17 reads every object it could read before.

The keyring file of section 18 carries its own `version`. Version 1 is what every
release so far writes and reads. Version 2 adds tenants; a file is written as
version 2 only once it has a tenant, so a deployment without tenants keeps files
older releases can open.

The audit log of section 14 carries its own version, in the `v` field of each
head. It is at `1`, and it moves independently of the object format above: the
two describe different files, and a change to one has no reason to invalidate
readers of the other.

---

## 17. Object tags (`BBT1`)

An object's tag set is stored sealed, in a sidecar object of its own beside the
object, and never reaches the provider in plaintext
([ADR-037](adr/ADR-037-encrypted-object-tags.md)). One sidecar belongs to one
object version. An object without tags has none.

### 17.1 Placement

```
.blindbucket/t/<hex(SHA-256(StoredKey))>/<BindingID>

BindingID = base64url(SHA-256(bb-dek)[0:16])
```

`StoredKey` is the key the object is stored under, after the mapping of section 15
if names are encrypted, hashed as in section 10.1 so that the path is of fixed
width. `bb-dek` is the value of the object's `x-amz-meta-bb-dek` metadata exactly as
stored, its 80 characters, and `base64url` is unpadded (22 characters). Every write
mints a new data key, so every object version has its own `BindingID`. Anything
that can read the object's metadata can compute it, without any key.

A sidecar carries its object's `StoredKey` in its metadata, as
`x-amz-meta-bb-key`: the key's bytes in unpadded base64url, because a key may hold
bytes a metadata value may not. It is there for a reader without the object's key in
hand -- `gc`, which finds sidecars by listing -- to learn which object a directory
belongs to. The value is not authenticated, and a reader MUST use it only once it
hashes back to the directory the sidecar was found in, as a manifest's key is checked
(section 10.1). It tells the provider nothing new: it is the name the provider stores
the object under.

The rules of section 10.1 for the `.blindbucket/` prefix apply: a proxy MUST refuse
client access to it and MUST omit it from listings.

### 17.2 The tag set

```
TagSet = uint8_be(n) || for each tag, in ascending bytewise order of key: lp(key) || lp(value)
```

`n` is the number of tags, at most 10. Keys and values are UTF-8. A key is never
empty and occurs once; a value may be empty. The empty set is the single byte
`0x00`.

The encoding is canonical, and a decoder MUST reject anything else: a count above
10, an empty key, keys that are not in strictly ascending bytewise order (which
rejects a key given twice), a field cut short, and bytes after the last tag.

What a tag may contain is S3's rule, not the format's, and a proxy SHOULD enforce
it before it stores a set: keys of 1 to 128 characters, values of up to 256,
letters, numbers, spaces and `+ - = . _ : / @`, and no key in the reserved `aws:`
prefix. A decoder MUST NOT reject a canonical set for breaking it.

### 17.3 Sealing

```
TagKey  = HKDF-SHA256(ikm = DEK, salt = "", info = "blindbucket/v1/tags", L = 32)
AAD     = "blindbucket/v1/tags" || lp(bucket) || lp(key)
Sidecar = "BBT1" || Nonce(12) || AES-256-GCM.Seal(TagKey, Nonce, TagSet, AAD)
```

`DEK` is the object's data key, unwrapped (section 6). `bucket` and `key` are the
ones the client named, as in the data key's own associated data (section 6.1), so
the seal is the same with names encrypted or not. `Nonce` is 12 random bytes,
fresh for every sidecar written. The `info` string is ASCII, 19 bytes, and
separates the tag key from the segment subkeys the same `DEK` derives with another
label (section 4.2).

A reader computes the `BindingID` from the object's current `bb-dek` and reads the
sidecar at that path. If there is none, the object has no tags. If there is one, it
MUST open under the object's `DEK` and the associated data above, and decode
canonically, or the reader MUST fail as for any integrity failure. A sidecar that
does not open is never taken for an empty set: its name already says which version
it belongs to.

### 17.4 Order and lifecycle

A sidecar MUST be written before the object version it belongs to becomes visible,
as a manifest is (section 10.7): the object is never visible without the tags it
was written with. An operation that writes a new `bb-dek` or a new stored key for
an object that keeps its tags — a key rotation, a name migration, a server-side
copy — writes the new sidecar first.

A sidecar whose object version is no longer visible is an orphan. Orphans hold no
plaintext. One MAY be deleted as a manifest may (ADR-010, rule R4): listed first,
skipped while an upload is open for the key, kept if it is the sidecar of the
object's current `bb-dek` read after the listing, and deleted only once it is older
than the same minimum age.

### 17.5 Test vectors

Known-answer vectors live in
[`testdata/vectors/tags_v1.json`](../testdata/vectors/tags_v1.json) and are a
normative part of this specification, on the same footing as those of sections 13
and 15.6. Each vector fixes the data key, the nonce, bucket, key, stored key, a
stand-in for `bb-dek` and the tag set, listed in canonical order. An
implementation that reproduces `encoded`, `sidecar` and `path` byte for byte
implements this section.

Regenerate them after a deliberate change with:

```sh
go test ./internal/crypto/tags -run TestKnownAnswerVectors -update
```

---

## 18. The keyring file

A keyring holds the key-encryption keys and the deployment's other secrets, each
wrapped under a root key ([ADR-002](adr/ADR-002-key-hierarchy.md),
[ADR-013](adr/ADR-013-root-key-sources.md)). It is not stored at the provider, but it
is data at rest all the same: every instance reads it, and a later release has to
open every file an earlier one wrote ([ADR-021](adr/ADR-021-what-1.0-promises.md)).
Version 1 is what every release so far has written. Version 2 adds tenants
([ADR-038](adr/ADR-038-tenants-and-crypto-shredding.md)): sets of buckets with keys of
their own, each sealed under a lock of its own.

The file is a UTF-8 JSON object. Binary values are standard base64 with padding.
A reader MUST ignore members it does not know, which is what lets a version 1 file
carry `generation` (§18.1) without older readers noticing.

### 18.1 Version 1

| Member | Content |
|---|---|
| `version` | `1` |
| `generation` | optional; an integer that increases with every write of the file. Not authenticated, and used for nothing but reporting which file an instance loaded |
| `kdf` | for a passphrase keyring: `algorithm` (`"argon2id"`), `salt`, `time`, `memory_kib`, `parallelism` |
| `root_key` | for a keyring sealed by a key service: `source` (`"vault-transit"` or `"awskms"`), `ciphertext`, `key_name`, `context` |
| `active_kid` | the key id new data keys are wrapped under |
| `keys` | one or more `{kid, created, wrapped}`; `created` is RFC 3339 and may be absent |
| `audit_key` | optional; `{wrapped, public_key}` (§14.6) |
| `name_key` | optional; `{wrapped}` (§15.1) |
| `freshness_key` | optional; `{wrapped}`, the rollback index's key |

A passphrase keyring has `kdf`, and a `root_key` that is either absent (files
written before key services existed) or `{"source": "passphrase"}`. A keyring sealed
by a key service has `root_key` and no `kdf`. The **root key** is 32 bytes. For a passphrase it is
`Argon2id(passphrase, salt, time, memory_kib, parallelism, 32)`, and a reader MUST
refuse a `salt` shorter than 16 bytes, `time` outside 1..16, `memory_kib` outside
1..1048576 and `parallelism` outside 1..16, since the parameters come from the
file. For a key service it is what that service decrypts `ciphertext` to; how is the
service's protocol, not this format's.

Every `wrapped` value is

```
Wrapped = Nonce(12) || AES-256-GCM-Seal(key = root key, nonce = Nonce, plaintext = secret, aad = AAD)
```

over a 32-byte secret, with these associated data:

| Secret | AAD |
|---|---|
| KEK | `"blindbucket/v1/kek" \|\| lp(kid)` |
| audit secret | `"blindbucket/v1/audit-secret"` |
| name key | `"blindbucket/v1/name-key"` |
| freshness key | `"blindbucket/v1/freshness-key"` |

`active_kid` MUST name one of `keys`, and key ids MUST be unique and valid (§3.1).
A reader MUST refuse a file in which any of these fails, or in which any `wrapped`
value does not open: the keys of a version 1 file are opened together or not at all.

### 18.2 Version 2

A version 2 file is a version 1 file, read as in §18.1, with two more members and
`generation` required:

| Member | Content |
|---|---|
| `directory` | `Wrapped` (§18.1) of the directory (§18.3) under the deployment's root key, with the AAD `"blindbucket/v1/directory"` |
| `tenants` | one section per live tenant (§18.4) |

What §18.1 describes becomes the **default tenant**: its keys, its name key, and
the deployment-wide audit and freshness keys. Every bucket that no tenant claims
belongs to it, so a version 2 file without a single bucket assigned means what the
same file in version 1 means.

A writer MUST write version 2 when the directory lists at least one tenant or one
tombstone, and version 1 otherwise. Once a tenant has been destroyed, its tombstone
stays, so the file stays version 2. Releases that read only version 1 refuse it,
and they have to: a reader that ignored the tenants would wrap their buckets under
the default tenant's keys.

### 18.3 The directory

The directory is a JSON object, sealed whole, so that nothing in it can be read or
changed without the deployment's root key:

```json
{
  "generation": 7,
  "tenants": [
    {
      "name": "acme",
      "buckets": ["acme-*", "shared-reports"],
      "kids": ["acme-2026-10"],
      "active_kid": "acme-2026-10",
      "locks": [
        {"source": "awskms", "key_name": "alias/bb-acme-2025"},
        {"source": "awskms", "key_name": "alias/bb-acme"}
      ]
    }
  ],
  "tombstones": [
    {
      "name": "globex",
      "buckets": ["globex-*"],
      "kids": ["globex-1"],
      "locks": [{"source": "passphrase", "salt": "q83vEjRWeJA..."}],
      "destroyed": "2026-11-02T10:00:00Z"
    }
  ]
}
```

- `generation` MUST equal the file's own `generation`. The copy in clear is for
  reporting; this one is what is trusted.
- A tenant's `name` is 1 to 64 bytes of `A-Z a-z 0-9 . _ -`, like a key id
  (§3.1), and MUST NOT be `default`, which names the default tenant.
- `kids` lists every KEK the tenant has, current or retired, at least one.
  `active_kid` is one of them, or the empty string while the tenant is not yet
  active. A tenant that is not active owns its buckets, but writes to them are
  still wrapped under the default tenant's active KEK (ADR-038, rule 1).
- `locks` is every lock the tenant's section has ever been sealed under, oldest
  first; the last one is the current lock. A lock is
  `{"source": "deployment"}` for a tenant under the deployment's own root key,
  `{"source": "passphrase", "salt": …}` with its Argon2id salt, or
  `{"source": "vault-transit" | "awskms", "key_name": …}`.
- A tombstone keeps a destroyed tenant's `name`, `buckets`, `kids` and `locks`,
  and the time it was destroyed. It has no section.

### 18.4 Tenant sections

Each member of `tenants` is

| Member | Content |
|---|---|
| `name` | the tenant's name |
| `kdf` or `root_key` | as in §18.1, for a tenant with a lock of its own; neither for a tenant under the deployment's root key |
| `keys` | `{kid, created, wrapped}` for every id in the directory's `kids` |
| `name_key` | `{wrapped}`, the tenant's name key |

Its secrets are wrapped as in §18.1, under the **tenant's root key**: what its
`kdf` or `root_key` yields, or the deployment's root key for a tenant without
either. The associated data name the tenant, so that a section cannot be moved to
another name:

| Secret | AAD |
|---|---|
| KEK | `"blindbucket/v1/tenant-kek" \|\| lp(name) \|\| lp(kid)` |
| name key | `"blindbucket/v1/tenant-name-key" \|\| lp(name)` |

No prefix in §18.1 or here is a prefix of another, so no wrapped secret opens as a
secret of another kind.

### 18.5 Which tenant a bucket is in

An entry of `buckets` is a bucket name, 3 to 63 bytes of `a-z 0-9 . -`, or a
prefix of 1 to 62 such bytes followed by `*`. A bucket name matches an entry that
equals it, and a prefix entry that it starts with.

No two entries anywhere in the directory, live tenants and tombstones together,
may **overlap**: two names overlap if they are equal, a name and a prefix if the
name starts with the prefix, and two prefixes if one starts with the other. So a
bucket matches at most one entry, and:

- a bucket that matches a live tenant's entry is in that tenant;
- a bucket that matches a tombstone's entry is in a destroyed tenant, and a reader
  MUST refuse every request for it (ADR-038);
- every other bucket is in the default tenant.

A bucket's tenant decides the KEK a write is wrapped under: the tenant's
`active_kid`, or the default tenant's while the tenant is not active. A read
unwraps with the KEK `bb-kid` names, whichever tenant holds it (ADR-038). The
tenant also decides the name key of §15 and the audit names of §14.5.

### 18.6 Reading

A reader MUST refuse to open a version 2 file, as a whole, if

- `directory` is missing or does not open under the deployment's root key, or its
  `generation` differs from the file's;
- a tenant name is invalid or `default`, or is used twice among tenants and
  tombstones;
- a key id is used twice among the default tenant's `keys`, all tenants' `kids`
  and all tombstones' `kids`;
- a `buckets` entry is malformed, or two entries overlap (§18.5);
- an `active_kid` is neither empty nor one of its tenant's `kids`;
- the live tenants of the directory and the sections of `tenants` do not
  correspond one to one by `name`;
- a section's `keys` are not exactly its tenant's `kids`, or it has no
  `name_key`;
- a section's `kdf` or `root_key` does not match its tenant's last lock: its
  source, and its `key_name` or `salt`.

These are failures of the file, all visible without a key, and a file that fails
one of them cannot be trusted to say which buckets are whose.

A tenant whose root key the reader cannot obtain, or whose section has a `wrapped`
value that does not open under it, is **unopened**. That is a failure of the tenant, not of the file. A reader MUST
NOT use any key of an unopened tenant's section, MUST refuse requests for its
buckets, and MUST NOT treat them as the default tenant's. Every other tenant is
served. The deployment's own root key is different: if it cannot be obtained, the
file cannot be opened at all.

### 18.7 Writing

Every write of the file MUST increase `generation`, in clear and in the directory
alike. A writer MUST keep every rule of §18.6, and also:

- a bucket entry, once in a tenant, stays there until the tenant is destroyed: a
  tenant's `buckets` only grow;
- a key id is never issued twice, including the ids of a destroyed tenant;
- resealing a tenant appends its new lock to `locks`;
- destroying a tenant removes its section and moves its `name`, `buckets`, `kids`
  and `locks` into a tombstone, and a tombstone is never removed.

The first rule is what keeps a destruction from reaching another tenant's data,
and the last one what keeps a destroyed tenant's buckets refused rather than
falling back to the default tenant (ADR-038).

### 18.8 Test vectors

Known-answer vectors live in
[`testdata/vectors/keyring_v2.json`](../testdata/vectors/keyring_v2.json) and are a
normative part of this specification, as those of sections 13, 15.6 and 17.5 are.
Each fixes the root keys, the file, and what opening it must yield: the keys of
every opened tenant, which tenants are unopened, and which bucket names fall in
which tenant. Negative vectors fix files a reader must refuse, each for one rule of
§18.6.

Regenerate them after a deliberate change with:

```sh
go test ./internal/crypto/keys -run TestKeyringV2Vectors -update
```
