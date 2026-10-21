"""An independent implementation of the blindbucket tag sidecar.

Written from `docs/FORMAT.md` section 17 and nothing else, to answer for the
sidecar what the reference decoder answers for the segment format: **is the
specification sufficient to implement from?**

The rules implemented here are:

  §17.1  the path: .blindbucket/t/<hex(SHA-256(stored key))>/<BindingID>,
         BindingID = unpadded base64url of SHA-256(bb-dek)[0:16]
  §17.2  the tag set: a count, then lp(key) || lp(value) in ascending bytewise
         order of key, canonical or rejected
  §17.3  the seal: AES-256-GCM under HKDF-SHA256(DEK, "", "blindbucket/v1/tags"),
         with "blindbucket/v1/tags" || lp(bucket) || lp(key) as associated data
"""

from __future__ import annotations

import base64
import hashlib
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"BBT1"
LABEL = b"blindbucket/v1/tags"
MAX_TAGS = 10
NONCE_SIZE = 12


class TagError(Exception):
    """A sidecar or tag set this implementation refuses."""


def lp(b: bytes) -> bytes:
    if len(b) > 0xFFFF:
        raise TagError("a field longer than a length prefix")
    return struct.pack(">H", len(b)) + b


def binding_id(bb_dek: str) -> str:
    digest = hashlib.sha256(bb_dek.encode()).digest()[:16]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def path(stored_key: str, bb_dek: str) -> str:
    return ".blindbucket/t/" + hashlib.sha256(stored_key.encode()).hexdigest() + "/" + binding_id(bb_dek)


def encode(tags: list[tuple[str, str]]) -> bytes:
    if len(tags) > MAX_TAGS:
        raise TagError("more than ten tags")
    ordered = sorted(tags, key=lambda t: t[0].encode())
    out = bytes([len(ordered)])
    previous = None
    for key, value in ordered:
        k = key.encode()
        if not k:
            raise TagError("an empty key")
        if k == previous:
            raise TagError("a key twice")
        previous = k
        out += lp(k) + lp(value.encode())
    return out


def decode(b: bytes) -> list[tuple[str, str]]:
    if not b:
        raise TagError("no count")
    n, rest = b[0], b[1:]
    if n > MAX_TAGS:
        raise TagError("more than ten tags")

    def field(data: bytes) -> tuple[bytes, bytes]:
        if len(data) < 2:
            raise TagError("a length prefix cut short")
        (length,) = struct.unpack(">H", data[:2])
        if len(data) < 2 + length:
            raise TagError("a field cut short")
        return data[2 : 2 + length], data[2 + length :]

    tags: list[tuple[str, str]] = []
    previous = None
    for _ in range(n):
        key, rest = field(rest)
        value, rest = field(rest)
        if not key:
            raise TagError("an empty key")
        if previous is not None and key <= previous:
            raise TagError("keys not in strictly ascending order")
        previous = key
        tags.append((key.decode(), value.decode()))
    if rest:
        raise TagError("bytes after the last tag")
    return tags


def _aead(dek: bytes, bucket: str, key: str) -> tuple[AESGCM, bytes]:
    tag_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=LABEL).derive(dek)
    return AESGCM(tag_key), LABEL + lp(bucket.encode()) + lp(key.encode())


def seal(dek: bytes, nonce: bytes, bucket: str, key: str, tags: list[tuple[str, str]]) -> bytes:
    aead, aad = _aead(dek, bucket, key)
    return MAGIC + nonce + aead.encrypt(nonce, encode(tags), aad)


def open_(dek: bytes, bucket: str, key: str, sidecar: bytes) -> list[tuple[str, str]]:
    if len(sidecar) < len(MAGIC) + NONCE_SIZE or sidecar[: len(MAGIC)] != MAGIC:
        raise TagError("not a BBT1 sidecar")
    aead, aad = _aead(dek, bucket, key)
    nonce = sidecar[len(MAGIC) : len(MAGIC) + NONCE_SIZE]
    try:
        plain = aead.decrypt(nonce, sidecar[len(MAGIC) + NONCE_SIZE :], aad)
    except Exception as err:  # cryptography raises InvalidTag
        raise TagError("the sidecar does not open for this object") from err
    return decode(plain)
