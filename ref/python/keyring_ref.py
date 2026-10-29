"""An independent reader of the blindbucket keyring file, version 2.

Written from `docs/FORMAT.md` section 18 and nothing else, to answer for the
keyring what the reference decoder answers for the segment format: **is the
specification sufficient to implement from?**

It takes root keys as given, the way a key service or a passphrase yields them,
and implements:

  §18.1  version 1, the default tenant: KEKs under "blindbucket/v1/kek" || lp(kid),
         the name key under "blindbucket/v1/name-key", all opened or none
  §18.2  version 2: the directory and the tenant sections
  §18.3  the directory, sealed under "blindbucket/v1/directory"
  §18.4  tenant sections, under "blindbucket/v1/tenant-kek" || lp(name) || lp(kid)
         and "blindbucket/v1/tenant-name-key" || lp(name)
  §18.5  bucket entries, overlap, and which tenant a bucket is in
  §18.6  what refuses the file, and what leaves only a tenant unopened
"""

from __future__ import annotations

import base64
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT = "default"
NONCE = 12
KID = re.compile(r"[A-Za-z0-9._-]{1,64}")
BUCKET_CHARS = re.compile(r"[a-z0-9.-]*")


class Malformed(Exception):
    """The file breaks a rule of §18.6 and must be refused as a whole."""


class NoKey(Exception):
    """A wrapped value did not open."""


def lp(s: str) -> bytes:
    b = s.encode()
    if len(b) > 0xFFFF:
        raise ValueError("field too long for its length prefix")
    return struct.pack(">H", len(b)) + b


def unwrap(root: bytes, wrapped_b64: str, aad: bytes) -> bytes:
    raw = base64.b64decode(wrapped_b64, validate=True)
    if len(raw) < NONCE + 16:
        raise NoKey("too short")
    try:
        return AESGCM(root).decrypt(raw[:NONCE], raw[NONCE:], aad)
    except InvalidTag as e:
        raise NoKey("does not open") from e


@dataclass
class Tenant:
    active_kid: str
    keks: dict[str, bytes]
    name_key: Optional[bytes]


@dataclass
class Opened:
    default: Tenant
    directory: dict
    tenants: dict[str, Tenant] = field(default_factory=dict)
    unopened: list[str] = field(default_factory=list)

    def tenant_of(self, bucket: str) -> tuple[str, bool]:
        """§18.5: the tenant a bucket is in, and whether it is destroyed."""
        for t in self.directory["tenants"]:
            if any(matches(e, bucket) for e in t["buckets"]):
                return t["name"], False
        for t in self.directory["tombstones"]:
            if any(matches(e, bucket) for e in t["buckets"]):
                return t["name"], True
        return DEFAULT, False


def matches(entry: str, bucket: str) -> bool:
    if entry.endswith("*"):
        return bucket.startswith(entry[:-1])
    return entry == bucket


def valid_entry(entry: str) -> bool:
    prefix = entry.endswith("*")
    body = entry[:-1] if prefix else entry
    lo, hi = (1, 62) if prefix else (3, 63)
    return lo <= len(body) <= hi and BUCKET_CHARS.fullmatch(body) is not None


def overlaps(a: str, b: str) -> bool:
    pa, pb = a.endswith("*"), b.endswith("*")
    if pa and pb:
        return a[:-1].startswith(b[:-1]) or b[:-1].startswith(a[:-1])
    if pa:
        return b.startswith(a[:-1])
    if pb:
        return a.startswith(b[:-1])
    return a == b


def open_default(f: dict, root: bytes) -> Tenant:
    """§18.1: every KEK and the name key open under the root key, or none do."""
    keys = f.get("keys") or []
    if not keys:
        raise Malformed("no keys")
    keks = {}
    for e in keys:
        kid = e["kid"]
        if not KID.fullmatch(kid) or kid in keks:
            raise Malformed(f"key id {kid!r}")
        keks[kid] = unwrap(root, e["wrapped"], b"blindbucket/v1/kek" + lp(kid))
    if f.get("active_kid") not in keks:
        raise Malformed("active_kid is not one of the keys")
    name_key = None
    if f.get("name_key"):
        name_key = unwrap(root, f["name_key"]["wrapped"], b"blindbucket/v1/name-key")
    return Tenant(f["active_kid"], keks, name_key)


def section_lock(s: dict) -> dict:
    """How a section is sealed, in the directory's terms (§18.3, §18.4)."""
    kdf, rk = s.get("kdf"), s.get("root_key")
    if kdf is not None and (rk is None or rk.get("source") == "passphrase"):
        return {"source": "passphrase", "salt": kdf.get("salt")}
    if kdf is None and rk is None:
        return {"source": "deployment"}
    if kdf is None and rk is not None and rk.get("source") not in (None, "", "passphrase"):
        return {"source": rk["source"], "key_name": rk.get("key_name")}
    return {"source": None}


def lock_matches(section: dict, lock: dict) -> bool:
    have = section_lock(section)
    if have["source"] is None or have["source"] != lock.get("source"):
        return False
    if have["source"] == "passphrase":
        return have["salt"] == lock.get("salt")
    if have["source"] == "deployment":
        return True
    return have["key_name"] == lock.get("key_name")


def validate_directory(d: dict, default_kids: list[str]) -> None:
    """§18.6, the rules inside the directory."""
    names: set[str] = set()
    kids = {k: DEFAULT for k in default_kids}
    entries: list[str] = []

    def claim(t: dict) -> None:
        name = t["name"]
        if name == DEFAULT or not KID.fullmatch(name):
            raise Malformed(f"tenant name {name!r}")
        if name in names:
            raise Malformed(f"tenant {name!r} twice")
        names.add(name)
        if not t["kids"]:
            raise Malformed(f"tenant {name!r} has no keys")
        for kid in t["kids"]:
            if not KID.fullmatch(kid) or kid in kids:
                raise Malformed(f"key id {kid!r}")
            kids[kid] = name
        for e in t["buckets"]:
            if not valid_entry(e):
                raise Malformed(f"bucket entry {e!r}")
            if any(overlaps(prev, e) for prev in entries):
                raise Malformed(f"bucket entry {e!r} overlaps")
            entries.append(e)

    for t in d["tenants"]:
        claim(t)
        if t["active_kid"] not in ("", *t["kids"]):
            raise Malformed("active_kid")
        if not t["locks"]:
            raise Malformed("no lock")
    for t in d["tombstones"]:
        claim(t)


def open_keyring(data: bytes, root: bytes, tenant_root: Callable[[str, dict], Optional[bytes]]) -> Opened:
    f = json.loads(data)
    if f.get("version") != 2:
        raise Malformed("not version 2")
    default = open_default(f, root)

    if not f.get("directory"):
        raise Malformed("no directory")
    try:
        d = json.loads(unwrap(root, f["directory"], b"blindbucket/v1/directory"))
    except NoKey as e:
        raise Malformed("the directory does not open") from e
    if d.get("generation") != f.get("generation"):
        raise Malformed("generations differ")
    d.setdefault("tenants", [])
    d.setdefault("tombstones", [])
    d["tenants"] = d["tenants"] or []
    d["tombstones"] = d["tombstones"] or []
    validate_directory(d, list(default.keks))

    sections: dict[str, dict] = {}
    for s in f.get("tenants") or []:
        if s["name"] in sections:
            raise Malformed("two sections for one tenant")
        sections[s["name"]] = s
    if set(sections) != {t["name"] for t in d["tenants"]}:
        raise Malformed("tenants and sections do not correspond")
    for t in d["tenants"]:
        s = sections[t["name"]]
        if sorted(e["kid"] for e in s.get("keys") or []) != sorted(t["kids"]):
            raise Malformed("a section's keys are not its tenant's kids")
        if not s.get("name_key"):
            raise Malformed("a section has no name key")
        if not lock_matches(s, t["locks"][-1]):
            raise Malformed("a section does not match its last lock")

    out = Opened(default, d)
    for t in d["tenants"]:
        name, s, lock = t["name"], sections[t["name"]], t["locks"][-1]
        troot = root if lock["source"] == "deployment" else tenant_root(name, lock)
        if troot is None:
            out.unopened.append(name)
            continue
        try:
            keks = {
                e["kid"]: unwrap(troot, e["wrapped"], b"blindbucket/v1/tenant-kek" + lp(name) + lp(e["kid"]))
                for e in s["keys"]
            }
            nk = unwrap(troot, s["name_key"]["wrapped"], b"blindbucket/v1/tenant-name-key" + lp(name))
        except NoKey:
            out.unopened.append(name)
            continue
        out.tenants[name] = Tenant(t["active_kid"], keks, nk)
    out.unopened.sort()
    return out
