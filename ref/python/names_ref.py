"""An independent implementation of the blindbucket object name mapping.

Written from `docs/FORMAT.md` section 15 and nothing else. It answers, for the
name mapping, the question the reference decoder answers for the segment format:
**is the specification sufficient to implement from?**

The mapping needs a second implementation more than the rest of the format does,
because it is the one place where blindbucket composes a construction rather than
calling one. ADR-015 chose to build the SIV paradigm from standard parts --
HMAC-SHA256 as the PRF, AES-CTR under the synthetic IV -- instead of taking a
long-unmaintained dependency. That is a defensible choice only if the
composition is checked by something other than the code that implements it.

Unlike the segment decoder, this implements **both** directions. There it was
enough to decode, because decoding is what a reader needs. Here the mapping is
deterministic, so the specification fixes the *stored* key exactly: reproducing
it character for character is the check, and that requires encrypting.

The rules implemented here are:

  §15.1  K_prf / K_enc = HKDF-SHA256(name_key, salt="", info=".../name-prf|enc")
  §15.2  split on "/", per-segment SIV, context = the path up to and including
         the separator before the segment
  §15.3  base32, RFC 4648 standard alphabet, no padding, canonical or rejected
  §15.4  decryption, and the constant-time check of the recomputed IV
  §15.5  the 1024-byte limit on a stored key

Usage:
    python3 names_ref.py encrypt --name-key <hex> a/b/c.txt
    python3 names_ref.py decrypt --name-key <hex> <stored key>
"""

from __future__ import annotations

import argparse
import base64
import hmac
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32
IV_SIZE = 16
MAX_STORED_KEY = 1024

INFO_PRF = b"blindbucket/v1/name-prf"
INFO_ENC = b"blindbucket/v1/name-enc"


class NameError_(Exception):
    """A stored key this name key did not produce."""


class TooLongError(Exception):
    """A key whose encrypted form exceeds what S3 accepts."""


def lp(value: bytes) -> bytes:
    """section 1: length-prefixed byte string."""
    if len(value) > 0xFFFF:
        raise NameError_(f"lp() input of {len(value)} bytes exceeds 65535")
    return len(value).to_bytes(2, "big") + value


def derive_keys(name_key: bytes) -> tuple[bytes, bytes]:
    """section 15.1: the PRF key and the encryption key.

    salt="" is RFC 5869's empty salt, which HKDF-Extract replaces with HashLen
    zero bytes. `cryptography` spells that salt=None.
    """
    if len(name_key) != KEY_SIZE:
        raise NameError_(f"name key is {len(name_key)} bytes, want {KEY_SIZE}")
    prf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None,
               info=INFO_PRF).derive(name_key)
    enc = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None,
               info=INFO_ENC).derive(name_key)
    return prf, enc


def synthetic_iv(prf_key: bytes, context: str, segment: str) -> bytes:
    """section 15.2: IV = HMAC-SHA256(K_prf, lp(context) || lp(segment))[0:16]."""
    mac = hmac.new(prf_key, digestmod="sha256")
    mac.update(lp(context.encode()))
    mac.update(lp(segment.encode()))
    return mac.digest()[:IV_SIZE]


def _ctr(enc_key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CTR with iv as the initial counter block. Its own inverse."""
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
    worker = cipher.encryptor()
    return worker.update(data) + worker.finalize()


def b32encode(raw: bytes) -> str:
    """section 15.3: RFC 4648 base32, standard alphabet, no padding."""
    return base64.b32encode(raw).decode().rstrip("=")


def b32decode(text: str) -> bytes:
    """section 15.3: decode, and reject anything not canonically encoded.

    Base32 puts 17 bytes into 28 characters, which carry 140 bits against the
    136 in use. A decoder that ignores the four spare bits accepts sixteen
    spellings of one segment -- sixteen stored keys naming one object. So the
    check is not "does it decode" but "does it re-encode to exactly what came
    in".
    """
    padding = "=" * (-len(text) % 8)
    try:
        raw = base64.b32decode(text + padding, casefold=False)
    except Exception as err:  # noqa: BLE001 - any decode failure is one rejection
        raise NameError_(f"segment is not valid base32: {err}") from err
    if b32encode(raw) != text:
        raise NameError_("segment is not canonically encoded")
    return raw


def _seal_segment(prf_key: bytes, enc_key: bytes, context: str, segment: str) -> str:
    iv = synthetic_iv(prf_key, context, segment)
    return b32encode(iv + _ctr(enc_key, iv, segment.encode()))


def _open_segment(prf_key: bytes, enc_key: bytes, context: str, segment: str) -> str:
    raw = b32decode(segment)
    if len(raw) < IV_SIZE:
        raise NameError_(f"segment holds {len(raw)} bytes, too few for a {IV_SIZE}-byte IV")
    iv, ciphertext = raw[:IV_SIZE], raw[IV_SIZE:]
    plain = _ctr(enc_key, iv, ciphertext)
    try:
        recovered = plain.decode()
    except UnicodeDecodeError as err:
        raise NameError_(f"segment does not decrypt to text: {err}") from err

    # section 15.4 step 5: the IV is recomputed over the recovered plaintext and
    # compared in constant time. This is what authenticates the segment and
    # binds it to its position.
    if not hmac.compare_digest(synthetic_iv(prf_key, context, recovered), iv):
        raise NameError_("segment does not match its synthetic IV")
    return recovered


def encrypt_key(name_key: bytes, plain: str) -> str:
    """section 15.2: map an object key to the key the provider stores it under."""
    if plain == "":
        return ""
    prf_key, enc_key = derive_keys(name_key)

    out: list[str] = []
    offset = 0
    for segment in plain.split("/"):
        # The context is the plaintext path up to and including the separator
        # before this segment, so the same name under two parents differs.
        out.append(_seal_segment(prf_key, enc_key, plain[:offset], segment))
        offset += len(segment) + 1

    stored = "/".join(out)
    if len(stored) > MAX_STORED_KEY:
        raise TooLongError(
            f"{len(plain)} bytes encrypts to {len(stored)}, the maximum is {MAX_STORED_KEY}")
    return stored


def decrypt_key(name_key: bytes, stored: str) -> str:
    """section 15.4: reverse the mapping."""
    if stored == "":
        return ""
    prf_key, enc_key = derive_keys(name_key)

    recovered: list[str] = []
    for segment in stored.split("/"):
        context = "".join(s + "/" for s in recovered)
        recovered.append(_open_segment(prf_key, enc_key, context, segment))
    return "/".join(recovered)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("direction", choices=("encrypt", "decrypt"))
    parser.add_argument("--name-key", required=True, help="the 32-byte name key, hex")
    parser.add_argument("key", help="the object key, or the stored key")
    args = parser.parse_args(argv)

    name_key = bytes.fromhex(args.name_key)
    try:
        if args.direction == "encrypt":
            print(encrypt_key(name_key, args.key))
        else:
            print(decrypt_key(name_key, args.key))
    except (NameError_, TooLongError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
