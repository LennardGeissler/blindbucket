#!/usr/bin/env python3
"""boto3 compatibility scenarios for the blindbucket gateway.

This is one of the few places a language other than Go is justified: a claim
that boto3 works can only be substantiated with boto3. See
docs/adr/ADR-011-languages-outside-the-go-core.md.

Every scenario asserts on plaintext. The gateway is transparent if and only if
boto3 cannot tell the difference between it and the real service -- except for
the ETag, which is the MD5 of ciphertext and is documented as such in
docs/COMPATIBILITY.md.

Usage:
    BLINDBUCKET_ENDPOINT=http://127.0.0.1:9000 \
    BLINDBUCKET_BUCKET=blindbucket-dev \
    [BLINDBUCKET_PREFIX=boto3-scenarios/] \
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    python3 scenarios.py
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time
import traceback

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

MIB = 1024 * 1024

ENDPOINT = os.environ.get("BLINDBUCKET_ENDPOINT", "http://127.0.0.1:9000")
BUCKET = os.environ.get("BLINDBUCKET_BUCKET", "blindbucket-dev")
# Against a shared bucket, BLINDBUCKET_PREFIX puts the run under a prefix that
# the test suites' sweep already cleans up after.
PREFIX = f"{os.environ.get('BLINDBUCKET_PREFIX', 'boto3-scenarios/')}{int(time.time() * 1e6)}/"

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
)

_failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
        return
    _failures.append(name)
    print(f"  FAIL  {name}{': ' + detail if detail else ''}")


def scenario(fn):
    """Run one scenario, turning an exception into a failure rather than a crash."""
    print(f"\n{fn.__name__}")
    try:
        fn()
    except Exception:  # noqa: BLE001 - a scenario failing must not stop the rest
        _failures.append(fn.__name__)
        print(f"  FAIL  {fn.__name__} raised:")
        for line in traceback.format_exc().splitlines()[-4:]:
            print(f"        {line}")
    return fn


@scenario
def put_and_get_round_trip():
    """The plaintext a client puts is the plaintext it gets back."""
    for size in (0, 1, 65535, 65536, 65537, 300_000):
        key = f"{PREFIX}roundtrip-{size}"
        payload = os.urandom(size)
        s3.put_object(Bucket=BUCKET, Key=key, Body=payload)

        got = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
        check(f"round trip of {size} bytes", got == payload,
              f"got {len(got)} bytes")
        s3.delete_object(Bucket=BUCKET, Key=key)


@scenario
def sizes_are_plaintext_sizes():
    """HEAD and listings report the plaintext size, not the ciphertext size."""
    key = f"{PREFIX}sizes"
    payload = os.urandom(123_456)
    s3.put_object(Bucket=BUCKET, Key=key, Body=payload)

    head = s3.head_object(Bucket=BUCKET, Key=key)
    check("head_object size", head["ContentLength"] == len(payload),
          f"got {head['ContentLength']}")

    listing = s3.list_objects_v2(Bucket=BUCKET, Prefix=key)
    entry = listing["Contents"][0]
    check("list_objects_v2 size", entry["Size"] == len(payload), f"got {entry['Size']}")
    s3.delete_object(Bucket=BUCKET, Key=key)


@scenario
def ranges_return_the_right_bytes():
    """Byte ranges map onto ciphertext chunks without shifting the data."""
    key = f"{PREFIX}ranged"
    payload = bytes((i * 7 + 11) % 256 for i in range(300_000))
    s3.put_object(Bucket=BUCKET, Key=key, Body=payload)

    cases = [
        (0, 0), (0, 99), (65535, 65536), (65536, 131071),
        (200_000, 299_999), (299_999, 299_999),
    ]
    for start, end in cases:
        resp = s3.get_object(Bucket=BUCKET, Key=key, Range=f"bytes={start}-{end}")
        got = resp["Body"].read()
        check(f"range {start}-{end}", got == payload[start:end + 1],
              f"got {len(got)} bytes")

    suffix = s3.get_object(Bucket=BUCKET, Key=key, Range="bytes=-100")["Body"].read()
    check("suffix range", suffix == payload[-100:])

    open_ended = s3.get_object(Bucket=BUCKET, Key=key, Range="bytes=299000-")["Body"].read()
    check("open-ended range", open_ended == payload[299000:])
    s3.delete_object(Bucket=BUCKET, Key=key)


@scenario
def metadata_survives_but_gateway_metadata_is_hidden():
    """Client metadata round-trips; the gateway's own never reaches the client."""
    key = f"{PREFIX}metadata"
    s3.put_object(
        Bucket=BUCKET, Key=key, Body=b"payload",
        Metadata={"origin": "boto3", "run": "scenarios"},
        ContentType="application/json", CacheControl="max-age=60",
    )

    head = s3.head_object(Bucket=BUCKET, Key=key)
    check("user metadata preserved",
          head["Metadata"].get("origin") == "boto3" and head["Metadata"].get("run") == "scenarios",
          str(head["Metadata"]))
    check("content type preserved", head["ContentType"] == "application/json",
          head.get("ContentType", ""))
    check("cache control preserved", head.get("CacheControl") == "max-age=60",
          head.get("CacheControl", ""))

    leaked = [k for k in head["Metadata"] if k.lower().startswith("bb-")]
    check("gateway metadata hidden", not leaked, f"leaked {leaked}")
    s3.delete_object(Bucket=BUCKET, Key=key)


@scenario
def checksums_are_verified_and_echoed():
    """A checksum a client supplies is verified against the plaintext."""
    key = f"{PREFIX}checksum"
    payload = os.urandom(50_000)

    resp = s3.put_object(Bucket=BUCKET, Key=key, Body=payload, ChecksumAlgorithm="CRC32")
    check("checksum echoed", any(k.startswith("Checksum") for k in resp),
          f"response keys: {sorted(resp)}")

    got = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    check("body intact after a checksummed upload", got == payload)
    s3.delete_object(Bucket=BUCKET, Key=key)

    # A deliberately wrong checksum must be refused, and must store nothing.
    bad_key = f"{PREFIX}checksum-bad"
    try:
        s3.put_object(Bucket=BUCKET, Key=bad_key, Body=payload,
                      ChecksumCRC32="AAAAAA==")
        check("a wrong checksum is refused", False, "the upload was accepted")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        check("a wrong checksum is refused", code in ("BadDigest", "InvalidRequest"), code)

    try:
        s3.head_object(Bucket=BUCKET, Key=bad_key)
        check("a refused upload stores nothing", False, "the object exists")
    except ClientError:
        check("a refused upload stores nothing", True)


@scenario
def listing_pagination_and_delimiters():
    """Pagination and delimiters behave as the client expects."""
    keys = [f"{PREFIX}page/{i:03d}.bin" for i in range(7)]
    keys += [f"{PREFIX}page/sub/{i:03d}.bin" for i in range(3)]
    for key in keys:
        s3.put_object(Bucket=BUCKET, Key=key, Body=b"x" * 100)

    paginator = s3.get_paginator("list_objects_v2")
    seen = [
        obj["Key"]
        for page in paginator.paginate(Bucket=BUCKET, Prefix=f"{PREFIX}page/",
                                       PaginationConfig={"PageSize": 3})
        for obj in page.get("Contents", [])
    ]
    check("pagination returns every key", sorted(seen) == sorted(keys),
          f"{len(seen)} of {len(keys)}")

    grouped = s3.list_objects_v2(Bucket=BUCKET, Prefix=f"{PREFIX}page/", Delimiter="/")
    prefixes = [p["Prefix"] for p in grouped.get("CommonPrefixes", [])]
    check("delimiter groups sub-prefixes", prefixes == [f"{PREFIX}page/sub/"], str(prefixes))
    check("delimiter excludes grouped keys",
          len(grouped.get("Contents", [])) == 7, str(len(grouped.get("Contents", []))))

    s3.delete_objects(Bucket=BUCKET, Delete={"Objects": [{"Key": k} for k in keys]})
    left = s3.list_objects_v2(Bucket=BUCKET, Prefix=f"{PREFIX}page/").get("Contents", [])
    check("delete_objects removes them all", not left, f"{len(left)} left")


@scenario
def missing_objects_report_nosuchkey():
    """A missing object is a 404 NoSuchKey, not a gateway fault."""
    try:
        s3.get_object(Bucket=BUCKET, Key=f"{PREFIX}definitely-absent")
        check("missing object raises", False, "the call succeeded")
    except ClientError as exc:
        check("missing object raises NoSuchKey",
              exc.response["Error"]["Code"] in ("NoSuchKey", "404"),
              exc.response["Error"]["Code"])


@scenario
def multipart_round_trip():
    """boto3's own transfer manager, over the multipart threshold.

    upload_file switches to multipart above the threshold and parallelises the
    parts, which is the code path a real caller uses. Asserting on plaintext
    after a download_file is the whole claim of the milestone.
    """
    key = f"{PREFIX}multipart-roundtrip"
    payload = os.urandom(20 * 1024 * 1024)
    config = TransferConfig(multipart_threshold=8 * MIB, multipart_chunksize=8 * MIB,
                            max_concurrency=4)

    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "payload.bin")
        restored = os.path.join(tmp, "restored.bin")
        with open(source, "wb") as fh:
            fh.write(payload)

        s3.upload_file(source, BUCKET, key, Config=config)
        s3.download_file(BUCKET, key, restored, Config=config)
        with open(restored, "rb") as fh:
            got = fh.read()

    check("multipart round trip is byte-identical", got == payload,
          f"got {len(got)} bytes, want {len(payload)}")
    check("sha256 matches",
          hashlib.sha256(got).hexdigest() == hashlib.sha256(payload).hexdigest())

    head = s3.head_object(Bucket=BUCKET, Key=key)
    check("head_object reports the plaintext size",
          head["ContentLength"] == len(payload), str(head["ContentLength"]))
    check("the ETag carries a part count", "-" in head["ETag"], head["ETag"])

    listed = s3.list_objects_v2(Bucket=BUCKET, Prefix=key)["Contents"][0]
    check("the listing reports the plaintext size",
          listed["Size"] == len(payload), str(listed["Size"]))

    # A range that straddles a part boundary is the one the prefix sums have to
    # get right; inside a part it is the ordinary single-segment mapping.
    boundary = 8 * MIB
    for start, end in ((0, 99), (boundary - 10, boundary + 10), (len(payload) - 100, len(payload) - 1)):
        body = s3.get_object(Bucket=BUCKET, Key=key, Range=f"bytes={start}-{end}")["Body"].read()
        check(f"range {start}-{end}", body == payload[start:end + 1], f"got {len(body)} bytes")

    s3.delete_object(Bucket=BUCKET, Key=key)


@scenario
def multipart_part_sizes_are_enforced():
    """A non-final part off the chunk grid is refused, and nothing is stored.

    The rule exists so the plaintext size stays recoverable from a listing
    (docs/FORMAT.md 7.3). Refusing is what keeps an unrecoverable object from
    being written at all.
    """
    key = f"{PREFIX}multipart-unaligned"
    upload = s3.create_multipart_upload(Bucket=BUCKET, Key=key)
    upload_id = upload["UploadId"]

    first = s3.upload_part(Bucket=BUCKET, Key=key, UploadId=upload_id,
                           PartNumber=1, Body=os.urandom(5 * MIB + 1))
    second = s3.upload_part(Bucket=BUCKET, Key=key, UploadId=upload_id,
                            PartNumber=2, Body=b"tail")
    try:
        s3.complete_multipart_upload(
            Bucket=BUCKET, Key=key, UploadId=upload_id,
            MultipartUpload={"Parts": [
                {"PartNumber": 1, "ETag": first["ETag"]},
                {"PartNumber": 2, "ETag": second["ETag"]},
            ]},
        )
        check("an unaligned part is refused", False, "the completion succeeded")
    except ClientError as exc:
        check("an unaligned part is refused with InvalidRequest",
              exc.response["Error"]["Code"] == "InvalidRequest",
              exc.response["Error"]["Code"])

    try:
        s3.head_object(Bucket=BUCKET, Key=key)
        check("a refused completion stores nothing", False, "the object exists")
    except ClientError:
        check("a refused completion stores nothing", True)


@scenario
def multipart_abort_leaves_nothing():
    """An aborted upload produces no object, and its token stops working."""
    key = f"{PREFIX}multipart-abort"
    upload = s3.create_multipart_upload(Bucket=BUCKET, Key=key)
    upload_id = upload["UploadId"]
    s3.upload_part(Bucket=BUCKET, Key=key, UploadId=upload_id,
                   PartNumber=1, Body=os.urandom(5 * MIB))
    s3.abort_multipart_upload(Bucket=BUCKET, Key=key, UploadId=upload_id)

    try:
        s3.head_object(Bucket=BUCKET, Key=key)
        check("an aborted upload stores nothing", False, "the object exists")
    except ClientError:
        check("an aborted upload stores nothing", True)

    try:
        s3.upload_part(Bucket=BUCKET, Key=key, UploadId=upload_id,
                       PartNumber=2, Body=b"more")
        check("a spent upload id is refused", False, "the part was accepted")
    except ClientError as exc:
        check("a spent upload id is refused",
              exc.response["Error"]["Code"] in ("NoSuchUpload", "404"),
              exc.response["Error"]["Code"])


@scenario
def upload_tokens_are_bound_to_their_object():
    """The upload id is a sealed token, not the provider's own.

    It is bound to the bucket and key it was issued for, so a client that may
    write one key cannot use its token to write another.
    """
    mine = f"{PREFIX}token-mine"
    other = f"{PREFIX}token-other"
    upload = s3.create_multipart_upload(Bucket=BUCKET, Key=mine)

    check("the upload id is not the provider's own",
          len(upload["UploadId"]) > 60, f"{len(upload['UploadId'])} characters")

    try:
        s3.upload_part(Bucket=BUCKET, Key=other, UploadId=upload["UploadId"],
                       PartNumber=1, Body=b"payload")
        check("a token does not work on another key", False, "the part was accepted")
    except ClientError as exc:
        check("a token does not work on another key",
              exc.response["Error"]["Code"] in ("NoSuchUpload", "404"),
              exc.response["Error"]["Code"])

    s3.abort_multipart_upload(Bucket=BUCKET, Key=mine, UploadId=upload["UploadId"])


@scenario
def the_manifest_prefix_is_unreachable():
    """A client that could delete a manifest could break its own object."""
    key = f"{PREFIX}manifest-guard"
    payload = os.urandom(12 * MIB)
    config = TransferConfig(multipart_threshold=8 * MIB, multipart_chunksize=8 * MIB)

    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "payload.bin")
        with open(source, "wb") as fh:
            fh.write(payload)
        s3.upload_file(source, BUCKET, key, Config=config)

    listed = s3.list_objects_v2(Bucket=BUCKET, Prefix=".blindbucket/")
    check("the manifest prefix is invisible in listings",
          listed.get("KeyCount", 0) == 0 and not listed.get("Contents"),
          str(listed.get("KeyCount")))

    try:
        s3.delete_object(Bucket=BUCKET, Key=".blindbucket/m/whatever/id")
        check("the manifest prefix refuses deletes", False, "the delete succeeded")
    except ClientError as exc:
        check("the manifest prefix refuses deletes",
              exc.response["Error"]["Code"] == "AccessDenied",
              exc.response["Error"]["Code"])

    check("the object is still readable",
          s3.get_object(Bucket=BUCKET, Key=key)["Body"].read() == payload)
    s3.delete_object(Bucket=BUCKET, Key=key)


@scenario
def list_multipart_uploads_is_refused_with_a_reason():
    """It cannot be implemented, and says so rather than returning unusable ids.

    See docs/adr/ADR-006-upload-token.md: a token carries the data key and the
    manifest id, and the provider's listing has neither.
    """
    try:
        s3.list_multipart_uploads(Bucket=BUCKET)
        check("ListMultipartUploads is refused", False, "the call succeeded")
    except ClientError as exc:
        check("ListMultipartUploads is refused with NotImplemented",
              exc.response["Error"]["Code"] == "NotImplemented",
              exc.response["Error"]["Code"])


@scenario
def ciphertext_never_matches_plaintext():
    """A recognisable payload must not appear in what the provider stores.

    This is checked through the gateway rather than against the provider, so it
    only proves the round trip is faithful; the direct check against the
    provider lives in the Go integration tests, which have its credentials.
    """
    key = f"{PREFIX}opaque"
    marker = b"RECOGNISABLE-PLAINTEXT-MARKER-" * 100
    s3.put_object(Bucket=BUCKET, Key=key, Body=marker)
    got = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    check("marker survives the round trip", got == marker)
    check("sha256 matches",
          hashlib.sha256(got).hexdigest() == hashlib.sha256(marker).hexdigest())
    s3.delete_object(Bucket=BUCKET, Key=key)


def main() -> int:
    print(f"blindbucket boto3 scenarios against {ENDPOINT}, bucket {BUCKET}")
    print(f"boto3 {boto3.__version__}")
    if _failures:
        print(f"\n{len(_failures)} failing: {', '.join(_failures)}")
        return 1
    print("\nall scenarios passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
