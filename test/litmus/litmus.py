#!/usr/bin/env python3
"""Litmus tests for S3-compatible object stores.

Each test is a fixed sequence of S3 requests against a scratch key, and its
verdict is decided by what the store answers *and* what it holds afterwards.
The tests measure the provider semantics this project depends on, the ones a
design on S3 tends to assume without checking:

  cond-put-inm        PutObject with If-None-Match: * over an existing object
  cond-put-im         PutObject with a wrong If-Match
  cond-complete-im    CompleteMultipartUpload with a wrong If-Match
  cond-complete-inm   CompleteMultipartUpload with If-None-Match: * over an existing object
  copy-source-im      UploadPartCopy with a wrong x-amz-copy-source-if-match
  overlap-mpu-mpu     upload A created, then B; B completes, then A
  overlap-mpu-put     upload A created, then a PUT; then A completes
  read-after-write    a PUT is seen at once by HEAD and by a listing

and, across all of them, whether any 200 carried an <Error> body.

Standard library only, with its own SigV4 signer and path-style addressing,
so that no SDK retries, parses or hides a response. Usage:

  litmus.py --endpoint http://localhost:9002 --region us-east-1 \\
            --bucket blindbucket-test --access-key ... --secret-key ... \\
            --provider minio --repeat 3 --out results/minio.jsonl

Writes only under litmus/<run id>/ in the bucket and deletes what it wrote.
"""
import argparse
import datetime as dt
import hashlib
import hmac
import http.client
import json
import re
import sys
import time
import urllib.parse
import uuid

EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class S3:
    def __init__(self, endpoint, region, access_key, secret_key, bucket):
        u = urllib.parse.urlparse(endpoint)
        self.scheme, self.host = u.scheme, u.netloc
        self.region, self.ak, self.sk, self.bucket = region, access_key, secret_key, bucket
        self.error_in_200 = []  # (operation, error code) for every 200 with an <Error> body

    def _conn(self):
        cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
        return cls(self.host, timeout=60)

    def request(self, op, method, key, query=None, headers=None, body=b""):
        query = query or {}
        headers = dict(headers or {})
        path = "/" + self.bucket + ("/" + urllib.parse.quote(key, safe="/~") if key is not None else "")
        qs = "&".join(
            f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(str(v), safe='~')}"
            for k, v in sorted(query.items()))
        now = dt.datetime.now(dt.timezone.utc)
        amzdate, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        payload = hashlib.sha256(body).hexdigest() if body else EMPTY_SHA
        headers.update({"host": self.host, "x-amz-date": amzdate, "x-amz-content-sha256": payload})
        signed = sorted(k.lower() for k in headers)
        canon_headers = "".join(f"{k}:{' '.join(str(headers[h]).split())}\n"
                                for k in signed for h in headers if h.lower() == k)
        canonical = "\n".join([method, path, qs, canon_headers, ";".join(signed), payload])
        scope = f"{date}/{self.region}/s3/aws4_request"
        sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])
        k = b"AWS4" + self.sk.encode()
        for part in (date, self.region, "s3", "aws4_request"):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.ak}/{scope}, "
                                    f"SignedHeaders={';'.join(signed)}, Signature={sig}")
        c = self._conn()
        c.request(method, path + ("?" + qs if qs else ""), body=body or None, headers=headers)
        r = c.getresponse()
        data = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        code = None
        m = re.search(rb"<Error>.*?<Code>([^<]+)</Code>", data, re.S)
        if m:
            code = m.group(1).decode()
            if r.status == 200:
                self.error_in_200.append((op, code))
        return Resp(r.status, hdrs, data, code)

    # Operations, each returning Resp.
    def put(self, key, body, headers=None):
        return self.request("PutObject", "PUT", key, headers=headers, body=body)

    def get(self, key):
        return self.request("GetObject", "GET", key)

    def head(self, key):
        return self.request("HeadObject", "HEAD", key)

    def delete(self, key):
        return self.request("DeleteObject", "DELETE", key)

    def list(self, prefix):
        return self.request("ListObjectsV2", "GET", None, query={"list-type": "2", "prefix": prefix})

    def create(self, key):
        r = self.request("CreateMultipartUpload", "POST", key, query={"uploads": ""})
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", r.body)
        return m.group(1).decode() if m else None, r

    def part(self, key, upload, body):
        r = self.request("UploadPart", "PUT", key, query={"partNumber": "1", "uploadId": upload}, body=body)
        return r.headers.get("etag"), r

    def part_copy(self, key, upload, source, headers=None):
        h = {"x-amz-copy-source": f"/{self.bucket}/{urllib.parse.quote(source, safe='/~')}"}
        h.update(headers or {})
        return self.request("UploadPartCopy", "PUT", key,
                            query={"partNumber": "1", "uploadId": upload}, headers=h)

    def complete(self, key, upload, etag, headers=None):
        body = (f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>").encode()
        return self.request("CompleteMultipartUpload", "POST", key,
                            query={"uploadId": upload}, headers=headers, body=body)

    def abort(self, key, upload):
        return self.request("AbortMultipartUpload", "DELETE", key, query={"uploadId": upload})


class Resp:
    def __init__(self, status, headers, body, error):
        self.status, self.headers, self.body, self.error = status, headers, body, error

    @property
    def ok(self):
        return 200 <= self.status < 300 and self.error is None

    def __str__(self):
        return f"{self.status}{'/' + self.error if self.error else ''}"


def condition_verdict(resp, holds, original, attempted):
    """Enforced: refused with 412 and the original kept. Ignored: accepted and
    the attempted content landed. Refused: any other error. Anything else is
    reported as it is, rather than forced into one of the three."""
    if resp.status == 412 or resp.error == "PreconditionFailed":
        return "enforced" if holds == original else "412-but-overwritten"
    if resp.ok and holds == attempted:
        return "ignored"
    if resp.ok and holds == original:
        return "accepted-not-applied"
    if not resp.ok:
        return f"refused({resp})"
    return f"unexpected({resp}, holds={holds!r})"


def content(s3, key):
    r = s3.get(key)
    return r.body.decode(errors="replace") if r.ok else f"<{r}>"


def t_cond_put_inm(s3, k):
    s3.put(k, b"original")
    r = s3.put(k, b"attempted", {"If-None-Match": "*"})
    return {"response": str(r), "verdict": condition_verdict(r, content(s3, k), "original", "attempted")}


def t_cond_put_im(s3, k):
    s3.put(k, b"original")
    r = s3.put(k, b"attempted", {"If-Match": '"00000000000000000000000000000000"'})
    return {"response": str(r), "verdict": condition_verdict(r, content(s3, k), "original", "attempted")}


def _complete_with(s3, k, headers):
    s3.put(k, b"original")
    upload, _ = s3.create(k)
    etag, _ = s3.part(k, upload, b"attempted")
    r = s3.complete(k, upload, etag, headers)
    if not r.ok:
        s3.abort(k, upload)
    return {"response": str(r), "verdict": condition_verdict(r, content(s3, k), "original", "attempted")}


def t_cond_complete_im(s3, k):
    return _complete_with(s3, k, {"If-Match": '"00000000000000000000000000000000"'})


def t_cond_complete_inm(s3, k):
    return _complete_with(s3, k, {"If-None-Match": "*"})


def t_copy_source_im(s3, k):
    src = k + ".src"
    s3.put(src, b"source")
    s3.put(k, b"original")
    upload, _ = s3.create(k)
    r = s3.part_copy(k, upload, src, {"x-amz-copy-source-if-match": '"00000000000000000000000000000000"'})
    if r.ok:
        m = re.search(rb"<ETag>([^<]+)</ETag>", r.body)
        s3.complete(k, upload, m.group(1).decode().replace("&quot;", '"') if m else '""')
    else:
        s3.abort(k, upload)
    s3.delete(src)
    return {"response": str(r), "verdict": condition_verdict(r, content(s3, k), "original", "source")}


def t_overlap_mpu_mpu(s3, k):
    a, _ = s3.create(k)
    time.sleep(1.1)  # creation times a second apart, so that "created first" is unambiguous
    b, _ = s3.create(k)
    ea, _ = s3.part(k, a, b"A")
    eb, _ = s3.part(k, b, b"B")
    rb_ = s3.complete(k, b, eb)
    ra = s3.complete(k, a, ea)
    holds = content(s3, k)
    if holds == "A":
        kept = "last-completed"
    elif holds == "B":
        kept = "last-created" + ("; loser acknowledged" if ra.ok else f"; loser refused ({ra})")
    else:
        kept = f"neither ({holds})"
    return {"B": str(rb_), "A": str(ra), "holds": holds, "verdict": kept}


def t_overlap_mpu_put(s3, k):
    a, _ = s3.create(k)
    time.sleep(1.1)
    p = s3.put(k, b"PUT")
    ea, _ = s3.part(k, a, b"A")
    ra = s3.complete(k, a, ea)
    holds = content(s3, k)
    if holds == "A":
        kept = "last-completed"
    elif holds == "PUT":
        kept = "last-begun" + ("; loser acknowledged" if ra.ok else f"; loser refused ({ra})")
    else:
        kept = f"neither ({holds})"
    return {"PUT": str(p), "A": str(ra), "holds": holds, "verdict": kept}


def t_read_after_write(s3, k):
    misses = 0
    for i in range(20):
        kk = f"{k}/{i}"
        s3.put(kk, b"x")
        h = s3.head(kk)
        lst = s3.list(kk)
        if not h.ok or kk.encode() not in lst.body:
            misses += 1
        s3.delete(kk)
    return {"writes": 20, "misses": misses, "verdict": "consistent" if misses == 0 else f"{misses} of 20 missed"}


TESTS = [
    ("cond-put-inm", t_cond_put_inm),
    ("cond-put-im", t_cond_put_im),
    ("cond-complete-im", t_cond_complete_im),
    ("cond-complete-inm", t_cond_complete_inm),
    ("copy-source-im", t_copy_source_im),
    ("overlap-mpu-mpu", t_overlap_mpu_mpu),
    ("overlap-mpu-put", t_overlap_mpu_put),
    ("read-after-write", t_read_after_write),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for a in ("endpoint", "region", "bucket", "access-key", "secret-key", "provider"):
        ap.add_argument("--" + a, required=True)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    s3 = S3(args.endpoint, args.region, args.access_key, args.secret_key, args.bucket)
    run = f"litmus/{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    with open(args.out, "a") as f:
        for rep in range(1, args.repeat + 1):
            for name, fn in TESTS:
                key = f"{run}/{name}/{rep}"
                before = len(s3.error_in_200)
                try:
                    res = fn(s3, key)
                except Exception as e:  # recorded, not fatal: one broken test must not hide the others
                    res = {"verdict": f"exception({type(e).__name__}: {e})"}
                res.update({"provider": args.provider, "test": name, "repeat": rep,
                            "error_in_200": s3.error_in_200[before:],
                            "time": dt.datetime.now(dt.timezone.utc).isoformat()})
                f.write(json.dumps(res) + "\n")
                print(f"{args.provider:8s} {name:18s} #{rep}  {res['verdict']}"
                      + (f"  error-in-200: {res['error_in_200']}" if res["error_in_200"] else ""))
                for suffix in ("", ".src"):
                    try:
                        s3.delete(key + suffix)
                    except OSError:
                        pass  # the store went away; the verdict above already says so


if __name__ == "__main__":
    sys.exit(main())
