package proxy

import (
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// The bb-* metadata encoding lives in internal/objectmeta, because
// `blindbucket rotate` reads and rewrites exactly the same fields. These aliases
// keep the proxy's own code reading as it did.
type objectMeta = objectmeta.Meta

func parseObjectMeta(md map[string]string, fallbackLog2C uint8) (objectMeta, error) {
	return objectmeta.Parse(md, fallbackLog2C)
}

const metaPrefix = objectmeta.Prefix

// clientMetadata extracts the user metadata a client sent, and refuses any
// attempt to write blindbucket's own keys.
//
// Letting a client set bb-dek would let it swap the wrapped key of an object it
// is allowed to write for one from an object it is not.
func clientMetadata(h http.Header) (map[string]string, error) {
	out := make(map[string]string)
	for name, values := range h {
		if !strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") || len(values) == 0 {
			continue
		}
		key := name[len("x-amz-meta-"):]
		if strings.HasPrefix(strings.ToLower(key), metaPrefix) {
			return nil, fmt.Errorf("metadata key %q uses the reserved %q prefix", key, metaPrefix)
		}
		out[key] = values[0]
	}
	return out, nil
}

// responseHeadersToStrip are removed before a response reaches the client.
//
// The checksum headers are the subtle ones: they describe the ciphertext, so an
// SDK that validates them against the plaintext it received would report
// corruption on a perfectly good object.
var responseHeadersToStrip = []string{
	"X-Amz-Checksum-Crc32",
	"X-Amz-Checksum-Crc32c",
	"X-Amz-Checksum-Crc64nvme",
	"X-Amz-Checksum-Sha1",
	"X-Amz-Checksum-Sha256",
	"X-Amz-Checksum-Type",
	"X-Amz-Sdk-Checksum-Algorithm",
	"Content-Length",
	"Content-Range",
	"Accept-Ranges",
}

// copyResponseHeaders forwards the upstream's headers to the client, minus
// blindbucket's own metadata and anything that describes the ciphertext.
//
// User metadata is emitted with a lower-case name, written straight into the
// map so net/http does not canonicalise it back. S3 lower-cases metadata keys,
// and SDKs surface them as sent: boto3 hands the caller
// response["Metadata"]["origin"], so a canonicalised "X-Amz-Meta-Origin" would
// arrive as "Origin" and quietly break every lookup. Found by running the real
// boto3 against this gateway, which is what docs/COMPATIBILITY.md is for.
func copyResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-meta-"+metaPrefix) {
			continue
		}
		if strings.HasPrefix(lower, "x-amz-meta-") {
			dst[lower] = slicesClone(values)
			continue
		}
		dst[name] = slicesClone(values)
	}
	for _, name := range responseHeadersToStrip {
		dst.Del(name)
	}
}

// copyObjectHeaders is copyResponseHeaders for an object read, followed by the
// headers the read asked for with response-content-type and its siblings
// (ADR-032). Called just before the status line of a 200 or 206, so that an
// error response carries none of them.
func copyObjectHeaders(dst http.Header, r *http.Request, src http.Header) {
	copyResponseHeaders(dst, src)
	for name, value := range s3api.ResponseOverrides(r.URL.Query()) {
		dst.Set(name, value)
	}
}

func slicesClone(v []string) []string {
	out := make([]string, len(v))
	copy(out, v)
	return out
}

// mergeMetadata combines the client's metadata with blindbucket's own.
func mergeMetadata(client map[string]string, own objectMeta) map[string]string {
	out := make(map[string]string, len(client)+4)
	maps.Copy(out, client)
	maps.Copy(out, own.Headers())
	return out
}
