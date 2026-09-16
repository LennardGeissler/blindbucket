package proxy

import (
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// maxDeleteBody bounds a DeleteObjects request. S3 allows 1000 keys of up to
// 1024 bytes, so two megabytes is generous.
const maxDeleteBody = 2 << 20

// listObjects forwards a listing and rewrites the sizes it reports.
//
// The sizes are converted with the configured chunk size, because a listing
// carries no per-object metadata to read one from. That makes them a hint: they
// are right for every object this deployment wrote, and they are not
// authenticated in any case, which docs/THREAT_MODEL.md states plainly. The
// authenticated size is established when an object is actually read.
func (p *Proxy) listObjects(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	query := r.URL.Query()
	if p.names != nil {
		translated, apiErr := p.encryptedListingQuery(query)
		if apiErr != nil {
			return apiErr
		}
		query = translated
	}

	result, err := p.upstream.ListObjects(r.Context(), req.Bucket, query)
	if err != nil {
		return translateUpstream(err)
	}

	// Names come back as the provider stores them, so they are turned back into
	// the client's -- and put into the client's order -- before anything else
	// reads them. Reserved-prefix filtering happens in there too, because it has
	// to run against the stored key.
	if p.names != nil {
		if apiErr := p.decryptListing(result, r.URL.Query(), log); apiErr != nil {
			return apiErr
		}
	}

	kept := make([]upstream.ObjectEntry, 0, len(result.Contents))
	for _, entry := range result.Contents {
		if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
			continue
		}
		// A multipart object needs its part count, and the ETag suffix S3 appends
		// is where a listing can get one -- there is no per-object metadata here
		// to read a manifest id from. See docs/FORMAT.md section 7.2.
		segments := int64(1)
		if count, ok := partCountFromETag(entry.ETag); ok {
			segments = count
		}
		if plain, err := stream.OpenedSizeSegments(entry.Size, p.log2C, segments); err == nil {
			entry.Size = plain
		} else {
			// Not a size this format produces at the configured chunk size: a
			// foreign object, or one written under a different setting. Its own
			// size is a better answer than a wrong conversion.
			log.Debug("listing size left unconverted",
				"key", entry.Key, "size", entry.Size, "segments", segments)
		}
		kept = append(kept, entry)
	}
	result.Contents = kept

	prefixes := make([]upstream.CommonPrefix, 0, len(result.CommonPrefixes))
	for _, cp := range result.CommonPrefixes {
		if touchesReservedPrefix(cp.Prefix) {
			continue
		}
		prefixes = append(prefixes, cp)
	}
	result.CommonPrefixes = prefixes

	// Filtering can leave a page with fewer entries than MaxKeys, or none at
	// all, while IsTruncated stays true. That is S3-conformant -- a client must
	// follow the continuation token regardless -- and it is why KeyCount is
	// recomputed rather than forwarded.
	if result.KeyCount > 0 || req.Op == s3api.OpListObjectsV2 {
		result.KeyCount = len(result.Contents) + len(result.CommonPrefixes)
	}

	return writeXML(w, http.StatusOK, result)
}

// touchesReservedPrefix reports whether a common prefix would reveal the
// gateway's own objects.
//
// The obvious direction is a prefix under the reserved one. The other direction
// matters too: with a delimiter other than "/", a grouping such as ".blindbu"
// is shorter than the reserved prefix but still groups exactly those objects.
func touchesReservedPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	if strings.HasPrefix(prefix, s3api.ReservedPrefix) {
		return true
	}
	// Written out rather than as a reversed HasPrefix, because the reversed
	// form reads like a mistake even when it is deliberate.
	return len(prefix) < len(s3api.ReservedPrefix) &&
		s3api.ReservedPrefix[:len(prefix)] == prefix
}

// deleteObjects removes several objects in one request.
func (p *Proxy) deleteObjects(w http.ResponseWriter, r *http.Request, req s3api.Request, _ *slog.Logger) *s3api.Error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeleteBody))
	if err != nil {
		return s3api.ErrIncompleteBody.WithMessage("could not read the request body")
	}

	var in upstream.DeleteRequest
	if err := xml.Unmarshal(body, &in); err != nil {
		return s3api.ErrInvalidRequest.WithMessage("the Delete body is not valid XML")
	}
	if len(in.Objects) == 0 {
		return s3api.ErrInvalidRequest.WithMessage("the Delete body names no objects")
	}
	for _, obj := range in.Objects {
		if strings.HasPrefix(obj.Key, s3api.ReservedPrefix) {
			return s3api.ErrAccessDenied.WithMessage(
				"the %s prefix is reserved by the gateway", s3api.ReservedPrefix)
		}
	}

	// The request names the client's keys and the response has to as well, so
	// the mapping runs in both directions around the provider. A key the client
	// asked to delete comes back under that same name whatever happened to it.
	back := map[string]string{}
	if p.names != nil {
		for i, obj := range in.Objects {
			stored, apiErr := p.storedKey(obj.Key)
			if apiErr != nil {
				return apiErr
			}
			in.Objects[i].Key = stored
			back[stored] = obj.Key
		}
	}

	result, err := p.upstream.DeleteObjects(r.Context(), req.Bucket, in)
	if err != nil {
		return translateUpstream(err)
	}
	if p.names != nil {
		for i, entry := range result.Deleted {
			if plain, ok := back[entry.Key]; ok {
				result.Deleted[i].Key = plain
			}
		}
		for i, entry := range result.Errors {
			if plain, ok := back[entry.Key]; ok {
				result.Errors[i].Key = plain
			}
		}
	}
	return writeXML(w, http.StatusOK, result)
}

// passthrough forwards an operation whose body blindbucket does not transform.
//
// Bucket existence, location, creation, deletion and the bucket list carry no
// object content, so reproducing the provider's answer verbatim is both simpler
// and more accurate than paraphrasing it.
func (p *Proxy) passthrough(w http.ResponseWriter, r *http.Request, req s3api.Request, _ *slog.Logger) *s3api.Error {
	var body []byte
	if r.Body != nil && r.ContentLength > 0 {
		read, err := io.ReadAll(io.LimitReader(r.Body, maxDeleteBody))
		if err != nil {
			return s3api.ErrIncompleteBody.WithMessage("could not read the request body")
		}
		body = read
	}

	resp, err := p.upstream.Passthrough(r.Context(), r.Method, req.Bucket, r.URL.Query(), body)
	if err != nil {
		return translateUpstream(err)
	}

	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Length", strconv.Itoa(len(resp.Body)))
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		//nolint:gosec // an XML document from the provider, forwarded verbatim
		// under an application/xml content type; there is no HTML context here.
		_, _ = w.Write(resp.Body)
	}
	return nil
}

// writeXML renders an S3 response body.
func writeXML(w http.ResponseWriter, status int, payload any) *s3api.Error {
	encoded, err := xml.Marshal(payload)
	if err != nil {
		return s3api.ErrInternal.WithMessage("could not encode the response")
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(xml.Header)+len(encoded)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	//nolint:gosec // encoding/xml output under an application/xml content type.
	_, _ = w.Write(encoded)
	return nil
}

// echoVerifiedChecksums returns the checksums the proxy actually verified.
//
// They describe the plaintext. Anything the provider reports describes
// ciphertext and is stripped on the way out, so without this a client that asked
// for a checksum would get none back at all.
func echoVerifiedChecksums(dst, requestHeaders, trailer http.Header) {
	for name, values := range requestHeaders {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-checksum-") && len(values) > 0 {
			dst.Set(name, values[0])
		}
	}
	for name, values := range trailer {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-checksum-") && len(values) > 0 {
			dst.Set(name, values[0])
		}
	}
}
