package proxy

import (
	"encoding/xml"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objcopy"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// copyObjectResult is the body S3 answers a copy with.
//
// The ETag is the destination's, quoted as the provider reported it, and
// LastModified is when this gateway published the object. Neither describes the
// plaintext: an ETag never does for an encrypted object, which is why
// docs/COMPATIBILITY.md tells sync tools not to compare them.
type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// copySource is a parsed x-amz-copy-source.
type copySource struct {
	Bucket string
	// Key is the key the client named, which is the source object's identity.
	// Stored is where the provider keeps it; the two differ only when names are
	// encrypted, and it is filled in by whoever is about to address the
	// provider, because parsing the header cannot know the keyring.
	Key    string
	Stored string
}

// copyObject serves CopyObject: a PUT carrying x-amz-copy-source.
//
// The ciphertext never moves. What moves is the data key: it is unwrapped under
// the source's identity and wrapped again under the destination's, because the
// wrap is bound to bucket and key (FORMAT §6.1). A copy that skipped that step
// would store a key that cannot be opened where it now lives, and nothing would
// notice until somebody tried to read the object.
//
// Everything after the checks is objcopy's, which `blindbucket rotate` uses too:
// same re-wrap, same part-preserving copy, same manifest lifecycle rules.
func (p *Proxy) copyObject(
	w http.ResponseWriter, r *http.Request, req s3api.Request, authResult *auth.Result, log *slog.Logger,
) *s3api.Error {
	src, apiErr := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if apiErr != nil {
		return apiErr
	}

	// The destination's bucket was authorised before this handler ran. The
	// source's was not, and a credential scoped to one bucket must not be able
	// to read another one by naming it as a copy source.
	if !authResult.Client.MayAccess(src.Bucket) {
		log.Warn("copy source is outside the credential's buckets",
			"source_bucket", src.Bucket)
		return s3api.ErrAccessDenied
	}
	if strings.HasPrefix(src.Key, s3api.ReservedPrefix) {
		return s3api.ErrInvalidRequest.WithMessage(
			"the %s prefix is reserved by the gateway", s3api.ReservedPrefix)
	}

	directive := strings.ToUpper(strings.TrimSpace(r.Header.Get("X-Amz-Metadata-Directive")))
	if directive == "" {
		directive = "COPY"
	}
	if directive != "COPY" && directive != "REPLACE" {
		return s3api.ErrInvalidArgument.WithMessage(
			"x-amz-metadata-directive must be COPY or REPLACE, not %q", directive)
	}

	// S3 refuses a copy onto itself that changes nothing, because it is almost
	// always a mistake rather than a request. With REPLACE it is the documented
	// way to rewrite an object's metadata, and it works here: the wrap is bound
	// to bucket and key, which a self-copy does not change.
	sameObject := src.Bucket == req.Bucket && src.Key == req.Key
	if sameObject && directive == "COPY" {
		return s3api.ErrInvalidRequest.WithMessage(
			"the copy source and destination are the same object; " +
				"use x-amz-metadata-directive: REPLACE to rewrite its metadata")
	}

	// Both objects are addressed by their stored keys and identified by the keys
	// the client named. Keeping the two apart is what lets this path serve a copy
	// while names are encrypted: the wrapped key stays bound to the identity, and
	// only the provider is told the address.
	srcStored, apiErr := p.storedKey(src.Key)
	if apiErr != nil {
		return apiErr
	}
	destStored, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}

	info, err := p.upstream.HeadObject(r.Context(), src.Bucket, srcStored)
	if err != nil {
		return translateUpstream(err)
	}
	if apiErr := checkCopyConditions(r.Header, info.ETag, info.LastModified); apiErr != nil {
		return apiErr
	}

	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		// Copying a foreign object would produce something this gateway cannot
		// read back, and it is the same refusal a GET of it would give.
		return errNotEncryptedAPI
	}
	if err != nil {
		return p.integrityError(log, "object metadata", err)
	}

	// A self-copy keeps its own manifest chain: the destination version it
	// replaces is the source, so the manifest that becomes an orphan is known
	// here and can be removed under rule R3 rather than left to gc. For a copy
	// to a different key the destination's previous state is not known without
	// another HEAD, and a plain PutObject over a multipart object leaves that to
	// gc as well, so this follows the same rule.
	var replaced *manifest.ID
	if sameObject && meta.Multipart {
		id := meta.ManifestID
		replaced = &id
	}

	dest := objcopy.Dest{
		Bucket: req.Bucket, Key: req.Key, StoredKey: destStored,
		KeyID:              p.keys.ActiveKID(),
		ContentType:        info.ContentType,
		CacheControl:       info.CacheControl,
		ContentDisposition: info.Header.Get("Content-Disposition"),
		ContentEncoding:    info.Header.Get("Content-Encoding"),
		ContentLanguage:    info.Header.Get("Content-Language"),
	}
	if directive == "REPLACE" {
		clientMeta, err := clientMetadata(r.Header)
		if err != nil {
			return s3api.ErrInvalidArgument.WithMessage("%v", err)
		}
		dest.UserMetadata = clientMeta
		dest.ContentType = r.Header.Get("Content-Type")
		dest.CacheControl = r.Header.Get("Cache-Control")
		dest.ContentDisposition = r.Header.Get("Content-Disposition")
		dest.ContentEncoding = passthroughContentEncoding(r)
		dest.ContentLanguage = r.Header.Get("Content-Language")
	} else {
		dest.UserMetadata = userMetadataOf(info.Metadata)
	}

	out, err := objcopy.Do(r.Context(), objcopy.Deps{
		Upstream: p.upstream, Keys: p.keys, Log: log,
	}, objcopy.Request{
		Source: objcopy.Source{
			Bucket: src.Bucket, Key: src.Key, StoredKey: srcStored, Info: info, Meta: meta,
		},
		Dest: dest,
		// The source could be replaced between the HEAD above and the copy
		// below. Without this the copy can pair one version's metadata -- its
		// wrapped key included -- with another version's bytes, which produces
		// an object that fails authentication on the first read.
		SourceIfMatch:    info.ETag,
		ReplacedManifest: replaced,
	})
	switch {
	case errors.Is(err, objcopy.ErrPreconditionFailed):
		log.Info("copy source changed while it was being copied",
			"source_bucket", src.Bucket, "source_key", src.Key)
		return s3api.ErrPreconditionFailed.WithMessage(
			"the copy source changed while it was being copied")
	case err != nil:
		log.Warn("copy failed", "source_bucket", src.Bucket, "source_key", src.Key, "err", err)
		return translateUpstream(err)
	}

	// The destination holds the source's ciphertext, whose salts this path never
	// reads -- objcopy moves the bytes inside the provider and reports no tag. So
	// the index is told to forget rather than to record: keeping the entry the
	// copy replaced would make a perfectly good object read back as a rollback.
	// The destination is unchecked until it has been read once, which ADR-018
	// names as the cost of a copy.
	if p.fresh != nil {
		if err := p.fresh.Invalidate(req.Bucket, req.Key); err != nil {
			log.Error("could not drop the copy destination from the freshness index; "+
				"it may read back as a rollback", "err", err)
		}
	}

	p.noteObject(r, dest.KeyID, 0)
	log.Info("object copied",
		"source_bucket", src.Bucket, "source_key", src.Key,
		"multipart", meta.Multipart, "kid", dest.KeyID)

	// S3 answers a copy 200 and then reports failures inside the body, because
	// a copy of many gigabytes takes long enough that the provider has to commit
	// to a status first. This gateway does not need that: the copy is finished
	// by the time anything is written, so a failure here is a real status code
	// and this body is only ever the success case.
	return writeXML(w, http.StatusOK, copyObjectResult{
		ETag:         out.ETag,
		LastModified: out.LastModified.Format(time.RFC3339),
	})
}

// parseCopySource reads the x-amz-copy-source header.
//
// The value is a path, percent-encoded, with an optional leading slash and an
// optional ?versionId=. Splitting on the first slash of the decoded value would
// be wrong: a key may contain a slash and a bucket may not, so the split has to
// happen before decoding.
func parseCopySource(raw string) (copySource, *s3api.Error) {
	if raw == "" {
		return copySource{}, s3api.ErrInvalidArgument.WithMessage("the request names no copy source")
	}
	value := strings.TrimPrefix(raw, "/")

	// A versionId selects a version of the source. This gateway does not
	// implement versioned reads, and silently copying the current version
	// instead of the one asked for would be the wrong kind of helpful.
	if path, query, ok := strings.Cut(value, "?"); ok {
		params, err := url.ParseQuery(query)
		if err != nil {
			return copySource{}, s3api.ErrInvalidArgument.WithMessage("the copy source is malformed")
		}
		if params.Get("versionId") != "" {
			return copySource{}, s3api.ErrNotImplemented.WithMessage(
				"copying a specific versionId is not implemented in this build")
		}
		value = path
	}

	bucket, key, ok := strings.Cut(value, "/")
	if !ok || bucket == "" || key == "" {
		return copySource{}, s3api.ErrInvalidArgument.WithMessage(
			"the copy source must be /bucket/key, not %q", raw)
	}
	decodedBucket, err := url.PathUnescape(bucket)
	if err != nil {
		return copySource{}, s3api.ErrInvalidArgument.WithMessage("the copy source bucket is malformed")
	}
	decodedKey, err := url.PathUnescape(key)
	if err != nil {
		return copySource{}, s3api.ErrInvalidArgument.WithMessage("the copy source key is malformed")
	}
	return copySource{Bucket: decodedBucket, Key: decodedKey}, nil
}

// checkCopyConditions applies the x-amz-copy-source-if-* preconditions.
//
// S3 evaluates these against the source, and a failure is 412 rather than the
// 304 the equivalent request headers would produce on a GET: this is a write,
// and there is no cached copy for the client to fall back on.
func checkCopyConditions(h http.Header, etag string, modified time.Time) *s3api.Error {
	if want := h.Get("X-Amz-Copy-Source-If-Match"); want != "" && !etagMatches(want, etag) {
		return s3api.ErrPreconditionFailed.WithMessage(
			"the copy source does not have the expected ETag")
	}
	if want := h.Get("X-Amz-Copy-Source-If-None-Match"); want != "" && etagMatches(want, etag) {
		return s3api.ErrPreconditionFailed.WithMessage(
			"the copy source has the excluded ETag")
	}
	if raw := h.Get("X-Amz-Copy-Source-If-Unmodified-Since"); raw != "" {
		since, err := http.ParseTime(raw)
		if err != nil {
			return s3api.ErrInvalidArgument.WithMessage(
				"x-amz-copy-source-if-unmodified-since is not a valid HTTP date")
		}
		if modified.After(since) {
			return s3api.ErrPreconditionFailed.WithMessage(
				"the copy source was modified after the given time")
		}
	}
	if raw := h.Get("X-Amz-Copy-Source-If-Modified-Since"); raw != "" {
		since, err := http.ParseTime(raw)
		if err != nil {
			return s3api.ErrInvalidArgument.WithMessage(
				"x-amz-copy-source-if-modified-since is not a valid HTTP date")
		}
		if !modified.After(since) {
			return s3api.ErrPreconditionFailed.WithMessage(
				"the copy source was not modified after the given time")
		}
	}
	return nil
}

// etagMatches compares an If-Match value against an ETag.
//
// Quoting is not reliable on either side -- providers differ, and clients echo
// what they were given -- so both are compared unquoted. "*" matches any
// existing object, which by the time this runs is the only kind there is.
func etagMatches(want, have string) bool {
	have = strings.Trim(have, `"`)
	for _, candidate := range strings.Split(want, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.Trim(strings.TrimPrefix(candidate, "W/"), `"`) == have {
			return true
		}
	}
	return false
}

// userMetadataOf returns the source's metadata without blindbucket's own
// entries, which the destination gets fresh ones of.
func userMetadataOf(md map[string]string) map[string]string {
	out := make(map[string]string, len(md))
	for name, value := range md {
		if strings.HasPrefix(strings.ToLower(name), metaPrefix) {
			continue
		}
		out[name] = value
	}
	return out
}
