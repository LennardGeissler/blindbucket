package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// storedKey maps a client's object key to the key the provider stores it under.
//
// The identity when name encryption is off, which is what lets every call site
// use it unconditionally. The mapping is deterministic and needs no lookup, so
// this is a pure function of the key -- the property ADR-015 chose determinism
// for, and the reason a point lookup stays a point lookup.
//
// The plaintext key is what the caller keeps for everything that is not an
// address: the associated data binding the wrapped data key (FORMAT section 6.1)
// stays over the plaintext key, so the envelope is unchanged by whether names
// are encrypted, and an object does not have to be rewritten to move between the
// two. What does have to be rewritten is where it lives.
func (p *Proxy) storedKey(key string) (string, *s3api.Error) {
	if p.names == nil || key == "" {
		return key, nil
	}
	stored, err := p.names.EncryptKey(key)
	if err != nil {
		if errors.Is(err, names.ErrTooLong) {
			return "", s3api.ErrKeyTooLong.WithMessage(
				"this key is within S3's 1024-byte limit but its encrypted form is not; " +
					"encryption grows a key by a factor set by how many '/'-separated " +
					"segments it has, so a deep path of short segments reaches the limit " +
					"much sooner than a shallow one")
		}
		return "", s3api.ErrInternal
	}
	return stored, nil
}

// nameEncryptionGate refuses operations that have not been taught what an
// encrypted name means, and returns nil for the rest.
//
// A whitelist rather than a blacklist. An operation added to the router later is
// refused here until somebody has decided what its key should be, which is the
// direction it is safe to be wrong in: a refusal is visible, while an operation
// that addressed the provider with a plaintext key while everything else used an
// encrypted one would write objects nothing could find again.
func (p *Proxy) nameEncryptionGate(op s3api.Operation) *s3api.Error {
	if p.names == nil {
		return nil
	}
	switch op {
	case s3api.OpPutObject, s3api.OpGetObject, s3api.OpHeadObject, s3api.OpDeleteObject,
		s3api.OpDeleteObjects, s3api.OpGetObjectTagging:
		return nil
	// Listings are served for a prefix that comes back whole in one page, and
	// refuse the shapes they cannot sort. ADR-017 has the tiers.
	case s3api.OpListObjects, s3api.OpListObjectsV2:
		return nil
	// Multipart, and the copies that go through it. The upload token is sealed
	// against the key the client named; every request to the provider carries
	// the key it stores. openToken hands back both so that no handler has to
	// remember the second.
	case s3api.OpCreateMultipartUpload, s3api.OpUploadPart, s3api.OpUploadPartCopy,
		s3api.OpCompleteMultipartUpload, s3api.OpAbortMultipartUpload, s3api.OpListParts,
		s3api.OpCopyObject:
		return nil
	// Bucket-level operations carry no object key at all.
	case s3api.OpListBuckets, s3api.OpHeadBucket, s3api.OpCreateBucket,
		s3api.OpDeleteBucket, s3api.OpGetBucketLocation:
		return nil
	}
	// Nothing the router serves is left, so this is reached only by an operation
	// added later. Refusing it until someone has decided what its key means is
	// the direction it is safe to be wrong in.
	return s3api.ErrNotImplemented.WithMessage(
		"%s has not been taught what an object name means while object-name "+
			"encryption is on. See ADR-015 and ADR-017.", op)
}

// serveEncryptedListing answers a listing when object names are encrypted.
//
// The provider orders by the stored key, so nothing can be served until the
// whole prefix has been read, decrypted and sorted -- ADR-017 measured what an
// unsorted listing does to a client, and it is delete objects that exist. What
// is served from that sorted prefix is then ordinary S3 paging.
//
// The resume state is one string, the last key already served, which the client
// hands back as a continuation token, a marker or start-after depending on which
// listing it is using. Nothing is kept on the gateway that an answer depends on;
// listbuffer.go has why that matters.
func (p *Proxy) serveEncryptedListing(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	query := stripPresign(r.URL.Query())
	v2 := req.Op == s3api.OpListObjectsV2

	delimiter := query.Get("delimiter")
	if delimiter != "" && delimiter != "/" {
		return s3api.ErrNotImplemented.WithMessage(
			"delimiter=%q is not available while object-name encryption is on: the "+
				"stored layout is built on '/', which is the one separator that "+
				"survives encryption, so no other delimiter can be served from it",
			delimiter)
	}

	prefix := query.Get("prefix")
	storedPrefix, whole, err := p.names.EncryptPrefix(prefix)
	if err != nil {
		return s3api.ErrInternal
	}
	if !whole {
		// "photos/2026" against a segment "2026-01": a partial segment has no
		// encrypted form that is a prefix of anything. Serving it means listing
		// the parent and filtering on decrypted names, which changes what
		// max-keys counts -- its own decision, and not one this makes.
		return s3api.ErrNotImplemented.WithMessage(
			"prefix=%q does not end on a '/' boundary, and while object-name "+
				"encryption is on a prefix must: encryption is per path segment, so a "+
				"partial segment has no encrypted form to match against (ADR-015)", prefix)
	}

	maxKeys, apiErr := listingMaxKeys(query)
	if apiErr != nil {
		return apiErr
	}
	after, apiErr := listingCursor(query, v2)
	if apiErr != nil {
		return apiErr
	}
	// Only an opaque token this gateway minted marks a continuation. A marker or
	// start-after the client chose is a fresh listing that happens to begin in
	// the middle, and it must see everything written up to now.
	continuing := v2 && query.Get("continuation-token") != ""

	rows, apiErr := p.sortedPrefix(
		r.Context(), req.Bucket, prefix, storedPrefix, delimiter, continuing, log)
	if apiErr != nil {
		return apiErr
	}

	result := &upstream.ListBucketResult{
		Xmlns: s3ListXmlns, Name: req.Bucket, Prefix: prefix, Delimiter: delimiter,
	}
	if v2 {
		result.ContinuationToken = query.Get("continuation-token")
		result.StartAfter = query.Get("start-after")
	} else {
		result.Marker = query.Get("marker")
	}
	servePage(result, rows, after, maxKeys, v2)
	p.convertListedSizes(result, log)
	if v2 {
		result.KeyCount = len(result.Contents) + len(result.CommonPrefixes)
	}
	return writeXML(w, http.StatusOK, result)
}

// sortedPrefix returns the whole prefix in the client's order, reading it from
// the provider unless this is the continuation of a listing already in progress.
//
// **A first page is never served from the cache.** S3 has been strongly
// read-after-write consistent since 2020 and clients lean on it hard: `aws s3
// sync` lists the destination before it uploads anything, and if that listing
// were served again afterwards from a snapshot taken before the writes, the next
// sync would see an empty prefix and upload everything twice. Found exactly that
// way, with the real client.
//
// A *continuation* is different, and caching one is not merely safe but more
// correct: S3 does not promise that keys written during a paginated listing
// appear in it, so serving every page of one walk from the snapshot the first
// page took is the behaviour a client expects. That is also the only place the
// cache was ever worth having, since it is what turns an n-page walk from
// n prefix reads into one.
//
// The semaphore is taken only around a read, because that is what holds the
// memory. A cache hit costs nothing and does not queue.
func (p *Proxy) sortedPrefix(
	ctx context.Context, bucket, prefix, storedPrefix, delimiter string,
	continuing bool, log *slog.Logger,
) ([]listingRow, *s3api.Error) {
	if continuing {
		if rows, ok := p.listCache.get(bucket, prefix, delimiter); ok {
			return rows, nil
		}
	}
	select {
	case p.listings <- struct{}{}:
		defer func() { <-p.listings }()
	case <-ctx.Done():
		return nil, s3api.ErrInternal
	}
	// Another page of the same walk may have filled it while this one queued.
	if continuing {
		if rows, ok := p.listCache.get(bucket, prefix, delimiter); ok {
			return rows, nil
		}
	}

	rows, apiErr := p.bufferPrefix(ctx, bucket, storedPrefix, delimiter, log)
	if apiErr != nil {
		return nil, apiErr
	}
	p.listCache.put(bucket, prefix, delimiter, rows)
	return rows, nil
}

// listingCursor reads the resume point out of whichever parameter this listing
// version spells it with.
//
// v1's marker and v2's start-after are plaintext object keys, which is exactly
// what the cursor is, so they are honoured directly. v2's continuation-token is
// opaque and minted here, so it carries the same key encoded.
func listingCursor(query url.Values, v2 bool) (string, *s3api.Error) {
	if v2 {
		if token := query.Get("continuation-token"); token != "" {
			return decodeCursor(token)
		}
		return query.Get("start-after"), nil
	}
	return query.Get("marker"), nil
}
