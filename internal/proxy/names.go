package proxy

import (
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"

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
	case s3api.OpPutObject, s3api.OpGetObject, s3api.OpHeadObject, s3api.OpDeleteObject:
		return nil
	// Listings are served for a prefix that comes back whole in one page, and
	// refuse the shapes they cannot sort. ADR-017 has the tiers.
	case s3api.OpListObjects, s3api.OpListObjectsV2:
		return nil
	// Bucket-level operations carry no object key at all.
	case s3api.OpListBuckets, s3api.OpHeadBucket, s3api.OpCreateBucket,
		s3api.OpDeleteBucket, s3api.OpGetBucketLocation:
		return nil
	}
	return s3api.ErrNotImplemented.WithMessage(
		"%s is not available while object-name encryption is on. Multipart, copy and "+
			"tagging each still need their own answer to what an encrypted name "+
			"means. See ADR-015 and ADR-017.", op)
}

// encryptedListingQuery rewrites a client's listing query for the provider, or
// refuses a shape this tier cannot serve correctly.
//
// ADR-017 serves listings in three tiers, of which this is the first: a prefix
// whose whole result fits in one upstream page is decrypted and sorted in place,
// which is free, exactly correct, and the overwhelmingly common listing. The
// buffered tier and its bound are not built yet, so everything that would need
// them is refused here rather than answered in an order the client cannot use.
//
// The separators survive encryption, so a delimiter of "/" groups at exactly the
// segment boundaries it would have grouped at in plaintext, and the provider's
// own grouping can be reused rather than reimplemented.
func (p *Proxy) encryptedListingQuery(query url.Values) (url.Values, *s3api.Error) {
	// Pagination in means pagination out, and a page of an encrypted listing is
	// only correct once the whole prefix has been sorted -- which is the tier
	// that does not exist yet.
	for _, param := range []string{"continuation-token", "marker", "start-after"} {
		if query.Get(param) != "" {
			return nil, s3api.ErrNotImplemented.WithMessage(
				"%s is not available while object-name encryption is on: a page of an "+
					"encrypted listing is only in the client's order once the whole "+
					"prefix has been read and sorted, and that tier is not built yet "+
					"(ADR-017)", param)
		}
	}
	if d := query.Get("delimiter"); d != "" && d != "/" {
		return nil, s3api.ErrNotImplemented.WithMessage(
			"delimiter=%q is not available while object-name encryption is on: the "+
				"stored layout is built on '/', which is the one separator that "+
				"survives encryption, so no other delimiter can be served from it", d)
	}

	out := make(url.Values, len(query))
	for k, v := range query {
		out[k] = v
	}

	prefix := query.Get("prefix")
	stored, whole, err := p.names.EncryptPrefix(prefix)
	if err != nil {
		return nil, s3api.ErrInternal
	}
	if !whole {
		// "photos/2026" against a segment "2026-01": a partial segment has no
		// encrypted form that is a prefix of anything. Serving it means listing
		// the parent and filtering on decrypted names, which changes what
		// max-keys counts -- its own decision, not this tier's.
		return nil, s3api.ErrNotImplemented.WithMessage(
			"prefix=%q does not end on a '/' boundary, and while object-name "+
				"encryption is on a prefix must: encryption is per path segment, so a "+
				"partial segment has no encrypted form to match against (ADR-015)", prefix)
	}
	if stored == "" {
		out.Del("prefix")
	} else {
		out.Set("prefix", stored)
	}
	return out, nil
}

// decryptListing turns a provider's answer back into the client's names, in the
// client's order.
//
// The reserved prefix is filtered before anything is decrypted: the gateway's
// own objects are stored under unencrypted keys, so feeding one to the decrypter
// would fail on an object that was never encrypted in the first place.
func (p *Proxy) decryptListing(
	result *upstream.ListBucketResult, query url.Values, log *slog.Logger,
) *s3api.Error {
	if result.IsTruncated {
		return s3api.ErrNotImplemented.WithMessage(
			"this prefix is larger than one page, and while object-name encryption is " +
				"on the gateway can only serve a listing it can sort whole: the " +
				"provider orders by the encrypted key, so a partial answer would " +
				"reach the client in an arbitrary order -- which makes some clients " +
				"delete objects that exist. Narrow the prefix, or raise max-keys " +
				"enough for the whole prefix to come back at once (ADR-017)")
	}

	kept := make([]upstream.ObjectEntry, 0, len(result.Contents))
	for _, entry := range result.Contents {
		if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
			continue
		}
		plain, err := p.names.DecryptKey(entry.Key)
		if err != nil {
			// Something in the bucket this keyring did not write. GetObject
			// answers ObjectNotEncrypted for the same case; a listing has no
			// way to present a name it cannot read, so it leaves it out.
			log.Warn("a stored key in this listing is not one this keyring produced",
				"err", err)
			continue
		}
		entry.Key = plain
		kept = append(kept, entry)
	}
	result.Contents = kept

	prefixes := make([]upstream.CommonPrefix, 0, len(result.CommonPrefixes))
	for _, cp := range result.CommonPrefixes {
		plain, err := p.names.DecryptKey(strings.TrimSuffix(cp.Prefix, "/"))
		if err != nil {
			log.Warn("a common prefix in this listing is not one this keyring produced",
				"err", err)
			continue
		}
		prefixes = append(prefixes, upstream.CommonPrefix{Prefix: plain + "/"})
	}
	result.CommonPrefixes = prefixes

	// The point of the exercise. Encrypted names sort differently from plaintext
	// ones, and a listing that reaches a client out of order makes `aws s3 sync
	// --delete` delete objects that exist -- measured in ADR-017.
	slices.SortFunc(result.Contents, func(a, b upstream.ObjectEntry) int {
		return strings.Compare(a.Key, b.Key)
	})
	slices.SortFunc(result.CommonPrefixes, func(a, b upstream.CommonPrefix) int {
		return strings.Compare(a.Prefix, b.Prefix)
	})

	// The provider echoed the encrypted prefix back; the client asked with its
	// own and must see its own.
	result.Prefix = query.Get("prefix")
	return nil
}
