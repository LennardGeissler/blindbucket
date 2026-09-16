package proxy

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Serving a listing whose prefix does not fit in one upstream page.
//
// The provider orders by the stored key, so a page of an encrypted listing is
// only in the client's order once the *whole* prefix has been read and sorted.
// ADR-017 measured what that costs -- 213 bytes per object, and a first page
// that waits on every upstream round trip -- and settled on a bound with a
// refusal past it.
//
// # Why this needs no server state to be correct
//
// ADR-017 expected a cache keyed by continuation token, and called that the
// gateway's first server-side state, against ADR-006 having gone to the trouble
// of a sealed upload token to avoid exactly that.
//
// It turned out not to be needed. S3's own pagination parameters are already
// "resume after this key": v1's marker and v2's start-after are plaintext keys,
// and v2's continuation-token is opaque but minted by this gateway, so it can
// carry the same thing. The entire resume state of an encrypted listing is
// therefore one string -- the last key already served -- which the client holds
// and hands back.
//
// So any instance can answer any page: buffer the prefix, sort, skip past the
// cursor, serve. The cache below is an optimisation and nothing else. A miss
// costs a re-read of the prefix and returns exactly the same answer, which is
// what separates it from the upload token, where a miss would lose an upload.
type listingCache struct {
	mu      sync.Mutex
	entries map[string]*listingEntry
	ttl     time.Duration
	max     int
}

type listingEntry struct {
	rows []listingRow
	born time.Time
}

// listingRow is one line of a listing: either an object or a common prefix.
//
// They are held in one sorted slice because S3 pages over both together -- a
// page is the next n lines in key order, whichever kind they are -- and
// splitting them only at the end is what keeps that true.
type listingRow struct {
	key    string
	object *upstream.ObjectEntry
}

func newListingCache(ttl time.Duration, capacity int) *listingCache {
	return &listingCache{entries: make(map[string]*listingEntry), ttl: ttl, max: capacity}
}

func (c *listingCache) key(bucket, prefix, delimiter string) string {
	return bucket + "\x00" + prefix + "\x00" + delimiter
}

func (c *listingCache) get(bucket, prefix, delimiter string) ([]listingRow, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[c.key(bucket, prefix, delimiter)]
	if !ok {
		return nil, false
	}
	if time.Since(entry.born) > c.ttl {
		delete(c.entries, c.key(bucket, prefix, delimiter))
		return nil, false
	}
	return entry.rows, true
}

func (c *listingCache) put(bucket, prefix, delimiter string, rows []listingRow) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Evict expired first, then the oldest, rather than growing without bound.
	// The cap is on entries because each is already bounded by the key limit.
	if len(c.entries) >= c.max {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.entries {
			if time.Since(e.born) > c.ttl {
				delete(c.entries, k)
				continue
			}
			if oldestKey == "" || e.born.Before(oldest) {
				oldestKey, oldest = k, e.born
			}
		}
		if len(c.entries) >= c.max && oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[c.key(bucket, prefix, delimiter)] = &listingEntry{rows: rows, born: time.Now()}
}

// encodeCursor renders a resume point as a continuation token.
//
// Deliberately not sealed, unlike the upload token of ADR-006. That one carries
// a wrapped data key and a manifest id -- secrets, and state whose forgery would
// matter. This carries one object key the client has just been shown, and
// forging it buys nothing a client could not get by asking for that prefix
// directly. Sealing it would be ceremony, and ceremony in a security-facing
// codebase is worse than nothing because it suggests a guarantee that is not
// there.
func encodeCursor(after string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(after))
}

func decodeCursor(token string) (string, *s3api.Error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return "", s3api.ErrInvalidArgument.WithMessage(
			"the continuation token is not one this gateway issued")
	}
	return string(raw), nil
}

// bufferPrefix reads a whole prefix, decrypts every name and sorts by plaintext.
//
// It pages upstream at the provider's maximum rather than the client's, because
// the number of round trips is what the client waits on and the client's page
// size has nothing to do with it.
func (p *Proxy) bufferPrefix(
	ctx context.Context, bucket, storedPrefix, delimiter string, log *slog.Logger,
) ([]listingRow, *s3api.Error) {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if storedPrefix != "" {
		query.Set("prefix", storedPrefix)
	}
	if delimiter != "" {
		query.Set("delimiter", delimiter)
	}

	rows := make([]listingRow, 0, 1024)
	for {
		page, err := p.upstream.ListObjects(ctx, bucket, query)
		if err != nil {
			return nil, translateUpstream(err)
		}
		for _, entry := range page.Contents {
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			plain, decErr := p.names.DecryptKey(entry.Key)
			if decErr != nil {
				log.Warn("a stored key in this listing is not one this keyring produced",
					"err", decErr)
				continue
			}
			entry.Key = plain
			rows = append(rows, listingRow{key: plain, object: &entry})
		}
		for _, cp := range page.CommonPrefixes {
			plain, decErr := p.names.DecryptKey(strings.TrimSuffix(cp.Prefix, "/"))
			if decErr != nil {
				log.Warn("a common prefix in this listing is not one this keyring produced",
					"err", decErr)
				continue
			}
			rows = append(rows, listingRow{key: plain + "/"})
		}

		if len(rows) > p.maxListingKeys {
			return nil, s3api.ErrNotImplemented.WithMessage(
				"this prefix holds more than %d keys, which is the most this gateway "+
					"will sort at once. With object-name encryption on the provider "+
					"orders by the encrypted key, so a listing can only be served in "+
					"the client's order once the whole prefix has been read -- and past "+
					"this bound the client waits longer than it is willing to. Narrow "+
					"the prefix, or raise names.max_listing_keys (ADR-017)",
				p.maxListingKeys)
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}

	slices.SortFunc(rows, func(a, b listingRow) int { return strings.Compare(a.key, b.key) })
	return rows, nil
}

// servePage cuts one page out of a sorted prefix and fills in the pagination
// fields the client's listing version expects.
func servePage(
	result *upstream.ListBucketResult, rows []listingRow, after string, maxKeys int, v2 bool,
) {
	start := 0
	if after != "" {
		start, _ = slices.BinarySearchFunc(rows, after, func(r listingRow, target string) int {
			return strings.Compare(r.key, target)
		})
		// BinarySearch lands on the cursor itself when it is still present, and
		// the cursor names a key already served.
		if start < len(rows) && rows[start].key == after {
			start++
		}
	}

	end := min(start+maxKeys, len(rows))
	page := rows[start:end]

	contents := make([]upstream.ObjectEntry, 0, len(page))
	prefixes := make([]upstream.CommonPrefix, 0)
	for _, row := range page {
		if row.object != nil {
			contents = append(contents, *row.object)
			continue
		}
		prefixes = append(prefixes, upstream.CommonPrefix{Prefix: row.key})
	}
	result.Contents = contents
	result.CommonPrefixes = prefixes
	result.MaxKeys = maxKeys
	result.IsTruncated = end < len(rows)

	if !result.IsTruncated {
		result.NextContinuationToken = ""
		result.NextMarker = ""
		return
	}
	last := page[len(page)-1].key
	if v2 {
		result.NextContinuationToken = encodeCursor(last)
		return
	}
	// v1 has no opaque token: NextMarker is a key, and the client sends it back
	// as marker. It is the same resume point spelled the way v1 spells it.
	result.NextMarker = last
}

// listingMaxKeys reads the client's page size, with S3's own default and cap.
func listingMaxKeys(query url.Values) (int, *s3api.Error) {
	raw := query.Get("max-keys")
	if raw == "" {
		return 1000, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, s3api.ErrInvalidArgument.WithMessage("max-keys is not a number")
	}
	return min(n, 1000), nil
}

const (
	// defaultMaxListingKeys comes from ADR-017's latency table: 100 000 keys is
	// roughly 2.3 seconds to the first page against a same-region provider,
	// which is about as long as a client will wait. A memory budget would have
	// allowed ten times that, at which point the client has given up.
	defaultMaxListingKeys = 100_000

	// defaultMaxConcurrentListings keeps the worst case in hand: the bound above
	// holds about 20 MiB, so eight at once is about 170 MiB.
	defaultMaxConcurrentListings = 8

	// listingCacheTTL covers one client walking one prefix, and nothing beyond
	// that. The cache is consulted only for a continuation (see sortedPrefix),
	// so this is how long a paused walk may resume from its own snapshot before
	// it starts again from the provider.
	listingCacheTTL = 60 * time.Second
)

// s3ListXmlns is the namespace S3 puts on a listing. A forwarded listing carries
// the provider's own; one built here has to state it, because some clients check.
const s3ListXmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
