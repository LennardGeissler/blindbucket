// Package census counts, for each bucket of a tenant, the objects that are not
// wrapped under the tenant's keys: those a destruction of the tenant would
// leave readable (ADR-038, the first step of a destruction).
//
// It reads each object's metadata and decrypts nothing, so it needs no key,
// the tenant's lock included. The key id it reads is the one every read of the
// object goes by.
package census

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Config is one census.
type Config struct {
	Upstream *upstream.Client
	// Entries are the tenant's bucket entries: bucket names, or prefixes of
	// them ending in '*', as the keyring's directory records them.
	Entries []string
	// KIDs are the tenant's key ids. An object under any other is counted off
	// the tenant.
	KIDs []string
	// Prefix restricts the count to object keys under it, as stored. A
	// destruction's census counts whole buckets and leaves it empty; it exists
	// for tests that share a bucket.
	Prefix string
	// Log2ChunkSize is the fallback for metadata that records none.
	Log2ChunkSize uint8

	Concurrency int
	Log         *slog.Logger
}

// Bucket is what one bucket held.
type Bucket struct {
	Name string
	// Missing is a bucket named exactly by an entry that does not exist at
	// the provider. It holds nothing, so it strands nothing.
	Missing   bool
	Scanned   int64
	OnTenant  int64
	OffTenant int64
	// Foreign counts objects the gateway did not write. They carry no key
	// and are not encrypted, so destroying the tenant changes nothing for
	// them either way.
	Foreign int64
	// Failed counts objects whose metadata could not be read: nothing is
	// known about them, so a census with any is incomplete.
	Failed int64

	mu sync.Mutex
	// OffKIDs counts the objects off the tenant by the key they are under.
	OffKIDs map[string]int64
}

// Result is a census.
type Result struct {
	Buckets []*Bucket
}

// OffTenant is how many objects in all the tenant's buckets are not under its
// keys.
func (r *Result) OffTenant() int64 { return r.sum(func(b *Bucket) int64 { return b.OffTenant }) }

// Failed is how many objects could not be counted.
func (r *Result) Failed() int64 { return r.sum(func(b *Bucket) int64 { return b.Failed }) }

func (r *Result) sum(f func(*Bucket) int64) int64 {
	var n int64
	for _, b := range r.Buckets {
		n += f(b)
	}
	return n
}

// Run takes the census.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("census: an upstream client is required")
	case len(cfg.KIDs) == 0:
		return nil, errors.New("census: the tenant's key ids are required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	names, err := buckets(ctx, cfg)
	if err != nil {
		return nil, err
	}
	result := &Result{}
	for _, name := range names {
		b := &Bucket{Name: name, OffKIDs: map[string]int64{}}
		result.Buckets = append(result.Buckets, b)
		if err := count(ctx, cfg, b); err != nil {
			return result, err
		}
	}
	return result, nil
}

// buckets resolves the entries to the buckets they name: an exact name as it
// is, a prefix by the provider's list of buckets.
func buckets(ctx context.Context, cfg Config) ([]string, error) {
	var out, prefixes []string
	for _, e := range cfg.Entries {
		if p, ok := strings.CutSuffix(e, "*"); ok {
			prefixes = append(prefixes, p)
		} else {
			out = append(out, e)
		}
	}
	if len(prefixes) > 0 {
		all, err := listBuckets(ctx, cfg.Upstream)
		if err != nil {
			return nil, err
		}
		out = append(out, Matching(all, prefixes)...)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Matching returns the buckets that start with any of prefixes.
func Matching(buckets, prefixes []string) []string {
	var out []string
	for _, b := range buckets {
		for _, p := range prefixes {
			if strings.HasPrefix(b, p) {
				out = append(out, b)
				break
			}
		}
	}
	return out
}

type listAllMyBuckets struct {
	Buckets []struct {
		Name string `xml:"Name"`
	} `xml:"Buckets>Bucket"`
}

func listBuckets(ctx context.Context, up *upstream.Client) ([]string, error) {
	resp, err := up.Passthrough(ctx, http.MethodGet, "", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("census: listing buckets: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("census: listing buckets: the provider answered %d", resp.StatusCode)
	}
	var list listAllMyBuckets
	if err := xml.Unmarshal(resp.Body, &list); err != nil {
		return nil, fmt.Errorf("census: the provider's list of buckets is not valid XML: %w", err)
	}
	out := make([]string, 0, len(list.Buckets))
	for _, b := range list.Buckets {
		out = append(out, b.Name)
	}
	return out, nil
}

// count reads the metadata of every object in one bucket.
func count(ctx context.Context, cfg Config, b *Bucket) error {
	work := make(chan string)
	var wg sync.WaitGroup
	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range work {
				one(ctx, cfg, b, key)
			}
		}()
	}

	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	var err error
list:
	for {
		var page *upstream.ListBucketResult
		page, err = cfg.Upstream.ListObjects(ctx, b.Name, query)
		if err != nil {
			break
		}
		for _, entry := range page.Contents {
			// Manifests and tag sidecars belong to their objects and carry
			// no key of their own; the probe's object is not a client's.
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			select {
			case work <- entry.Key:
			case <-ctx.Done():
				err = ctx.Err()
				break list
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
	close(work)
	wg.Wait()

	if ae, ok := upstream.AsAPIError(err); ok && ae.Code == "NoSuchBucket" {
		b.Missing = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("census: listing %s: %w", b.Name, err)
	}
	return nil
}

func one(ctx context.Context, cfg Config, b *Bucket, key string) {
	atomic.AddInt64(&b.Scanned, 1)
	info, err := cfg.Upstream.HeadObject(ctx, b.Name, key)
	if upstream.NotFound(err) {
		// Deleted since the listing: nothing left to strand.
		atomic.AddInt64(&b.Scanned, -1)
		return
	}
	if err != nil {
		cfg.Log.Warn("could not read the object", "bucket", b.Name, "key", key, "err", err)
		atomic.AddInt64(&b.Failed, 1)
		return
	}
	meta, err := objectmeta.Parse(info.Metadata, cfg.Log2ChunkSize)
	switch {
	case errors.Is(err, objectmeta.ErrNotEncrypted):
		atomic.AddInt64(&b.Foreign, 1)
	case err != nil:
		cfg.Log.Warn("object metadata is unusable", "bucket", b.Name, "key", key, "err", err)
		atomic.AddInt64(&b.Failed, 1)
	case slices.Contains(cfg.KIDs, meta.KeyID):
		atomic.AddInt64(&b.OnTenant, 1)
	default:
		atomic.AddInt64(&b.OffTenant, 1)
		b.mu.Lock()
		b.OffKIDs[meta.KeyID]++
		b.mu.Unlock()
	}
}
