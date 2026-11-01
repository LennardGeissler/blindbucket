// Package census counts, for each bucket of a tenant, the objects that are not
// wrapped under the tenant's keys: those a destruction of the tenant would
// leave readable (ADR-038, the first step of a destruction).
//
// It counts every version the provider keeps, not only current objects: in a
// versioned bucket, a version written under the default tenant's keys before
// the tenant was active survives being replaced, and a destruction (#218).
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
	Missing bool
	// Versioned says the provider listed the bucket's versions. A provider
	// that does not implement listing them (Garage v2.4.1 answers 501) keeps
	// no earlier versions either, and the bucket is listed as objects.
	Versioned bool
	// Scanned counts every version read, current or not, and Noncurrent the
	// versions among them that are not current.
	Scanned    int64
	Noncurrent int64
	OnTenant   int64
	// OffTenant counts current objects not under the tenant's keys, which
	// rotate can move, and NoncurrentOff earlier versions, which it cannot:
	// they go by deleting them, or by a lifecycle rule.
	OffTenant     int64
	NoncurrentOff int64
	// Foreign counts objects the gateway did not write. They carry no key
	// and are not encrypted, so destroying the tenant changes nothing for
	// them either way.
	Foreign int64
	// Failed counts objects whose metadata could not be read: nothing is
	// known about them, so a census with any is incomplete.
	Failed int64

	mu sync.Mutex
	// OffKIDs counts the current objects off the tenant by the key they are
	// under, and NoncurrentKIDs the earlier versions.
	OffKIDs        map[string]int64
	NoncurrentKIDs map[string]int64
}

// Result is a census.
type Result struct {
	Buckets []*Bucket
}

// OffTenant is how many objects in all the tenant's buckets are not under its
// keys.
func (r *Result) OffTenant() int64 { return r.sum(func(b *Bucket) int64 { return b.OffTenant }) }

// NoncurrentOff is how many earlier versions in all the tenant's buckets are
// not under its keys.
func (r *Result) NoncurrentOff() int64 {
	return r.sum(func(b *Bucket) int64 { return b.NoncurrentOff })
}

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
		b := &Bucket{Name: name, OffKIDs: map[string]int64{}, NoncurrentKIDs: map[string]int64{}}
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

// version is one object version to read: a current object when versionID is
// empty or the version is the latest.
type version struct {
	key, versionID string
	latest         bool
}

// count reads the metadata of every version in one bucket, or of every object
// where the provider does not list versions.
func count(ctx context.Context, cfg Config, b *Bucket) error {
	work := make(chan version)
	var wg sync.WaitGroup
	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := range work {
				one(ctx, cfg, b, v)
			}
		}()
	}
	send := func(v version) error {
		// Manifests and tag sidecars belong to their objects and carry no
		// key of their own; the probe's object is not a client's.
		if strings.HasPrefix(v.key, s3api.ReservedPrefix) {
			return nil
		}
		select {
		case work <- v:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	err := listVersions(ctx, cfg, b, send)
	if ae, ok := upstream.AsAPIError(err); ok && ae.Code == "NotImplemented" {
		err = listObjects(ctx, cfg, b, send)
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

// listVersions hands on every version in the bucket. Delete markers have no
// content and no key, and are skipped. It returns the provider's error for
// the first page unchanged, so that NotImplemented can be told apart.
func listVersions(ctx context.Context, cfg Config, b *Bucket, send func(version) error) error {
	query := url.Values{"max-keys": {"1000"}}
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	for {
		page, err := cfg.Upstream.ListObjectVersions(ctx, b.Name, query)
		if err != nil {
			return err
		}
		b.Versioned = true
		for _, v := range page.Versions {
			if err := send(version{key: v.Key, versionID: v.VersionID, latest: v.IsLatest}); err != nil {
				return err
			}
		}
		if !page.IsTruncated || page.NextKeyMarker == "" && page.NextVersionIDMarker == "" {
			return nil
		}
		query.Set("key-marker", page.NextKeyMarker)
		query.Set("version-id-marker", page.NextVersionIDMarker)
	}
}

// listObjects hands on every current object, for a provider that does not
// list versions.
func listObjects(ctx context.Context, cfg Config, b *Bucket, send func(version) error) error {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	for {
		page, err := cfg.Upstream.ListObjects(ctx, b.Name, query)
		if err != nil {
			return err
		}
		for _, entry := range page.Contents {
			if err := send(version{key: entry.Key, latest: true}); err != nil {
				return err
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}

func one(ctx context.Context, cfg Config, b *Bucket, v version) {
	atomic.AddInt64(&b.Scanned, 1)
	if !v.latest {
		atomic.AddInt64(&b.Noncurrent, 1)
	}
	var (
		info *upstream.ObjectInfo
		err  error
	)
	if v.versionID == "" || v.versionID == "null" {
		info, err = cfg.Upstream.HeadObject(ctx, b.Name, v.key)
	} else {
		info, err = cfg.Upstream.HeadObjectVersion(ctx, b.Name, v.key, v.versionID)
	}
	if upstream.NotFound(err) {
		// Deleted since the listing: nothing left to strand.
		atomic.AddInt64(&b.Scanned, -1)
		if !v.latest {
			atomic.AddInt64(&b.Noncurrent, -1)
		}
		return
	}
	if err != nil {
		cfg.Log.Warn("could not read the object", "bucket", b.Name, "key", v.key, "version", v.versionID, "err", err)
		atomic.AddInt64(&b.Failed, 1)
		return
	}
	meta, err := objectmeta.Parse(info.Metadata, cfg.Log2ChunkSize)
	switch {
	case errors.Is(err, objectmeta.ErrNotEncrypted):
		atomic.AddInt64(&b.Foreign, 1)
	case err != nil:
		cfg.Log.Warn("object metadata is unusable", "bucket", b.Name, "key", v.key, "version", v.versionID, "err", err)
		atomic.AddInt64(&b.Failed, 1)
	case slices.Contains(cfg.KIDs, meta.KeyID):
		atomic.AddInt64(&b.OnTenant, 1)
	case v.latest:
		atomic.AddInt64(&b.OffTenant, 1)
		b.mu.Lock()
		b.OffKIDs[meta.KeyID]++
		b.mu.Unlock()
	default:
		atomic.AddInt64(&b.NoncurrentOff, 1)
		b.mu.Lock()
		b.NoncurrentKIDs[meta.KeyID]++
		b.mu.Unlock()
	}
}
