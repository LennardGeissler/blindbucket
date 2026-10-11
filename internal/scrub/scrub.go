// Package scrub verifies every stored object under a prefix without waiting for
// a client to read it.
//
// It exists because the gateway authenticates an object only when it serves
// one. A chunk the provider altered, a part it dropped or a manifest that went
// missing otherwise surfaces at the read that needed the data. A scrub reads
// each object in full through internal/verify -- the checks a GET performs, not
// a copy of them -- discards the plaintext, and reports what failed. It writes
// nothing (ADR-028).
package scrub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/LennardGeissler/blindbucket/internal/verify"
)

// Config is one scrub run.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	Bucket   string
	// Prefix is the client's, as for a listing through the gateway; with name
	// encryption on it is mapped before it goes upstream.
	Prefix string
	// Log2ChunkSize is the fallback for objects whose metadata does not record
	// one, as the gateway's own configuration supplies it.
	Log2ChunkSize uint8
	// Names is the gateway's name encrypter, nil when names are stored in the
	// clear. A scrub needs it for the same reason a rotation does: it finds
	// objects by their stored names, and their data keys are bound to the names
	// clients use.
	Names *names.Encrypter

	Concurrency int
	Log         *slog.Logger

	// Hook, when set, is called after an object's first verification and before
	// any recheck. It exists so that an integration test can replace an object,
	// or stop the run, at exactly that point; it is nil everywhere else.
	Hook func(key string)
}

// errKeptChanging is an object that failed twice, in two versions, and had
// moved on again by the time the second failure was checked. Nothing settled
// long enough to be judged, so it is unreadable rather than a finding.
var errKeptChanging = errors.New("scrub: the object changed during each of two verifications")

// Finding is an object that failed verification.
type Finding struct {
	// Key is the object's name as a client uses it.
	Key  string
	Kind verify.Kind
	// Detail is the failed check and what it found, for a person.
	Detail string
}

// Unreadable is an object nothing could be established about: the provider
// did not deliver it, or it kept changing while it was checked. It is not a
// finding, and it is not benign either -- a provider that sends less than it
// announces turns a damaged object into one of these -- so it is named, not
// only counted.
type Unreadable struct {
	Key    string
	Detail string
}

// Result reports what a run found.
type Result struct {
	Scanned  int64
	Verified int64
	// Failed counts objects that did not verify. Each one is in Findings.
	Failed int64
	// Foreign counts objects the gateway did not write: no bb-* metadata, or,
	// with name encryption on, a stored name this keyring does not produce.
	Foreign int64
	// Vanished counts objects deleted between the listing and the read.
	Vanished int64
	// Errors counts objects that could not be read at all. Nothing is known
	// about them, so a run with any is incomplete. Each one is in Unreadable.
	Errors int64
	// CipherBytes is the ciphertext read and verified, manifests excluded.
	CipherBytes int64

	mu         sync.Mutex
	Findings   []Finding
	Unreadable []Unreadable
}

// Incomplete reports whether the run leaves anything unverified or broken.
func (r *Result) Incomplete() bool { return r.Failed > 0 || r.Errors > 0 }

func (r *Result) add(f Finding) {
	atomic.AddInt64(&r.Failed, 1)
	r.mu.Lock()
	r.Findings = append(r.Findings, f)
	r.mu.Unlock()
}

func (r *Result) unreadable(u Unreadable) {
	atomic.AddInt64(&r.Errors, 1)
	r.mu.Lock()
	r.Unreadable = append(r.Unreadable, u)
	r.mu.Unlock()
}

// Run verifies every object under the configured prefix.
//
// The error is about the run, not about objects: a listing that failed, or a
// run that was interrupted. What the objects turned out to be is in the Result,
// which is returned with whatever had been counted either way.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("scrub: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("scrub: a key provider is required")
	case cfg.Bucket == "":
		return nil, errors.New("scrub: a bucket is required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.Log2ChunkSize == 0 {
		cfg.Log2ChunkSize = stream.DefaultLog2ChunkSize
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	result := &Result{}
	targets := make(chan verify.Target)
	var wg sync.WaitGroup
	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				scrubOne(ctx, cfg, t, result)
			}
		}()
	}

	err := eachObject(ctx, cfg, result, func(t verify.Target) bool {
		select {
		case targets <- t:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(targets)
	wg.Wait()
	// The listing can finish handing out keys before the last of them are
	// verified, so an interrupt during those reaches no one but the workers.
	// It is still an interrupt, and the run did not finish.
	if err == nil {
		err = ctx.Err()
	}

	// In key order, so that two runs over the same bucket print the same list.
	slices.SortFunc(result.Findings, func(a, b Finding) int { return strings.Compare(a.Key, b.Key) })
	slices.SortFunc(result.Unreadable, func(a, b Unreadable) int { return strings.Compare(a.Key, b.Key) })
	return result, err
}

// scrubOne verifies one object, and confirms a failure before reporting it.
//
// A failure may be the object changing under the read rather than the object
// being broken: an overwrite between reading a multipart object and reading
// its manifest deletes the manifest the read started with (rule R3), and the
// read then finds it missing. So a failure becomes a finding only when a HEAD
// shows the object still at the version that failed. A replaced object is
// verified once more in its new version, and a second failure is confirmed the
// same way; one that moved on again, or a HEAD that fails, leaves the object
// unreadable rather than judged.
func scrubOne(ctx context.Context, cfg Config, t verify.Target, result *Result) {
	atomic.AddInt64(&result.Scanned, 1)
	log := cfg.Log.With("key", t.Identity)

	res, err := verify.Object(ctx, cfg.Upstream, cfg.Keys, t, cfg.Log2ChunkSize)
	if cfg.Hook != nil {
		cfg.Hook(t.Identity)
	}
	for attempt := 1; ; attempt++ {
		if _, isFailure := verify.AsFailure(err); !isFailure {
			break
		}
		info, headErr := cfg.Upstream.HeadObject(ctx, t.Bucket, t.Stored)
		if headErr != nil {
			if upstream.NotFound(headErr) {
				atomic.AddInt64(&result.Vanished, 1)
				log.Debug("deleted while it was being verified")
				return
			}
			err = fmt.Errorf("the object failed verification, and the HEAD that would "+
				"confirm it is still that version failed: %w", headErr)
			break
		}
		if info.ETag == res.ETag {
			break // confirmed: the version that failed is the one stored
		}
		if attempt == 2 {
			err = errKeptChanging
			break
		}
		log.Debug("replaced while it was being verified; verifying the new version")
		res, err = verify.Object(ctx, cfg.Upstream, cfg.Keys, t, cfg.Log2ChunkSize)
	}
	record(log, t, res, err, result)
}

// record counts one object's outcome.
func record(log *slog.Logger, t verify.Target, res verify.Result, err error, result *Result) {
	if err == nil {
		atomic.AddInt64(&result.Verified, 1)
		atomic.AddInt64(&result.CipherBytes, res.CipherBytes)
		log.Debug("verified", "kid", res.KeyID, "parts", res.Parts, "plaintext_bytes", res.PlainBytes)
		return
	}
	if f, isFailure := verify.AsFailure(err); isFailure {
		result.add(Finding{Key: t.Identity, Kind: f.Kind, Detail: f.Error()})
		log.Error("object failed verification", "kind", f.Kind, "err", f)
		return
	}
	switch {
	case errors.Is(err, objectmeta.ErrNotEncrypted):
		atomic.AddInt64(&result.Foreign, 1)
		log.Debug("not written by the gateway")
	case upstream.NotFound(err):
		atomic.AddInt64(&result.Vanished, 1)
		log.Debug("deleted before it could be read")
	default:
		result.unreadable(Unreadable{Key: t.Identity, Detail: err.Error()})
		log.Error("object could not be read", "err", err)
	}
}

// eachObject walks the prefix, skipping the gateway's own objects.
//
// It lists the provider, so every key it sees is a stored one; with name
// encryption on, each is mapped back to the name its data key is bound to. A
// stored name this keyring does not produce is counted as foreign.
func eachObject(ctx context.Context, cfg Config, result *Result, visit func(verify.Target) bool) error {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		prefix := cfg.Prefix
		if cfg.Names != nil {
			stored, whole, err := cfg.Names.EncryptPrefix(prefix)
			if err != nil {
				return fmt.Errorf("scrub: mapping the prefix: %w", err)
			}
			if !whole {
				return fmt.Errorf("scrub: prefix %q does not end on a '/' boundary, "+
					"and with object-name encryption on it must: encryption is per path "+
					"segment, so a partial segment has no encrypted form to match against",
					prefix)
			}
			prefix = stored
		}
		if prefix != "" {
			query.Set("prefix", prefix)
		}
	}
	for {
		page, err := cfg.Upstream.ListObjects(ctx, cfg.Bucket, query)
		if err != nil {
			return fmt.Errorf("scrub: listing %s: %w", cfg.Bucket, err)
		}
		for _, entry := range page.Contents {
			// Manifests are verified with the object they belong to: on their
			// own they say nothing, and an orphaned one is gc's concern.
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			t := verify.Target{Bucket: cfg.Bucket, Identity: entry.Key, Stored: entry.Key}
			if cfg.Names != nil {
				plain, err := cfg.Names.DecryptKey(entry.Key)
				if err != nil {
					atomic.AddInt64(&result.Scanned, 1)
					atomic.AddInt64(&result.Foreign, 1)
					cfg.Log.Debug("skipping a stored key this keyring did not produce", "err", err)
					continue
				}
				t.Identity = plain
			}
			if !visit(t) {
				return ctx.Err()
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}
