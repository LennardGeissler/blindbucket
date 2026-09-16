// Package rotate re-wraps the data keys of stored objects under a new KEK.
//
// What moves is metadata. An object's data key stays the same; only the key that
// wraps it changes, so the ciphertext never leaves the provider and a terabyte
// rotates as cheaply as a megabyte. That is also the honest limit of what
// rotation buys: it protects against a compromised or expiring KEK, not against
// a compromised DEK. See docs/adr/ADR-009-rotation-by-copy.md.
//
// The hard part is not the re-wrapping, it is doing it while clients are
// writing. Rotation reads an object and writes it back some time later, and in
// between a client may have replaced it. Writing back unconditionally would
// discard that write -- invariant I2, "rotation causes no lost update", which
// spec/tla/Multipart.tla produces a six-state counterexample for when the
// conditional write is removed. So the final write carries If-Match with the
// ETag seen at the start, and a 412 means the object changed and is skipped.
package rotate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objcopy"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Config describes one rotation run.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	Bucket   string
	// Prefix restricts the run to object keys under it.
	Prefix string
	// TargetKID is the KEK to wrap under. Objects already on it are skipped,
	// which is what makes a run idempotent and resumable after an interruption.
	TargetKID string
	// Log2ChunkSize is the fallback for objects whose metadata records none.
	Log2ChunkSize uint8

	// Names maps between the key a client uses and the key the provider stores
	// it under (ADR-015). Nil means names are in clear and the two are equal.
	//
	// A rotation needs both. It finds its work by listing the *provider*, so
	// every key it sees is a stored one; but the data key it re-wraps is bound
	// to the key the *client* names, so rotating with the stored key as
	// associated data produces an object no read can open. The unwrap of the old
	// key fails first and nothing is written, so the failure is loud rather than
	// silent -- but it is still a rotation that cannot run.
	Names *names.Encrypter

	Concurrency int
	DryRun      bool
	// AllowUnconditional drops the If-Match on the final write.
	//
	// It exists for providers that do not implement conditional writes, and it
	// gives up invariant I2: a client write that lands mid-rotation is silently
	// replaced by the pre-rotation version. Callers must not set it without the
	// operator having said so, and must not run it while anything writes to the
	// prefix.
	AllowUnconditional bool

	Log *slog.Logger

	// Hook is called at the steps of the Rot process in spec/tla/Multipart.tla,
	// named as the model names them. It exists so that an integration test can
	// hold a rotation open and replay the I2 counterexample; it is nil
	// everywhere else.
	Hook func(point, key string)
}

// Step names of the rotation, matching the model's actions.
const (
	HookHead     = "rotHead"     // after the object and its etag are read
	HookCreate   = "rotCreate"   // after the upload is opened
	HookManifest = "rotManifest" // after the new manifest is written
	HookComplete = "rotComplete" // after the conditional write lands
)

func (c Config) at(point, key string) {
	if c.Hook != nil {
		c.Hook(point, key)
	}
}

// Result reports what a run did.
type Result struct {
	Scanned int64
	Rotated int64
	// AlreadyCurrent counts objects already wrapped under the target KEK.
	AlreadyCurrent int64
	// Conflicted counts objects a client wrote during the rotation. They keep
	// the client's version and the old KEK, and a later run picks them up.
	Conflicted int64
	// Foreign counts objects this gateway did not write.
	Foreign int64
	Failed  int64
}

// Run rotates every object under the configured prefix.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("rotate: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("rotate: a key provider is required")
	case cfg.Bucket == "":
		return nil, errors.New("rotate: a bucket is required")
	}
	if err := keys.ValidateKID(cfg.TargetKID); err != nil {
		return nil, fmt.Errorf("rotate: target key id: %w", err)
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Log2ChunkSize == 0 {
		cfg.Log2ChunkSize = stream.DefaultLog2ChunkSize
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	result := &Result{}
	keysCh := make(chan objectKeys)
	var wg sync.WaitGroup

	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range keysCh {
				rotateOne(ctx, cfg, key, result)
			}
		}()
	}

	err := eachObject(ctx, cfg, func(key objectKeys) bool {
		select {
		case keysCh <- key:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(keysCh)
	wg.Wait()
	return result, err
}

// objectKeys is one object's two names: the key a client uses, which is its
// identity, and the key the provider keeps it under, which is its address. They
// are the same string unless object-name encryption is on.
type objectKeys struct {
	identity string
	stored   string
}

// eachObject walks the prefix, skipping the gateway's own objects.
//
// The prefix is the client's, so it is mapped before it goes upstream, the same
// way a listing through the gateway maps one.
func eachObject(ctx context.Context, cfg Config, visit func(objectKeys) bool) error {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		prefix := cfg.Prefix
		if cfg.Names != nil {
			stored, whole, err := cfg.Names.EncryptPrefix(prefix)
			if err != nil {
				return fmt.Errorf("rotate: mapping the prefix: %w", err)
			}
			if !whole {
				return fmt.Errorf("rotate: prefix %q does not end on a '/' boundary, "+
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
			return fmt.Errorf("rotate: listing %s: %w", cfg.Bucket, err)
		}
		for _, entry := range page.Contents {
			// Manifests are rotated with the object they belong to, never on
			// their own: they carry no wrapped key of their own.
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			key := objectKeys{identity: entry.Key, stored: entry.Key}
			if cfg.Names != nil {
				plain, err := cfg.Names.DecryptKey(entry.Key)
				if err != nil {
					// Something in the bucket this keyring did not write. It has
					// no wrapped key to rotate either way.
					cfg.Log.Warn("skipping a stored key this keyring did not produce",
						"err", err)
					continue
				}
				key.identity = plain
			}
			if !visit(key) {
				return ctx.Err()
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}

// rotateOne re-wraps one object's data key.
func rotateOne(ctx context.Context, cfg Config, key objectKeys, result *Result) {
	atomic.AddInt64(&result.Scanned, 1)
	// The identity in the log: it is the name an operator recognises, and the
	// gateway host is inside the trust boundary that already sees it.
	log := cfg.Log.With("key", key.identity)

	info, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, key.stored)
	if err != nil {
		log.Warn("could not read the object", "err", err)
		atomic.AddInt64(&result.Failed, 1)
		return
	}

	meta, err := objectmeta.Parse(info.Metadata, cfg.Log2ChunkSize)
	if errors.Is(err, objectmeta.ErrNotEncrypted) {
		// A bucket may hold objects this gateway never wrote. They have no
		// wrapped key, so there is nothing to rotate and nothing to complain
		// about.
		atomic.AddInt64(&result.Foreign, 1)
		return
	}
	if err != nil {
		log.Warn("object metadata is unusable", "err", err)
		atomic.AddInt64(&result.Failed, 1)
		return
	}

	// Idempotence: a run that is interrupted and started again does the
	// remaining work and nothing else.
	if meta.KeyID == cfg.TargetKID {
		atomic.AddInt64(&result.AlreadyCurrent, 1)
		return
	}

	cfg.at(HookHead, key.identity)

	if cfg.DryRun {
		log.Info("would rotate", "from", meta.KeyID, "to", cfg.TargetKID)
		atomic.AddInt64(&result.Rotated, 1)
		return
	}

	switch err := writeBack(ctx, cfg, key, info, meta); {
	case err == nil:
		log.Debug("rotated", "from", meta.KeyID, "to", cfg.TargetKID)
		atomic.AddInt64(&result.Rotated, 1)
	case errors.Is(err, errChangedUnderUs):
		// A client wrote while the rotation was in flight. Its version stands;
		// this is invariant I2 holding, not a failure.
		log.Info("skipped: a client wrote during the rotation")
		atomic.AddInt64(&result.Conflicted, 1)
	default:
		log.Warn("could not write the rotated object back", "err", err)
		atomic.AddInt64(&result.Failed, 1)
	}
}

// errChangedUnderUs reports that the object was replaced mid-rotation.
var errChangedUnderUs = objcopy.ErrPreconditionFailed

// writeBack republishes the object with its new metadata.
//
// The work itself is objcopy's: re-wrap the data key, copy the segments inside
// the provider, keep the manifest lifecycle rules. Rotation is the case where
// the destination is the source, which is what makes the two conditions below
// both about the same object.
func writeBack(ctx context.Context, cfg Config, key objectKeys, info *upstream.ObjectInfo,
	meta objectmeta.Meta,
) error {
	clientMeta := map[string]string{}
	for name, value := range info.Metadata {
		if !strings.HasPrefix(strings.ToLower(name), objectmeta.Prefix) {
			clientMeta[name] = value
		}
	}

	// There are two windows in which a client can replace the object, and each
	// has its own guard. x-amz-copy-source-if-match covers the copy: if the
	// object changed between the HEAD and here, the provider refuses and the
	// rotation never reads a version it was not looking at. If-Match on the
	// completion covers the rest -- a write that lands after the parts are
	// copied but before the object is published. Both are 412, and both mean the
	// same thing to a caller: leave the client's version alone.
	destIfMatch := info.ETag
	if cfg.AllowUnconditional {
		destIfMatch = ""
	}

	// Rotation knows the manifest it is replacing, because it is replacing its
	// own source. It can therefore delete it under rule R3 rather than leaving
	// it to gc.
	var replaced *manifest.ID
	if meta.Multipart {
		id := meta.ManifestID
		replaced = &id
	}

	_, err := objcopy.Do(ctx, objcopy.Deps{
		Upstream: cfg.Upstream, Keys: cfg.Keys, Log: cfg.Log,
	}, objcopy.Request{
		Source: objcopy.Source{
			Bucket: cfg.Bucket, Key: key.identity, StoredKey: key.stored,
			Info: info, Meta: meta,
		},
		Dest: objcopy.Dest{
			Bucket: cfg.Bucket, Key: key.identity, StoredKey: key.stored,
			KeyID:        cfg.TargetKID,
			UserMetadata: clientMeta,
			ContentType:  info.ContentType,
			CacheControl: info.CacheControl,
		},
		SourceIfMatch:    info.ETag,
		DestIfMatch:      destIfMatch,
		ReplacedManifest: replaced,
		Hook:             cfg.hookAdapter(key.identity),
	})
	return err
}

// hookAdapter maps objcopy's step names onto the rotation step names the model
// and the integration tests use.
func (c Config) hookAdapter(key string) func(string) {
	if c.Hook == nil {
		return nil
	}
	return func(point string) {
		switch point {
		case objcopy.HookCreate:
			c.at(HookCreate, key)
		case objcopy.HookManifest:
			c.at(HookManifest, key)
		case objcopy.HookComplete:
			c.at(HookComplete, key)
		}
	}
}

// Duration is a convenience for the CLI's summary.
func (r *Result) Duration(started time.Time) time.Duration {
	return time.Since(started).Round(time.Millisecond)
}
