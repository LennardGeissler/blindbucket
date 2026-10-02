// Package migrate moves objects written with object-name encryption off to the
// keys they have with it on.
//
// With names.encrypt on, an object lives at the encrypted form of its key
// (ADR-015), so a bucket that holds objects when the switch is thrown loses
// sight of all of them. This moves each one from P, its key in clear, to E(P).
// It is a rename at the provider and not a re-encryption: an object's data key
// is bound to the key the client names, which does not change, so the data key,
// the KEK and the ciphertext stay as they are. What does have to change is the
// manifest of a multipart object, which is bound to the stored key; objcopy
// writes the new one under R1 and R2, as for any copy.
//
// The gateway serves with names encrypted throughout a run (ADR-022), so clients
// may write an object's encrypted key while the run is still on its way to it.
// That is the one window a run guards: the copy is published with
// If-None-Match, and a run that finds something at E(P) -- the copy an earlier
// run published before it died, or a client's newer write -- deletes P as
// obsolete. spec/tla/Migrate.tla checks that order, and has a counterexample for
// each of the alternatives; the hook names below are its action names.
package migrate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objcopy"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/probe"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// maxAttempts bounds how often one object is started over because it changed
// under the run. Each restart follows a write somebody else made, so the loop
// ends on its own; the bound is for a key that is being written continuously,
// which a run reports as failed rather than chases.
const maxAttempts = 3

// Config describes one migration run.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	// Names is the mapping objects are moved into. Required: it is the point.
	Names  *names.Encrypter
	Bucket string
	// Prefix restricts the run to keys in clear under it. It is a prefix of the
	// keys as they are stored now, which is to say in clear, so unlike rotate's
	// it need not end on a '/'.
	Prefix string
	// Log2ChunkSize is the fallback for objects whose metadata records none.
	Log2ChunkSize uint8

	Concurrency int
	DryRun      bool
	// AllowUnconditional publishes copies without If-None-Match, and skips the
	// measurement of whether the provider would have honoured it.
	//
	// It exists for providers that ignore the condition, Garage among them, and
	// it gives up the one guard a migration has: a client write that reaches an
	// object's encrypted key while the run is copying it there is replaced by
	// the older object. Callers must not set it without the operator having
	// said so, and the operator must not run it while anything writes to the
	// prefix (MCMigrateNoCreateGuard).
	AllowUnconditional bool

	Log *slog.Logger

	// Hook is called after each step of the Mig process in spec/tla/Migrate.tla,
	// named as the model names it. It exists so that an integration test can
	// hold a run and replay a counterexample; it is nil everywhere else.
	Hook func(point, key string)
}

// Step names of a migration, matching the model's actions. Each is called
// after its step.
const (
	HookHeadPlain   = "migHeadPlain"   // P has been read
	HookHeadEnc     = "migHeadEnc"     // E(P) has been read
	HookCreate      = "migCreate"      // the copy's upload is open
	HookCopy        = "migCopy"        // the parts are copied
	HookManifest    = "migManifest"    // the manifest under E(P) is written
	HookComplete    = "migComplete"    // the copy is published at E(P)
	HookDelete      = "migDelete"      // P is deleted
	HookManifestDel = "migManifestDel" // P's manifest is deleted
)

func (c Config) at(point, key string) {
	if c.Hook != nil {
		c.Hook(point, key)
	}
}

// UnguardedError refuses a run on a provider that does not enforce the one
// conditional write a migration relies on.
type UnguardedError struct {
	Bucket     string
	Conditions probe.Conditions
}

func (e *UnguardedError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "migrate-names: the provider behind %s does not enforce the conditional "+
		"write a migration relies on:", e.Bucket)
	for _, check := range e.Conditions.MigrationChecks() {
		if check.Outcome == probe.Enforced {
			continue
		}
		fmt.Fprintf(&b, "\n  %s: %s", check.Name, check.Outcome)
		if check.Detail != "" {
			fmt.Fprintf(&b, " (%s)", check.Detail)
		}
	}
	b.WriteString("\nA client write during the migration could be replaced by the older " +
		"object. Migrate with --allow-unconditional once nothing writes to the prefix (ADR-022).")
	return b.String()
}

// Result reports what a run did, or in a dry run would have done.
type Result struct {
	// Scanned counts keys in clear the listing returned. One that another run
	// finished while this one was getting to it is counted in nothing else.
	Scanned int64
	// Migrated counts objects copied to their encrypted key and deleted in
	// clear.
	Migrated int64
	// Resumed counts objects an earlier run had copied and died before
	// deleting: the copy at E(P) has the same data key, and P was deleted.
	Resumed int64
	// Superseded counts objects a client wrote at E(P) since the switch: the
	// object there is newer than P, and P was deleted.
	Superseded int64
	// Conflicted counts objects left in clear because what is at E(P) is not
	// something this run may delete P in favour of -- not written by the
	// gateway, or not newer than P. They need an operator.
	Conflicted int64
	// Foreign counts objects in clear this gateway did not write, which stay
	// where they are, as rotation leaves them.
	Foreign int64
	// TooLong counts keys whose encrypted form would exceed S3's 1024 bytes.
	// They stay in clear, which with names encrypted means out of reach.
	TooLong int64
	Failed  int64
}

// Incomplete reports whether anything the gateway wrote under the prefix is
// still in clear after the run -- or, for a dry run, would be.
func (r *Result) Incomplete() bool {
	return r.Conflicted > 0 || r.TooLong > 0 || r.Failed > 0
}

// Run migrates every object stored in clear under the configured prefix.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("migrate-names: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("migrate-names: a key provider is required")
	case cfg.Names == nil:
		return nil, errors.New("migrate-names: a name encrypter is required")
	case cfg.Bucket == "":
		return nil, errors.New("migrate-names: a bucket is required")
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

	// Before any object is touched, and in a dry run too, as for rotation
	// (ADR-020): whether a real run would be safe is part of what a dry run is
	// asked.
	if !cfg.AllowUnconditional {
		conditions, err := probe.ConditionalWrites(ctx, cfg.Upstream, cfg.Bucket)
		if err != nil {
			return nil, fmt.Errorf("migrate-names: measuring conditional writes: %w", err)
		}
		if !conditions.SafeForMigration() {
			return nil, &UnguardedError{Bucket: cfg.Bucket, Conditions: conditions}
		}
		cfg.Log.Debug("provider enforces If-None-Match on the completion")
	}

	result := &Result{}
	work := make(chan string)
	var wg sync.WaitGroup
	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range work {
				migrateOne(ctx, cfg, key, result)
			}
		}()
	}

	err := eachKeyInClear(ctx, cfg, func(key string) bool {
		select {
		case work <- key:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(work)
	wg.Wait()
	return result, err
}

// eachKeyInClear walks the prefix and hands on every key that is not already
// encrypted.
//
// The listing is the provider's, so it holds both kinds of key, and the copies
// this run publishes appear in it as it goes. A key that decrypts is at its
// encrypted name already; the synthetic IV it carries (FORMAT §15.4) makes it
// impossible for a key in clear to pass for one.
func eachKeyInClear(ctx context.Context, cfg Config, visit func(string) bool) error {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	for {
		page, err := cfg.Upstream.ListObjects(ctx, cfg.Bucket, query)
		if err != nil {
			return fmt.Errorf("migrate-names: listing %s: %w", cfg.Bucket, err)
		}
		for _, entry := range page.Contents {
			// Manifests move with the object they belong to, and the probe's
			// object is not a client's.
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			if _, err := cfg.Names.DecryptKey(entry.Key); err == nil {
				continue
			}
			if !visit(entry.Key) {
				return ctx.Err()
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}

// outcome is what became of one object.
type outcome int

const (
	gone outcome = iota // another run finished it first
	migrated
	resumed
	superseded
	conflicted
	foreign
	tooLong
	failed
	again // it changed under the run: start over on it
)

// migrateOne moves one object, starting over a bounded number of times when it
// changes under the run.
func migrateOne(ctx context.Context, cfg Config, key string, result *Result) {
	atomic.AddInt64(&result.Scanned, 1)
	// The key in clear in the log: it is the name an operator recognises, and
	// the host running this is inside the trust boundary that already sees it.
	log := cfg.Log.With("key", key)

	got := again
	for attempt := 0; got == again && attempt < maxAttempts; attempt++ {
		got = attemptOne(ctx, cfg, key, log)
	}
	if got == again {
		log.Warn("the object kept changing during the migration; run again")
		got = failed
	}

	counter := map[outcome]*int64{
		migrated: &result.Migrated, resumed: &result.Resumed, superseded: &result.Superseded,
		conflicted: &result.Conflicted, foreign: &result.Foreign, tooLong: &result.TooLong,
		failed: &result.Failed,
	}[got]
	if counter != nil {
		atomic.AddInt64(counter, 1)
	}
}

// attemptOne is one pass through the steps of the model's Mig process.
func attemptOne(ctx context.Context, cfg Config, key string, log *slog.Logger) outcome {
	// migHeadPlain.
	plainInfo, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, key)
	if upstream.NotFound(err) {
		return gone
	}
	if err != nil {
		log.Warn("could not read the object", "err", err)
		return failed
	}
	plainMeta, err := objectmeta.Parse(plainInfo.Metadata, cfg.Log2ChunkSize)
	if errors.Is(err, objectmeta.ErrNotEncrypted) {
		return foreign
	}
	if err != nil {
		log.Warn("object metadata is unusable", "err", err)
		return failed
	}
	stored, err := cfg.Names.EncryptKey(key)
	if errors.Is(err, names.ErrTooLong) {
		log.Warn("the key is too long to encrypt and stays in clear, out of reach "+
			"of a gateway that encrypts names; rename the object to migrate it",
			"err", err)
		return tooLong
	}
	if err != nil {
		log.Warn("could not encrypt the key", "err", err)
		return failed
	}
	cfg.at(HookHeadPlain, key)

	// migHeadEnc.
	encInfo, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, stored)
	switch {
	case upstream.NotFound(err):
		encInfo = nil
	case err != nil:
		log.Warn("could not read the object's encrypted key", "err", err)
		return failed
	}
	cfg.at(HookHeadEnc, key)

	verdict := migrated
	if encInfo != nil {
		verdict = judgeExisting(ctx, cfg, key, plainInfo, plainMeta, encInfo, log)
		if verdict != resumed && verdict != superseded {
			return verdict
		}
	}
	if cfg.DryRun {
		return verdict
	}

	if encInfo == nil {
		switch err := copyToEncrypted(ctx, cfg, key, stored, plainInfo, plainMeta); {
		case err == nil:
		case errors.Is(err, objcopy.ErrPreconditionFailed), upstream.NotFound(err):
			// Something reached E(P), or P changed or went away -- another
			// run, or a client. Read both again and decide afresh; the model's
			// 412 branch goes back to migHeadEnc, and starting at migHeadPlain
			// instead only repeats a read.
			log.Debug("the object changed during the copy; starting over", "err", err)
			return again
		default:
			log.Warn("could not copy the object to its encrypted key", "err", err)
			return failed
		}
	}

	// migDelete and migManifestDel.
	if err := deletePlain(ctx, cfg, key, plainMeta, log); err != nil {
		log.Warn("the object is at its encrypted key, but its key in clear could not be "+
			"deleted; run again", "err", err)
		return failed
	}
	return verdict
}

// judgeExisting decides what the object already at E(P) means for P.
//
// Under ADR-022's precondition there are two things it can be, and both make P
// obsolete: the copy an earlier run published before it died, or a client's
// write through the switched gateway. The data keys tell them apart, for the
// report. What falls outside the precondition is a conflict and is left alone.
func judgeExisting(ctx context.Context, cfg Config, key string,
	plainInfo *upstream.ObjectInfo, plainMeta objectmeta.Meta, encInfo *upstream.ObjectInfo,
	log *slog.Logger,
) outcome {
	encMeta, err := objectmeta.Parse(encInfo.Metadata, cfg.Log2ChunkSize)
	if errors.Is(err, objectmeta.ErrNotEncrypted) {
		log.Warn("something the gateway did not write is at the object's encrypted key; " +
			"leaving the object in clear")
		return conflicted
	}
	if err != nil {
		log.Warn("the object at the encrypted key has unusable metadata", "err", err)
		return failed
	}

	same, err := sameDataKey(ctx, cfg, key, plainMeta, encMeta)
	if err != nil {
		log.Warn("could not compare the data keys", "err", err)
		return failed
	}
	if same {
		return resumed
	}
	// Another data key: a different version. Under the precondition it is a
	// client's write since the switch and newer than anything in clear. A bucket
	// that had names encrypted once before can hold an older one there, and
	// deleting P in its favour would lose the newer object -- so newer is
	// required, by the provider's own clock, and a tie is not newer.
	if !encInfo.LastModified.After(plainInfo.LastModified) {
		log.Warn("a different object at the encrypted key is not newer than the one in "+
			"clear; leaving both", "clear", plainInfo.LastModified, "encrypted", encInfo.LastModified)
		return conflicted
	}
	return superseded
}

// sameDataKey reports whether two objects carry the same data key, which is
// what makes them the same version: a copy keeps the data key (ADR-012), and
// every write generates a new one. Both are bound to the same identity -- the
// key in clear -- whichever key they are stored under (FORMAT §15.4).
func sameDataKey(ctx context.Context, cfg Config, key string, a, b objectmeta.Meta) (bool, error) {
	open := func(m objectmeta.Meta) ([]byte, error) {
		aad, err := keys.ObjectAAD(m.KeyID, cfg.Bucket, key)
		if err != nil {
			return nil, err
		}
		return cfg.Keys.Unwrap(ctx, m.KeyID, m.WrappedDEK, aad)
	}
	first, err := open(a)
	if err != nil {
		return false, err
	}
	defer clear(first)
	second, err := open(b)
	if err != nil {
		return false, err
	}
	defer clear(second)
	return subtle.ConstantTimeCompare(first, second) == 1, nil
}

// copyToEncrypted publishes the object at its encrypted key: migCreate to
// migComplete.
func copyToEncrypted(ctx context.Context, cfg Config, key, stored string,
	info *upstream.ObjectInfo, meta objectmeta.Meta,
) error {
	clientMeta := map[string]string{}
	for name, value := range info.Metadata {
		if !strings.HasPrefix(strings.ToLower(name), objectmeta.Prefix) {
			clientMeta[name] = value
		}
	}
	ifNoneMatch := "*"
	if cfg.AllowUnconditional {
		ifNoneMatch = ""
	}
	_, err := objcopy.Do(ctx, objcopy.Deps{
		Upstream: cfg.Upstream, Keys: cfg.Keys, Log: cfg.Log,
	}, objcopy.Request{
		Source: objcopy.Source{
			Bucket: cfg.Bucket, Key: key, StoredKey: key, Info: info, Meta: meta,
		},
		Dest: objcopy.Dest{
			Bucket: cfg.Bucket, Key: key, StoredKey: stored,
			// The KEK stays. A migration that rotated on the way would be two
			// operations reported as one, and rotation has a command.
			KeyID:              meta.KeyID,
			UserMetadata:       clientMeta,
			ContentType:        info.ContentType,
			CacheControl:       info.CacheControl,
			ContentDisposition: info.Header.Get("Content-Disposition"),
			ContentEncoding:    info.Header.Get("Content-Encoding"),
			ContentLanguage:    info.Header.Get("Content-Language"),
		},
		SourceIfMatch:   info.ETag,
		DestIfNoneMatch: ifNoneMatch,
		Hook:            cfg.hookAdapter(key),
	})
	return err
}

// deletePlain removes the object in clear, then its manifest.
//
// Unconditionally: with every instance encrypting names nothing writes P any
// more, and a condition here would not save a write from an instance that
// still does, because the run has read the version it deletes
// (MCMigrateStaleWriter). The manifest goes second, as R3 orders it: a reader
// still on P must not find the object without its manifest. Only the id read
// at migHeadPlain is deleted, and a failure leaves an orphan for gc rather than
// a broken object.
func deletePlain(ctx context.Context, cfg Config, key string, meta objectmeta.Meta,
	log *slog.Logger,
) error {
	if err := cfg.Upstream.DeleteObject(ctx, cfg.Bucket, key); err != nil {
		return err
	}
	cfg.at(HookDelete, key)
	if meta.Multipart {
		if err := cfg.Upstream.DeleteObject(ctx, cfg.Bucket, meta.ManifestID.ObjectKey(key)); err != nil {
			log.Warn("could not remove the manifest left in clear; gc will collect it", "err", err)
		}
	}
	cfg.at(HookManifestDel, key)
	return nil
}

// hookAdapter maps objcopy's step names onto the model's.
func (c Config) hookAdapter(key string) func(string) {
	if c.Hook == nil {
		return nil
	}
	return func(point string) {
		switch point {
		case objcopy.HookCreate:
			c.at(HookCreate, key)
		case objcopy.HookParts:
			c.at(HookCopy, key)
		case objcopy.HookManifest:
			c.at(HookManifest, key)
		case objcopy.HookComplete:
			c.at(HookComplete, key)
		}
	}
}
