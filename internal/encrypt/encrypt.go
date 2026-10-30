// Package encrypt turns the plaintext objects a bucket held before the gateway
// into objects the gateway wrote, in place (ADR-034).
//
// A gateway put in front of a bucket that already holds objects cannot read
// them: every read answers ObjectNotEncrypted, because the gateway never serves
// plaintext it did not encrypt. This reads each such object, encrypts it under a
// new data key bound to the key the client names, and writes it back where the
// gateway will look for it.
//
// Where that is depends on the configuration, and the two cases are two
// operations the formal models already check:
//
//   - With names in clear, the object goes back to its own key. That is an
//     overwrite, in rotation's order: the manifest first, the open uploads of the
//     key given way to, If-Match on the completion. spec/tla/Multipart.tla's
//     rotation process with Initial = "plaintext" (MCEncrypt).
//   - With names.encrypt, it goes to the encrypted form of its key and the
//     plaintext is deleted afterwards, in migrate-names' order: If-None-Match on
//     the completion, then the delete. spec/tla/Migrate.tla (MCMigrate).
//
// A client writing through the gateway during a run wins in both, which is what
// the conditions are for. The hook names below are the models' action names.
package encrypt

import (
	"context"
	"crypto/md5" //nolint:gosec // compared with the provider's own MD5 ETag, not used for security.
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/probe"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// maxAttempts bounds how often one object is started over because it changed
// under the run, as in migrate-names.
const maxAttempts = 3

// DefaultPartSize is the plaintext size of a part when an object is written in
// parts. An object up to this size is written as one segment, with no manifest.
const DefaultPartSize = 64 << 20

// Config describes one run.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	// KID is the KEK data keys are wrapped under: the one the gateway's writes
	// to the bucket use, its tenant's once the tenant is active (ADR-038).
	// Empty means Keys.ActiveKID().
	KID string
	// Names is the mapping objects are written into. Nil means names in clear:
	// each object is overwritten at its own key.
	Names  *names.Encrypter
	Bucket string
	// Prefix restricts the run to keys under it, as they are stored now: in
	// clear, which is how a plaintext object is stored either way.
	Prefix string
	// Log2ChunkSize is the chunk size objects are encrypted with, and the
	// fallback for reading the metadata of objects that record none.
	Log2ChunkSize uint8
	// PartSize is the plaintext size of a part; 0 means DefaultPartSize. It is
	// rounded up to a multiple of the chunk size (FORMAT §7.3).
	PartSize int64

	Concurrency int
	DryRun      bool
	// AllowUnconditional writes without the condition the run relies on, and
	// skips the measurement of whether the provider would honour it. A client
	// write landing during the run can then be lost (MCEncryptUnconditional).
	// Callers must not set it without the operator having said so.
	AllowUnconditional bool
	// KeepVersions runs on a versioned bucket, whose old plaintext versions
	// this command does not remove. The operator's statement that they are
	// handled elsewhere.
	KeepVersions bool

	Log *slog.Logger

	// Hook is called after each step, named as the model names it. It exists so
	// that an integration test can hold a run and replay a counterexample; it is
	// nil everywhere else.
	Hook func(point, key string)
}

// Step names. With names in clear the run is Multipart.tla's rotation process,
// with names encrypted Migrate.tla's migration process; each hook is called
// after its step.
const (
	HookRotHead     = "rotHead"     // the object has been read and is a candidate
	HookRotCreate   = "rotCreate"   // the upload is open
	HookRotManifest = "rotManifest" // the parts are written, and the manifest if any
	HookRotUploads  = "rotUploads"  // the key's open uploads have been checked
	HookRotComplete = "rotComplete" // the encrypted object is published

	HookMigHeadPlain = "migHeadPlain" // the plaintext has been read and is a candidate
	HookMigHeadEnc   = "migHeadEnc"   // the encrypted key has been read
	HookMigCreate    = "migCreate"    // the upload is open
	HookMigCopy      = "migCopy"      // the parts are written
	HookMigManifest  = "migManifest"  // the manifest, if any, is written
	HookMigComplete  = "migComplete"  // the encrypted object is published
	HookMigDelete    = "migDelete"    // the plaintext is deleted
)

func (c Config) at(point, key string) {
	if c.Hook != nil {
		c.Hook(point, key)
	}
}

// UnguardedError refuses a run on a provider that does not enforce the
// conditional write the run relies on.
type UnguardedError struct {
	Bucket string
	Check  probe.Check
}

func (e *UnguardedError) Error() string {
	detail := ""
	if e.Check.Detail != "" {
		detail = " (" + e.Check.Detail + ")"
	}
	return fmt.Sprintf("encrypt-existing: the provider behind %s does not enforce the conditional "+
		"write this run relies on:\n  %s: %s%s\nA client write during the run could be lost. "+
		"Run with --allow-unconditional once nothing writes to the prefix (ADR-034).",
		e.Bucket, e.Check.Name, e.Check.Outcome, detail)
}

// VersionedError refuses a run on a bucket with versioning, whose overwrites
// and deletes keep the plaintext as noncurrent versions.
type VersionedError struct {
	Bucket string
	Status string
}

func (e *VersionedError) Error() string {
	return fmt.Sprintf("encrypt-existing: versioning on %s is %s, so every object this run encrypts "+
		"would keep its plaintext at the provider as a noncurrent version. Remove the old versions "+
		"after the run -- a lifecycle rule for noncurrent versions, or a deletion -- and say so with "+
		"--keep-versions (ADR-034).", e.Bucket, strings.ToLower(e.Status))
}

// Result reports what a run did, or in a dry run would have done.
type Result struct {
	// Scanned counts keys the listing returned.
	Scanned int64
	// Encrypted counts plaintext objects written as encrypted ones: at their
	// own key with names in clear, at their encrypted key with names encrypted.
	Encrypted int64
	// Obsolete counts plaintext objects deleted because an encrypted object was
	// already at their encrypted key -- a run that died before the delete, or a
	// client's newer write.
	Obsolete int64
	// Skipped counts objects the gateway wrote.
	Skipped int64
	// Conflicted counts plaintext objects left because a client wrote the key
	// during the run, because they carry the gateway's metadata prefix, or
	// because what is at their encrypted key is not something they may be
	// deleted in favour of. They need an operator, or a later run.
	Conflicted int64
	// NeedsNameMigration counts objects the gateway wrote with names in clear,
	// found by a run that encrypts names. migrate-names moves them.
	NeedsNameMigration int64
	// TooLong counts keys whose encrypted form would exceed S3's 1024 bytes.
	TooLong int64
	// Tagged counts objects with tags, which an overwrite would drop.
	Tagged int64
	// Locked counts objects under a legal hold or a retention period.
	Locked int64
	// Unreadable counts objects this run cannot read, such as SSE-C objects.
	Unreadable int64
	Failed     int64
	// BytesEncrypted is the plaintext the run encrypted, or would.
	BytesEncrypted int64
}

// Incomplete reports whether a plaintext object is left under the prefix -- or,
// for a dry run, would be.
func (r *Result) Incomplete() bool {
	return r.Conflicted > 0 || r.NeedsNameMigration > 0 || r.TooLong > 0 || r.Tagged > 0 ||
		r.Locked > 0 || r.Unreadable > 0 || r.Failed > 0
}

// Run encrypts every plaintext object under the configured prefix.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("encrypt-existing: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("encrypt-existing: a key provider is required")
	case cfg.Bucket == "":
		return nil, errors.New("encrypt-existing: a bucket is required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Log2ChunkSize == 0 {
		cfg.Log2ChunkSize = stream.DefaultLog2ChunkSize
	}
	if err := stream.ValidateLog2ChunkSize(cfg.Log2ChunkSize); err != nil {
		return nil, fmt.Errorf("encrypt-existing: %w", err)
	}
	if cfg.PartSize <= 0 {
		cfg.PartSize = DefaultPartSize
	}
	chunk := int64(1) << cfg.Log2ChunkSize
	cfg.PartSize = (cfg.PartSize + chunk - 1) / chunk * chunk
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	// Both checks before any object is touched, and in a dry run too: whether a
	// real run would go through is part of what a dry run answers.
	if !cfg.KeepVersions {
		status, err := versioning(ctx, cfg.Upstream, cfg.Bucket)
		if err != nil {
			return nil, fmt.Errorf("encrypt-existing: reading the versioning of %s: %w", cfg.Bucket, err)
		}
		if status != "" {
			return nil, &VersionedError{Bucket: cfg.Bucket, Status: status}
		}
	}
	if !cfg.AllowUnconditional {
		conditions, err := probe.ConditionalWrites(ctx, cfg.Upstream, cfg.Bucket)
		if err != nil {
			return nil, fmt.Errorf("encrypt-existing: measuring conditional writes: %w", err)
		}
		check := conditions.CompleteIfMatch
		if cfg.Names != nil {
			check = conditions.CompleteIfNoneMatch
		}
		if check.Outcome != probe.Enforced {
			return nil, &UnguardedError{Bucket: cfg.Bucket, Check: check}
		}
	}

	result := &Result{}
	work := make(chan string)
	var wg sync.WaitGroup
	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range work {
				encryptOne(ctx, cfg, key, result)
			}
		}()
	}
	err := eachCandidateKey(ctx, cfg, func(key string) bool {
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

// versioning returns the bucket's versioning status, "" if it was never
// enabled. Suspended counts: the versions made while it was enabled are there.
func versioning(ctx context.Context, up *upstream.Client, bucket string) (string, error) {
	resp, err := up.Passthrough(ctx, http.MethodGet, bucket, url.Values{"versioning": {""}}, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the provider answered %d", resp.StatusCode)
	}
	var doc struct {
		Status string `xml:"Status"`
	}
	if err := xml.Unmarshal(resp.Body, &doc); err != nil {
		return "", fmt.Errorf("parsing the versioning configuration: %w", err)
	}
	return doc.Status, nil
}

// eachCandidateKey walks the prefix and hands on every key that may hold a
// plaintext object. The reserved prefix holds manifests and the probe's object,
// and with names encrypted a key that decrypts is an object the gateway wrote.
func eachCandidateKey(ctx context.Context, cfg Config, visit func(string) bool) error {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	for {
		page, err := cfg.Upstream.ListObjects(ctx, cfg.Bucket, query)
		if err != nil {
			return fmt.Errorf("encrypt-existing: listing %s: %w", cfg.Bucket, err)
		}
		for _, entry := range page.Contents {
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			if cfg.Names != nil {
				if _, err := cfg.Names.DecryptKey(entry.Key); err == nil {
					continue
				}
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
	gone outcome = iota // deleted, or finished by another run, before this one got to it
	encrypted
	obsolete
	skipped
	conflicted
	needsNameMigration
	tooLong
	tagged
	locked
	unreadable
	failed
	again // it changed under the run: start over on it
)

func encryptOne(ctx context.Context, cfg Config, key string, result *Result) {
	atomic.AddInt64(&result.Scanned, 1)
	// The key in clear in the log: the name an operator recognises, on a host
	// inside the trust boundary that sees it anyway.
	log := cfg.Log.With("key", key)

	got, size := again, int64(0)
	for attempt := 0; got == again && attempt < maxAttempts; attempt++ {
		got, size = attemptOne(ctx, cfg, key, log)
	}
	if got == again {
		log.Warn("the object kept changing during the run; run again")
		got = failed
	}
	if got == encrypted {
		atomic.AddInt64(&result.BytesEncrypted, size)
	}
	counter := map[outcome]*int64{
		encrypted: &result.Encrypted, obsolete: &result.Obsolete, skipped: &result.Skipped,
		conflicted: &result.Conflicted, needsNameMigration: &result.NeedsNameMigration,
		tooLong: &result.TooLong, tagged: &result.Tagged, locked: &result.Locked,
		unreadable: &result.Unreadable, failed: &result.Failed,
	}[got]
	if counter != nil {
		atomic.AddInt64(counter, 1)
	}
}

// attemptOne is one pass over one object. It returns what became of it and,
// for an object it encrypted, its plaintext size.
func attemptOne(ctx context.Context, cfg Config, key string, log *slog.Logger) (outcome, int64) {
	info, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, key)
	if upstream.NotFound(err) {
		return gone, 0
	}
	if err != nil {
		var apiErr *upstream.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest {
			// What an SSE-C object answers a HEAD without its key.
			log.Warn("the object cannot be read without a key it was stored with "+
				"(SSE-C?); leaving it", "err", err)
			return unreadable, 0
		}
		log.Warn("could not read the object", "err", err)
		return failed, 0
	}
	if verdict, ok := judgePlain(cfg, info, log); !ok {
		return verdict, 0
	}

	if cfg.Names == nil {
		cfg.at(HookRotHead, key)
		if cfg.DryRun {
			return encrypted, info.ContentLength
		}
		ifMatch := info.ETag
		if cfg.AllowUnconditional {
			ifMatch = ""
		}
		switch err := write(ctx, cfg, key, key, info, ifMatch, "", rotHooks); {
		case err == nil:
			return encrypted, info.ContentLength
		case errors.Is(err, errSourceChanged):
			// The object changed between the HEAD and the read. Read it again.
			log.Debug("the object changed before it was read; starting over", "err", err)
			return again, 0
		case errors.Is(err, errPreconditionFailed), errors.Is(err, errUploadInProgress):
			// A client wrote the key, or is uploading to it: its version stands
			// (I2). It is an object the gateway wrote, and a later run skips it.
			log.Info("a client wrote the object during the run; its version stands", "err", err)
			return conflicted, 0
		default:
			log.Warn("could not encrypt the object", "err", err)
			return failed, 0
		}
	}

	stored, err := cfg.Names.EncryptKey(key)
	if errors.Is(err, names.ErrTooLong) {
		log.Warn("the key is too long to encrypt; rename the object to encrypt it", "err", err)
		return tooLong, 0
	}
	if err != nil {
		log.Warn("could not encrypt the key", "err", err)
		return failed, 0
	}
	cfg.at(HookMigHeadPlain, key)

	encInfo, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, stored)
	switch {
	case upstream.NotFound(err):
		encInfo = nil
	case err != nil:
		log.Warn("could not read the object's encrypted key", "err", err)
		return failed, 0
	}
	cfg.at(HookMigHeadEnc, key)

	if encInfo != nil {
		// Something is at E(P) already: this command's own write from a run that
		// died before the delete, or a client's write through the switched
		// gateway. Either makes the plaintext obsolete (ADR-034, after ADR-022).
		if verdict := judgeExisting(cfg, info, encInfo, log); verdict != obsolete {
			return verdict, 0
		}
		if cfg.DryRun {
			return obsolete, 0
		}
		if err := deletePlain(ctx, cfg, key); err != nil {
			log.Warn("could not delete the obsolete plaintext; run again", "err", err)
			return failed, 0
		}
		return obsolete, 0
	}
	if cfg.DryRun {
		return encrypted, info.ContentLength
	}

	ifNoneMatch := "*"
	if cfg.AllowUnconditional {
		ifNoneMatch = ""
	}
	switch err := write(ctx, cfg, key, stored, info, "", ifNoneMatch, migHooks); {
	case err == nil:
	case errors.Is(err, errUploadInProgress):
		// A client is uploading to the encrypted key: its write is newer, and
		// publishing first could make the provider discard it (ADR-025). The next
		// run finds the client's object and the plaintext obsolete.
		log.Warn("an upload to the object's encrypted key is in progress; run again")
		return failed, 0
	case errors.Is(err, errPreconditionFailed), errors.Is(err, errSourceChanged):
		// Something reached E(P), or the plaintext changed: look again.
		log.Debug("the object changed during the run; starting over", "err", err)
		return again, 0
	default:
		log.Warn("could not encrypt the object", "err", err)
		return failed, 0
	}
	if err := deletePlain(ctx, cfg, key); err != nil {
		log.Warn("the object is encrypted at its encrypted key, but its plaintext could not be "+
			"deleted; run again", "err", err)
		return failed, 0
	}
	return encrypted, info.ContentLength
}

// judgePlain decides whether a HEAD shows a plaintext object this run may
// encrypt, and otherwise what it is.
func judgePlain(cfg Config, info *upstream.ObjectInfo, log *slog.Logger) (outcome, bool) {
	_, err := objectmeta.Parse(info.Metadata, cfg.Log2ChunkSize)
	switch {
	case err == nil:
		if cfg.Names != nil {
			log.Warn("the gateway wrote this object with names in clear; migrate-names moves it")
			return needsNameMigration, false
		}
		return skipped, false
	case !errors.Is(err, objectmeta.ErrNotEncrypted):
		log.Warn("the object carries the gateway's metadata, but it does not parse; leaving it",
			"err", err)
		return conflicted, false
	}
	for name := range info.Metadata {
		if strings.HasPrefix(strings.ToLower(name), objectmeta.Prefix) {
			// A client cannot set this prefix through the gateway (FORMAT §6.3),
			// and carrying it across would read as the gateway's own.
			log.Warn("the object has metadata under the gateway's prefix; leaving it",
				"metadata", name)
			return conflicted, false
		}
	}
	if n, _ := strconv.Atoi(info.Header.Get("x-amz-tagging-count")); n > 0 {
		log.Warn("the object has tags, which an overwrite would drop; leaving it", "tags", n)
		return tagged, false
	}
	if strings.EqualFold(info.Header.Get("x-amz-object-lock-legal-hold"), "ON") {
		log.Warn("the object is under a legal hold; leaving it")
		return locked, false
	}
	if until := info.Header.Get("x-amz-object-lock-retain-until-date"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err != nil || t.After(time.Now()) {
			log.Warn("the object is under a retention period; leaving it", "until", until)
			return locked, false
		}
	}
	if info.Header.Get("x-amz-server-side-encryption-customer-algorithm") != "" {
		log.Warn("the object is encrypted with a customer key (SSE-C); leaving it")
		return unreadable, false
	}
	return 0, true
}

// judgeExisting decides what the object at E(P) means for the plaintext at P.
func judgeExisting(cfg Config, plain, enc *upstream.ObjectInfo, log *slog.Logger) outcome {
	if _, err := objectmeta.Parse(enc.Metadata, cfg.Log2ChunkSize); err != nil {
		log.Warn("something the gateway did not write is at the object's encrypted key; "+
			"leaving the plaintext", "err", err)
		return conflicted
	}
	// Under the precondition, whatever the gateway wrote at E(P) is newer than
	// the plaintext. A bucket that had names encrypted once before can hold an
	// older one there, so newer is required, by the provider's clock; a tie is
	// not newer.
	if !enc.LastModified.After(plain.LastModified) {
		log.Warn("the object at the encrypted key is not newer than the plaintext; leaving both",
			"plaintext", plain.LastModified, "encrypted", enc.LastModified)
		return conflicted
	}
	return obsolete
}

// deletePlain deletes the plaintext, unconditionally, as migrate-names deletes
// P: with every instance encrypting names nothing writes it any more
// (ADR-022, MCMigrateStaleWriter).
func deletePlain(ctx context.Context, cfg Config, key string) error {
	if err := cfg.Upstream.DeleteObject(ctx, cfg.Bucket, key); err != nil {
		return err
	}
	cfg.at(HookMigDelete, key)
	return nil
}

var (
	errSourceChanged      = errors.New("encrypt-existing: the object changed before it was read")
	errPreconditionFailed = errors.New("encrypt-existing: the key was written during the run")
	errUploadInProgress   = errors.New("encrypt-existing: an upload of the key is in progress")
	errDigestMismatch     = errors.New("encrypt-existing: what was read does not match the provider's MD5")
)

// hooks maps the steps of write onto one model's action names.
type hooks struct{ create, parts, manifest, uploads, complete string }

var (
	rotHooks = hooks{HookRotCreate, "", HookRotManifest, HookRotUploads, HookRotComplete}
	migHooks = hooks{HookMigCreate, HookMigCopy, HookMigManifest, "", HookMigComplete}
)

func (c Config) step(point, key string) {
	if point != "" {
		c.at(point, key)
	}
}

// write reads the plaintext at key and publishes it encrypted at stored.
//
// The order is objcopy's, and the model's: open the upload, write the parts,
// write the manifest (R2), check for other open uploads of the key (ADR-025),
// complete with the condition. An object up to the part size becomes one
// single-part segment, uploaded as part 1 with no manifest, which is how
// rotation writes a single-part object too; a larger one becomes a multipart
// object. Every failure aborts the upload.
func write(ctx context.Context, cfg Config, key, stored string, info *upstream.ObjectInfo,
	ifMatch, ifNoneMatch string, h hooks,
) error {
	plainSize := info.ContentLength
	partSize := cfg.PartSize
	if plainSize > partSize {
		// At most 10,000 parts: a larger object takes larger parts.
		chunk := int64(1) << cfg.Log2ChunkSize
		if least := (plainSize + stream.MaxParts - 1) / stream.MaxParts; least > partSize {
			partSize = (least + chunk - 1) / chunk * chunk
		}
		maxPart, err := manifest.MaxPartPlaintext(cfg.Log2ChunkSize)
		if err != nil {
			return err
		}
		if partSize > maxPart {
			return fmt.Errorf("the object is %d bytes, more than %d parts of at most %d bytes",
				plainSize, stream.MaxParts, maxPart)
		}
	}
	multipart := plainSize > partSize

	kid := cfg.KID
	if kid == "" {
		kid = cfg.Keys.ActiveKID()
	}
	// Bound to the key the client names, whichever key it is stored under
	// (FORMAT §6.1).
	aad, err := keys.ObjectAAD(kid, cfg.Bucket, key)
	if err != nil {
		return err
	}
	dek, err := keys.NewDEK()
	if err != nil {
		return err
	}
	defer dek.Wipe()
	wrapped, err := cfg.Keys.Wrap(ctx, kid, dek.Bytes(), aad)
	if err != nil {
		return fmt.Errorf("wrapping the data key: %w", err)
	}
	meta := objectmeta.Meta{
		Version: stream.Version, KeyID: kid, WrappedDEK: wrapped, Log2ChunkSize: cfg.Log2ChunkSize,
	}
	if multipart {
		id, err := manifest.NewID()
		if err != nil {
			return err
		}
		meta.ManifestID, meta.Multipart = id, true
	}
	metadata := map[string]string{}
	for name, value := range info.Metadata {
		metadata[name] = value
	}
	for name, value := range meta.Headers() {
		metadata[name] = value
	}

	src, err := cfg.Upstream.GetObject(ctx, upstream.GetObjectInput{
		Bucket: cfg.Bucket, Key: key, IfMatch: info.ETag,
	})
	if err != nil {
		if upstream.PreconditionFailed(err) || upstream.NotFound(err) {
			return fmt.Errorf("%w: %w", errSourceChanged, err)
		}
		return fmt.Errorf("reading the object: %w", err)
	}
	defer func() { _ = src.Body.Close() }()
	if src.ContentLength != plainSize || (src.ETag != "" && src.ETag != info.ETag) {
		return fmt.Errorf("%w: the read is not the version the HEAD saw", errSourceChanged)
	}

	// The provider's MD5 of what it stores, where its ETag is one: a single-part
	// object stored in clear, not under SSE-KMS.
	var sum hash.Hash
	var want string
	if etag := strings.Trim(info.ETag, `"`); len(etag) == 32 && isHex(etag) &&
		info.Header.Get("x-amz-server-side-encryption") != "aws:kms" {
		sum, want = md5.New(), etag //nolint:gosec // see the import.
	}
	body := io.Reader(src.Body)
	if sum != nil {
		body = io.TeeReader(src.Body, sum)
	}

	uploadID, err := cfg.Upstream.CreateMultipartUpload(ctx, upstream.CreateMultipartUploadInput{
		Bucket: cfg.Bucket, Key: stored,
		ContentType:        info.ContentType,
		CacheControl:       info.CacheControl,
		ContentDisposition: info.Header.Get("Content-Disposition"),
		ContentEncoding:    info.Header.Get("Content-Encoding"),
		ContentLanguage:    info.Header.Get("Content-Language"),
		Metadata:           metadata,
	})
	if err != nil {
		return fmt.Errorf("opening the upload: %w", err)
	}
	cfg.step(h.create, key)
	committed := false
	defer func() {
		if !committed {
			if err := cfg.Upstream.AbortMultipartUpload(ctx, cfg.Bucket, stored, uploadID); err != nil {
				cfg.Log.Warn("could not abort a failed upload", "key", key, "err", err)
			}
		}
	}()

	var completed []upstream.CompletedPart
	var layout []manifest.Part
	if !multipart {
		etag, _, err := uploadSegment(ctx, cfg, stored, uploadID, 1, body, plainSize,
			stream.SegmentParams{Log2ChunkSize: cfg.Log2ChunkSize}, dek.Bytes())
		if err != nil {
			return err
		}
		completed = []upstream.CompletedPart{{PartNumber: 1, ETag: etag}}
	} else {
		for number, left := 1, plainSize; left > 0; number++ {
			size := min(partSize, left)
			etag, salt, err := uploadSegment(ctx, cfg, stored, uploadID, number, body, size,
				//nolint:gosec // at most stream.MaxParts, checked above.
				stream.SegmentParams{Log2ChunkSize: cfg.Log2ChunkSize, Multipart: true, Index: uint32(number)},
				dek.Bytes())
			if err != nil {
				return err
			}
			completed = append(completed, upstream.CompletedPart{PartNumber: number, ETag: etag})
			//nolint:gosec // as above.
			layout = append(layout, manifest.Part{Number: uint32(number), PlainSize: size, Salt: salt})
			left -= size
		}
	}
	cfg.step(h.parts, key)

	if sum != nil {
		if got := hex.EncodeToString(sum.Sum(nil)); got != want {
			return fmt.Errorf("%w: read %s, the provider stores %s", errDigestMismatch, got, want)
		}
	}

	// Rule R2: the manifest exists before the object that names it.
	if multipart {
		m := &manifest.Manifest{Bucket: cfg.Bucket, Key: stored, ID: meta.ManifestID, Parts: layout}
		raw, err := m.Marshal(dek.Bytes())
		if err != nil {
			return fmt.Errorf("building the manifest: %w", err)
		}
		if _, err := cfg.Upstream.PutObject(ctx, upstream.PutObjectInput{
			Bucket: cfg.Bucket, Key: meta.ManifestID.ObjectKey(stored),
			Body: strings.NewReader(string(raw)), ContentLength: int64(len(raw)),
			ContentType: "application/octet-stream",
		}); err != nil {
			return fmt.Errorf("storing the manifest: %w", err)
		}
	}
	cfg.step(h.manifest, key)

	// ADR-025: give way to an upload of the key a client opened, which a
	// provider ranking writes by when they began would otherwise discard in
	// this write's favour. Checked after this upload exists, so none is unseen.
	if !cfg.AllowUnconditional {
		open, err := cfg.Upstream.ListMultipartUploads(ctx, cfg.Bucket, stored)
		if err != nil {
			return fmt.Errorf("listing the open uploads of the key: %w", err)
		}
		for _, u := range open {
			if u.Key == stored && u.UploadID != uploadID {
				return errUploadInProgress
			}
		}
	}
	cfg.step(h.uploads, key)

	if _, err := cfg.Upstream.CompleteMultipartUpload(ctx, upstream.CompleteMultipartUploadInput{
		Bucket: cfg.Bucket, Key: stored, UploadID: uploadID,
		Parts: completed, IfMatch: ifMatch, IfNoneMatch: ifNoneMatch,
	}); err != nil {
		if upstream.PreconditionFailed(err) {
			return errPreconditionFailed
		}
		return fmt.Errorf("completing the upload: %w", err)
	}
	committed = true
	cfg.step(h.complete, key)
	return nil
}

// uploadSegment encrypts size bytes of src as one segment and uploads it as a
// part, returning the part's ETag and the segment's salt. The encryption runs
// into a pipe the upload reads, so nothing is held in memory but a chunk.
func uploadSegment(ctx context.Context, cfg Config, stored, uploadID string, number int,
	src io.Reader, size int64, params stream.SegmentParams, dek []byte,
) (string, [stream.SaltSize]byte, error) {
	var salt [stream.SaltSize]byte
	sealed, err := stream.SealedSize(size, cfg.Log2ChunkSize)
	if err != nil {
		return "", salt, err
	}
	pr, pw := io.Pipe()
	saltCh := make(chan [stream.SaltSize]byte, 1)
	done := make(chan error, 1)
	go func() {
		w, err := stream.NewEncryptWriter(pw, dek, params)
		if err != nil {
			close(saltCh)
			_ = pw.CloseWithError(err)
			done <- err
			return
		}
		saltCh <- w.Salt()
		n, err := io.CopyN(w, src, size)
		if err == nil && n != size {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			err = w.Close()
		}
		_ = pw.CloseWithError(err)
		done <- err
	}()

	etag, upErr := cfg.Upstream.UploadPart(ctx, upstream.UploadPartInput{
		Bucket: cfg.Bucket, Key: stored, UploadID: uploadID,
		PartNumber: number, Body: pr, ContentLength: sealed,
	})
	// Unblock the encrypter if the upload stopped reading early.
	_ = pr.CloseWithError(errors.New("the upload ended"))
	encErr := <-done
	if encErr != nil && !errors.Is(encErr, io.ErrClosedPipe) {
		return "", salt, fmt.Errorf("reading the object: %w", encErr)
	}
	if upErr != nil {
		return "", salt, fmt.Errorf("uploading part %d: %w", number, upErr)
	}
	if encErr != nil {
		return "", salt, fmt.Errorf("reading the object: %w", encErr)
	}
	salt, ok := <-saltCh
	if !ok {
		return "", salt, errors.New("the encrypter did not start")
	}
	return etag, salt, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
