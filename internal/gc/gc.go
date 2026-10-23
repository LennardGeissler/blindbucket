// Package gc collects orphaned multipart manifests.
//
// A manifest becomes an orphan whenever an object version stops being visible
// without its manifest being removed: a single-part PUT over a multipart object
// (which skips the HEAD deliberately, to keep the common write path cheap), an
// upload that crashed or was aborted, a DeleteObjects batch. Orphans hold no
// plaintext and cost only storage, but they accumulate.
//
// Deleting them is the dangerous half. A manifest that looks orphaned may belong
// to an upload that is about to complete, and removing it produces exactly the
// failure invariant I1 forbids: a visible multipart object that nothing can read.
// The order below is rule R4 from ADR-010, it is checked by the
// model in spec/tla/Multipart.tla, and two of its steps are load-bearing in ways
// that are not obvious from reading them:
//
//  1. List the manifests of the key.
//  2. ListMultipartUploads; if anything is open for that key, skip it entirely.
//  3. HEAD the object for the manifest id in use right now.
//  4. Delete the listed manifests that are neither current nor younger than a
//     minimum age.
//
// Steps 1 and 2 both only read, and swapping them breaks the invariant: the
// model finds a counterexample in twelve states, because a check that runs
// before the listing says nothing about manifests written after it. Listing
// first is what gives the check its meaning.
package gc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// DefaultMinAge is how old an orphan must be before gc removes it.
//
// It is the second line of defence behind the ordering rules: those already make
// the deletion safe under the upstream consistency assumptions of section 10.8,
// and this covers the case where one of those assumptions does not hold at a
// particular provider. The default assumes the seven-day lifecycle rule for
// incomplete multipart uploads that the README recommends, plus a day.
const DefaultMinAge = 8 * 24 * time.Hour

// maxManifestBytes bounds a manifest read from the provider.
const maxManifestBytes = 1 << 20

// Config configures a collection run.
type Config struct {
	Upstream *upstream.Client
	Bucket   string
	// Prefix restricts the run to object keys under it. Empty means the whole
	// bucket.
	Prefix string
	// MinAge is the minimum age of a manifest before it may be deleted. Zero
	// selects DefaultMinAge, so a caller cannot lose the guard by forgetting it.
	MinAge time.Duration
	// DisableMinAge drops the age guard entirely, leaving only the ordering
	// rules. Those are what actually make the deletion safe -- the age is the
	// second line of defence behind them -- but dropping it is a deliberate
	// choice, not something a zero value should do silently.
	DisableMinAge bool
	// DryRun reports what would be deleted without deleting anything.
	DryRun bool

	Now func() time.Time
	Log *slog.Logger

	// Hook is called after each step of the R4 order, named as in
	// spec/tla/Multipart.tla. It exists so that the integration tests can hold a
	// pass between two steps and replay the model's counterexamples; it is nil
	// everywhere else.
	Hook func(point, objectKey string)
}

// Step names of the R4 order, matching the model's actions.
const (
	HookList    = "gcStepOne" // after the manifests are listed
	HookUploads = "gcStepTwo" // after ListMultipartUploads
	HookHead    = "gcHead"    // after the current manifest id is read
	HookDelete  = "gcDelete"  // after the orphans are deleted
)

// at runs the hook, if one is installed.
func (c Config) at(point, objectKey string) {
	if c.Hook != nil {
		c.Hook(point, objectKey)
	}
}

// Result reports what a run did.
type Result struct {
	ManifestsSeen int
	KeysScanned   int
	// KeysSkipped counts keys passed over because an upload was in flight.
	KeysSkipped int
	Deleted     int
	// KeptCurrent counts manifests that belong to the visible object version.
	KeptCurrent int
	// KeptTooYoung counts orphans held back by the minimum age.
	KeptTooYoung int
	// KeptUnreadable counts manifests whose own location contradicts the key
	// they name, which means they were not written by this gateway.
	KeptUnreadable int
	Errors         int
}

// Run performs one collection pass.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Upstream == nil {
		return nil, errors.New("gc: an upstream client is required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("gc: a bucket is required")
	}
	if cfg.MinAge == 0 {
		cfg.MinAge = DefaultMinAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	// Step 1, for every key at once: the manifests that exist right now. Doing
	// this before any open-upload check is what rule R4 requires, and the reason
	// the listing happens up front rather than per key.
	groups, result, err := listManifests(ctx, cfg)
	if err != nil {
		return nil, err
	}
	cfg.at(HookList, "")

	for _, entries := range groups {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		collectKey(ctx, cfg, entries, result)
	}
	return result, nil
}

// manifestEntry is one manifest as the listing reports it.
type manifestEntry struct {
	objectKey    string // the manifest's own key, under .blindbucket/m/
	id           manifest.ID
	lastModified time.Time
}

// listManifests performs step 1: every manifest under the reserved prefix,
// grouped by the hash directory that stands for one object key.
func listManifests(ctx context.Context, cfg Config) (map[string][]manifestEntry, *Result, error) {
	result := &Result{}
	groups := make(map[string][]manifestEntry)

	query := url.Values{"list-type": {"2"}, "prefix": {manifest.Prefix}, "max-keys": {"1000"}}
	for {
		page, err := cfg.Upstream.ListObjects(ctx, cfg.Bucket, query)
		if err != nil {
			return nil, nil, fmt.Errorf("gc: listing manifests: %w", err)
		}
		for _, entry := range page.Contents {
			hash, id, ok := splitManifestKey(entry.Key)
			if !ok {
				cfg.Log.Debug("ignoring an object under the manifest prefix", "key", entry.Key)
				continue
			}
			modified, _ := time.Parse(time.RFC3339, entry.LastModified)
			groups[hash] = append(groups[hash], manifestEntry{
				objectKey: entry.Key, id: id, lastModified: modified,
			})
			result.ManifestsSeen++
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
	return groups, result, nil
}

// collectKey runs steps 2 to 4 for the manifests of one object key.
func collectKey(ctx context.Context, cfg Config, entries []manifestEntry, result *Result) {
	// The object key is not in the path -- only its hash is -- so it has to come
	// out of a manifest. That value is unauthenticated, which is why it is only
	// used once it hashes back to the directory it was found in.
	objectKey, ok := resolveObjectKey(ctx, cfg, entries)
	if !ok {
		result.KeptUnreadable += len(entries)
		return
	}
	if cfg.Prefix != "" && !strings.HasPrefix(objectKey, cfg.Prefix) {
		return
	}
	result.KeysScanned++
	log := cfg.Log.With("key", objectKey)

	// Step 2: an upload in flight may be about to publish one of the manifests
	// listed in step 1, and nothing here can tell which. Skip the key entirely.
	uploads, err := cfg.Upstream.ListMultipartUploads(ctx, cfg.Bucket, objectKey)
	if err != nil {
		log.Warn("could not list open uploads; skipping the key", "err", err)
		result.Errors++
		return
	}
	cfg.at(HookUploads, objectKey)
	for _, upload := range uploads {
		if upload.Key == objectKey {
			log.Debug("an upload is in flight; skipping the key")
			result.KeysSkipped++
			return
		}
	}

	// Step 3: which manifest the visible object actually uses. Only a HEAD
	// that says the object is gone licenses deleting every manifest of the key;
	// one that failed says nothing, and taking it for "gone" would delete the
	// manifest of a visible object -- the failure I1 forbids.
	current, hasCurrent, err := currentManifestID(ctx, cfg, objectKey)
	if err != nil {
		log.Warn("could not read the object's manifest id; skipping the key", "err", err)
		result.Errors++
		return
	}
	cfg.at(HookHead, objectKey)

	// Step 4: everything else, once it is old enough.
	//
	// The comparison is between the provider's clock, which stamped the
	// manifest, and this host's. They are not the same clock, so a manifest can
	// look a second old or a second into the future. At the real threshold --
	// days -- that is noise. It is only visible when the guard is switched off,
	// which is why switching it off skips the comparison rather than setting the
	// threshold to zero.
	cutoff := cfg.Now().Add(-cfg.MinAge)
	tooYoung := func(entry manifestEntry) bool {
		if cfg.DisableMinAge {
			return false
		}
		return entry.lastModified.IsZero() || entry.lastModified.After(cutoff)
	}

	for _, entry := range entries {
		if hasCurrent && entry.id == current {
			result.KeptCurrent++
			continue
		}
		if tooYoung(entry) {
			result.KeptTooYoung++
			continue
		}
		if cfg.DryRun {
			log.Info("would delete an orphaned manifest", "manifest_id", entry.id.String())
			result.Deleted++
			continue
		}
		if err := cfg.Upstream.DeleteObject(ctx, cfg.Bucket, entry.objectKey); err != nil {
			log.Warn("could not delete an orphaned manifest",
				"manifest_id", entry.id.String(), "err", err)
			result.Errors++
			continue
		}
		log.Info("deleted an orphaned manifest", "manifest_id", entry.id.String())
		result.Deleted++
	}
	cfg.at(HookDelete, objectKey)
}

// resolveObjectKey learns which object a hash directory belongs to.
//
// It reads the key out of a manifest and accepts it only if the key hashes back
// to the directory the manifest was found in. SHA-256 is collision-resistant, so
// a key that passes is the key that directory belongs to -- which means a forged
// manifest cannot make gc look at, and act on, a different object.
func resolveObjectKey(ctx context.Context, cfg Config, entries []manifestEntry) (string, bool) {
	for _, entry := range entries {
		out, err := cfg.Upstream.GetObject(ctx, upstream.GetObjectInput{
			Bucket: cfg.Bucket, Key: entry.objectKey,
		})
		if err != nil {
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(out.Body, maxManifestBytes))
		_ = out.Body.Close()
		if readErr != nil {
			continue
		}
		_, key, _, err := manifest.PeekIdentity(raw)
		if err != nil {
			continue
		}
		if !manifest.MatchesLocation(key, entry.objectKey) {
			cfg.Log.Warn("a manifest names a key that does not hash to its own location; ignoring it",
				"manifest", entry.objectKey)
			continue
		}
		return key, true
	}
	return "", false
}

// currentManifestID reports the manifest id of the visible object, if it is a
// multipart one. An error is a HEAD that failed for any reason but the object
// being gone.
func currentManifestID(ctx context.Context, cfg Config, objectKey string) (manifest.ID, bool, error) {
	info, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, objectKey)
	if upstream.NotFound(err) {
		// A missing object means every manifest here is an orphan, which is the
		// ordinary case after a delete.
		return manifest.ID{}, false, nil
	}
	if err != nil {
		return manifest.ID{}, false, err
	}
	for name, value := range info.Metadata {
		if !strings.EqualFold(name, "bb-mid") {
			continue
		}
		id, err := manifest.ParseID(value)
		if err != nil {
			// A bb-mid that does not parse names no manifest, and nothing is
			// gained by deleting the ones there are.
			return manifest.ID{}, false, fmt.Errorf("the object's bb-mid %q does not parse: %w", value, err)
		}
		return id, true, nil
	}
	return manifest.ID{}, false, nil
}

// splitManifestKey takes a manifest's own object key apart.
func splitManifestKey(key string) (hash string, id manifest.ID, ok bool) {
	rest, found := strings.CutPrefix(key, manifest.Prefix)
	if !found {
		return "", manifest.ID{}, false
	}
	hash, rawID, found := strings.Cut(rest, "/")
	if !found || len(hash) != 64 || strings.Contains(rawID, "/") {
		return "", manifest.ID{}, false
	}
	parsed, err := manifest.ParseID(rawID)
	if err != nil {
		return "", manifest.ID{}, false
	}
	return hash, parsed, true
}
