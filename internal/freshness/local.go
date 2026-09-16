package freshness

import (
	"bufio"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The on-disk shape. A fixed-width record is what makes replay O(1) per entry
// and a torn tail recoverable: there is no framing to resynchronise, so a short
// or corrupt record can only ever be the last one.
const (
	fileMagic   = "BBFX"
	fileVersion = 1
	headerSize  = 16
	recordSize  = 48

	kindPresent   = 1
	kindTombstone = 2
	// kindInvalid marks a key the index deliberately knows nothing about, after
	// an operation changed the object without the gateway learning which write
	// it produced. It has to be on disk rather than merely absent from the map,
	// or a replay would bring back the entry it replaced.
	kindInvalid = 3
)

// indexInfo derives the key the index actually uses from the keyring's secret.
// Its own info string, so the secret could gain a second use later without the
// two being the same bytes.
const indexInfo = "blindbucket/v1/freshness-index"

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrDamaged reports an index file that is not one, as opposed to one whose tail
// is torn. A wrong magic or version is a configuration mistake -- a path pointing
// at something else -- and silently overwriting it would be the wrong direction
// to be wrong in.
var ErrDamaged = errors.New("freshness: not an index file")

type nameHash [16]byte

type entry struct {
	tag  Tag
	kind uint8
	when int64
}

// Local is a per-instance index backed by an append-only file.
//
// It is deliberately not tamper-evident, and that is not an oversight. ADR-016
// gives the audit log a hash chain and signed checkpoints because its adversary
// is someone who reaches the log file; this index's adversary is the storage
// provider, and THREAT_MODEL §3 already grants that anyone who controls the
// gateway host controls everything on it. A chain here would prove nothing the
// threat model does not already concede. What the per-record checksum does buy
// is the failure that actually happens: a torn write, caught rather than
// replayed as a valid entry.
type Local struct {
	path      string
	retention time.Duration
	syncEvery int64
	log       *slog.Logger
	// now is the clock, overridable in tests. Timestamps have second
	// granularity, which is right for a retention measured in days and useless
	// for a test that wants to observe one expiring.
	now func() int64

	// macs pools the keyed hashes. Building one per call costs 376 ns against
	// 233 ns for a reused one, on a check that happens once per read.
	macs sync.Pool

	mu      sync.Mutex
	m       map[nameHash]entry
	f       *os.File
	records int64
	// sinceSync counts records written since the last fsync. A lost tail costs
	// detection for those objects and nothing else, which is why this is a
	// counter and not an fsync per record.
	sinceSync int64
	closed    bool
}

// Options configures a local index.
type Options struct {
	// Path is the index file. Its directory must exist.
	Path string
	// Key is the keyring's freshness secret, KeySize bytes.
	Key []byte
	// TombstoneRetention is how long a delete is remembered. Tombstones are the
	// one entry that does not shrink when the bucket does, so they expire; past
	// this, a suppressed delete is no longer detectable. Zero means the default.
	TombstoneRetention time.Duration
	// SyncEvery is how many records may be written between fsyncs. Zero means
	// the default.
	SyncEvery int64
	// Logger receives the torn-tail and compaction notices. Zero means discard.
	Logger *slog.Logger
}

const (
	defaultRetention = 90 * 24 * time.Hour
	defaultSyncEvery = 256
	// compactFloor keeps a small index from compacting on every other write.
	compactFloor = 4096
)

// Open loads an index, creating it if it is not there.
//
// A missing file is not an error: an index is advisory, and a gateway starting
// with an empty one is a gateway that has not learned anything yet, not one that
// has failed. A file that exists but is not an index is an error, because that is
// a misconfigured path rather than a fresh start.
func Open(opts Options) (*Local, error) {
	if len(opts.Key) != KeySize {
		return nil, fmt.Errorf("freshness: key is %d bytes, want %d", len(opts.Key), KeySize)
	}
	if opts.Path == "" {
		return nil, errors.New("freshness: no index path configured")
	}
	prf, err := hkdf.Key(sha256.New, opts.Key, nil, indexInfo, KeySize)
	if err != nil {
		return nil, fmt.Errorf("freshness: deriving the index key: %w", err)
	}
	defer clear(prf)

	l := &Local{
		path:      opts.Path,
		retention: cmpOr(opts.TombstoneRetention, defaultRetention),
		syncEvery: cmpOr(opts.SyncEvery, int64(defaultSyncEvery)),
		log:       opts.Logger,
		now:       func() int64 { return time.Now().Unix() },
		m:         make(map[nameHash]entry),
	}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	key := append([]byte(nil), prf...)
	l.macs.New = func() any { return hmac.New(sha256.New, key) }

	if err := l.load(); err != nil {
		return nil, err
	}
	//nolint:gosec // the path comes from the operator's configuration.
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("freshness: opening the index: %w", err)
	}
	l.f = f
	if l.records == 0 {
		if err := l.writeHeader(f); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return l, nil
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
}

// load replays the file into the map.
//
// A torn tail ends the replay and is reported, not treated as corruption of the
// whole: the records before it are intact by construction, because each is
// fixed-width and checksummed. Every object past the tear falls back to trust on
// first use, which is the same place a lost index leaves them.
func (l *Local) load() error {
	//nolint:gosec // the path comes from the operator's configuration.
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("freshness: opening the index: %w", err)
	}
	defer func() { _ = f.Close() }()

	r := bufio.NewReaderSize(f, 1<<20)
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// A file that exists but holds less than a header is one a previous
			// process created and died before writing to. Start over on it.
			l.log.Warn("the freshness index is empty and is being started over",
				"path", l.path)
			return nil
		}
		return fmt.Errorf("freshness: reading the index header: %w", err)
	}
	if string(hdr[0:4]) != fileMagic {
		return fmt.Errorf("%w: %q does not begin with %s", ErrDamaged, l.path, fileMagic)
	}
	if hdr[4] != fileVersion {
		return fmt.Errorf("%w: %q is version %d, this build writes %d",
			ErrDamaged, l.path, hdr[4], fileVersion)
	}
	if got := binary.BigEndian.Uint16(hdr[6:8]); got != recordSize {
		return fmt.Errorf("%w: %q has %d-byte records, this build writes %d",
			ErrDamaged, l.path, got, recordSize)
	}

	var rec [recordSize]byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				l.log.Warn("the freshness index ends in a partial record, which is "+
					"where a previous process stopped; objects after it fall back to "+
					"trust on first use",
					"path", l.path, "records", l.records)
				break
			}
			return fmt.Errorf("freshness: reading the index: %w", err)
		}
		want := binary.BigEndian.Uint32(rec[44:48])
		if crc32.Checksum(rec[0:44], crcTable) != want {
			l.log.Warn("the freshness index ends in a record that does not checksum; "+
				"objects after it fall back to trust on first use",
				"path", l.path, "records", l.records)
			break
		}
		var h nameHash
		copy(h[:], rec[0:16])
		var t Tag
		copy(t[:], rec[16:32])
		// A timestamp past the int64 range cannot have been written by this code
		// and only reaches here from a file someone rebuilt by hand. Zero rather
		// than refuse: it makes the entry look infinitely old, so a tombstone
		// expires at the next compaction instead of outliving the bucket.
		when := binary.BigEndian.Uint64(rec[36:44])
		if when > math.MaxInt64 {
			when = 0
		}
		if rec[32] == kindInvalid {
			delete(l.m, h)
		} else {
			l.m[h] = entry{tag: t, kind: rec[32], when: int64(when)}
		}
		l.records++
	}
	return nil
}

func (l *Local) writeHeader(w io.Writer) error {
	var hdr [headerSize]byte
	copy(hdr[0:4], fileMagic)
	hdr[4] = fileVersion
	binary.BigEndian.PutUint16(hdr[6:8], recordSize)
	//nolint:gosec // a unix timestamp does not overflow int64 in this universe.
	binary.BigEndian.PutUint64(hdr[8:16], uint64(time.Now().Unix()))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("freshness: writing the index header: %w", err)
	}
	return nil
}

// name derives the stored hash of one object's identity.
//
// Bucket and key are length-prefixed for FORMAT.md §1's reason: without it,
// bucket "a" with key "b/c" and bucket "a/b" with key "c" would hash the same,
// and the index would confuse two objects.
func (l *Local) name(bucket, key string) nameHash {
	mac, _ := l.macs.Get().(hash.Hash)
	defer l.macs.Put(mac)
	mac.Reset()
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(bucket)))
	_, _ = mac.Write(lp[:])
	_, _ = mac.Write([]byte(bucket))
	binary.BigEndian.PutUint64(lp[:], uint64(len(key)))
	_, _ = mac.Write(lp[:])
	_, _ = mac.Write([]byte(key))
	var h nameHash
	copy(h[:], mac.Sum(nil))
	return h
}

// Check implements Store.
func (l *Local) Check(bucket, key string, tag Tag) (Verdict, error) {
	h := l.name(bucket, key)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return Unknown, errors.New("freshness: the index is closed")
	}
	got, ok := l.m[h]
	switch {
	case !ok:
		// Trust on first use. Recorded under the same lock that found it absent,
		// so two concurrent first reads of one object cannot each decide to
		// record a different tag.
		if err := l.appendLocked(h, tag, kindPresent); err != nil {
			return Unknown, err
		}
		return Unknown, nil
	case got.kind == kindTombstone:
		return Deleted, nil
	case got.tag == tag:
		return Fresh, nil
	default:
		return Stale, nil
	}
}

// Record implements Store.
func (l *Local) Record(bucket, key string, tag Tag) error {
	h := l.name(bucket, key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("freshness: the index is closed")
	}
	return l.appendLocked(h, tag, kindPresent)
}

// Forget implements Store.
func (l *Local) Forget(bucket, key string) error {
	h := l.name(bucket, key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("freshness: the index is closed")
	}
	return l.appendLocked(h, Tag{}, kindTombstone)
}

// Invalidate implements Store.
//
// It writes no record: the index is rebuilt from the file, so an entry that is
// dropped from both is simply absent, and absent is exactly the state wanted.
// The superseded records for this key stay in the file until the next compaction
// drops them, which is harmless because replay takes the last one and there is
// no last one for a key with no live entry.
func (l *Local) Invalidate(bucket, key string) error {
	h := l.name(bucket, key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("freshness: the index is closed")
	}
	if _, ok := l.m[h]; !ok {
		return nil
	}
	// A record has to be written even though the map entry is simply removed:
	// replay reads the file, and without it the entry just dropped would come
	// back at the next start.
	delete(l.m, h)
	if err := l.writeRecordLocked(h, Tag{}, kindInvalid, l.now()); err != nil {
		return err
	}
	return l.maintainLocked()
}

// writeRecordLocked appends one record and does not touch the map.
func (l *Local) writeRecordLocked(h nameHash, tag Tag, kind uint8, now int64) error {
	var rec [recordSize]byte
	copy(rec[0:16], h[:])
	copy(rec[16:32], tag[:])
	rec[32] = kind
	//nolint:gosec // a unix timestamp does not overflow int64 in this universe.
	binary.BigEndian.PutUint64(rec[36:44], uint64(now))
	binary.BigEndian.PutUint32(rec[44:48], crc32.Checksum(rec[0:44], crcTable))

	if _, err := l.f.Write(rec[:]); err != nil {
		return fmt.Errorf("freshness: appending to the index: %w", err)
	}
	l.records++
	l.sinceSync++
	return nil
}

func (l *Local) appendLocked(h nameHash, tag Tag, kind uint8) error {
	now := l.now()
	if err := l.writeRecordLocked(h, tag, kind, now); err != nil {
		// The entry is dropped rather than left behind. What is in the map is
		// the *previous* write of this object, and keeping it would be the
		// dangerous failure: the object that was just stored would read back as
		// a rollback of itself, and a full disk would turn good objects
		// unreadable. Forgetting degrades to trust on first use instead, which
		// is the direction ADR-018 says to be wrong in.
		delete(l.m, h)
		return err
	}
	l.m[h] = entry{tag: tag, kind: kind, when: now}
	return l.maintainLocked()
}

// maintainLocked syncs on the configured interval and compacts when the file has
// grown past twice what it needs to hold.
func (l *Local) maintainLocked() error {
	if l.sinceSync >= l.syncEvery {
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("freshness: syncing the index: %w", err)
		}
		l.sinceSync = 0
	}
	if l.records > 2*int64(len(l.m))+compactFloor {
		return l.compactLocked()
	}
	return nil
}

// compactLocked rewrites the file from the map, dropping superseded records and
// expired tombstones.
//
// Through a temporary file and a rename, so that a crash in the middle leaves
// the old index rather than half of a new one. Losing an index costs detection,
// but losing it *silently in the middle of maintenance* would be the kind of
// thing an operator finds out about at the worst moment.
func (l *Local) compactLocked() error {
	cutoff := l.now() - int64(l.retention.Seconds())
	tmp := l.path + ".compact"
	//nolint:gosec // the path comes from the operator's configuration.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("freshness: compacting the index: %w", err)
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}

	w := bufio.NewWriterSize(f, 1<<20)
	if err := l.writeHeader(w); err != nil {
		cleanup()
		return err
	}
	kept := make(map[nameHash]entry, len(l.m))
	var rec [recordSize]byte
	for h, e := range l.m {
		if e.kind == kindTombstone && e.when < cutoff {
			continue
		}
		copy(rec[0:16], h[:])
		copy(rec[16:32], e.tag[:])
		rec[32] = e.kind
		//nolint:gosec // a unix timestamp does not overflow int64 in this universe.
		binary.BigEndian.PutUint64(rec[36:44], uint64(e.when))
		binary.BigEndian.PutUint32(rec[44:48], crc32.Checksum(rec[0:44], crcTable))
		if _, err := w.Write(rec[:]); err != nil {
			cleanup()
			return fmt.Errorf("freshness: compacting the index: %w", err)
		}
		kept[h] = e
	}
	if err := w.Flush(); err != nil {
		cleanup()
		return fmt.Errorf("freshness: compacting the index: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("freshness: compacting the index: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("freshness: compacting the index: %w", err)
	}
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("freshness: replacing the index: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("freshness: closing the old index: %w", err)
	}
	//nolint:gosec // the path comes from the operator's configuration.
	reopened, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("freshness: reopening the index: %w", err)
	}
	dropped := len(l.m) - len(kept)
	l.f = reopened
	l.m = kept
	l.records = int64(len(kept))
	l.sinceSync = 0
	l.log.Info("compacted the freshness index",
		"objects", len(kept), "expired_tombstones", dropped, "path", l.path)
	return l.syncDir()
}

// syncDir makes the rename durable. Renaming is atomic, but on most filesystems
// the directory entry is not on disk until the directory itself is synced.
func (l *Local) syncDir() error {
	d, err := os.Open(filepath.Dir(l.path))
	if err != nil {
		return fmt.Errorf("freshness: opening the index directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("freshness: syncing the index directory: %w", err)
	}
	return nil
}

// Stats implements Store.
func (l *Local) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Stats{Records: l.records}
	for _, e := range l.m {
		if e.kind == kindTombstone {
			s.Tombstones++
		} else {
			s.Objects++
		}
	}
	return s
}

// Close implements Store.
func (l *Local) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if err := l.f.Sync(); err != nil {
		_ = l.f.Close()
		return fmt.Errorf("freshness: syncing the index: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("freshness: closing the index: %w", err)
	}
	return nil
}
