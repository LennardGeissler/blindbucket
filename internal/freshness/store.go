package freshness

import "errors"

// Verdict is what an index has to say about one object.
type Verdict int

const (
	// Unknown means the index has never seen this object. It is not a failure:
	// an index that has just been created, or lost, knows nothing, and the read
	// proceeds. A Store records the object when it answers this, which is the
	// trust-on-first-use bound of ADR-018.
	Unknown Verdict = iota

	// Fresh means the object carries the tag the index recorded.
	Fresh

	// Stale means it does not. In a single-writer deployment that is a rollback.
	// In one where several instances write the same objects it may equally be a
	// peer's legitimate write, because a tag carries no order -- ADR-018 says so
	// in those words, and it is why this is off by default.
	Stale

	// Deleted means the index recorded a delete for this key and the provider
	// produced an object anyway: a suppressed DeleteObject.
	Deleted
)

func (v Verdict) String() string {
	switch v {
	case Unknown:
		return "unknown"
	case Fresh:
		return "fresh"
	case Stale:
		return "stale"
	case Deleted:
		return "deleted"
	}
	return "invalid"
}

// OK reports whether a read may proceed on this verdict.
func (v Verdict) OK() bool { return v == Unknown || v == Fresh }

// ErrStale reports a read whose object does not match the index. It is the error
// a caller turns into a refusal; ErrDeleted is its counterpart for a key the
// index recorded as gone.
var (
	ErrStale   = errors.New("freshness: the object is not the version this gateway last recorded")
	ErrDeleted = errors.New("freshness: this key was deleted and the provider produced an object anyway")
)

// Stats describes what an index is holding, for the metrics endpoint and for
// `blindbucket freshness`.
type Stats struct {
	// Objects and Tombstones are live entries. Objects is the number the memory
	// cost of ADR-018 is proportional to.
	Objects    int
	Tombstones int
	// Records is how many entries the backing file holds, live or superseded.
	// The ratio to Objects+Tombstones is what compaction acts on.
	Records int64
}

// Store remembers which write of each object is the current one.
//
// The local implementation is per instance and holds no lock any other instance
// waits on. The interface exists because ADR-018 leaves room for a shared one:
// a local index cannot tell a rollback from a peer instance's write, and a
// deployment that needs it to can pay for a backend that can.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Check reports what the index knows about an object, and records the tag
	// when the answer is Unknown.
	Check(bucket, key string, tag Tag) (Verdict, error)

	// Record notes that this write is now the current one, replacing whatever
	// was there. It is called after a write the provider has acknowledged, never
	// before: recording a write that did not land would make the next read of a
	// perfectly good object look like a rollback.
	Record(bucket, key string, tag Tag) error

	// Forget records that the key is gone. A tombstone rather than a deletion,
	// because an index that simply dropped the entry would let a provider ignore
	// the delete and keep serving the object with nothing to disagree.
	Forget(bucket, key string) error

	// Invalidate drops what the index knows about a key, returning it to trust
	// on first use.
	//
	// For the operation that changed an object without the gateway being able to
	// name the write it produced -- a server-side copy, where the destination's
	// ciphertext comes from the source and its salts are never read. Neither of
	// the other two would do: keeping the old tag would make the copy read back
	// as a rollback of whatever it replaced, and a tombstone would make it read
	// back as a suppressed delete. Both would refuse a perfectly good object.
	Invalidate(bucket, key string) error

	// Stats describes what is held.
	Stats() Stats

	// Close flushes and releases the index.
	Close() error
}
