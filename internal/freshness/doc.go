// Package freshness detects rollback: a storage provider serving an older but
// genuine version of an object.
//
// The attack this answers is the one thing an active provider can do that the
// object format cannot catch by itself. A swapped object fails to unwrap, because
// the wrapping AAD binds bucket and key (ADR-002). A substituted part is caught by
// the salt the manifest records (ADR-014). A truncated object fails the size check
// of FORMAT.md §10.4. But an *older* version of the same key is not wrong in any
// way a single object can express: the gateway produced it, it is bound to the
// right identity, and every tag verifies. Freshness is not a property of a
// message. It is a property of a message relative to what was seen before, so
// something has to remember.
//
// # What is remembered
//
// One tag per object, derived from the segment salts that FORMAT.md §4.1 already
// requires to be fresh per write and authenticates as associated data of every
// chunk. A provider cannot forge a salt without breaking every tag in the
// segment; it can only serve a whole genuine segment, which is exactly the attack
// being detected. See Tag.
//
// Nothing in the format changes, and the tag survives key rotation for free:
// ADR-009 rotates by re-wrapping metadata and does not move ciphertext.
//
// # The shape of the guarantee
//
// A Store answers Unknown for an object it has not seen, and records it -- trust
// on first use. Every later read of that object is checked. Two limits follow,
// and both are the caller's to communicate rather than this package's to hide:
//
//   - The first read of any object is unchecked. An index that has just been
//     created, or lost, trusts whatever it is shown.
//   - A tag carries no order. Stale means "not the write I last saw", not
//     "older" -- so in a deployment where several instances write the same
//     objects, a peer's legitimate write is indistinguishable from a rollback.
//     That is why rollback detection is off by default and why Store is an
//     interface with room for a shared implementation.
//
// An index is advisory. Losing it loses detection, never data and never
// plaintext, and that asymmetry is what makes a local one affordable where
// ADR-002 rejected a shared one.
//
// The design, its alternatives and what it costs are in
// docs/adr/ADR-018-rollback-detection.md.
package freshness
