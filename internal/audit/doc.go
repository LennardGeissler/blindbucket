// Package audit writes and verifies the gateway's tamper-evident record of what
// it served.
//
// Each served request becomes one entry, and each entry carries the hash of the
// entry before it. Periodically the chain is signed with Ed25519 and flushed.
// Editing, reordering, removing or splicing anything before the last signature
// changes a hash that the signature covers, so it is detectable afterwards -- by
// someone who was not there at the time, and who holds nothing but the public
// key. The design, and what it deliberately does not do, is
// docs/adr/ADR-016-audit-log.md; the on-disk format is docs/FORMAT.md section 14.
//
// # What is and is not claimed
//
// The property is per chain, and it is *this file has not been changed since it
// was signed*. Three things follow that a reader should have straight:
//
// Entries written after the last checkpoint are chained but not signed. Whoever
// holds the file can drop them, and what is left verifies. That window is
// bounded by the checkpoint settings and closed only by comparing against a
// checkpoint recorded somewhere the attacker does not control -- which is what
// Result.SignedThrough is reported for.
//
// This is not rollback protection. Nothing here makes a read consult the log,
// and THREAT_MODEL section 5.1 is unchanged by its existence.
//
// The signing key is on the gateway host. Against an attacker who has the
// running process this proves nothing, and the threat model already says so.
// What it protects is the log after it leaves: a copy, a backup, an archive.
//
// # Names
//
// Bucket and object names in an entry are encrypted with the deterministic
// per-segment construction of internal/crypto/names, under a key derived from
// the audit secret. A log can therefore be shipped off the host without handing
// over what the encrypted bucket does not. Determinism has the cost it always
// has: equality is visible, and a guessed name can be confirmed.
//
// # Concurrency
//
// A Writer is safe for concurrent use. Appends are serialised, because a chain
// is a sequence: two goroutines hashing against the same predecessor would
// produce two entries claiming one position.
package audit
