// Package verify is the read path's authentication of a stored object, apart
// from the HTTP that serves it.
//
// It exists separately because two callers must run exactly the same checks:
// the proxy, which verifies an object while it streams the plaintext to a
// client, and `blindbucket scrub`, which verifies an object to say whether it
// is intact and throws the plaintext away (ADR-028). A scrub that checked
// differently from a read would be a second opinion rather than a check -- an
// object it passed could still fail the read that mattered.
//
// What is here is the whole of what a GET of an entire object establishes: the
// metadata parses, the data key unwraps under the object's bucket and key
// (FORMAT.md §6), the segment header is the one the reader demands, every chunk
// authenticates, and for a multipart object the manifest verifies under the data
// key, its geometry matches the stored size, and every part is the attempt the
// manifest names (FORMAT.md §10). Rollback detection is not here: it needs the
// freshness index, which belongs to a running gateway (ADR-018).
//
// Range reads stay in the proxy. They map plaintext offsets onto this package's
// Layout, but serving a range is a different question from whether an object is
// intact.
package verify
