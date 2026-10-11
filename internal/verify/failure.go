package verify

import (
	"errors"
	"fmt"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

// Kind is what kind of check an object failed.
//
// The set is the one blindbucket_integrity_failures_total{kind} already uses,
// plus the two outcomes that are not tampering but still mean the object cannot
// be read: metadata that does not parse, and a key the keyring does not hold. It
// is bounded on purpose, because scrub reports it in a stable JSON document and
// a reader has to be able to act on every value.
type Kind string

const (
	// KindMetadata is bb-* metadata that does not parse.
	KindMetadata Kind = "metadata"
	// KindUnknownKID is a data key wrapped under a KEK the keyring does not
	// hold. Not evidence of tampering -- a key removed too early looks the same
	// -- but the object cannot be read with this keyring.
	KindUnknownKID Kind = "unknown_kid"
	// KindDEKUnwrap is a data key that fails to unwrap: wrong bucket or key in
	// its associated data, or altered.
	KindDEKUnwrap Kind = "dek_unwrap"
	// KindHeader is a segment header that is malformed or not the one demanded.
	KindHeader Kind = "header"
	// KindChunk is a chunk that fails authentication.
	KindChunk Kind = "chunk"
	// KindSize is a stored size no encoder could produce, or one that disagrees
	// with the manifest.
	KindSize Kind = "size"
	// KindManifest is a manifest that is missing, fails to verify, or names a
	// different attempt for a part than the one stored.
	//
	// The last case is where this set and the proxy's metric label differ. The
	// proxy finds a substituted attempt while opening the part's header and
	// counts it under "header"; a scrub names it for what it is, a part the
	// manifest does not describe. The verdict is the same either way.
	KindManifest Kind = "manifest"
)

// Failure is an object that failed a check. Anything else this package returns
// is a failure to reach the provider, which says nothing about the object.
type Failure struct {
	Kind Kind
	// Check names the step that failed, in the words the proxy has always
	// logged and labelled metrics with ("first chunk", "object size"). It is for
	// people and for the proxy's metric mapping; Kind is for programs.
	Check string
	Err   error
}

func (f *Failure) Error() string { return fmt.Sprintf("%s: %v", f.Check, f.Err) }
func (f *Failure) Unwrap() error { return f.Err }

// AsFailure reports whether err is a Failure.
func AsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}

func fail(kind Kind, check string, err error) *Failure {
	return &Failure{Kind: kind, Check: check, Err: err}
}

// streamKind classifies an error from reading a segment: an authentication
// failure inside the stream by what the stream says it was, a manifest mismatch
// discovered while opening a part as a manifest failure.
func streamKind(err error) (Kind, bool) {
	if ie, ok := stream.AsIntegrityError(err); ok {
		switch ie.Kind {
		case stream.KindHeader:
			return KindHeader, true
		case stream.KindSize:
			return KindSize, true
		default:
			return KindChunk, true
		}
	}
	if errors.Is(err, manifest.ErrVerify) {
		return KindManifest, true
	}
	return "", false
}
