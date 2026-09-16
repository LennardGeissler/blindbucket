package proxy

import (
	"log/slog"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/freshness"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// The index is keyed on the object's *identity* -- the key the client named --
// and never on the key the provider stores it under. Same choice as the wrapping
// AAD of ADR-002 and for the same reason: turning name encryption on or off must
// not make the gateway forget every object it has seen.

// checkFreshness refuses an object that is not the write the index recorded.
//
// Called where ADR-014's salt comparison is already made: after the header is
// authenticated and the manifest verified, and before a status line goes out.
// That ordering is ADR-004's, and it is the difference between an S3 error and a
// truncated body.
//
// A nil store checks nothing. So does an empty salt list, which is how a caller
// says the object cannot be identified -- a manifest written before BBM2 records
// no salts, and guessing would be worse than declining.
func (p *Proxy) checkFreshness(
	bucket, key string, salts [][stream.SaltSize]byte, log *slog.Logger,
) *s3api.Error {
	if p.fresh == nil || len(salts) == 0 {
		return nil
	}
	tag, err := freshness.TagFromSalts(salts)
	if err != nil {
		log.Error("deriving the freshness tag failed", "err", err)
		return nil
	}
	verdict, err := p.fresh.Check(bucket, key, tag)
	if err != nil {
		// An index that cannot answer is not a reason to refuse an object that
		// authenticated. ADR-018: losing the index costs detection, never data,
		// and a broken index that took the gateway down with it would be a
		// worse failure than the one it guards against.
		log.Error("the freshness index could not be consulted; this read is unchecked",
			"err", err)
		return nil
	}
	switch verdict {
	case freshness.Stale:
		p.metrics.IntegrityFailure(obs.KindFreshness)
		log.Error("rollback detected: the provider served an object that is not the "+
			"write this gateway last recorded",
			"tag", tag.String(), "verdict", verdict.String())
		return s3api.ErrRollback.WithMessage(
			"this object authenticated, but it is not the write this gateway last " +
				"recorded for that key. See docs/adr/ADR-018-rollback-detection.md")
	case freshness.Deleted:
		p.metrics.IntegrityFailure(obs.KindFreshness)
		log.Error("rollback detected: the provider served an object for a key this "+
			"gateway deleted", "tag", tag.String())
		return s3api.ErrRollback.WithMessage(
			"this key was deleted through this gateway and the provider produced an " +
				"object for it anyway. See docs/adr/ADR-018-rollback-detection.md")
	case freshness.Unknown, freshness.Fresh:
		return nil
	}
	return nil
}

// recordFreshness notes a write the provider has acknowledged.
//
// Never before the acknowledgement: recording a write that did not land would
// make the next read of a perfectly good object look like a rollback.
//
// A failure here does not fail the request, because the object *is* stored and
// reporting otherwise would be a lie the client acts on. It is logged loudly and
// counted, and the index drops the entry rather than keeping the previous one --
// so the object falls back to trust on first use instead of reading as a
// rollback of itself.
func (p *Proxy) recordFreshness(
	bucket, key string, salts [][stream.SaltSize]byte, log *slog.Logger,
) {
	if p.fresh == nil || len(salts) == 0 {
		return
	}
	tag, err := freshness.TagFromSalts(salts)
	if err != nil {
		log.Error("deriving the freshness tag failed", "err", err)
		return
	}
	if err := p.fresh.Record(bucket, key, tag); err != nil {
		log.Error("recording the object in the freshness index failed; rollback of "+
			"this object will not be detected until it is read once", "err", err)
	}
}

// forgetFreshness records a delete.
//
// A tombstone rather than a dropped entry: an index that simply forgot would let
// a provider ignore the delete and keep serving the object with nothing to
// disagree.
func (p *Proxy) forgetFreshness(bucket, key string, log *slog.Logger) {
	if p.fresh == nil {
		return
	}
	if err := p.fresh.Forget(bucket, key); err != nil {
		log.Error("recording the delete in the freshness index failed; a suppressed "+
			"delete of this key will not be detected", "err", err)
	}
}

// manifestSalts is the multipart case: the part salts in part order.
//
// Empty for a manifest written before BBM2, which records none. Nothing can be
// said about such an object, and an all-zero salt per part would be a confident
// wrong answer instead of an absent one.
func manifestSalts(m *manifest.Manifest) [][stream.SaltSize]byte {
	if m == nil || !m.HasSalts() {
		return nil
	}
	out := make([][stream.SaltSize]byte, len(m.Parts))
	for i := range m.Parts {
		out[i] = m.Parts[i].Salt
	}
	return out
}

// saltsOf is the single-segment case of a salt list.
func saltsOf(salt [stream.SaltSize]byte) [][stream.SaltSize]byte {
	return [][stream.SaltSize]byte{salt}
}
