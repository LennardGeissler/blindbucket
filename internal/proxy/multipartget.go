package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/LennardGeissler/blindbucket/internal/verify"
)

// rangeSpan is one part's contribution to a range request.
type rangeSpan struct {
	index int
	rng   stream.Range
	// headerSeparate reports whether this part's header lies before the
	// ciphertext the body request starts at, so it has to be fetched on its own.
	headerSeparate bool
	// rawHeader holds the separately fetched header.
	rawHeader []byte
}

// planRange works out which parts a plaintext range touches and what ciphertext
// has to be fetched for each.
//
// Only the first touched part can begin mid-part: every later one is entered at
// its own offset zero. That is what keeps the fetch to a single contiguous
// ciphertext run, plus at most one small request for the first part's header --
// the same shape as a range on a single-part object.
func planRange(l *verify.Layout, start, end int64) ([]rangeSpan, error) {
	if start < 0 || end < start || start >= l.TotalPlain {
		return nil, stream.ErrRangeNotSatisfiable
	}
	if end >= l.TotalPlain {
		end = l.TotalPlain - 1
	}

	first := l.Locate(start)
	last := l.Locate(end)
	spans := make([]rangeSpan, 0, last-first+1)

	for i := first; i <= last; i++ {
		localStart := start - l.PlainStart[i]
		if localStart < 0 {
			localStart = 0
		}
		localEnd := end - l.PlainStart[i]
		if localEnd > l.Parts[i].PlainSize-1 {
			localEnd = l.Parts[i].PlainSize - 1
		}
		rng, err := stream.MapRange(localStart, localEnd, l.Sealed[i], l.Log2C)
		if err != nil {
			return nil, err
		}
		spans = append(spans, rangeSpan{index: i, rng: rng, headerSeparate: rng.NeedsSeparateHeader})
	}
	return spans, nil
}

// bodyRange returns the inclusive ciphertext range covering every span.
func bodyRange(l *verify.Layout, spans []rangeSpan) (int64, int64) {
	firstSpan := spans[0]
	start := l.CipherStart[firstSpan.index]
	if firstSpan.headerSeparate {
		start += firstSpan.rng.CipherStart
	}
	lastSpan := spans[len(spans)-1]
	end := l.CipherStart[lastSpan.index] + lastSpan.rng.CipherEnd
	return start, end
}

// rangeChain emits the plaintext of a range that may span several parts.
type rangeChain struct {
	src    io.Reader
	dek    []byte
	layout *verify.Layout
	spans  []rangeSpan

	idx int
	cur *stream.RangeReader
	err error
}

func newRangeChain(src io.Reader, dek []byte, layout *verify.Layout, spans []rangeSpan) (*rangeChain, error) {
	c := &rangeChain{src: src, dek: dek, layout: layout, spans: spans}
	if err := c.open(); err != nil {
		return nil, err
	}
	return c, nil
}

// VerifyFirst authenticates the first chunk the range touches.
func (c *rangeChain) VerifyFirst() error {
	if c.cur == nil {
		return c.err
	}
	return c.cur.VerifyFirst()
}

func (c *rangeChain) open() error {
	span := c.spans[c.idx]
	part := c.layout.Parts[span.index]

	header := span.rawHeader
	if header == nil {
		// The header sits immediately before this part's chunks in the stream.
		header = make([]byte, stream.HeaderSize)
		if _, err := io.ReadFull(c.src, header); err != nil {
			c.err = fmt.Errorf("%w: reading the header of part %d: %w",
				manifest.ErrVerify, part.Number, err)
			return c.err
		}
	}

	if salt, ok := stream.SaltFromHeader(header); !ok {
		c.err = fmt.Errorf("%w: the header of part %d is short",
			manifest.ErrVerify, part.Number)
		return c.err
	} else if err := c.layout.CheckSalt(span.index, salt); err != nil {
		c.err = err
		return err
	}

	// Exactly the ciphertext of the chunks this part contributes, so the reader
	// cannot run into the next part's bytes.
	length := span.rng.CipherEnd - span.rng.CipherStart + 1
	reader, err := stream.NewRangeReader(
		io.LimitReader(c.src, length), header, c.dek,
		stream.SegmentParams{Log2ChunkSize: c.layout.Log2C, Multipart: true, Index: part.Number},
		span.rng,
	)
	if err != nil {
		c.err = err
		return err
	}
	c.cur = reader
	return nil
}

func (c *rangeChain) Read(p []byte) (int, error) {
	for {
		if c.err != nil {
			return 0, c.err
		}
		n, err := c.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if !errors.Is(err, io.EOF) {
			if err != nil {
				c.err = err
			}
			return 0, err
		}
		_ = c.cur.Close()
		c.cur = nil
		c.idx++
		if c.idx >= len(c.spans) {
			c.err = io.EOF
			return 0, io.EOF
		}
		if err := c.open(); err != nil {
			return 0, err
		}
	}
}

func (c *rangeChain) Close() error {
	if c.cur != nil {
		_ = c.cur.Close()
		c.cur = nil
	}
	return nil
}

// rangeLength is the total plaintext a set of spans emits.
func rangeLength(spans []rangeSpan) int64 {
	var total int64
	for _, s := range spans {
		total += s.rng.Length
	}
	return total
}

// isMultipart reports whether an object's metadata names a manifest.
func (p *Proxy) isMultipart(metadata map[string]string, log *slog.Logger) (bool, *s3api.Error) {
	meta, err := parseObjectMeta(metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return false, errNotEncryptedAPI
	}
	if err != nil {
		return false, p.integrityError(log, "object metadata", err)
	}
	return meta.Multipart, nil
}

// plainSize converts a stored ciphertext size into a plaintext size.
//
// For a multipart object the part count comes from the ETag suffix S3 appends
// ("<hash>-<M>"), which is what makes the conversion possible without opening
// the manifest -- the property HEAD and ListObjectsV2 rest on.
func (p *Proxy) plainSize(cipherLen int64, etag string, meta objectMeta) (int64, error) {
	if !meta.Multipart {
		return stream.OpenedSize(cipherLen, meta.Log2ChunkSize)
	}
	segments, ok := partCountFromETag(etag)
	if !ok {
		return 0, fmt.Errorf("object names a manifest but its ETag %q carries no part count", etag)
	}
	return stream.OpenedSizeSegments(cipherLen, meta.Log2ChunkSize, segments)
}

// partCountFromETag reads M from a multipart ETag of the form "<hash>-<M>".
func partCountFromETag(etag string) (int64, bool) {
	trimmed := strings.Trim(etag, `"`)
	_, suffix, found := strings.Cut(trimmed, "-")
	if !found {
		return 0, false
	}
	count, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil || count < 1 || count > stream.MaxParts {
		return 0, false
	}
	return count, true
}

// getMultipartObject serves a whole multipart object.
//
// The manifest is what turns a run of independently authenticated segments into
// one object: without it a provider could drop a part, and every remaining
// segment would still verify on its own. Loading and checking it before the
// status line keeps the fail-closed rule of ADR-004 intact.
func (p *Proxy) getMultipartObject(
	w http.ResponseWriter, r *http.Request, req s3api.Request,
	out *upstream.GetObjectOutput, log *slog.Logger,
) *s3api.Error {
	meta, err := parseObjectMeta(out.Metadata, p.log2C)
	if err != nil {
		return p.integrityError(log, "object metadata", err)
	}
	dek, apiErr := p.unwrapDEK(r, req, meta, log)
	if apiErr != nil {
		return apiErr
	}
	defer clear(dek)

	layout, apiErr := p.multipartLayout(r, req, meta, out.ContentLength, dek, log)
	if apiErr != nil {
		return apiErr
	}

	chain, err := verify.NewSegmentChain(out.Body, dek, layout)
	if err != nil {
		return p.integrityError(log, "segment header", err)
	}
	defer func() { _ = chain.Close() }()

	if err := chain.VerifyFirst(); err != nil {
		return p.integrityError(log, "first chunk", err)
	}

	// Before the status line, like every other check that can refuse a read.
	if apiErr := p.checkFreshness(req.Bucket, req.Key, layout.Salts(), log); apiErr != nil {
		return apiErr
	}

	copyObjectHeaders(w.Header(), r, out.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(layout.TotalPlain, 10))
	w.WriteHeader(http.StatusOK)

	p.metrics.StreamStarted(obs.Download)
	defer p.metrics.StreamFinished(obs.Download)

	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	toClient := &guardedWriter{dst: w, guard: guard}
	written, copyErr := io.Copy(toClient, chain)
	p.metrics.Bytes(obs.InCipher, out.ContentLength)
	p.metrics.Bytes(obs.OutPlain, written)
	p.noteObject(r, meta.KeyID, written)
	if copyErr != nil {
		p.abortResponse(r, log, written, layout.TotalPlain, copyErr, toClient)
	}
	log.Info("multipart object served",
		"parts", len(layout.Parts), "plaintext_bytes", layout.TotalPlain, "kid", meta.KeyID)
	return nil
}

// getMultipartRange serves a byte range of a multipart object.
//
// The manifest's prefix sums locate the part holding the first byte; from there
// the mapping inside each part is the ordinary single-segment one. Only the
// first part touched can start mid-part, so the fetch stays a single contiguous
// ciphertext run plus at most one small request for that part's header.
func (p *Proxy) getMultipartRange(
	w http.ResponseWriter, r *http.Request, req s3api.Request,
	info *upstream.ObjectInfo, meta objectMeta, spec string, log *slog.Logger,
) *s3api.Error {
	dek, apiErr := p.unwrapDEK(r, req, meta, log)
	if apiErr != nil {
		return apiErr
	}
	defer clear(dek)

	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}

	layout, apiErr := p.multipartLayout(r, req, meta, info.ContentLength, dek, log)
	if apiErr != nil {
		return apiErr
	}

	start, end, apiErr := parseRange(spec, layout.TotalPlain)
	if apiErr != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", layout.TotalPlain))
		return apiErr
	}

	spans, err := planRange(layout, start, end)
	if err != nil {
		if errors.Is(err, stream.ErrRangeNotSatisfiable) {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", layout.TotalPlain))
			return s3api.ErrInvalidRange
		}
		return p.integrityError(log, "range mapping", err)
	}

	// The header of the first part touched has to be fetched separately when the
	// range starts past that part's first chunk.
	if spans[0].headerSeparate {
		offset := layout.CipherStart[spans[0].index]
		header, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
			Bucket: req.Bucket, Key: storedKey,
			Range:   fmt.Sprintf("bytes=%d-%d", offset, offset+stream.HeaderSize-1),
			IfMatch: info.ETag,
		})
		if err != nil {
			return translateUpstream(err)
		}
		raw := make([]byte, stream.HeaderSize)
		_, readErr := io.ReadFull(header.Body, raw)
		_ = header.Body.Close()
		if readErr != nil {
			return p.integrityError(log, "segment header", readErr)
		}
		spans[0].rawHeader = raw
	}

	fetchStart, fetchEnd := bodyRange(layout, spans)
	out, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
		Bucket: req.Bucket, Key: storedKey,
		Range:   fmt.Sprintf("bytes=%d-%d", fetchStart, fetchEnd),
		IfMatch: info.ETag,
	})
	if err != nil {
		return translateUpstream(err)
	}
	defer func() { _ = out.Body.Close() }()

	chain, err := newRangeChain(out.Body, dek, layout, spans)
	if err != nil {
		return p.integrityError(log, "segment header", err)
	}
	defer func() { _ = chain.Close() }()

	if err := chain.VerifyFirst(); err != nil {
		return p.integrityError(log, "first chunk", err)
	}

	// The salts come from the manifest, which is itself bound to bucket, key and
	// manifest id (FORMAT.md §10.3) -- so an old manifest served with an old
	// object is a different tag, and this catches the pair.
	if apiErr := p.checkFreshness(req.Bucket, req.Key, layout.Salts(), log); apiErr != nil {
		return apiErr
	}

	length := rangeLength(spans)
	copyObjectHeaders(w.Header(), r, out.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, layout.TotalPlain))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(http.StatusPartialContent)

	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	toClient := &guardedWriter{dst: w, guard: guard}
	written, copyErr := io.Copy(toClient, chain)
	p.noteObject(r, meta.KeyID, written)
	if copyErr != nil {
		p.abortResponse(r, log, written, length, copyErr, toClient)
	}
	log.Info("multipart range served", "start", start, "end", end,
		"bytes", length, "parts_touched", len(spans), "kid", meta.KeyID)
	return nil
}

// multipartLayout loads the manifest and derives the object's geometry from it.
func (p *Proxy) multipartLayout(
	r *http.Request, req s3api.Request, meta objectMeta, storedCipher int64, dek []byte, log *slog.Logger,
) (*verify.Layout, *s3api.Error) {
	// The manifest lives at the hash of the *stored* key and is bound to it,
	// which is what keeps gc free of the name key. The data key went the other
	// way, bound to the identity.
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return nil, apiErr
	}
	m, err := p.loadManifest(r.Context(), req.Bucket, storedKey, meta.ManifestID, dek)
	if err != nil {
		if isManifestFailure(err) {
			return nil, p.integrityError(log, "manifest", err)
		}
		return nil, translateUpstream(err)
	}

	layout, err := verify.NewLayout(m.Parts, meta.Log2ChunkSize, m.HasSalts())
	if err != nil {
		return nil, p.integrityError(log, "manifest", err)
	}
	if err := layout.CheckAgainst(storedCipher); err != nil {
		return nil, p.integrityError(log, "object size", err)
	}
	return layout, nil
}
