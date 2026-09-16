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
)

// partLayout is the ciphertext geometry of a multipart object.
//
// A multipart object is the concatenation of one segment per part, so every
// part's ciphertext offset follows from the plaintext sizes in the manifest and
// the chunk size. That arithmetic is what makes a range request on a multipart
// object cost the chunks it touches rather than the whole object.
type partLayout struct {
	parts []manifest.Part
	// sealed[i] is the ciphertext size of part i's segment.
	sealed []int64
	// cipherStart[i] and plainStart[i] are part i's offsets within the object.
	cipherStart []int64
	plainStart  []int64

	totalCipher int64
	totalPlain  int64
	log2C       uint8
	// hasSalts reports that the manifest names which attempt each part is, so
	// the segment headers can be checked against it. False for a manifest
	// written before BBM2, where there is nothing to check against and an
	// all-zero salt must not be mistaken for one.
	hasSalts bool
}

// checkSalt refuses a segment that is not the attempt the manifest names.
//
// A client that retries a part leaves two valid segments under the same part
// number, both authentic. Without this, a provider could serve either one and
// every tag would verify -- THREAT_MODEL section 5.2. The salt is in the
// authenticated header, so a provider cannot fake it without breaking every
// chunk in the segment; it can only substitute a whole genuine segment, which
// is exactly what this catches.
func (l *partLayout) checkSalt(i int, got [stream.SaltSize]byte) error {
	if !l.hasSalts {
		return nil
	}
	if got != l.parts[i].Salt {
		return fmt.Errorf(
			"%w: part %d is a different attempt than the manifest names",
			manifest.ErrVerify, l.parts[i].Number)
	}
	return nil
}

// salts returns the part salts in part order, for the freshness tag of ADR-018.
//
// Empty when the manifest predates BBM2 and records none. Nothing can be said
// about such an object's identity, and an all-zero salt per part would be a
// confident wrong answer rather than an absent one.
func (l *partLayout) salts() [][stream.SaltSize]byte {
	if !l.hasSalts {
		return nil
	}
	out := make([][stream.SaltSize]byte, len(l.parts))
	for i := range l.parts {
		out[i] = l.parts[i].Salt
	}
	return out
}

// newPartLayout computes the geometry of the parts a manifest describes.
func newPartLayout(parts []manifest.Part, log2C uint8, hasSalts bool) (*partLayout, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: the manifest lists no parts", manifest.ErrVerify)
	}
	l := &partLayout{
		parts:       parts,
		hasSalts:    hasSalts,
		sealed:      make([]int64, len(parts)),
		cipherStart: make([]int64, len(parts)),
		plainStart:  make([]int64, len(parts)),
		log2C:       log2C,
	}
	for i, part := range parts {
		sealed, err := stream.SealedSize(part.PlainSize, log2C)
		if err != nil {
			return nil, fmt.Errorf("%w: part %d has an impossible size: %w",
				manifest.ErrVerify, part.Number, err)
		}
		l.sealed[i] = sealed
		l.cipherStart[i] = l.totalCipher
		l.plainStart[i] = l.totalPlain
		l.totalCipher += sealed
		l.totalPlain += part.PlainSize
	}
	return l, nil
}

// checkAgainst verifies the manifest's geometry against the object the provider
// actually stores.
//
// The manifest is authenticated and the stored size is not, so a mismatch means
// the provider is serving something other than the object this manifest
// describes -- a truncated object, or parts from elsewhere. Either way it is an
// integrity failure and not a size to be worked around.
func (l *partLayout) checkAgainst(storedCipher int64) error {
	if storedCipher != l.totalCipher {
		return fmt.Errorf("%w: the object is %d bytes of ciphertext, the manifest describes %d",
			manifest.ErrVerify, storedCipher, l.totalCipher)
	}
	return nil
}

// locate returns the index of the part holding a plaintext offset.
func (l *partLayout) locate(offset int64) int {
	// Linear from the front is fine: the list is at most 10000 entries and this
	// runs once per range request, not per chunk.
	for i := len(l.parts) - 1; i >= 0; i-- {
		if offset >= l.plainStart[i] {
			return i
		}
	}
	return 0
}

// segmentChain decrypts the segments of a multipart object in order.
//
// Each part is its own segment and must be decrypted as one: a DecryptReader
// decides whether a chunk is the segment's last by looking one byte ahead, so
// feeding it the concatenation directly would make every part but the last fail
// authentication. Bounding each part to its exact ciphertext size is what puts
// the end of the stream where the format says it is.
type segmentChain struct {
	src    io.Reader
	dek    []byte
	layout *partLayout

	idx int
	cur *stream.DecryptReader
	err error
}

func newSegmentChain(src io.Reader, dek []byte, layout *partLayout) (*segmentChain, error) {
	c := &segmentChain{src: src, dek: dek, layout: layout}
	if err := c.open(); err != nil {
		return nil, err
	}
	return c, nil
}

// VerifyFirst authenticates the first chunk of the first part, before the caller
// commits to a status line. See docs/adr/ADR-004-fail-closed.md.
func (c *segmentChain) VerifyFirst() error {
	if c.cur == nil {
		return c.err
	}
	return c.cur.VerifyFirst()
}

// open starts the segment at c.idx.
func (c *segmentChain) open() error {
	part := c.layout.parts[c.idx]
	reader, err := stream.NewDecryptReader(
		io.LimitReader(c.src, c.layout.sealed[c.idx]),
		c.dek,
		// The part number is demanded, not merely read: a provider that serves
		// part 7 where part 3 belongs fails here, because the index is
		// authenticated in the segment header.
		stream.SegmentParams{Log2ChunkSize: c.layout.log2C, Multipart: true, Index: part.Number},
	)
	if err != nil {
		c.err = err
		return err
	}
	if err := c.layout.checkSalt(c.idx, reader.Salt()); err != nil {
		_ = reader.Close()
		c.err = err
		return err
	}
	c.cur = reader
	return nil
}

func (c *segmentChain) Read(p []byte) (int, error) {
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
		if c.idx >= len(c.layout.parts) {
			c.err = io.EOF
			return 0, io.EOF
		}
		if err := c.open(); err != nil {
			return 0, err
		}
	}
}

func (c *segmentChain) Close() error {
	if c.cur != nil {
		_ = c.cur.Close()
		c.cur = nil
	}
	return nil
}

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
func (l *partLayout) planRange(start, end int64) ([]rangeSpan, error) {
	if start < 0 || end < start || start >= l.totalPlain {
		return nil, stream.ErrRangeNotSatisfiable
	}
	if end >= l.totalPlain {
		end = l.totalPlain - 1
	}

	first := l.locate(start)
	last := l.locate(end)
	spans := make([]rangeSpan, 0, last-first+1)

	for i := first; i <= last; i++ {
		localStart := start - l.plainStart[i]
		if localStart < 0 {
			localStart = 0
		}
		localEnd := end - l.plainStart[i]
		if localEnd > l.parts[i].PlainSize-1 {
			localEnd = l.parts[i].PlainSize - 1
		}
		rng, err := stream.MapRange(localStart, localEnd, l.sealed[i], l.log2C)
		if err != nil {
			return nil, err
		}
		spans = append(spans, rangeSpan{index: i, rng: rng, headerSeparate: rng.NeedsSeparateHeader})
	}
	return spans, nil
}

// bodyRange returns the inclusive ciphertext range covering every span.
func (l *partLayout) bodyRange(spans []rangeSpan) (int64, int64) {
	firstSpan := spans[0]
	start := l.cipherStart[firstSpan.index]
	if firstSpan.headerSeparate {
		start += firstSpan.rng.CipherStart
	}
	lastSpan := spans[len(spans)-1]
	end := l.cipherStart[lastSpan.index] + lastSpan.rng.CipherEnd
	return start, end
}

// rangeChain emits the plaintext of a range that may span several parts.
type rangeChain struct {
	src    io.Reader
	dek    []byte
	layout *partLayout
	spans  []rangeSpan

	idx int
	cur *stream.RangeReader
	err error
}

func newRangeChain(src io.Reader, dek []byte, layout *partLayout, spans []rangeSpan) (*rangeChain, error) {
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
	part := c.layout.parts[span.index]

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
	} else if err := c.layout.checkSalt(span.index, salt); err != nil {
		c.err = err
		return err
	}

	// Exactly the ciphertext of the chunks this part contributes, so the reader
	// cannot run into the next part's bytes.
	length := span.rng.CipherEnd - span.rng.CipherStart + 1
	reader, err := stream.NewRangeReader(
		io.LimitReader(c.src, length), header, c.dek,
		stream.SegmentParams{Log2ChunkSize: c.layout.log2C, Multipart: true, Index: part.Number},
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

	chain, err := newSegmentChain(out.Body, dek, layout)
	if err != nil {
		return p.integrityError(log, "segment header", err)
	}
	defer func() { _ = chain.Close() }()

	if err := chain.VerifyFirst(); err != nil {
		return p.integrityError(log, "first chunk", err)
	}

	// Before the status line, like every other check that can refuse a read.
	if apiErr := p.checkFreshness(req.Bucket, req.Key, layout.salts(), log); apiErr != nil {
		return apiErr
	}

	copyResponseHeaders(w.Header(), out.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(layout.totalPlain, 10))
	w.WriteHeader(http.StatusOK)

	p.metrics.StreamStarted(obs.Download)
	defer p.metrics.StreamFinished(obs.Download)

	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	written, copyErr := io.Copy(guardedWriter{dst: w, guard: guard}, chain)
	p.metrics.Bytes(obs.InCipher, out.ContentLength)
	p.metrics.Bytes(obs.OutPlain, written)
	p.noteObject(r, meta.KeyID, written)
	if copyErr != nil {
		p.abortResponse(r, log, written, layout.totalPlain, copyErr)
	}
	log.Info("multipart object served",
		"parts", len(layout.parts), "plaintext_bytes", layout.totalPlain, "kid", meta.KeyID)
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

	start, end, apiErr := parseRange(spec, layout.totalPlain)
	if apiErr != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", layout.totalPlain))
		return apiErr
	}

	spans, err := layout.planRange(start, end)
	if err != nil {
		if errors.Is(err, stream.ErrRangeNotSatisfiable) {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", layout.totalPlain))
			return s3api.ErrInvalidRange
		}
		return p.integrityError(log, "range mapping", err)
	}

	// The header of the first part touched has to be fetched separately when the
	// range starts past that part's first chunk.
	if spans[0].headerSeparate {
		offset := layout.cipherStart[spans[0].index]
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

	fetchStart, fetchEnd := layout.bodyRange(spans)
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
	if apiErr := p.checkFreshness(req.Bucket, req.Key, layout.salts(), log); apiErr != nil {
		return apiErr
	}

	length := rangeLength(spans)
	copyResponseHeaders(w.Header(), out.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, layout.totalPlain))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(http.StatusPartialContent)

	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	written, copyErr := io.Copy(guardedWriter{dst: w, guard: guard}, chain)
	p.noteObject(r, meta.KeyID, written)
	if copyErr != nil {
		p.abortResponse(r, log, written, length, copyErr)
	}
	log.Info("multipart range served", "start", start, "end", end,
		"bytes", length, "parts_touched", len(spans), "kid", meta.KeyID)
	return nil
}

// multipartLayout loads the manifest and derives the object's geometry from it.
func (p *Proxy) multipartLayout(
	r *http.Request, req s3api.Request, meta objectMeta, storedCipher int64, dek []byte, log *slog.Logger,
) (*partLayout, *s3api.Error) {
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

	layout, err := newPartLayout(m.Parts, meta.Log2ChunkSize, m.HasSalts())
	if err != nil {
		return nil, p.integrityError(log, "manifest", err)
	}
	if err := layout.checkAgainst(storedCipher); err != nil {
		return nil, p.integrityError(log, "object size", err)
	}
	return layout, nil
}
