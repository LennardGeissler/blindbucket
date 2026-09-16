package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// putObject encrypts the client's body and streams the ciphertext upstream.
//
// Nothing is buffered. The exact upstream Content-Length is known before the
// first byte, because the segment format is deterministic in length, and the
// client's checksum is settled in the window between the last full chunk and the
// encrypter's Close.
func (p *Proxy) putObject(
	w http.ResponseWriter, r *http.Request, req s3api.Request, authResult *auth.Result, log *slog.Logger,
) *s3api.Error {
	if apiErr := rejectUnsupportedUpload(r); apiErr != nil {
		return apiErr
	}

	body, plainLen, err := auth.NewBodyReader(r, authResult)
	if err != nil {
		return translateBody(err)
	}
	if plainLen < 0 {
		return s3api.ErrMissingContentLength
	}

	// The same rule in the other direction: an upload may take as long as it
	// takes, but a client that sends nothing for a minute is not uploading.
	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	sealedLen, err := stream.SealedSize(plainLen, p.log2C)
	if err != nil {
		return s3api.ErrEntityTooLarge.WithMessage("object of %d bytes cannot be stored: %v", plainLen, err)
	}

	clientMeta, err := clientMetadata(r.Header)
	if err != nil {
		return s3api.ErrInvalidArgument.WithMessage("%v", err)
	}

	// The address the provider sees. The associated data below deliberately does
	// not use it: the wrapped key stays bound to the key the client named, so
	// the envelope reads the same whether or not names are encrypted.
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}

	kid := p.keys.ActiveKID()
	aad, err := keys.ObjectAAD(kid, req.Bucket, req.Key)
	if err != nil {
		return s3api.ErrInvalidArgument.WithMessage("%v", err)
	}
	dek, err := keys.NewDEK()
	if err != nil {
		return s3api.ErrInternal
	}
	defer dek.Wipe()

	wrapped, err := p.keys.Wrap(r.Context(), kid, dek.Bytes(), aad)
	if err != nil {
		log.Error("wrapping the data key failed", "err", err)
		return s3api.ErrInternal
	}

	meta := objectMeta{
		Version:       stream.Version,
		KeyID:         kid,
		WrappedDEK:    wrapped,
		Log2ChunkSize: p.log2C,
	}

	// The encrypter runs in its own goroutine writing into a pipe, and the
	// upstream request reads the other end. There is no buffer between them, so
	// a slow upstream slows the read from the client through TCP flow control.
	p.metrics.StreamStarted(obs.Upload)
	defer p.metrics.StreamFinished(obs.Upload)

	pr, pw := io.Pipe()
	encDone := make(chan error, 1)
	// The salt is minted inside the encrypter and is what identifies this write
	// for ADR-018, so it has to come back out. Same channel handoff UploadPart
	// already uses for the same reason.
	saltCh := make(chan [stream.SaltSize]byte, 1)
	go func() {
		ew, err := stream.NewEncryptWriter(pw, dek.Bytes(), stream.SegmentParams{Log2ChunkSize: p.log2C})
		if err != nil {
			close(saltCh)
			_ = pw.CloseWithError(err)
			encDone <- err
			return
		}
		saltCh <- ew.Salt()
		// A checksum failure surfaces from this copy, before Close. Close writes
		// the final chunk, so a body that failed verification never becomes a
		// complete segment and the upstream stores nothing.
		_, copyErr := io.Copy(ew, guardedReader{src: body, guard: guard})
		if copyErr == nil {
			copyErr = ew.Close()
		}
		_ = pw.CloseWithError(copyErr)
		encDone <- copyErr
	}()

	out, putErr := p.upstream.PutObject(r.Context(), upstream.PutObjectInput{
		Bucket:             req.Bucket,
		Key:                storedKey,
		Body:               pr,
		ContentLength:      sealedLen,
		ContentType:        r.Header.Get("Content-Type"),
		CacheControl:       r.Header.Get("Cache-Control"),
		ContentDisposition: r.Header.Get("Content-Disposition"),
		ContentEncoding:    passthroughContentEncoding(r),
		ContentLanguage:    r.Header.Get("Content-Language"),
		Metadata:           mergeMetadata(clientMeta, meta),
	})

	// Unblock the encrypter if the upstream refused before reading the body.
	_ = pr.Close()
	encErr := <-encDone

	// An upstream that refuses before reading a byte -- an expired upload, a
	// missing bucket, a denied request -- makes the encrypter fail too, because
	// closing the pipe is how it is unblocked. That consequence must not be
	// reported in place of its cause: the client needs to hear NoSuchUpload, not
	// IncompleteBody. Any other encrypter error is a real one (a failed checksum,
	// a client that stopped sending) and still takes precedence.
	if encErr != nil && putErr != nil && errors.Is(encErr, io.ErrClosedPipe) {
		encErr = nil
	}

	switch {
	case encErr != nil:
		log.Warn("upload rejected before completion", "err", encErr)
		return translateBody(encErr)
	case putErr != nil:
		log.Warn("upstream rejected the upload", "err", putErr)
		return translateUpstream(putErr)
	}

	if out.ETag != "" {
		w.Header().Set("ETag", out.ETag)
	}
	if out.VersionID != "" {
		w.Header().Set("x-amz-version-id", out.VersionID)
	}
	// Echo the checksums that were actually verified. The client compares them
	// against its own, and they describe the plaintext -- unlike anything the
	// provider could report, which describes ciphertext.
	echoVerifiedChecksums(w.Header(), r.Header, body.Trailer())

	// After the upstream acknowledged, never before: an index entry for a write
	// that did not land would make the next read of a perfectly good object look
	// like a rollback.
	if salt, ok := <-saltCh; ok {
		p.recordFreshness(req.Bucket, req.Key, saltsOf(salt), log)
	}

	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	p.metrics.Bytes(obs.InPlain, plainLen)
	p.metrics.Bytes(obs.OutCipher, sealedLen)
	p.noteObject(r, kid, plainLen)
	log.Info("object stored", "plaintext_bytes", plainLen, "ciphertext_bytes", sealedLen, "kid", kid)
	return nil
}

// getObject decrypts an object on the way to the client, whole or by range.
//
// The order is the whole of the fail-closed rule: the data key is unwrapped and
// the first chunk authenticated *before* a status line is written, so a wrong
// key, forged metadata or a tampered header produces a proper S3 error rather
// than a truncated body. See docs/adr/ADR-004-fail-closed.md.
func (p *Proxy) getObject(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	if spec := r.Header.Get("Range"); spec != "" {
		return p.getObjectRange(w, r, req, spec, log)
	}

	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}

	out, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
		Bucket: req.Bucket, Key: storedKey,
	})
	if err != nil {
		return translateUpstream(err)
	}
	defer func() { _ = out.Body.Close() }()

	// A multipart object is a concatenation of segments whose boundaries only
	// the manifest knows, so it takes a different path entirely.
	if multipart, apiErr := p.isMultipart(out.Metadata, log); apiErr != nil {
		return apiErr
	} else if multipart {
		return p.getMultipartObject(w, r, req, out, log)
	}

	reader, meta, apiErr := p.openSegment(r, req, out.Metadata, out.Body, log)
	if apiErr != nil {
		return apiErr
	}
	defer func() { _ = reader.Close() }()

	plainLen, err := stream.OpenedSize(out.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		return p.integrityError(log, "ciphertext size", err)
	}

	// Before the status line, like every other check that can refuse a read.
	if apiErr := p.checkFreshness(req.Bucket, req.Key, saltsOf(reader.Salt()), log); apiErr != nil {
		return apiErr
	}

	copyResponseHeaders(w.Header(), out.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(plainLen, 10))
	w.WriteHeader(http.StatusOK)

	p.metrics.StreamStarted(obs.Download)
	defer p.metrics.StreamFinished(obs.Download)

	// A download may run for hours; it may not stall for a minute (12.3).
	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	written, copyErr := io.Copy(guardedWriter{dst: w, guard: guard}, reader)
	p.metrics.Bytes(obs.InCipher, out.ContentLength)
	p.metrics.Bytes(obs.OutPlain, written)
	// Noted before the abort check, so that a download cut off by a failing
	// chunk is recorded with what it actually delivered rather than not at all.
	p.noteObject(r, meta.KeyID, written)
	if copyErr != nil {
		p.abortResponse(r, log, written, plainLen, copyErr)
	}
	log.Info("object served", "plaintext_bytes", plainLen, "kid", meta.KeyID)
	return nil
}

// getObjectRange serves a byte range.
//
// It costs a HEAD before the ranged read. The chunk boundaries a range maps onto
// depend on the object's chunk size and total length, and neither is known until
// the object has been looked at -- so the alternative would be guessing the
// chunk size from local configuration and being wrong for any object written
// under a different one. The read is pinned to the ETag seen by the HEAD, so the
// two requests cannot straddle an overwrite.
func (p *Proxy) getObjectRange(
	w http.ResponseWriter, r *http.Request, req s3api.Request, spec string, log *slog.Logger,
) *s3api.Error {
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}

	info, err := p.upstream.HeadObject(r.Context(), req.Bucket, storedKey)
	if err != nil {
		return translateUpstream(err)
	}

	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return errNotEncryptedAPI
	}
	if err != nil {
		return p.integrityError(log, "object metadata", err)
	}

	if meta.Multipart {
		return p.getMultipartRange(w, r, req, info, meta, spec, log)
	}

	plainLen, err := stream.OpenedSize(info.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		return p.integrityError(log, "ciphertext size", err)
	}

	start, end, apiErr := parseRange(spec, plainLen)
	if apiErr != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", plainLen))
		return apiErr
	}

	rng, err := stream.MapRange(start, end, info.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		if errors.Is(err, stream.ErrRangeNotSatisfiable) {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", plainLen))
			return s3api.ErrInvalidRange
		}
		return p.integrityError(log, "range mapping", err)
	}

	// One request when the header is adjacent to the range, two when it is not.
	fetchStart := rng.CipherStart
	if !rng.NeedsSeparateHeader {
		fetchStart = 0
	}
	out, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
		Bucket:  req.Bucket,
		Key:     storedKey,
		Range:   fmt.Sprintf("bytes=%d-%d", fetchStart, rng.CipherEnd),
		IfMatch: info.ETag,
	})
	if err != nil {
		return translateUpstream(err)
	}
	defer func() { _ = out.Body.Close() }()

	rawHeader := make([]byte, stream.HeaderSize)
	if rng.NeedsSeparateHeader {
		header, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
			Bucket: req.Bucket, Key: storedKey,
			Range:   fmt.Sprintf("bytes=0-%d", stream.HeaderSize-1),
			IfMatch: info.ETag,
		})
		if err != nil {
			return translateUpstream(err)
		}
		_, readErr := io.ReadFull(header.Body, rawHeader)
		_ = header.Body.Close()
		if readErr != nil {
			return p.integrityError(log, "segment header", readErr)
		}
	} else if _, err := io.ReadFull(out.Body, rawHeader); err != nil {
		return p.integrityError(log, "segment header", err)
	}

	dek, apiErr := p.unwrapDEK(r, req, meta, log)
	if apiErr != nil {
		return apiErr
	}
	defer clear(dek)

	reader, err := stream.NewRangeReader(out.Body, rawHeader, dek,
		stream.SegmentParams{Log2ChunkSize: stream.AnyChunkSize}, rng)
	if err != nil {
		return p.integrityError(log, "segment header", err)
	}
	defer func() { _ = reader.Close() }()

	if err := reader.VerifyFirst(); err != nil {
		return p.integrityError(log, "first chunk", err)
	}

	// A range must be checked too, or a client that reads by ranges -- which is
	// every parallel downloader -- would bypass rollback detection entirely.
	salt, ok := stream.SaltFromHeader(rawHeader)
	if !ok {
		return p.integrityError(log, "segment header",
			errors.New("the segment header is too short to carry a salt"))
	}
	if apiErr := p.checkFreshness(req.Bucket, req.Key, saltsOf(salt), log); apiErr != nil {
		return apiErr
	}

	copyResponseHeaders(w.Header(), out.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, plainLen))
	w.Header().Set("Content-Length", strconv.FormatInt(rng.Length, 10))
	w.WriteHeader(http.StatusPartialContent)

	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	written, copyErr := io.Copy(guardedWriter{dst: w, guard: guard}, reader)
	p.noteObject(r, meta.KeyID, written)
	if copyErr != nil {
		p.abortResponse(r, log, written, rng.Length, copyErr)
	}
	log.Info("range served", "start", start, "end", end, "bytes", rng.Length, "kid", meta.KeyID)
	return nil
}

// headObject reports an object's plaintext size without reading it.
func (p *Proxy) headObject(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}
	info, err := p.upstream.HeadObject(r.Context(), req.Bucket, storedKey)
	if err != nil {
		return translateUpstream(err)
	}

	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return errNotEncryptedAPI
	}
	if err != nil {
		return p.integrityError(log, "object metadata", err)
	}

	// A HEAD never reads the body, so the chunk size cannot be taken from the
	// authenticated segment header here. It comes from the object's own
	// metadata, which is why that is recorded at write time.
	//
	// For a multipart object the part count comes from the ETag suffix, which is
	// what makes the size recoverable without loading the manifest. Neither
	// input is authenticated; the size a HEAD reports is a hint, exactly as it
	// is for single-part objects, and the authenticated one is established when
	// the object is read. See docs/FORMAT.md section 7.2.
	plainLen, err := p.plainSize(info.ContentLength, info.ETag, meta)
	if err != nil {
		return p.integrityError(log, "ciphertext size", err)
	}

	copyResponseHeaders(w.Header(), info.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(plainLen, 10))
	w.WriteHeader(http.StatusOK)
	// A HEAD moves no object data, so the byte count is zero and the key id is
	// the whole of what it contributes.
	p.noteObject(r, meta.KeyID, 0)
	return nil
}

// deleteObject removes an object and, if it was a multipart one, its manifest.
//
// The order is rule R3 from ADR-010, and it is the same shape as
// a completion: observe what is visible, act, and only then delete the manifest
// that was observed -- never "the manifests of this key", and never one that was
// not seen beforehand. The model in spec/tla/Multipart.tla covers this path as
// its Del process.
func (p *Proxy) deleteObject(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	// Step 1: what is visible now. This observation is the only thing step 3 is
	// allowed to delete.
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}
	observed, hadManifest := p.observedManifest(r.Context(), req.Bucket, storedKey)
	p.at(hookDelHead, req)

	// Step 2: the object goes.
	if err := p.upstream.DeleteObject(r.Context(), req.Bucket, storedKey); err != nil {
		return translateUpstream(err)
	}
	p.at(hookDelRemove, req)

	// Step 3: and only now the manifest of the version that was just removed.
	// Best effort: a failure leaves an orphan, which holds no plaintext and
	// which gc collects.
	if hadManifest {
		// The stored key, because a manifest path is the hash of the key the
		// object lives under -- ADR-015 section "Consequences if accepted".
		if err := p.deleteManifest(r.Context(), req.Bucket, storedKey, observed); err != nil {
			log.Warn("could not remove the manifest of the deleted object; gc will collect it",
				"manifest_id", observed.String(), "err", err)
		}
	}

	p.at(hookDelManifest, req)

	// A tombstone, not a dropped entry: an index that simply forgot would let a
	// provider ignore this delete and keep serving the object with nothing to
	// disagree.
	p.forgetFreshness(req.Bucket, req.Key, log)

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// unwrapDEK recovers an object's data key, bound to its bucket and key.
func (p *Proxy) unwrapDEK(r *http.Request, req s3api.Request, meta objectMeta, log *slog.Logger) ([]byte, *s3api.Error) {
	aad, err := keys.ObjectAAD(meta.KeyID, req.Bucket, req.Key)
	if err != nil {
		return nil, s3api.ErrInvalidArgument.WithMessage("%v", err)
	}
	dek, err := p.keys.Unwrap(r.Context(), meta.KeyID, meta.WrappedDEK, aad)
	if err != nil {
		if errors.Is(err, keys.ErrUnknownKID) {
			return nil, s3api.ErrIntegrity.WithMessage(
				"the key %q that protects this object is not in the keyring", meta.KeyID)
		}
		return nil, p.integrityError(log, "data key", err)
	}
	return dek, nil
}

// openSegment unwraps the data key and authenticates the first chunk.
//
// Everything that can fail is made to fail here, while an error response is
// still possible.
func (p *Proxy) openSegment(
	r *http.Request, req s3api.Request, metadata map[string]string, body io.Reader, log *slog.Logger,
) (*stream.DecryptReader, objectMeta, *s3api.Error) {
	meta, err := parseObjectMeta(metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return nil, objectMeta{}, errNotEncryptedAPI
	}
	if err != nil {
		return nil, objectMeta{}, p.integrityError(log, "object metadata", err)
	}

	dek, apiErr := p.unwrapDEK(r, req, meta, log)
	if apiErr != nil {
		return nil, objectMeta{}, apiErr
	}
	defer clear(dek)

	// AnyChunkSize: the segment states its own size, and unlike the metadata
	// that statement is authenticated.
	reader, err := stream.NewDecryptReader(body, dek, stream.SegmentParams{Log2ChunkSize: stream.AnyChunkSize})
	if err != nil {
		return nil, objectMeta{}, p.integrityError(log, "segment header", err)
	}
	if err := reader.VerifyFirst(); err != nil {
		_ = reader.Close()
		return nil, objectMeta{}, p.integrityError(log, "first chunk", err)
	}

	// Past this point the header is authenticated, so it can be trusted over the
	// metadata. A recorded chunk size that disagrees with it means the metadata
	// was altered.
	authenticated := reader.Header().Log2ChunkSize
	if meta.HasChunkSize && meta.Log2ChunkSize != authenticated {
		_ = reader.Close()
		return nil, objectMeta{}, p.integrityError(log, "chunk size",
			errors.New("object metadata disagrees with the authenticated segment header"))
	}
	meta.Log2ChunkSize = authenticated

	return reader, meta, nil
}

// abortResponse drops the connection after the headers have gone out.
//
// There is no legal way to report a failure here: appending an error document
// would hand the client bytes it would read as object content. A short read
// against the declared Content-Length is unmistakable instead.
func (p *Proxy) abortResponse(
	r *http.Request, log *slog.Logger, written, expected int64, err error,
) {
	log.Error("aborting response after an integrity or transport failure",
		"written_bytes", written, "expected_bytes", expected, "err", err)
	// The audit record is written by a deferred call that this panic unwinds
	// through, so the code is set here for it to pick up. Without it the entry
	// would say 200 and nothing else, which is the status the client was
	// promised but not what happened.
	p.noteCode(r, s3api.ErrIntegrity.Code)
	panic(http.ErrAbortHandler)
}

// integrityError logs a failed authentication and renders it for the client.
//
// A rise in these is security-relevant: it means either a bug or a provider
// modifying stored data, which is why it is also counted as
// blindbucket_integrity_failures_total{kind} and is the one metric worth an
// alert.
func (p *Proxy) integrityError(log *slog.Logger, kind string, err error) *s3api.Error {
	p.metrics.IntegrityFailure(metricKind(kind))
	log.Error("integrity check failed", "kind", kind, "err", err)
	return s3api.ErrIntegrity.WithMessage("the stored object failed authentication (%s)", kind)
}

// metricKind maps the human phrase an integrity failure is logged with onto the
// bounded label set of blindbucket_integrity_failures_total.
//
// The log line stays free to say something specific; the metric label may not,
// because an unbounded label is a memory leak in the scraper.
func metricKind(kind string) string {
	switch kind {
	case "first chunk", "chunk size":
		return obs.KindChunk
	case "segment header":
		return obs.KindHeader
	case "data key", "upload data key":
		return obs.KindDEKUnwrap
	case "manifest":
		return obs.KindManifest
	case "ciphertext size", "object size", "range mapping":
		return obs.KindSize
	default:
		return obs.KindHeader
	}
}

// parseRange parses a single HTTP byte range against a known size.
//
// S3 serves one range at a time, so a multi-range request is refused rather than
// silently reduced to its first part.
func parseRange(spec string, size int64) (start, end int64, apiErr *s3api.Error) {
	value, ok := strings.CutPrefix(strings.TrimSpace(spec), "bytes=")
	if !ok {
		return 0, 0, s3api.ErrInvalidRange.WithMessage("range unit is not bytes")
	}
	if strings.Contains(value, ",") {
		return 0, 0, s3api.ErrNotImplemented.WithMessage("multiple ranges in one request are not supported")
	}

	first, last, found := strings.Cut(value, "-")
	if !found {
		return 0, 0, s3api.ErrInvalidRange.WithMessage("range %q is malformed", spec)
	}
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)

	switch {
	case first == "" && last == "":
		return 0, 0, s3api.ErrInvalidRange.WithMessage("range %q names no bytes", spec)

	case first == "":
		// A suffix range: the last n bytes.
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, s3api.ErrInvalidRange.WithMessage("suffix length %q is not a positive number", last)
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, nil

	case last == "":
		start, err := strconv.ParseInt(first, 10, 64)
		if err != nil || start < 0 {
			return 0, 0, s3api.ErrInvalidRange.WithMessage("offset %q is not a number", first)
		}
		if start >= size {
			return 0, 0, s3api.ErrInvalidRange
		}
		return start, size - 1, nil

	default:
		start, err1 := strconv.ParseInt(first, 10, 64)
		end, err2 := strconv.ParseInt(last, 10, 64)
		if err1 != nil || err2 != nil || start < 0 || end < start {
			return 0, 0, s3api.ErrInvalidRange.WithMessage("range %q is malformed", spec)
		}
		if start >= size {
			return 0, 0, s3api.ErrInvalidRange
		}
		if end >= size {
			end = size - 1
		}
		return start, end, nil
	}
}

// passthroughContentEncoding forwards the client's Content-Encoding, minus the
// aws-chunked marker, which describes the transfer framing rather than the
// object and must not be recorded against the stored object.
func passthroughContentEncoding(r *http.Request) string {
	value := r.Header.Get("Content-Encoding")
	if value == "" {
		return ""
	}
	var kept []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" && !strings.EqualFold(trimmed, "aws-chunked") {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, ", ")
}

// rejectUnsupportedUpload refuses request features this build cannot honour.
//
// A copy source reaching here means the router did not classify the request as
// a copy -- an UploadPart carrying one, for instance. The routing handles the
// cases it knows; this is the backstop that keeps a copy source from being
// silently ignored and an empty body stored as the object.
func rejectUnsupportedUpload(r *http.Request) *s3api.Error {
	if r.Header.Get("X-Amz-Copy-Source") != "" {
		return s3api.ErrNotImplemented.WithMessage(
			"this operation does not accept x-amz-copy-source in this build")
	}
	// Silently dropping tags would be worse than refusing them: a client would
	// believe its object carries them. Storing them would be worse still --
	// they are plaintext at the provider.
	if r.Header.Get("X-Amz-Tagging") != "" {
		return s3api.ErrNotImplemented.WithMessage(
			"object tags are not accepted: the provider would store them in plaintext")
	}
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-server-side-encryption") {
			return s3api.ErrNotImplemented.WithMessage(
				"server-side encryption headers are not accepted; this gateway encrypts already")
		}
	}
	return nil
}

// getObjectTagging forwards the tagging sub-resource to the provider.
//
// The gateway writes no tags, so for an object it stored this is an empty set.
// It is forwarded rather than answered locally because tags set out of band are
// the provider's to report, and inventing an empty answer would hide them.
func (p *Proxy) getObjectTagging(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}
	resp, err := p.upstream.ObjectPassthrough(r.Context(), http.MethodGet,
		req.Bucket, storedKey, url.Values{"tagging": {""}})
	if err != nil {
		return translateUpstream(err)
	}
	log.Debug("object tagging served", "status", resp.StatusCode)

	for name, values := range resp.Header {
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		w.Header()[name] = values
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(resp.Body)))
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		//nolint:gosec // the provider's own XML under its own content type.
		_, _ = w.Write(resp.Body)
	}
	return nil
}
