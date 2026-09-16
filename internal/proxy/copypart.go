package proxy

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upload"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// copyPartResult is the body S3 answers an UploadPartCopy with. The ETag is the
// one the client hands back at completion, and it is the provider's over the
// ciphertext, exactly as an ordinary UploadPart's is.
type copyPartResult struct {
	XMLName      xml.Name `xml:"CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// uploadPartCopy serves UploadPartCopy: a part whose bytes come from a range of
// another object rather than from the request body.
//
// Unlike CopyObject this one cannot stay inside the provider, and that is a
// consequence of the format rather than an omission. A part is a segment: it has
// its own header, its own salt, and chunk counters that start at zero
// (FORMAT §4). The destination's part N therefore shares no bytes with the
// source's ciphertext even when it covers exactly the same plaintext, because it
// is encrypted under the destination's data key with a different salt. So the
// range is read, decrypted, re-encrypted and uploaded -- at O(chunk size)
// memory, but at the cost of the bytes crossing this process. ADR-012 records
// the alternatives that were considered and why they were not taken.
//
// This is what the AWS CLI uses for `aws s3 cp s3://a s3://b` above its 8 MiB
// multipart threshold, which is to say: for most objects worth copying.
func (p *Proxy) uploadPartCopy(
	w http.ResponseWriter, r *http.Request, req s3api.Request, authResult *auth.Result, log *slog.Logger,
) *s3api.Error {
	token, storedKey, apiErr := p.openToken(r, req)
	if apiErr != nil {
		return apiErr
	}
	destDEK, apiErr := p.unwrapTokenDEK(r, req, token, log)
	if apiErr != nil {
		return apiErr
	}
	defer clear(destDEK)

	src, apiErr := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if apiErr != nil {
		return apiErr
	}
	if !authResult.Client.MayAccess(src.Bucket) {
		log.Warn("copy source is outside the credential's buckets", "source_bucket", src.Bucket)
		return s3api.ErrAccessDenied
	}
	if strings.HasPrefix(src.Key, s3api.ReservedPrefix) {
		return s3api.ErrInvalidRequest.WithMessage(
			"the %s prefix is reserved by the gateway", s3api.ReservedPrefix)
	}

	// UploadPartCopy is still refused while names are encrypted (see names.go),
	// but the source is addressed by its stored key here so that lifting the
	// refusal is lifting a refusal rather than another hunt for call sites.
	src.Stored, apiErr = p.storedKey(src.Key)
	if apiErr != nil {
		return apiErr
	}

	info, err := p.upstream.HeadObject(r.Context(), src.Bucket, src.Stored)
	if err != nil {
		return translateUpstream(err)
	}
	if apiErr := checkCopyConditions(r.Header, info.ETag, info.LastModified); apiErr != nil {
		return apiErr
	}

	reader, plainLen, apiErr := p.openSourceRange(r, src, info,
		r.Header.Get("X-Amz-Copy-Source-Range"), log)
	if apiErr != nil {
		return apiErr
	}
	defer func() { _ = reader.Close() }()

	sealedLen, err := stream.SealedSize(plainLen, p.log2C)
	if err != nil {
		return s3api.ErrEntityTooLarge.WithMessage(
			"a part of %d bytes cannot be stored: %v", plainLen, err)
	}
	if sealedLen > manifest.MaxPartCiphertext {
		maximum, _ := manifest.MaxPartPlaintext(p.log2C)
		return s3api.ErrEntityTooLarge.WithMessage(
			"a part of %d bytes exceeds the maximum part size of %d bytes", plainLen, maximum)
	}

	p.metrics.StreamStarted(obs.Upload)
	defer p.metrics.StreamFinished(obs.Upload)

	// Same shape as uploadPart: the encrypter writes into a pipe the upstream
	// request reads, so nothing is buffered beyond a chunk.
	pr, pw := io.Pipe()
	encDone := make(chan error, 1)
	// Like uploadPart: the salt is generated inside the writer and has to reach
	// the ETag, because that is how the completion learns which attempt this
	// part is (internal/upload/parttag.go).
	saltCh := make(chan [stream.SaltSize]byte, 1)
	go func() {
		ew, err := stream.NewEncryptWriter(pw, destDEK, stream.SegmentParams{
			Log2ChunkSize: p.log2C,
			Multipart:     true,
			//nolint:gosec // the router bounds the part number to 1..10000.
			Index: uint32(req.PartNumber),
		})
		if err != nil {
			close(saltCh)
			_ = pw.CloseWithError(err)
			encDone <- err
			return
		}
		saltCh <- ew.Salt()
		_, copyErr := io.Copy(ew, reader)
		if copyErr == nil {
			copyErr = ew.Close()
		}
		_ = pw.CloseWithError(copyErr)
		encDone <- copyErr
	}()

	etag, putErr := p.upstream.UploadPart(r.Context(), upstream.UploadPartInput{
		Bucket: req.Bucket, Key: storedKey, UploadID: token.UploadID,
		PartNumber: req.PartNumber, Body: pr, ContentLength: sealedLen,
	})

	_ = pr.Close()
	encErr := <-encDone
	if encErr != nil && putErr != nil && errors.Is(encErr, io.ErrClosedPipe) {
		encErr = nil
	}

	switch {
	case encErr != nil:
		// A failure here is a failure to read the *source*, and the source is
		// stored data: if it failed authentication, that is an integrity
		// problem and not a bad request.
		log.Warn("copying a part failed while reading the source",
			"part", req.PartNumber, "err", encErr)
		return p.integrityError(log, "chunk", encErr)
	case putErr != nil:
		if upstream.NoSuchUpload(putErr) {
			return s3api.ErrNoSuchUpload
		}
		log.Warn("the upstream rejected the copied part", "part", req.PartNumber, "err", putErr)
		return translateUpstream(putErr)
	}

	salt, ok := <-saltCh
	if !ok {
		return s3api.ErrInternal
	}
	tagged, err := upload.SealPartTag(r.Context(), p.keys, token.KID, etag, req.PartNumber, salt)
	if err != nil {
		log.Error("sealing the part tag failed", "part", req.PartNumber, "err", err)
		return s3api.ErrInternal
	}

	p.metrics.Bytes(obs.OutCipher, sealedLen)
	p.noteObject(r, token.KID, plainLen)
	log.Info("part copied", "part", req.PartNumber,
		"source_bucket", src.Bucket, "source_key", src.Key,
		"plaintext_bytes", plainLen, "ciphertext_bytes", sealedLen)

	return writeXML(w, http.StatusOK, copyPartResult{
		ETag:         tagged,
		LastModified: time.Now().UTC().Format(time.RFC3339),
	})
}

// openSourceRange returns a reader over a range of a stored object's plaintext.
//
// It is the read path of GetObject without the HTTP around it, for both object
// shapes: a single-part object maps the range onto chunk boundaries directly,
// and a multipart one goes through its manifest. The caller must close it.
func (p *Proxy) openSourceRange(
	r *http.Request, src copySource, info *upstream.ObjectInfo, spec string, log *slog.Logger,
) (io.ReadCloser, int64, *s3api.Error) {
	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return nil, 0, errNotEncryptedAPI
	}
	if err != nil {
		return nil, 0, p.integrityError(log, "object metadata", err)
	}

	// The source is a different object from the request's, so its data key is
	// bound to its own bucket and key.
	srcReq := s3api.Request{Bucket: src.Bucket, Key: src.Key}
	dek, apiErr := p.unwrapDEK(r, srcReq, meta, log)
	if apiErr != nil {
		return nil, 0, apiErr
	}
	// The key is not cleared here. A reader is being handed back, and a
	// multipart source derives a subkey per part as the chain advances -- so
	// the key has to outlive this function. The returned closer owns it and
	// wipes it, and every early return below wipes it too.
	if meta.Multipart {
		return p.openMultipartSourceRange(r, srcReq, info, meta, dek, spec, log)
	}

	fail := func(code *s3api.Error) (io.ReadCloser, int64, *s3api.Error) {
		clear(dek)
		return nil, 0, code
	}

	plainLen, err := stream.OpenedSize(info.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		return fail(p.integrityError(log, "ciphertext size", err))
	}
	start, end := int64(0), plainLen-1
	if spec != "" {
		start, end, apiErr = parseRange(spec, plainLen)
		if apiErr != nil {
			return fail(apiErr)
		}
	}
	if plainLen == 0 {
		clear(dek)
		return io.NopCloser(strings.NewReader("")), 0, nil
	}

	rng, err := stream.MapRange(start, end, info.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		if errors.Is(err, stream.ErrRangeNotSatisfiable) {
			return fail(s3api.ErrInvalidRange)
		}
		return fail(p.integrityError(log, "range mapping", err))
	}

	fetchStart := rng.CipherStart
	if !rng.NeedsSeparateHeader {
		fetchStart = 0
	}
	out, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
		Bucket: src.Bucket, Key: src.Stored,
		Range:   fmt.Sprintf("bytes=%d-%d", fetchStart, rng.CipherEnd),
		IfMatch: info.ETag,
	})
	if err != nil {
		return fail(translateUpstream(err))
	}

	rawHeader := make([]byte, stream.HeaderSize)
	if rng.NeedsSeparateHeader {
		header, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
			Bucket: src.Bucket, Key: src.Stored,
			Range:   fmt.Sprintf("bytes=0-%d", stream.HeaderSize-1),
			IfMatch: info.ETag,
		})
		if err != nil {
			_ = out.Body.Close()
			return fail(translateUpstream(err))
		}
		_, readErr := io.ReadFull(header.Body, rawHeader)
		_ = header.Body.Close()
		if readErr != nil {
			_ = out.Body.Close()
			return fail(p.integrityError(log, "segment header", readErr))
		}
	} else if _, err := io.ReadFull(out.Body, rawHeader); err != nil {
		_ = out.Body.Close()
		return fail(p.integrityError(log, "segment header", err))
	}

	reader, err := stream.NewRangeReader(out.Body, rawHeader, dek,
		stream.SegmentParams{Log2ChunkSize: stream.AnyChunkSize}, rng)
	if err != nil {
		_ = out.Body.Close()
		return fail(p.integrityError(log, "segment header", err))
	}
	// Everything that can fail is made to fail before a byte is re-encrypted,
	// so a corrupt source is an error response rather than a half-written part.
	if err := reader.VerifyFirst(); err != nil {
		_ = reader.Close()
		_ = out.Body.Close()
		return fail(p.integrityError(log, "first chunk", err))
	}
	return &bodyCloser{Reader: reader, closers: []io.Closer{reader, out.Body}, dek: dek}, rng.Length, nil
}

// openMultipartSourceRange is the same for a source made of several segments.
// The caller hands over ownership of dek: the returned closer wipes it, and so
// does every error path here.
func (p *Proxy) openMultipartSourceRange(
	r *http.Request, srcReq s3api.Request, info *upstream.ObjectInfo,
	meta objectMeta, dek []byte, spec string, log *slog.Logger,
) (io.ReadCloser, int64, *s3api.Error) {
	fail := func(code *s3api.Error) (io.ReadCloser, int64, *s3api.Error) {
		clear(dek)
		return nil, 0, code
	}

	// srcReq carries the source's identity, because that is what its data key
	// and its manifest are bound to. The byte ranges below go to the provider
	// and need the address.
	srcStored, apiErr := p.storedKey(srcReq.Key)
	if apiErr != nil {
		return fail(apiErr)
	}

	layout, apiErr := p.multipartLayout(r, srcReq, meta, info.ContentLength, dek, log)
	if apiErr != nil {
		return fail(apiErr)
	}

	start, end := int64(0), layout.totalPlain-1
	if spec != "" {
		start, end, apiErr = parseRange(spec, layout.totalPlain)
		if apiErr != nil {
			return fail(apiErr)
		}
	}
	if layout.totalPlain == 0 {
		clear(dek)
		return io.NopCloser(strings.NewReader("")), 0, nil
	}

	spans, err := layout.planRange(start, end)
	if err != nil {
		if errors.Is(err, stream.ErrRangeNotSatisfiable) {
			return fail(s3api.ErrInvalidRange)
		}
		return fail(p.integrityError(log, "range mapping", err))
	}

	if spans[0].headerSeparate {
		offset := layout.cipherStart[spans[0].index]
		header, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
			Bucket: srcReq.Bucket, Key: srcStored,
			Range:   fmt.Sprintf("bytes=%d-%d", offset, offset+stream.HeaderSize-1),
			IfMatch: info.ETag,
		})
		if err != nil {
			return fail(translateUpstream(err))
		}
		raw := make([]byte, stream.HeaderSize)
		_, readErr := io.ReadFull(header.Body, raw)
		_ = header.Body.Close()
		if readErr != nil {
			return fail(p.integrityError(log, "segment header", readErr))
		}
		spans[0].rawHeader = raw
	}

	fetchStart, fetchEnd := layout.bodyRange(spans)
	out, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
		Bucket: srcReq.Bucket, Key: srcStored,
		Range:   fmt.Sprintf("bytes=%d-%d", fetchStart, fetchEnd),
		IfMatch: info.ETag,
	})
	if err != nil {
		return fail(translateUpstream(err))
	}

	chain, err := newRangeChain(out.Body, dek, layout, spans)
	if err != nil {
		_ = out.Body.Close()
		return fail(p.integrityError(log, "segment header", err))
	}
	if err := chain.VerifyFirst(); err != nil {
		_ = chain.Close()
		_ = out.Body.Close()
		return fail(p.integrityError(log, "first chunk", err))
	}
	return &bodyCloser{
		Reader: chain, closers: []io.Closer{chain, out.Body}, dek: dek,
	}, rangeLength(spans), nil
}

// bodyCloser ties a decrypting reader to the upstream body underneath it and to
// the data key that opens it, so that closing it releases all three.
type bodyCloser struct {
	io.Reader
	closers []io.Closer
	dek     []byte
}

func (b *bodyCloser) Close() error {
	var err error
	for _, c := range b.closers {
		if cerr := c.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	clear(b.dek)
	return err
}
