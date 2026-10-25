package proxy

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/tags"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Object tags, sealed in a sidecar beside the object version they belong to
// (ADR-037, FORMAT.md section 17). No tag reaches the provider in plaintext.
//
// The sidecar is found from the object's bb-dek as the provider holds it, and
// opens only under the object's own data key, so a sidecar moved to another
// object or left over from an earlier version of this one does not open.

// maxTagBody bounds a PutObjectTagging body. Ten tags of S3's longest keys and
// values in UTF-8 fit several times over.
const maxTagBody = 64 << 10

// maxTagSidecar bounds what is read of a sidecar. A sealed set of ten tags of
// the longest keys and values is a few kilobytes; anything larger is not one.
const maxTagSidecar = 64 << 10

// errMalformedXML answers a body that is not the document it should be.
var errMalformedXML = &s3api.Error{Code: "MalformedXML",
	Message: "The XML you provided was not well-formed.", HTTPStatus: http.StatusBadRequest}

// errInvalidTag answers a tag set S3 would refuse, with S3's code.
var errInvalidTag = &s3api.Error{Code: "InvalidTag", Message: "The tag set is not valid.",
	HTTPStatus: http.StatusBadRequest}

// taggingDoc is the Tagging document of PutObjectTagging and GetObjectTagging.
// Read without a namespace, so that a body with or without S3's is accepted;
// written with it, as S3 writes it.
type taggingDoc struct {
	XMLName xml.Name `xml:"Tagging"`
	Tags    []tagXML `xml:"TagSet>Tag"`
}

type tagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// taggingOut always carries a TagSet, empty or not, as S3 answers: the AWS CLI
// reads it before a multipart server-side copy.
type taggingOut struct {
	XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Tagging"`
	TagSet  tagSetXML `xml:"TagSet"`
}

type tagSetXML struct {
	Tags []tagXML `xml:"Tag"`
}

// tagTarget is the object version a tag operation acts on: where its sidecar
// is, and the data key that seals it.
type tagTarget struct {
	storedKey string
	path      string
	dek       []byte
}

// errUntaggable reports an object the gateway did not write. It has no data
// key of the gateway's, so it can have no sidecar.
var errUntaggable = errors.New("not written by the gateway")

// findTagTarget reads the object's metadata and unwraps its data key. The
// caller clears the key.
func (p *Proxy) findTagTarget(r *http.Request, req s3api.Request, log *slog.Logger) (*tagTarget, *s3api.Error, error) {
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return nil, apiErr, nil
	}
	info, err := p.upstream.HeadObject(r.Context(), req.Bucket, storedKey)
	if err != nil {
		return nil, translateUpstream(err), nil
	}
	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return nil, nil, errUntaggable
	}
	if err != nil {
		return nil, p.integrityError(log, "object metadata", err), nil
	}
	dek, apiErr := p.unwrapDEK(r, req, meta, log)
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return &tagTarget{
		storedKey: storedKey,
		path:      tags.Path(storedKey, objectmeta.StoredDEK(info.Metadata)),
		dek:       dek,
	}, nil, nil
}

// getObjectTagging answers with the object's tags, from its sidecar.
//
// An object the gateway did not write has no sidecar and no data key, so its
// tags are the provider's, set out of band, and are forwarded as they were
// before ADR-037.
func (p *Proxy) getObjectTagging(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	target, apiErr, err := p.findTagTarget(r, req, log)
	if errors.Is(err, errUntaggable) {
		return p.providerTagging(w, r, req, log)
	}
	if apiErr != nil {
		return apiErr
	}
	defer clear(target.dek)

	set, apiErr := p.readTags(r.Context(), req, target, log)
	if apiErr != nil {
		return apiErr
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return nil
	}
	var out taggingOut
	for _, t := range set {
		out.TagSet.Tags = append(out.TagSet.Tags, tagXML(t))
	}
	return writeXML(w, http.StatusOK, out)
}

// readTags reads and opens a version's sidecar. None is the empty set; one
// that does not open is tampering, never an empty set, because its name
// already says which version it belongs to (FORMAT.md section 17.3).
func (p *Proxy) readTags(ctx context.Context, req s3api.Request, target *tagTarget, log *slog.Logger) ([]tags.Tag, *s3api.Error) {
	out, err := p.upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: req.Bucket, Key: target.path})
	if upstream.NotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, translateUpstream(err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(out.Body, maxTagSidecar+1))
	if err != nil {
		return nil, translateUpstream(err)
	}
	if len(body) > maxTagSidecar {
		return nil, p.integrityError(log, "tag sidecar", fmt.Errorf("a sidecar of more than %d bytes", maxTagSidecar))
	}
	set, err := tags.Open(target.dek, req.Bucket, req.Key, body)
	if err != nil {
		return nil, p.integrityError(log, "tag sidecar", err)
	}
	return set, nil
}

// putObjectTagging replaces the tags of the current version.
func (p *Proxy) putObjectTagging(
	w http.ResponseWriter, r *http.Request, req s3api.Request, authResult *auth.Result, log *slog.Logger,
) *s3api.Error {
	raw, apiErr := readVerifiedBody(r, authResult, maxTagBody)
	if apiErr != nil {
		return apiErr
	}
	var in taggingDoc
	if err := xml.Unmarshal(raw, &in); err != nil {
		return errMalformedXML.WithMessage("the Tagging body is not valid XML")
	}
	set := make([]tags.Tag, 0, len(in.Tags))
	for _, t := range in.Tags {
		set = append(set, tags.Tag(t))
	}
	if err := tags.Validate(set); err != nil {
		return errInvalidTag.WithMessage("%v", err)
	}

	target, apiErr, err := p.findTagTarget(r, req, log)
	if errors.Is(err, errUntaggable) {
		return errNotEncryptedAPI.WithMessage(
			"the object was not written by this gateway, so it cannot carry sealed tags; " +
				"encrypt-existing moves it behind the gateway")
	}
	if apiErr != nil {
		return apiErr
	}
	defer clear(target.dek)

	if apiErr := p.writeTags(r.Context(), req.Bucket, req.Key, target, set, log); apiErr != nil {
		return apiErr
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	return nil
}

// writeTags seals a tag set and stores it as the version's sidecar.
func (p *Proxy) writeTags(
	ctx context.Context, bucket, key string, target *tagTarget, set []tags.Tag, log *slog.Logger,
) *s3api.Error {
	sealed, err := tags.Seal(target.dek, bucket, key, set)
	if err != nil {
		log.Error("sealing the tag set failed", "err", err)
		return s3api.ErrInternal
	}
	if _, err := p.upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: bucket, Key: target.path,
		Body: bytes.NewReader(sealed), ContentLength: int64(len(sealed)),
		Metadata: tags.Metadata(target.storedKey),
	}); err != nil {
		log.Warn("the upstream refused the tag sidecar", "err", err)
		return translateUpstream(err)
	}
	return nil
}

// deleteObjectTagging removes the tags of the current version.
func (p *Proxy) deleteObjectTagging(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	target, apiErr, err := p.findTagTarget(r, req, log)
	if errors.Is(err, errUntaggable) {
		return errNotEncryptedAPI.WithMessage(
			"the object was not written by this gateway, so it carries no sealed tags to remove")
	}
	if apiErr != nil {
		return apiErr
	}
	clear(target.dek)
	if err := p.upstream.DeleteObject(r.Context(), req.Bucket, target.path); err != nil && !upstream.NotFound(err) {
		return translateUpstream(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// tagsFromHeader reads x-amz-tagging, which carries a tag set as a URL query:
// key1=value1&key2=value2. A key given twice is refused, as S3 refuses it.
func tagsFromHeader(r *http.Request) ([]tags.Tag, *s3api.Error) {
	raw := r.Header.Get("X-Amz-Tagging")
	if raw == "" {
		return nil, nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, errInvalidTag.WithMessage("x-amz-tagging is not a URL-encoded query: %v", err)
	}
	set := make([]tags.Tag, 0, len(values))
	for key, vs := range values {
		if len(vs) != 1 {
			return nil, errInvalidTag.WithMessage("the tag %q is given %d times", key, len(vs))
		}
		set = append(set, tags.Tag{Key: key, Value: vs[0]})
	}
	if err := tags.Validate(set); err != nil {
		return nil, errInvalidTag.WithMessage("%v", err)
	}
	return set, nil
}

// writeTagsBeforeObject stores the sidecar of a version about to be written,
// before the object becomes visible, as a manifest is (FORMAT.md section 17.4):
// the object is never visible without the tags it was written with. A write
// that then fails leaves the sidecar as an orphan for gc.
func (p *Proxy) writeTagsBeforeObject(
	ctx context.Context, bucket, key, storedKey string, meta objectMeta, dek []byte,
	set []tags.Tag, log *slog.Logger,
) *s3api.Error {
	if len(set) == 0 {
		return nil
	}
	target := &tagTarget{storedKey: storedKey, path: tags.Path(storedKey, objectmeta.StoredDEKOf(meta)), dek: dek}
	return p.writeTags(ctx, bucket, key, target, set, log)
}

// providerTagging forwards GetObjectTagging for an object the gateway did not
// write: its tags, if any, are the provider's, set out of band.
func (p *Proxy) providerTagging(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	storedKey, apiErr := p.storedKey(req.Key)
	if apiErr != nil {
		return apiErr
	}
	resp, err := p.upstream.ObjectPassthrough(r.Context(), http.MethodGet,
		req.Bucket, storedKey, url.Values{"tagging": {""}})
	if apiErr, ok := upstream.AsAPIError(err); ok && apiErr.Code == "NotImplemented" {
		// A provider without tagging (Garage) holds no tags, so the empty set is
		// its true answer rather than an invented one.
		log.Debug("object tagging not implemented upstream, answered empty")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return nil
		}
		return writeXML(w, http.StatusOK, taggingOut{})
	}
	if err != nil {
		return translateUpstream(err)
	}
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
