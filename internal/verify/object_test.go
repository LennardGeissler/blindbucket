package verify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// errReader delivers some bytes and then fails, as a connection that drops does.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// A decoder cannot tell a stream the connection cut from one the provider
// truncated. Scrub must: the first is a failure to read, the second a finding,
// and reporting a dropped connection as tampering would be a false alarm.
func TestShortReadIsNotAFinding(t *testing.T) {
	finding := fail(KindChunk, "stream", errors.New("segment ends after a non-final chunk"))

	for name, tc := range map[string]struct {
		body      io.Reader
		announced int64
		err       error
		wantShort bool
	}{
		"the connection failed mid-body": {
			body: &errReader{data: []byte("partial"), err: io.ErrUnexpectedEOF}, announced: 100,
			err: finding, wantShort: true,
		},
		"the body ended before its announced length": {
			body: strings.NewReader("partial"), announced: 100, err: finding, wantShort: true,
		},
		"the body was complete, so the object is what failed": {
			body: strings.NewReader("all of it"), announced: 9, err: finding,
		},
		"an error that is not a finding passes through": {
			body: strings.NewReader("partial"), announced: 100, err: errors.New("provider unreachable"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := &countingReader{r: tc.body}
			_, _ = io.Copy(io.Discard, body)
			got := shortOr(tc.err, body, tc.announced)

			if short := errors.Is(got, ErrShortRead); short != tc.wantShort {
				t.Fatalf("shortOr = %v; ErrShortRead %v, want %v", got, short, tc.wantShort)
			}
			if !tc.wantShort && !errors.Is(got, tc.err) {
				t.Errorf("shortOr = %v, want the original error", got)
			}
			if _, isFailure := AsFailure(got); isFailure && tc.wantShort {
				t.Error("a short read is still reported as a failure of the object")
			}
		})
	}
}

// Every error a segment read can produce maps onto the bounded set of kinds a
// scrub reports, and nothing outside it does.
func TestStreamKindIsBounded(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want Kind
		ok   bool
	}{
		"a header failure": {fmt.Errorf("opening: %w", &stream.IntegrityError{Kind: stream.KindHeader}), KindHeader, true},
		"a chunk failure":  {&stream.IntegrityError{Kind: stream.KindChunk}, KindChunk, true},
		"a size failure":   {&stream.IntegrityError{Kind: stream.KindSize}, KindSize, true},
		"a part from another attempt": {
			fmt.Errorf("%w: part 1 is a different attempt", manifest.ErrVerify), KindManifest, true,
		},
		"a transport error": {io.ErrUnexpectedEOF, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := streamKind(tc.err)
			if got != tc.want || ok != tc.ok {
				t.Errorf("streamKind = %q, %v; want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// fakeProvider serves one genuine single-part object, and can be told to cut
// the body short or to flip a byte in it. It is enough of S3 for a GET and a
// HEAD of that one key.
func fakeProvider(t *testing.T, mode string) (*upstream.Client, keys.KeyProvider) {
	t.Helper()
	ring := keys.NewKeyring()
	if err := ring.Generate("k"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dek, err := keys.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad, err := keys.ObjectAAD("k", "bucket", "key")
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}
	wrapped, err := ring.Wrap(t.Context(), "k", dek[:], aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	var sealed bytes.Buffer
	w, err := stream.NewEncryptWriter(&sealed, dek[:], stream.SegmentParams{Log2ChunkSize: stream.MinLog2ChunkSize})
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("blindbucket"), 3<<stream.MinLog2ChunkSize/11)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body := sealed.Bytes()
	meta := objectmeta.Meta{
		Version: stream.Version, KeyID: "k", WrappedDEK: wrapped,
		Log2ChunkSize: stream.MinLog2ChunkSize, HasChunkSize: true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		for k, v := range meta.Headers() {
			rw.Header().Set("X-Amz-Meta-"+k, v)
		}
		rw.Header().Set("ETag", `"v1"`)
		rw.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodHead {
			return
		}
		switch mode {
		case "cut":
			// Half the announced body, then the handler returns: the server
			// closes the connection, as a dropped transfer would.
			_, _ = rw.Write(body[:len(body)/2])
		case "flip":
			out := bytes.Clone(body)
			out[len(out)/2] ^= 0x01
			_, _ = rw.Write(out)
		default:
			_, _ = rw.Write(body)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := upstream.New(upstream.Config{
		Endpoint: srv.URL, Region: "us-east-1", PathStyle: true,
		AccessKeyID: "synthetic", SecretAccessKey: "synthetic", MaxRetries: 1,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return client, ring
}

// TestObjectTellsADroppedConnectionFromDamage drives the whole of Object, not
// only shortOr: a body that ends early is a failure to read, a body that
// arrives whole but altered is a finding, and an intact one verifies.
func TestObjectTellsADroppedConnectionFromDamage(t *testing.T) {
	target := Target{Bucket: "bucket", Identity: "key", Stored: "key"}

	t.Run("cut short", func(t *testing.T) {
		up, kp := fakeProvider(t, "cut")
		_, err := Object(t.Context(), up, kp, target, stream.MinLog2ChunkSize)
		if !errors.Is(err, ErrShortRead) {
			t.Fatalf("Object = %v, want ErrShortRead", err)
		}
		if _, isFailure := AsFailure(err); isFailure {
			t.Error("a dropped connection was reported as damage to the object")
		}
	})
	t.Run("whole but altered", func(t *testing.T) {
		up, kp := fakeProvider(t, "flip")
		_, err := Object(t.Context(), up, kp, target, stream.MinLog2ChunkSize)
		if f, isFailure := AsFailure(err); !isFailure || f.Kind != KindChunk {
			t.Fatalf("Object = %v, want a chunk failure", err)
		}
	})
	t.Run("intact", func(t *testing.T) {
		up, kp := fakeProvider(t, "")
		res, err := Object(t.Context(), up, kp, target, stream.MinLog2ChunkSize)
		if err != nil {
			t.Fatalf("Object = %v", err)
		}
		if res.ETag != `"v1"` || res.Parts != 1 || res.CipherBytes == 0 {
			t.Errorf("result = %+v", res)
		}
	})
}
