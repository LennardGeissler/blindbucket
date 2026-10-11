package verify

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
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
