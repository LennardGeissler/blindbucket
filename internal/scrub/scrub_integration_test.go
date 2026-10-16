package scrub_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/scrub"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/LennardGeissler/blindbucket/internal/verify"
)

// These tests run a gateway through internal/proxy/proxytest, because they
// need what the proxy's tests have: a gateway to write genuine objects, and
// direct access to the provider to do to them what a hostile one would
// (ADR-028). Each hostile case asserts two things -- that scrub reports it,
// and that a GET refuses the same object -- because the point of sharing
// internal/verify is that the two never disagree.

// TestIntegrationScrubPassesWhatTheGatewayWrote: every shape of object the
// gateway produces verifies, and the bytes counted are exactly the bytes stored.
func TestIntegrationScrubPassesWhatTheGatewayWrote(t *testing.T) {
	h := proxytest.New(t)
	prefix := proxytest.ScrubPrefix(t)
	chunk := 1 << stream.MinLog2ChunkSize

	h.Store(t, prefix+"small", []byte("blindbucket"))
	h.Store(t, prefix+"chunks", proxytest.RandomBytes(t, 3*chunk+5))
	h.Store(t, prefix+"empty", nil)
	h.StoreParts(t, prefix+"multipart", proxytest.TestPart, proxytest.TestPart, 500)

	var stored int64
	for _, name := range []string{"small", "chunks", "empty", "multipart"} {
		info, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, prefix+name)
		if err != nil {
			t.Fatalf("HEAD %s: %v", name, err)
		}
		stored += info.ContentLength
	}

	result := h.Scrub(t, h.ScrubConfig(prefix))
	if result.Scanned != 4 || result.Verified != 4 || result.Incomplete() {
		t.Fatalf("scanned %d, verified %d, failed %d, unreadable %d; want 4 verified and nothing else (findings: %+v)",
			result.Scanned, result.Verified, result.Failed, result.Errors, result.Findings)
	}
	if result.CipherBytes != stored {
		t.Errorf("verified %d bytes of ciphertext, the provider stores %d", result.CipherBytes, stored)
	}
	if len(result.Findings) != 0 {
		t.Errorf("findings on a clean prefix: %+v", result.Findings)
	}
}

// TestIntegrationScrubReportsWhatAHostileProviderDid: each case is something an
// active provider (A2) can do to an object at rest. Scrub must name it with the
// right kind, and a GET of the same object must refuse it.
func TestIntegrationScrubReportsWhatAHostileProviderDid(t *testing.T) {
	sealed, err := stream.SealedSize(proxytest.TestPart, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}
	chunk := 1 << stream.MinLog2ChunkSize

	for name, tc := range map[string]struct {
		// damage stores an object under key and damages it; it returns the key
		// a client would read, which for the copy case is not key.
		damage func(t *testing.T, h *proxytest.Harness, key string) string
		want   verify.Kind
	}{
		"a flipped ciphertext byte": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				h.Store(t, key, proxytest.RandomBytes(t, 3*chunk))
				h.RewriteUpstream(t, key, func(b []byte) []byte {
					out := bytes.Clone(b)
					out[len(out)/2] ^= 0x01
					return out
				})
				return key
			},
			want: verify.KindChunk,
		},
		"a truncated object": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				h.Store(t, key, proxytest.RandomBytes(t, 3*chunk))
				h.RewriteUpstream(t, key, func(b []byte) []byte { return bytes.Clone(b[:len(b)-chunk]) })
				return key
			},
			// A whole chunk gone leaves a length no encoder produces, which is
			// caught before a byte is decrypted.
			want: verify.KindSize,
		},
		"an object copied to a key it was never written under": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				original := key + ".original"
				h.Store(t, original, []byte("bound to its own name"))
				get, err := h.Upstream.GetObject(t.Context(), upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: original})
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				raw, _ := io.ReadAll(get.Body)
				_ = get.Body.Close()
				if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
					Bucket: proxytest.Bucket, Key: key, Body: bytes.NewReader(raw),
					ContentLength: int64(len(raw)), Metadata: get.Metadata,
				}); err != nil {
					t.Fatalf("PUT: %v", err)
				}
				// Only the copy is under the prefix being scrubbed.
				if err := h.Upstream.DeleteObject(t.Context(), proxytest.Bucket, original); err != nil {
					t.Fatalf("DELETE: %v", err)
				}
				t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key) })
				return key
			},
			want: verify.KindDEKUnwrap,
		},
		"a deleted manifest": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				h.StoreParts(t, key, proxytest.TestPart, 500)
				manifestKey, _ := h.ManifestKeyOf(t, key)
				if err := h.Upstream.DeleteObject(t.Context(), proxytest.Bucket, manifestKey); err != nil {
					t.Fatalf("deleting the manifest: %v", err)
				}
				return key
			},
			want: verify.KindManifest,
		},
		"reordered parts": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				h.StoreParts(t, key, proxytest.TestPart, proxytest.TestPart, 500)
				h.RewriteUpstream(t, key, func(b []byte) []byte {
					out := bytes.Clone(b)
					copy(out[0:sealed], b[sealed:2*sealed])
					copy(out[sealed:2*sealed], b[0:sealed])
					return out
				})
				return key
			},
			want: verify.KindHeader,
		},
		"a dropped part": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				h.StoreParts(t, key, proxytest.TestPart, proxytest.TestPart, 500)
				h.RewriteUpstream(t, key, func(b []byte) []byte { return bytes.Clone(b[sealed:]) })
				return key
			},
			want: verify.KindSize,
		},
		"a part substituted by another genuine attempt": {
			damage: func(t *testing.T, h *proxytest.Harness, key string) string {
				parts := h.StoreParts(t, key, proxytest.TestPart, 500)
				substitute := h.ReencryptPart(t, key, 1, parts[0])
				h.RewriteUpstream(t, key, func(b []byte) []byte {
					out := bytes.Clone(b)
					copy(out, substitute)
					return out
				})
				return key
			},
			want: verify.KindManifest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := proxytest.New(t)
			prefix := proxytest.ScrubPrefix(t)
			key := tc.damage(t, h, prefix+"object")

			result := h.Scrub(t, h.ScrubConfig(prefix))
			if result.Failed != 1 || len(result.Findings) != 1 {
				t.Fatalf("failed %d, findings %+v; want exactly one finding", result.Failed, result.Findings)
			}
			got := result.Findings[0]
			if got.Key != key || got.Kind != tc.want {
				t.Errorf("finding %+v, want key %q with kind %q", got, key, tc.want)
			}
			if !result.Incomplete() {
				t.Error("a run with a finding does not report itself incomplete")
			}
			expectReadFails(t, h, key, name)
		})
	}
}

// expectReadFails asserts that a GET of the whole object does not deliver it:
// refused before the status line, or aborted mid-body when the damage lies past
// the first chunk (ADR-004). Either way no client takes it for a complete read.
func expectReadFails(t *testing.T, h *proxytest.Harness, key, what string) {
	t.Helper()
	resp := h.Do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if body := proxytest.ReadBody(t, resp); !strings.Contains(body, "IntegrityCheckFailed") {
			t.Errorf("%s: GET refused with %d, but not as an integrity failure: %s", what, resp.StatusCode, body)
		}
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err == nil || int64(len(body)) >= resp.ContentLength {
		t.Errorf("%s: a GET delivered the object (%d of %d bytes, err %v)", what, len(body), resp.ContentLength, err)
	}
}

// TestIntegrationScrubCountsWhatItCannotJudge: an object the gateway did not
// write is not a failure, and an object whose key is missing from the keyring
// is -- the scrub cannot vouch for it, and neither can a read.
func TestIntegrationScrubCountsWhatItCannotJudge(t *testing.T) {
	h := proxytest.New(t)

	t.Run("an object the gateway did not write", func(t *testing.T) {
		prefix := proxytest.ScrubPrefix(t)
		key := prefix + "foreign"
		body := []byte("written straight to the provider")
		if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
			Bucket: proxytest.Bucket, Key: key, Body: bytes.NewReader(body), ContentLength: int64(len(body)),
		}); err != nil {
			t.Fatalf("PUT: %v", err)
		}
		t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key) })

		result := h.Scrub(t, h.ScrubConfig(prefix))
		if result.Scanned != 1 || result.Foreign != 1 || result.Incomplete() {
			t.Errorf("scanned %d, foreign %d, failed %d; want one foreign object and no failure",
				result.Scanned, result.Foreign, result.Failed)
		}
	})

	t.Run("a key the keyring no longer holds", func(t *testing.T) {
		prefix := proxytest.ScrubPrefix(t)
		h.Store(t, prefix+"object", []byte("wrapped under a key that was removed"))

		other := keys.NewKeyring()
		if err := other.Generate("someone-else"); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		cfg := h.ScrubConfig(prefix)
		cfg.Keys = other
		result := h.Scrub(t, cfg)
		if result.Failed != 1 || len(result.Findings) != 1 || result.Findings[0].Kind != verify.KindUnknownKID {
			t.Errorf("failed %d, findings %+v; want one unknown_kid finding", result.Failed, result.Findings)
		}
	})
}

// TestIntegrationScrubUnderEncryptedNames: a scrub lists stored names and binds
// each data key to the name a client uses, exactly as a rotation does. Without
// the name key every object would look tampered with.
func TestIntegrationScrubUnderEncryptedNames(t *testing.T) {
	option, enc := proxytest.WithEncryptedNames(t)
	h := proxytest.New(t, option)
	prefix := fmt.Sprintf("scrub-names/%d/", time.Now().UnixNano())

	for _, name := range []string{"a.txt", "dir/b.txt", "dir/multipart.bin"} {
		key := prefix + name
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		h.CleanupStored(t, stored)
		if strings.HasSuffix(name, ".bin") {
			// The manifest lives at the hash of the *stored* name and its data
			// key is bound to the client's: a multipart object is the one that
			// would fail if scrub mixed the two up.
			h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 500)})
			continue
		}
		resp := h.Put(t, key, []byte("under an encrypted name: "+name), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s returned %d", name, resp.StatusCode)
		}
	}

	result := h.Scrub(t, h.ScrubConfig(prefix))
	if result.Verified != 3 || result.Incomplete() {
		t.Errorf("verified %d, failed %d (%+v); want all three objects verified",
			result.Verified, result.Failed, result.Findings)
	}
}

// putAsClient writes through the gateway without a *testing.T, for use from a
// scrub worker's goroutine, where t.Fatal must not be called.
func putAsClient(h *proxytest.Harness, key string, body []byte) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, h.URL(key), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PUT returned %d", resp.StatusCode)
	}
	return nil
}

// flipMiddleByte damages a stored object the way the hostile tests do, without
// a *testing.T.
func flipMiddleByte(h *proxytest.Harness, key string) error {
	ctx := context.Background()
	get, err := h.Upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: key})
	if err != nil {
		return err
	}
	stored, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		return err
	}
	stored[len(stored)/2] ^= 0x01
	_, err = h.Upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key, Body: bytes.NewReader(stored),
		ContentLength: int64(len(stored)), Metadata: get.Metadata,
	})
	return err
}

// TestIntegrationScrubRechecksBeforeReporting: an object that changes while it
// is being verified is not reported on the strength of the version it was. Here
// the first read sees a damaged object, and the hook changes it before the
// recheck -- the order of events an overwrite racing a multipart read
// produces, where the manifest the read started with is deleted (rule R3).
// Replaced by a good version, it verifies; deleted, it vanished; replaced by
// another damaged version, the recheck confirms that one, and it is reported.
func TestIntegrationScrubRechecksBeforeReporting(t *testing.T) {
	h := proxytest.New(t)
	damaged := func() []byte { return proxytest.RandomBytes(t, 3*(1<<stream.MinLog2ChunkSize)) }

	for name, tc := range map[string]struct {
		meanwhile                          func(h *proxytest.Harness, key string) error
		wantVerified, wantGone, wantFailed int64
	}{
		"replaced by a client": {
			meanwhile: func(h *proxytest.Harness, key string) error {
				return putAsClient(h, key, []byte("the client's new version"))
			},
			wantVerified: 1,
		},
		"deleted by a client": {
			meanwhile: func(h *proxytest.Harness, key string) error {
				return h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key)
			},
			wantGone: 1,
		},
		"replaced by another damaged version": {
			meanwhile: func(h *proxytest.Harness, key string) error {
				if err := putAsClient(h, key, bytes.Repeat([]byte("v2"), 3<<stream.MinLog2ChunkSize)); err != nil {
					return err
				}
				return flipMiddleByte(h, key)
			},
			wantFailed: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			prefix := proxytest.ScrubPrefix(t)
			key := prefix + "object"
			h.Store(t, key, damaged())
			if err := flipMiddleByte(h, key); err != nil {
				t.Fatalf("damaging the object: %v", err)
			}

			var hookErr atomic.Value
			cfg := h.ScrubConfig(prefix)
			cfg.Hook = func(string) {
				if err := tc.meanwhile(h, key); err != nil {
					hookErr.Store(err)
				}
			}
			result := h.Scrub(t, cfg)
			if err, _ := hookErr.Load().(error); err != nil {
				t.Fatalf("changing the object mid-scrub: %v", err)
			}
			if result.Failed != tc.wantFailed || result.Verified != tc.wantVerified || result.Vanished != tc.wantGone {
				t.Errorf("verified %d, vanished %d, failed %d (%+v); want verified %d, vanished %d, failed %d",
					result.Verified, result.Vanished, result.Failed, result.Findings,
					tc.wantVerified, tc.wantGone, tc.wantFailed)
			}
		})
	}
}

// TestIntegrationScrubInterruptedAtTheLastObject: the listing has handed out
// every key by the time the last ones are verified, so an interrupt then only
// reaches the workers. The run must still say it did not finish -- a summary
// of a run that was stopped is not the state of the prefix.
func TestIntegrationScrubInterruptedAtTheLastObject(t *testing.T) {
	h := proxytest.New(t)
	prefix := proxytest.ScrubPrefix(t)
	h.Store(t, prefix+"only", []byte("the last object of the prefix"))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := h.ScrubConfig(prefix)
	cfg.Hook = func(string) { cancel() }

	_, err := scrub.Run(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("scrub.Run = %v, want context.Canceled", err)
	}
}
