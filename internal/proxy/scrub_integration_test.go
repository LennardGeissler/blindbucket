package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/scrub"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/LennardGeissler/blindbucket/internal/verify"
)

// The scrub tests live with the proxy's because they need what the proxy's
// tests have: a gateway to write genuine objects, and direct access to the
// provider to do to them what a hostile one would (ADR-028). Each hostile case
// asserts two things -- that scrub reports it, and that a GET refuses the same
// object -- because the point of sharing internal/verify is that the two never
// disagree.

func (h *harness) scrubConfig(prefix string) scrub.Config {
	return scrub.Config{
		Upstream: h.upstream, Keys: h.keyring, Bucket: testBucket, Prefix: prefix,
		Log2ChunkSize: h.gateway.log2C, Names: h.gateway.names, Concurrency: 4,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (h *harness) scrub(t *testing.T, cfg scrub.Config) *scrub.Result {
	t.Helper()
	result, err := scrub.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("scrub.Run: %v", err)
	}
	return result
}

// scrubPrefix is a prefix of the test's own, ending on '/', so that a scrub
// sees this test's objects and nothing else.
func scrubPrefix(t *testing.T) string {
	t.Helper()
	return testKey(t, "")
}

// TestIntegrationScrubPassesWhatTheGatewayWrote: every shape of object the
// gateway produces verifies, and the bytes counted are exactly the bytes stored.
func TestIntegrationScrubPassesWhatTheGatewayWrote(t *testing.T) {
	h := newHarness(t)
	prefix := scrubPrefix(t)
	chunk := 1 << stream.MinLog2ChunkSize

	h.store(t, prefix+"small", []byte("blindbucket"))
	h.store(t, prefix+"chunks", randomBytes(t, 3*chunk+5))
	h.store(t, prefix+"empty", nil)
	h.storeParts(t, prefix+"multipart", testPart, testPart, 500)

	var stored int64
	for _, name := range []string{"small", "chunks", "empty", "multipart"} {
		info, err := h.upstream.HeadObject(t.Context(), testBucket, prefix+name)
		if err != nil {
			t.Fatalf("HEAD %s: %v", name, err)
		}
		stored += info.ContentLength
	}

	result := h.scrub(t, h.scrubConfig(prefix))
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
	sealed, err := stream.SealedSize(testPart, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}
	chunk := 1 << stream.MinLog2ChunkSize

	for name, tc := range map[string]struct {
		// damage stores an object under key and damages it; it returns the key
		// a client would read, which for the copy case is not key.
		damage func(t *testing.T, h *harness, key string) string
		want   verify.Kind
	}{
		"a flipped ciphertext byte": {
			damage: func(t *testing.T, h *harness, key string) string {
				h.store(t, key, randomBytes(t, 3*chunk))
				h.rewriteUpstream(t, key, func(b []byte) []byte {
					out := bytes.Clone(b)
					out[len(out)/2] ^= 0x01
					return out
				})
				return key
			},
			want: verify.KindChunk,
		},
		"a truncated object": {
			damage: func(t *testing.T, h *harness, key string) string {
				h.store(t, key, randomBytes(t, 3*chunk))
				h.rewriteUpstream(t, key, func(b []byte) []byte { return bytes.Clone(b[:len(b)-chunk]) })
				return key
			},
			// A whole chunk gone leaves a length no encoder produces, which is
			// caught before a byte is decrypted.
			want: verify.KindSize,
		},
		"an object copied to a key it was never written under": {
			damage: func(t *testing.T, h *harness, key string) string {
				original := key + ".original"
				h.store(t, original, []byte("bound to its own name"))
				get, err := h.upstream.GetObject(t.Context(), upstream.GetObjectInput{Bucket: testBucket, Key: original})
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				raw, _ := io.ReadAll(get.Body)
				_ = get.Body.Close()
				if _, err := h.upstream.PutObject(t.Context(), upstream.PutObjectInput{
					Bucket: testBucket, Key: key, Body: bytes.NewReader(raw),
					ContentLength: int64(len(raw)), Metadata: get.Metadata,
				}); err != nil {
					t.Fatalf("PUT: %v", err)
				}
				// Only the copy is under the prefix being scrubbed.
				if err := h.upstream.DeleteObject(t.Context(), testBucket, original); err != nil {
					t.Fatalf("DELETE: %v", err)
				}
				t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, key) })
				return key
			},
			want: verify.KindDEKUnwrap,
		},
		"a deleted manifest": {
			damage: func(t *testing.T, h *harness, key string) string {
				h.storeParts(t, key, testPart, 500)
				manifestKey, _ := h.manifestKeyOf(t, key)
				if err := h.upstream.DeleteObject(t.Context(), testBucket, manifestKey); err != nil {
					t.Fatalf("deleting the manifest: %v", err)
				}
				return key
			},
			want: verify.KindManifest,
		},
		"reordered parts": {
			damage: func(t *testing.T, h *harness, key string) string {
				h.storeParts(t, key, testPart, testPart, 500)
				h.rewriteUpstream(t, key, func(b []byte) []byte {
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
			damage: func(t *testing.T, h *harness, key string) string {
				h.storeParts(t, key, testPart, testPart, 500)
				h.rewriteUpstream(t, key, func(b []byte) []byte { return bytes.Clone(b[sealed:]) })
				return key
			},
			want: verify.KindSize,
		},
		"a part substituted by another genuine attempt": {
			damage: func(t *testing.T, h *harness, key string) string {
				parts := h.storeParts(t, key, testPart, 500)
				substitute := h.reencryptPart(t, key, 1, parts[0])
				h.rewriteUpstream(t, key, func(b []byte) []byte {
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
			h := newHarness(t)
			prefix := scrubPrefix(t)
			key := tc.damage(t, h, prefix+"object")

			result := h.scrub(t, h.scrubConfig(prefix))
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
			h.expectReadFails(t, key, name)
		})
	}
}

// expectReadFails asserts that a GET of the whole object does not deliver it:
// refused before the status line, or aborted mid-body when the damage lies past
// the first chunk (ADR-004). Either way no client takes it for a complete read.
func (h *harness) expectReadFails(t *testing.T, key, what string) {
	t.Helper()
	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if body := readBody(t, resp); !strings.Contains(body, "IntegrityCheckFailed") {
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
	h := newHarness(t)

	t.Run("an object the gateway did not write", func(t *testing.T) {
		prefix := scrubPrefix(t)
		key := prefix + "foreign"
		body := []byte("written straight to the provider")
		if _, err := h.upstream.PutObject(t.Context(), upstream.PutObjectInput{
			Bucket: testBucket, Key: key, Body: bytes.NewReader(body), ContentLength: int64(len(body)),
		}); err != nil {
			t.Fatalf("PUT: %v", err)
		}
		t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, key) })

		result := h.scrub(t, h.scrubConfig(prefix))
		if result.Scanned != 1 || result.Foreign != 1 || result.Incomplete() {
			t.Errorf("scanned %d, foreign %d, failed %d; want one foreign object and no failure",
				result.Scanned, result.Foreign, result.Failed)
		}
	})

	t.Run("a key the keyring no longer holds", func(t *testing.T) {
		prefix := scrubPrefix(t)
		h.store(t, prefix+"object", []byte("wrapped under a key that was removed"))

		other := keys.NewKeyring()
		if err := other.Generate("someone-else"); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		cfg := h.scrubConfig(prefix)
		cfg.Keys = other
		result := h.scrub(t, cfg)
		if result.Failed != 1 || len(result.Findings) != 1 || result.Findings[0].Kind != verify.KindUnknownKID {
			t.Errorf("failed %d, findings %+v; want one unknown_kid finding", result.Failed, result.Findings)
		}
	})
}

// TestIntegrationScrubUnderEncryptedNames: a scrub lists stored names and binds
// each data key to the name a client uses, exactly as a rotation does. Without
// the name key every object would look tampered with.
func TestIntegrationScrubUnderEncryptedNames(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	prefix := fmt.Sprintf("scrub-names/%d/", time.Now().UnixNano())

	for _, name := range []string{"a.txt", "dir/b.txt", "dir/multipart.bin"} {
		key := prefix + name
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		h.cleanupStored(t, stored)
		if strings.HasSuffix(name, ".bin") {
			// The manifest lives at the hash of the *stored* name and its data
			// key is bound to the client's: a multipart object is the one that
			// would fail if scrub mixed the two up.
			h.mpuStore(t, key, [][]byte{randomBytes(t, testPart), randomBytes(t, 500)})
			continue
		}
		resp := h.put(t, key, []byte("under an encrypted name: "+name), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s returned %d", name, resp.StatusCode)
		}
	}

	result := h.scrub(t, h.scrubConfig(prefix))
	if result.Verified != 3 || result.Incomplete() {
		t.Errorf("verified %d, failed %d (%+v); want all three objects verified",
			result.Verified, result.Failed, result.Findings)
	}
}

// putAsClient writes through the gateway without a *testing.T, for use from a
// scrub worker's goroutine, where t.Fatal must not be called.
func (h *harness) putAsClient(key string, body []byte) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, h.url(key), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	resp, err := h.client.Do(req)
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
func (h *harness) flipMiddleByte(key string) error {
	ctx := context.Background()
	get, err := h.upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: testBucket, Key: key})
	if err != nil {
		return err
	}
	stored, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		return err
	}
	stored[len(stored)/2] ^= 0x01
	_, err = h.upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: testBucket, Key: key, Body: bytes.NewReader(stored),
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
	h := newHarness(t)
	damaged := func() []byte { return randomBytes(t, 3*(1<<stream.MinLog2ChunkSize)) }

	for name, tc := range map[string]struct {
		meanwhile                          func(h *harness, key string) error
		wantVerified, wantGone, wantFailed int64
	}{
		"replaced by a client": {
			meanwhile: func(h *harness, key string) error {
				return h.putAsClient(key, []byte("the client's new version"))
			},
			wantVerified: 1,
		},
		"deleted by a client": {
			meanwhile: func(h *harness, key string) error {
				return h.upstream.DeleteObject(context.Background(), testBucket, key)
			},
			wantGone: 1,
		},
		"replaced by another damaged version": {
			meanwhile: func(h *harness, key string) error {
				if err := h.putAsClient(key, bytes.Repeat([]byte("v2"), 3<<stream.MinLog2ChunkSize)); err != nil {
					return err
				}
				return h.flipMiddleByte(key)
			},
			wantFailed: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			prefix := scrubPrefix(t)
			key := prefix + "object"
			h.store(t, key, damaged())
			if err := h.flipMiddleByte(key); err != nil {
				t.Fatalf("damaging the object: %v", err)
			}

			var hookErr atomic.Value
			cfg := h.scrubConfig(prefix)
			cfg.Hook = func(string) {
				if err := tc.meanwhile(h, key); err != nil {
					hookErr.Store(err)
				}
			}
			result := h.scrub(t, cfg)
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
	h := newHarness(t)
	prefix := scrubPrefix(t)
	h.store(t, prefix+"only", []byte("the last object of the prefix"))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := h.scrubConfig(prefix)
	cfg.Hook = func(string) { cancel() }

	_, err := scrub.Run(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("scrub.Run = %v, want context.Canceled", err)
	}
}
