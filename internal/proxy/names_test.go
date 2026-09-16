package proxy

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

func testEncrypter(t *testing.T) *names.Encrypter {
	t.Helper()
	key := make([]byte, names.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	enc, err := names.New(key)
	if err != nil {
		t.Fatalf("names.New: %v", err)
	}
	return enc
}

// TestStoredKeyIsTheIdentityWhenOff is what lets every call site apply it
// unconditionally: with names off the gateway must address the provider with
// exactly the key the client named, byte for byte.
func TestStoredKeyIsTheIdentityWhenOff(t *testing.T) {
	p := &Proxy{}
	for _, key := range []string{"", "a", "a/b/c.txt", "photos/2026/03/14/IMG.jpg",
		"weird//double", "trailing/", strings.Repeat("x", 1024)} {
		got, apiErr := p.storedKey(key)
		if apiErr != nil {
			t.Fatalf("storedKey(%q): %v", key, apiErr)
		}
		if got != key {
			t.Errorf("storedKey(%q) = %q, want the key unchanged", key, got)
		}
	}
}

func TestStoredKeyMapsAndRoundTripsWhenOn(t *testing.T) {
	enc := testEncrypter(t)
	p := &Proxy{names: enc}

	for _, key := range []string{"a", "a/b/c.txt", "photos/2026/03/14/IMG.jpg", "weird//double"} {
		stored, apiErr := p.storedKey(key)
		if apiErr != nil {
			t.Fatalf("storedKey(%q): %v", key, apiErr)
		}
		if stored == key {
			t.Errorf("storedKey(%q) returned the plaintext key", key)
		}
		if strings.Contains(stored, key) {
			t.Errorf("storedKey(%q) = %q still contains the plaintext", key, stored)
		}
		back, err := enc.DecryptKey(stored)
		if err != nil {
			t.Fatalf("DecryptKey(%q): %v", stored, err)
		}
		if back != key {
			t.Errorf("round trip gave %q, want %q", back, key)
		}
	}
}

// TestStoredKeyPreservesSeparators is why prefix listing can work at all: the
// '/' between segments survives encryption, so "a/b/" stays a prefix of
// "a/b/c.txt" upstream.
func TestStoredKeyPreservesSeparators(t *testing.T) {
	p := &Proxy{names: testEncrypter(t)}
	dir, apiErr := p.storedKey("a/b")
	if apiErr != nil {
		t.Fatalf("storedKey: %v", apiErr)
	}
	child, apiErr := p.storedKey("a/b/c.txt")
	if apiErr != nil {
		t.Fatalf("storedKey: %v", apiErr)
	}
	if !strings.HasPrefix(child, dir+"/") {
		t.Errorf("the encrypted child %q does not sit under the encrypted parent %q", child, dir)
	}
	if strings.Count(child, "/") != 2 {
		t.Errorf("segment count changed: %q has %d separators, want 2", child, strings.Count(child, "/"))
	}
}

// TestStoredKeyIsDeterministic is the property the whole design rests on: one
// plaintext key maps to one stored key, every time, with no lookup. Without it
// a point lookup would become a search.
func TestStoredKeyIsDeterministic(t *testing.T) {
	p := &Proxy{names: testEncrypter(t)}
	first, _ := p.storedKey("photos/2026/holiday.jpg")
	for range 8 {
		again, apiErr := p.storedKey("photos/2026/holiday.jpg")
		if apiErr != nil {
			t.Fatalf("storedKey: %v", apiErr)
		}
		if again != first {
			t.Fatalf("the same key encrypted two ways: %q then %q", first, again)
		}
	}
}

// TestStoredKeyRefusesAKeyTooLongToEncrypt: a key S3 would accept can have no
// legal encrypted form, and the client has to be told so rather than have its
// key truncated into a different object.
func TestStoredKeyRefusesAKeyTooLongToEncrypt(t *testing.T) {
	p := &Proxy{names: testEncrypter(t)}
	// Short segments pay the per-segment IV over and over, so this is well
	// inside S3's own 1024-byte limit.
	deep := strings.TrimSuffix(strings.Repeat("abcd/", 200), "/")
	if len(deep) > 1024 {
		t.Fatalf("the test key is %d bytes, which S3 would refuse on its own", len(deep))
	}
	_, apiErr := p.storedKey(deep)
	if apiErr == nil {
		t.Fatal("a key too long to encrypt was accepted")
	}
	if apiErr.Code != s3api.ErrKeyTooLong.Code {
		t.Errorf("code = %q, want %q", apiErr.Code, s3api.ErrKeyTooLong.Code)
	}
}

// TestNameEncryptionGateIsAWhitelist: with names on, anything not taught what an
// encrypted name means must be refused rather than guessed at.
func TestNameEncryptionGateIsAWhitelist(t *testing.T) {
	allowed := []s3api.Operation{
		s3api.OpPutObject, s3api.OpGetObject, s3api.OpHeadObject, s3api.OpDeleteObject,
		s3api.OpListObjects, s3api.OpListObjectsV2,
		s3api.OpListBuckets, s3api.OpHeadBucket, s3api.OpCreateBucket,
		s3api.OpDeleteBucket, s3api.OpGetBucketLocation,
	}
	refused := []s3api.Operation{
		s3api.OpDeleteObjects,
		s3api.OpCopyObject, s3api.OpGetObjectTagging,
		s3api.OpCreateMultipartUpload, s3api.OpUploadPart, s3api.OpUploadPartCopy,
		s3api.OpCompleteMultipartUpload, s3api.OpAbortMultipartUpload, s3api.OpListParts,
	}

	off := &Proxy{}
	for _, op := range append(append([]s3api.Operation{}, allowed...), refused...) {
		if gate := off.nameEncryptionGate(op); gate != nil {
			t.Errorf("with names off, %s was refused: %v", op, gate)
		}
	}

	on := &Proxy{names: testEncrypter(t)}
	for _, op := range allowed {
		if gate := on.nameEncryptionGate(op); gate != nil {
			t.Errorf("%s should be wired for encrypted names, got: %v", op, gate)
		}
	}
	for _, op := range refused {
		gate := on.nameEncryptionGate(op)
		if gate == nil {
			t.Errorf("%s is not wired for encrypted names but was allowed", op)
			continue
		}
		if gate.Code != s3api.ErrNotImplemented.Code {
			t.Errorf("%s refused with %q, want %q", op, gate.Code, s3api.ErrNotImplemented.Code)
		}
		if !strings.Contains(gate.Message, string(op)) {
			t.Errorf("the refusal for %s does not name the operation: %q", op, gate.Message)
		}
	}
}
