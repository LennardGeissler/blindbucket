package encrypt

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// TestJudgePlainLeavesWhatItMayNotTouch is ADR-034's list of objects a run
// leaves, each with its own count, and the one it takes: a plaintext object
// with nothing that an overwrite would lose or break.
func TestJudgePlainLeavesWhatItMayNotTouch(t *testing.T) {
	t.Parallel()
	gateway := objectmeta.Meta{
		Version: stream.Version, KeyID: "k1", WrappedDEK: make([]byte, 60), Log2ChunkSize: 16,
	}.Headers()
	tomorrow := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	yesterday := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)

	for _, tc := range []struct {
		name     string
		metadata map[string]string
		header   http.Header
		names    bool
		want     outcome
		take     bool
	}{
		{name: "a plaintext object is taken", take: true},
		{name: "plaintext with user metadata is taken", metadata: map[string]string{"owner": "a"}, take: true},
		{name: "an object the gateway wrote is skipped", metadata: gateway, want: skipped},
		{name: "with names encrypted, a gateway object at a key in clear needs migrate-names",
			metadata: gateway, names: true, want: needsNameMigration},
		{name: "metadata under the gateway's prefix is a conflict",
			metadata: map[string]string{"bb-note": "x"}, want: conflicted},
		{name: "a broken gateway envelope is a conflict",
			metadata: map[string]string{"bb-dek": "not base64!"}, want: conflicted},
		{name: "a tagged object is left", header: http.Header{"X-Amz-Tagging-Count": {"2"}}, want: tagged},
		{name: "a tag count of zero is no tag", header: http.Header{"X-Amz-Tagging-Count": {"0"}}, take: true},
		{name: "a legal hold is left", header: http.Header{"X-Amz-Object-Lock-Legal-Hold": {"ON"}}, want: locked},
		{name: "a retention period still running is left",
			header: http.Header{"X-Amz-Object-Lock-Retain-Until-Date": {tomorrow}}, want: locked},
		{name: "a retention period that ended is no lock",
			header: http.Header{"X-Amz-Object-Lock-Retain-Until-Date": {yesterday}}, take: true},
		{name: "an SSE-C object is unreadable",
			header: http.Header{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}}, want: unreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info := &upstream.ObjectInfo{Metadata: tc.metadata, Header: tc.header}
			if info.Header == nil {
				info.Header = http.Header{}
			}
			cfg := Config{Log2ChunkSize: 16}
			if tc.names {
				enc, err := names.New(make([]byte, names.KeySize))
				if err != nil {
					t.Fatalf("names.New: %v", err)
				}
				cfg.Names = enc
			}
			got, take := judgePlain(cfg, info, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if take != tc.take || (!take && got != tc.want) {
				t.Errorf("judgePlain = (%v, %v), want (%v, %v)", got, take, tc.want, tc.take)
			}
		})
	}
}

// TestRunRefusesAVersionedBucket: a run on a bucket with versioning would leave
// every object's plaintext at the provider as a noncurrent version, so it is
// refused before anything is listed or written -- unless the operator says the
// old versions are handled.
func TestRunRefusesAVersionedBucket(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"Enabled", "Suspended"} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			var touched []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, ok := r.URL.Query()["versioning"]; ok {
					_, _ = io.WriteString(w, `<VersioningConfiguration><Status>`+status+
						`</Status></VersioningConfiguration>`)
					return
				}
				touched = append(touched, r.Method+" "+r.URL.String())
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			up, err := upstream.New(upstream.Config{
				Endpoint: server.URL, Region: "us-east-1", PathStyle: true,
				AccessKeyID: "AKIDTEST", SecretAccessKey: "secret",
			})
			if err != nil {
				t.Fatalf("upstream.New: %v", err)
			}
			ring := keys.NewKeyring()
			if err := ring.Generate("k1"); err != nil {
				t.Fatalf("Generate: %v", err)
			}

			_, err = Run(context.Background(), Config{
				Upstream: up, Keys: ring, Bucket: "photos", AllowUnconditional: true,
				Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			var refusal *VersionedError
			if !errors.As(err, &refusal) {
				t.Fatalf("Run returned %v, want a VersionedError", err)
			}
			if !strings.Contains(err.Error(), "--keep-versions") {
				t.Errorf("the refusal does not name the way out: %v", err)
			}
			if len(touched) > 0 {
				t.Errorf("the refused run sent %v", touched)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"d41d8cd98f00b204e9800998ecf8427e":              true,
		"D41D8CD98F00B204E9800998ECF8427E":              false,
		"d41d8cd98f00b204e9800998ecf8427e-2"[:32] + "x": false,
	} {
		if got := isHex(s); got != want {
			t.Errorf("isHex(%q) = %v, want %v", s, got, want)
		}
	}
}
