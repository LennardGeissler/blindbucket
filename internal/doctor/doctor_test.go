package doctor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// fakeProvider answers every request with status, an S3 error document for
// code and message when code is set, and the given extra headers.
func fakeProvider(t *testing.T, status int, code, message string, header http.Header) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range header {
			w.Header()[k] = v
		}
		if code == "" {
			w.WriteHeader(status)
			_, _ = fmt.Fprint(w, `<ListBucketResult><Name>b</Name></ListBucketResult>`)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `<Error><Code>%s</Code><Message>%s</Message></Error>`, code, message)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// providerFor builds a Provider whose requests go through a Recorder, as
// doctor's do, to endpoint.
func providerFor(t *testing.T, endpoint string, base http.RoundTripper) Provider {
	t.Helper()
	recorder := NewRecorder(base)
	client, err := upstream.New(upstream.Config{
		Endpoint: endpoint, Region: "us-east-1", PathStyle: true,
		AccessKeyID: "k", SecretAccessKey: "s",
		HTTPClient: &http.Client{Transport: recorder}, MaxRetries: 1,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return Provider{Client: client, Recorder: recorder, Endpoint: endpoint, Region: "us-east-1"}
}

func TestBucketNamesTheFix(t *testing.T) {
	cases := map[string]struct {
		status  int
		code    string
		message string
		header  http.Header
		fix     string
	}{
		"unknown key":   {403, "InvalidAccessKeyId", "no such key", nil, "upstream.access_key_id"},
		"wrong secret":  {403, "SignatureDoesNotMatch", "mismatch", nil, "upstream.secret_access_key"},
		"skewed clock":  {403, "RequestTimeTooSkewed", "too skewed", nil, "NTP"},
		"missing":       {404, "NoSuchBucket", "gone", nil, "aws s3 mb s3://b"},
		"not permitted": {403, "AccessDenied", "denied", nil, "s3:ListBucket"},
		"region in the message": {400, "AuthorizationHeaderMalformed",
			"the region 'us-east-1' is wrong; expecting 'eu-central-1'", nil, `upstream.region to "eu-central-1"`},
		"region in a header": {301, "PermanentRedirect", "addressed elsewhere",
			http.Header{"X-Amz-Bucket-Region": {"ap-south-1"}}, `upstream.region to "ap-south-1"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv := fakeProvider(t, c.status, c.code, c.message, c.header)
			got := providerFor(t, srv.URL, http.DefaultTransport).Bucket(t.Context(), "b")
			if got.Outcome != Failed || got.Bucket != "b" {
				t.Fatalf("got %+v, want a failure for bucket b", got)
			}
			if !strings.Contains(got.Fix, c.fix) {
				t.Errorf("fix %q does not name %q", got.Fix, c.fix)
			}
			if !strings.Contains(got.Detail, c.code) {
				t.Errorf("detail %q does not carry the provider's code", got.Detail)
			}
		})
	}
}

func TestBucketPasses(t *testing.T) {
	srv := fakeProvider(t, http.StatusOK, "", "", nil)
	if got := providerFor(t, srv.URL, http.DefaultTransport).Bucket(t.Context(), "b"); got.Outcome != OK {
		t.Fatalf("got %+v", got)
	}
}

func TestBucketWithNothingListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	endpoint := "http://" + ln.Addr().String()
	_ = ln.Close()

	p := providerFor(t, endpoint, http.DefaultTransport)
	got := p.Bucket(t.Context(), "b")
	if got.Outcome != Failed || !strings.Contains(got.Fix, "upstream.endpoint") {
		t.Fatalf("got %+v, want a failure naming upstream.endpoint", got)
	}
	if clock := p.Clock(); clock.Outcome != Skipped {
		t.Errorf("clock = %+v, want skipped: no response carried a Date", clock)
	}
}

func TestBucketWithAnUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	// The default transport, which does not trust the test server's CA.
	got := providerFor(t, srv.URL, http.DefaultTransport).Bucket(t.Context(), "b")
	if got.Outcome != Failed || !strings.Contains(got.Fix, "certificate") {
		t.Fatalf("got %+v, want a failure about the certificate", got)
	}
}

func TestClockReadsTheProvidersDate(t *testing.T) {
	// A provider ten minutes behind this host, answering with an error: the
	// clock is read from failures as well.
	date := time.Now().Add(-10 * time.Minute).UTC().Format(http.TimeFormat)
	srv := fakeProvider(t, 403, "AccessDenied", "denied", http.Header{"Date": {date}})
	p := providerFor(t, srv.URL, http.DefaultTransport)
	_ = p.Bucket(t.Context(), "b")
	got := p.Clock()
	if got.Outcome != Warning || !strings.Contains(got.Detail, "ahead of") {
		t.Fatalf("got %+v, want a warning that this host is ahead", got)
	}
}

func TestClockThresholds(t *testing.T) {
	for _, c := range []struct {
		skew time.Duration
		want Outcome
	}{
		{0, OK},
		{30 * time.Second, OK},
		{-59 * time.Second, OK},
		{time.Minute, Warning},
		{-14 * time.Minute, Warning},
		{15 * time.Minute, Failed},
		{-time.Hour, Failed},
	} {
		if got := clockCheck(c.skew); got.Outcome != c.want {
			t.Errorf("skew %s: %s, want %s", c.skew, got.Outcome, c.want)
		}
	}
}

// writeCert writes a self-signed certificate valid from notBefore to notAfter,
// and its key, and returns their paths.
func writeCert(t *testing.T, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: notBefore, NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return certFile, keyFile
}

func TestTLS(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		from, until time.Time
		want        Outcome
	}{
		"valid":         {now.Add(-day), now.Add(90 * day), OK},
		"expiring soon": {now.Add(-day), now.Add(3 * day), Warning},
		"expired":       {now.Add(-90 * day), now.Add(-day), Failed},
		"not yet valid": {now.Add(day), now.Add(90 * day), Failed},
	} {
		t.Run(name, func(t *testing.T) {
			cert, key := writeCert(t, c.from, c.until)
			if got := TLS(cert, key, now); got.Outcome != c.want {
				t.Errorf("got %+v, want %s", got, c.want)
			}
		})
	}

	t.Run("a key of another certificate", func(t *testing.T) {
		cert, _ := writeCert(t, now.Add(-day), now.Add(90*day))
		_, otherKey := writeCert(t, now.Add(-day), now.Add(90*day))
		if got := TLS(cert, otherKey, now); got.Outcome != Failed || !strings.Contains(got.Fix, "server.tls") {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("missing", func(t *testing.T) {
		if got := TLS("/nonexistent/tls.crt", "/nonexistent/tls.key", now); got.Outcome != Failed {
			t.Errorf("got %+v", got)
		}
	})
}

func TestWritable(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for name, c := range map[string]struct {
		path string
		want Outcome
	}{
		"not there yet":       {filepath.Join(dir, "new.log"), OK},
		"there and writable":  {existing, OK},
		"a missing directory": {filepath.Join(dir, "nope", "audit.log"), Failed},
		"a directory":         {dir, Failed},
	} {
		t.Run(name, func(t *testing.T) {
			got := Writable(NameAuditLog, "audit.log", c.path)
			if got.Outcome != c.want {
				t.Errorf("got %+v, want %s", got, c.want)
			}
			if c.want == Failed && !strings.Contains(got.Fix, "audit.log") && !strings.Contains(got.Fix, "create") {
				t.Errorf("fix %q names neither the setting nor what to create", got.Fix)
			}
		})
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".blindbucket-doctor-*")); len(left) > 0 {
		t.Errorf("the check left %v behind", left)
	}

	t.Run("a directory nobody may write to", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("permissions do not stop this user")
		}
		locked := t.TempDir()
		if err := os.Chmod(locked, 0o500); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		if got := Writable(NameAuditLog, "audit.log", filepath.Join(locked, "audit.log")); got.Outcome != Failed {
			t.Errorf("got %+v", got)
		}
	})
}

// The provider checks against a real provider. MinIO enforces every condition,
// so conditional_writes passes there; Garage ignores two, and warns.
//
//	docker compose up -d
//	BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/doctor
func TestIntegrationProvider(t *testing.T) {
	tp := testprovider.Require(t)
	build := func(secret string) Provider {
		recorder := NewRecorder(upstream.DefaultHTTPClient().Transport)
		client, err := upstream.New(upstream.Config{
			Endpoint: tp.Endpoint, Region: tp.Region, PathStyle: tp.PathStyle,
			AccessKeyID: tp.AccessKey, SecretAccessKey: secret, SessionToken: tp.SessionToken,
			HTTPClient: &http.Client{Transport: recorder}, MaxRetries: 1,
		})
		if err != nil {
			t.Fatalf("upstream.New: %v", err)
		}
		return Provider{Client: client, Recorder: recorder, Endpoint: tp.Endpoint, Region: tp.Region}
	}

	p := build(tp.SecretKey)
	if got := p.Bucket(t.Context(), tp.Bucket); got.Outcome != OK {
		t.Fatalf("bucket: %+v", got)
	}
	want := Warning
	if tp.Guarded() && tp.MigrationGuarded() {
		want = OK
	}
	if got := p.ConditionalWrites(t.Context(), tp.Bucket); got.Outcome != want {
		t.Errorf("conditional writes: %+v, want %s", got, want)
	}
	if got := p.Clock(); got.Outcome == Skipped || got.Outcome == Failed {
		t.Errorf("clock: %+v", got)
	}
	if got := p.Bucket(t.Context(), "blindbucket-doctor-no-such-bucket"); got.Outcome != Failed ||
		!strings.Contains(got.Fix, "create") {
		t.Errorf("a missing bucket: %+v", got)
	}
	if got := build(tp.SecretKey+"-wrong").Bucket(t.Context(), tp.Bucket); got.Outcome != Failed ||
		!strings.Contains(got.Fix, "secret_access_key") {
		t.Errorf("a wrong secret: %+v", got)
	}
}
