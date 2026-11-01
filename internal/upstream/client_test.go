package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func testClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := New(Config{
		Endpoint:        endpoint,
		Region:          "us-east-1",
		PathStyle:       true,
		AccessKeyID:     "minioadmin",
		SecretAccessKey: "minioadmin",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestURIEncode pins the AWS UriEncode rules. Getting these wrong does not
// corrupt anything, it just makes every request with an affected key fail to
// authenticate -- loudly, but only for keys nobody thought to test.
func TestURIEncode(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"simple":          "simple",
		"with space":      "with%20space",
		"plus+sign":       "plus%2Bsign",
		"tilde~dash-dot.": "tilde~dash-dot.",
		"under_score":     "under_score",
		"colon:at@":       "colon%3Aat%40",
		"amp&eq=":         "amp%26eq%3D",
		"paren()":         "paren%28%29",
		"star*":           "star%2A",
		"quote'":          "quote%27",
		"bang!":           "bang%21",
		"dollar$":         "dollar%24",
		"comma,semi;":     "comma%2Csemi%3B",
		"question?hash#":  "question%3Fhash%23",
		"bracket[]":       "bracket%5B%5D",
		"percent%":        "percent%25",
		"umlautä":         "umlaut%C3%A4",
		"":                "",
	}

	for in, want := range tests {
		if got := uriEncode(in); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestURIEncodePathKeepsSeparators checks that key separators survive: S3 keys
// are flat strings, but the slashes in them are path separators on the wire.
func TestURIEncodePathKeepsSeparators(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"a/b/c":                "a/b/c",
		"dir/sub dir/file.txt": "dir/sub%20dir/file.txt",
		"2026/09/dump+1.sql":   "2026/09/dump%2B1.sql",
		"/leading":             "/leading",
		"trailing/":            "trailing/",
	}
	for in, want := range tests {
		if got := uriEncodePath(in); got != want {
			t.Errorf("uriEncodePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestObjectURL checks that the escaped path reaches the wire, because that is
// exactly what SigV4 signs.
func TestObjectURL(t *testing.T) {
	t.Parallel()

	c := testClient(t, "https://storage.example")
	u := c.objectURL("backups", "2026/09/db dump+1.sql")

	if got, want := u.EscapedPath(), "/backups/2026/09/db%20dump%2B1.sql"; got != want {
		t.Errorf("EscapedPath() = %q, want %q", got, want)
	}
	if got, want := u.Path, "/backups/2026/09/db dump+1.sql"; got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}

	t.Run("virtual hosted style", func(t *testing.T) {
		vc, err := New(Config{
			Endpoint: "https://storage.example", Region: "auto",
			AccessKeyID: "a", SecretAccessKey: "b",
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		vu := vc.objectURL("backups", "key")
		if vu.Host != "backups.storage.example" {
			t.Errorf("Host = %q, want the bucket as a subdomain", vu.Host)
		}
		if vu.EscapedPath() != "/key" {
			t.Errorf("EscapedPath() = %q, want %q", vu.EscapedPath(), "/key")
		}
	})
}

// TestSignedRequestShape checks the headers a signed request carries, and that
// the escaped path survives all the way into the request line.
func TestSignedRequestShape(t *testing.T) {
	t.Parallel()

	var got *http.Request
	var gotURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		gotURI = r.RequestURI
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	if _, err := c.PutObject(context.Background(), PutObjectInput{
		Bucket:        "bucket",
		Key:           "dir/an object+name",
		Body:          strings.NewReader("hello"),
		ContentLength: 5,
		ContentType:   "text/plain",
		Metadata:      map[string]string{"bb-v": "1"},
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	if want := "/bucket/dir/an%20object%2Bname"; gotURI != want {
		t.Errorf("request URI = %q, want %q", gotURI, want)
	}

	auth := got.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=minioadmin/") {
		t.Errorf("Authorization = %q, want a SigV4 header", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=") || !strings.Contains(auth, "Signature=") {
		t.Errorf("Authorization is missing SignedHeaders or Signature: %q", auth)
	}
	// The body is not hashed, because hashing a stream means buffering it.
	if h := got.Header.Get("X-Amz-Content-Sha256"); h != unsignedPayload {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", h, unsignedPayload)
	}
	if got.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date is missing")
	}
	if got.Header.Get("X-Amz-Meta-Bb-V") != "1" {
		t.Errorf("user metadata did not reach the request: %v", got.Header)
	}
	// Expect is deliberately not signed, so it must not appear in SignedHeaders.
	if strings.Contains(auth, "expect") {
		t.Errorf("Expect was signed, which it must not be: %q", auth)
	}
}

func TestErrorParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{
			name:   "documented XML error",
			status: http.StatusNotFound,
			body: `<?xml version="1.0"?><Error><Code>NoSuchKey</Code>` +
				`<Message>The specified key does not exist.</Message><RequestId>REQ1</RequestId></Error>`,
			wantCode: "NoSuchKey",
		},
		{
			name:     "empty body",
			status:   http.StatusForbidden,
			body:     "",
			wantCode: "AccessDenied",
		},
		{
			name:     "an HTML page from something in front of the provider",
			status:   http.StatusBadGateway,
			body:     "<html><body>502 Bad Gateway</body></html>",
			wantCode: "InternalError",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			// One attempt only, so a retryable status does not slow the test.
			c := testClient(t, srv.URL)
			c.maxRetries = 1

			_, err := c.HeadObject(context.Background(), "bucket", "key")
			ae, ok := AsAPIError(err)
			if !ok {
				t.Fatalf("got %T (%v), want *APIError", err, err)
			}
			if ae.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", ae.Code, tc.wantCode)
			}
			if ae.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", ae.StatusCode, tc.status)
			}
		})
	}
}

// TestRetryPolicy pins what may and may not be retried. An upload cannot be:
// its body has already been consumed from the client.
func TestRetryPolicy(t *testing.T) {
	t.Parallel()

	t.Run("bodyless requests are retried", func(t *testing.T) {
		t.Parallel()
		var attempts int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("ETag", `"ok"`)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		c := testClient(t, srv.URL)
		if _, err := c.HeadObject(context.Background(), "bucket", "key"); err != nil {
			t.Fatalf("HeadObject: %v", err)
		}
		if attempts != 3 {
			t.Errorf("made %d attempts, want 3", attempts)
		}
	})

	t.Run("uploads are not retried", func(t *testing.T) {
		t.Parallel()
		var attempts int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		c := testClient(t, srv.URL)
		_, err := c.PutObject(context.Background(), PutObjectInput{
			Bucket: "bucket", Key: "key",
			Body: strings.NewReader("data"), ContentLength: 4,
		})
		if err == nil {
			t.Fatal("expected an error")
		}
		if attempts != 1 {
			t.Errorf("made %d attempts, want exactly 1", attempts)
		}
	})

	t.Run("client errors are not retried", func(t *testing.T) {
		t.Parallel()
		var attempts int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		c := testClient(t, srv.URL)
		if _, err := c.HeadObject(context.Background(), "bucket", "key"); !NotFound(err) {
			t.Fatalf("got %v, want a not-found error", err)
		}
		if attempts != 1 {
			t.Errorf("made %d attempts, want exactly 1", attempts)
		}
	})
}

// TestEmptyBodySendsContentLength guards a subtle net/http behaviour: a non-nil
// Body with ContentLength 0 means "length unknown", so the transport switches to
// chunked encoding and S3 answers 411. An empty object must still be storable.
func TestEmptyBodySendsContentLength(t *testing.T) {
	t.Parallel()

	var gotLength int64
	var gotChunked bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLength = r.ContentLength
		gotChunked = slices.Contains(r.TransferEncoding, "chunked")
		w.Header().Set("ETag", `"empty"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	if _, err := c.PutObject(context.Background(), PutObjectInput{
		Bucket: "bucket", Key: "empty", Body: strings.NewReader(""), ContentLength: 0,
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if gotChunked {
		t.Error("an empty body was sent with chunked encoding, which S3 rejects with 411")
	}
	if gotLength != 0 {
		t.Errorf("ContentLength = %d, want 0", gotLength)
	}
}

// TestStoredContentEncodingIsNotDecoded: an object stored with
// Content-Encoding: gzip comes back with that header on every GET, because it
// describes the plaintext. The body is ciphertext all the same, and it has to
// reach the decoder byte for byte. Go's transport, left to itself, asks for gzip
// on a whole-object GET and then gunzips whatever answers with that header --
// which turns the ciphertext into an error and the read into a false integrity
// failure (#110).
func TestStoredContentEncodingIsNotDecoded(t *testing.T) {
	t.Parallel()

	ciphertext := []byte("not gzip: the segment header and the sealed chunks")
	var gotAcceptEncoding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(ciphertext)))
		w.Header().Set("ETag", `"stored"`)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	out, err := testClient(t, srv.URL).GetObject(context.Background(), GetObjectInput{
		Bucket: "bucket", Key: "page.html",
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}

	if gotAcceptEncoding != "" {
		t.Errorf("the request asked for Accept-Encoding %q; the provider's bytes must not be negotiated", gotAcceptEncoding)
	}
	if !bytes.Equal(body, ciphertext) {
		t.Errorf("body = %q, want the stored bytes unchanged", body)
	}
	if got := out.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want the stored gzip", got)
	}
	if out.ContentLength != int64(len(ciphertext)) {
		t.Errorf("ContentLength = %d, want %d", out.ContentLength, len(ciphertext))
	}
}

// TestCompletionCarriesItsConditions holds the completion to sending the two
// conditions that guard rotation and migration, under their own header names.
// Neither has a test that would fail by itself if it were dropped: a provider
// that never sees a condition behaves exactly like one that ignores it, which is
// what the probe measures and why the header has to be pinned here.
func TestCompletionCarriesItsConditions(t *testing.T) {
	t.Parallel()

	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = fmt.Fprint(w, `<CompleteMultipartUploadResult><ETag>"done-1"</ETag></CompleteMultipartUploadResult>`)
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	for _, tc := range []struct {
		in            CompleteMultipartUploadInput
		match, noneOf string
	}{
		{CompleteMultipartUploadInput{IfMatch: `"abc"`}, `"abc"`, ""},
		{CompleteMultipartUploadInput{IfNoneMatch: "*"}, "", "*"},
		{CompleteMultipartUploadInput{}, "", ""},
	} {
		in := tc.in
		in.Bucket, in.Key, in.UploadID = "bucket", "key", "upload"
		in.Parts = []CompletedPart{{PartNumber: 1, ETag: `"p1"`}}
		if _, err := c.CompleteMultipartUpload(context.Background(), in); err != nil {
			t.Fatalf("CompleteMultipartUpload: %v", err)
		}
		if g := got.Get("If-Match"); g != tc.match {
			t.Errorf("If-Match = %q, want %q", g, tc.match)
		}
		if g := got.Get("If-None-Match"); g != tc.noneOf {
			t.Errorf("If-None-Match = %q, want %q", g, tc.noneOf)
		}
	}
}

// TestEveryRequestAsksTheCredentialsProvider: credentials from a source that
// refreshes them are asked for before each request, so a rotated key is used
// from the next request on, and a source that fails stops the request before
// anything is sent (ADR-024).
func TestEveryRequestAsksTheCredentialsProvider(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		_, rest, _ := strings.Cut(auth, "Credential=")
		id, _, _ := strings.Cut(rest, "/")
		mu.Lock()
		seen = append(seen, id+" "+r.Header.Get("X-Amz-Security-Token"))
		mu.Unlock()
		w.Header().Set("ETag", `"e"`)
	}))
	defer srv.Close()

	var n atomic.Int64
	failing := atomic.Bool{}
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		if failing.Load() {
			return aws.Credentials{}, errors.New("the role may not be assumed")
		}
		return aws.Credentials{
			AccessKeyID: fmt.Sprintf("ASIA%d", n.Add(1)), SecretAccessKey: "s", SessionToken: "token",
		}, nil
	})
	c, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", PathStyle: true, Credentials: provider})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for range 2 {
		if _, err := c.HeadObject(context.Background(), "bucket", "key"); err != nil {
			t.Fatalf("HeadObject: %v", err)
		}
	}
	if want := []string{"ASIA1 token", "ASIA2 token"}; !slices.Equal(seen, want) {
		t.Errorf("signed with %v, want %v", seen, want)
	}

	failing.Store(true)
	_, err = c.HeadObject(context.Background(), "bucket", "key")
	if err == nil || !strings.Contains(err.Error(), "may not be assumed") {
		t.Errorf("got %v, want the source's error", err)
	}
	if len(seen) != 2 {
		t.Errorf("a request went out without credentials: %v", seen)
	}

	if _, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Credentials: provider,
		AccessKeyID: "a", SecretAccessKey: "b"}); err == nil {
		t.Error("keys and a provider were both accepted")
	}
}

func TestParseContentRangeTotal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in    string
		want  int64
		valid bool
	}{
		{"bytes 0-31/1000", 1000, true},
		{"bytes 0-0/1", 1, true},
		{"bytes */1000", 1000, true},
		{"", 0, false},
		{"bytes 0-31/*", 0, false},
		{"nonsense", 0, false},
		{"bytes 0-31/-5", 0, false},
	}
	for _, tc := range tests {
		got, ok := parseContentRangeTotal(tc.in)
		if ok != tc.valid || (ok && got != tc.want) {
			t.Errorf("parseContentRangeTotal(%q) = %d, %t; want %d, %t", tc.in, got, ok, tc.want, tc.valid)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	bad := []Config{
		{},
		{Endpoint: "http://x"},
		{Endpoint: "http://x", Region: "r"},
		{Endpoint: "http://x", Region: "r", AccessKeyID: "a"},
		{Endpoint: "ftp://x", Region: "r", AccessKeyID: "a", SecretAccessKey: "b"},
		{Endpoint: "://bad", Region: "r", AccessKeyID: "a", SecretAccessKey: "b"},
	}
	for i, cfg := range bad {
		if _, err := New(cfg); err == nil {
			t.Errorf("config %d was accepted: %+v", i, cfg)
		}
	}
}

func ExampleClient_objectURL() {
	c, _ := New(Config{
		Endpoint: "https://storage.example", Region: "auto", PathStyle: true,
		AccessKeyID: "a", SecretAccessKey: "b",
	})
	fmt.Println(c.objectURL("backups", "2026/09/db dump.sql").EscapedPath())
	// Output: /backups/2026/09/db%20dump.sql
}

// ListObjectVersions asks for ?versions with the caller's markers and reads
// versions and delete markers apart; HeadObjectVersion names the version.
func TestListObjectVersionsAndHeadObjectVersion(t *testing.T) {
	t.Parallel()

	var listQuery, headQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			headQuery = r.URL.Query()
			w.Header().Set("X-Amz-Meta-Bb-Kid", "2026-09")
			return
		}
		listQuery = r.URL.Query()
		_, _ = w.Write([]byte(`<ListVersionsResult><Name>b</Name><IsTruncated>true</IsTruncated>
<NextKeyMarker>k2</NextKeyMarker><NextVersionIdMarker>v9</NextVersionIdMarker>
<Version><Key>k1</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><Size>5</Size></Version>
<DeleteMarker><Key>k1</Key><VersionId>v3</VersionId><IsLatest>false</IsLatest></DeleteMarker>
<Version><Key>k1</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><Size>4</Size></Version>
</ListVersionsResult>`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL)

	got, err := c.ListObjectVersions(context.Background(), "b",
		url.Values{"key-marker": {"k0"}, "version-id-marker": {"v0"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := listQuery["versions"]; !ok || listQuery.Get("key-marker") != "k0" || listQuery.Get("version-id-marker") != "v0" {
		t.Errorf("listing query = %v", listQuery)
	}
	if !got.IsTruncated || got.NextKeyMarker != "k2" || got.NextVersionIDMarker != "v9" ||
		len(got.Versions) != 2 || len(got.DeleteMarkers) != 1 ||
		!got.Versions[0].IsLatest || got.Versions[1].VersionID != "v1" || got.DeleteMarkers[0].VersionID != "v3" {
		t.Errorf("listing = %+v", got)
	}

	info, err := c.HeadObjectVersion(context.Background(), "b", "k1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if headQuery.Get("versionId") != "v1" || info.Metadata["Bb-Kid"] != "2026-09" {
		t.Errorf("head query %v, metadata %v", headQuery, info.Metadata)
	}
}
