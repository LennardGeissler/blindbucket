package integration

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// A real browser uploading by presigned URL from a page on another origin
// (ADR-036): the preflight, the PUT, and the ETag the page reads back are what a
// browser decides, not what a test client happens to send. Chrome runs headless;
// without it the test skips. BLINDBUCKET_TEST_CHROME names the binary when it is
// not on the usual paths.

func chromePath(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("BLINDBUCKET_TEST_CHROME"),
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	t.Skip("no Chrome or Chromium found; set BLINDBUCKET_TEST_CHROME to run the browser test")
	return ""
}

// chromeProfile is a directory for Chrome's profile, removed when the test
// ends as far as Chrome lets it be. Not t.TempDir: Chrome's helper processes
// outlive the one the test kills and keep writing to it for a moment, which
// t.TempDir reports as a failure of the test.
func chromeProfile(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "blindbucket-chrome-") //nolint:usetesting // see above.
	if err != nil {
		t.Fatalf("a profile directory for Chrome: %v", err)
	}
	t.Cleanup(func() {
		for range 20 {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	return dir
}

// uploadPage uploads a body to a presigned URL and posts what it saw back to
// its own origin.
var uploadPage = template.Must(template.New("page").Parse(`<!doctype html>
<script>
fetch({{.URL}}, {method: "PUT", body: {{.Body}}, headers: {"Content-Type": "text/plain"}})
  .then(r => r.text().then(() => r.status + " " + (r.headers.get("ETag") || "no-etag")))
  .catch(e => "error " + e)
  .then(result => fetch("/result", {method: "POST", body: result}));
</script>`))

// partsPage uploads two parts by URL, as a browser library does for a large
// file: 5 MiB of ones, then a short tail. It posts each part's status and ETag
// back, one line each, for the backend to complete with.
var partsPage = template.Must(template.New("parts").Parse(`<!doctype html>
<script>
const parts = [[{{.First}}, new Uint8Array({{.FirstSize}}).fill(1)], [{{.Second}}, {{.Tail}}]];
Promise.all(parts.map(([url, body]) => fetch(url, {method: "PUT", body})
    .then(r => r.text().then(() => r.status + " " + (r.headers.get("ETag") || "no-etag")))))
  .then(lines => lines.join("\n"))
  .catch(e => "error " + e)
  .then(result => fetch("/result", {method: "POST", body: result}));
</script>`))

// runInChrome serves a page from an origin of its own, opens it in a headless
// Chrome and returns what the page posts to /result. prepare gets the page's
// origin before anything is served -- the gateway has to list it -- and
// returns the page.
func runInChrome(t *testing.T, chrome string, prepare func(origin string) []byte) string {
	t.Helper()
	results := make(chan string, 1)
	var html []byte
	// Unstarted, so that its address is known to prepare while the handler
	// starts only once html is written.
	page := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(html)
		case "/result":
			b, _ := io.ReadAll(r.Body)
			select {
			case results <- string(b):
			default:
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(page.Close)
	origin := "http://" + page.Listener.Addr().String()
	html = prepare(origin)
	page.Start()

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	args := []string{"--headless=new", "--disable-gpu", "--no-first-run",
		"--no-default-browser-check", "--user-data-dir=" + chromeProfile(t), "--remote-debugging-port=0"}
	// Ubuntu 24.04 restricts the user namespaces Chrome's sandbox needs, and
	// the page is the test's own.
	if os.Getenv("CI") != "" {
		args = append(args, "--no-sandbox")
	}
	cmd := exec.CommandContext(ctx, chrome, append(args, origin+"/")...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting Chrome: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	select {
	case got := <-results:
		return got
	case <-ctx.Done():
		t.Fatal("the page reported nothing within a minute")
		return ""
	}
}

// render executes a page template, failing the test if it cannot.
func render(t *testing.T, tmpl *template.Template, data any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := tmpl.Execute(&b, data); err != nil {
		t.Fatalf("rendering the page: %v", err)
	}
	return b.Bytes()
}

// browserUpload has a page upload body by presigned URL. listed says whether
// the gateway lists the page's origin.
func browserUpload(t *testing.T, chrome string, listed bool, body string) (string, *proxytest.Harness, string) {
	t.Helper()
	var h *proxytest.Harness
	key := proxytest.TestKey(t, "browser")
	got := runInChrome(t, chrome, func(origin string) []byte {
		origins := []string{"http://unrelated.example"}
		if listed {
			origins = []string{origin}
		}
		h = proxytest.New(t, withPresign(), withUploads(uploadLimit), withCORS(origins...))
		h.CleanupStored(t, key)
		target := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, nil, nil)
		return render(t, uploadPage, struct{ URL, Body string }{target, body})
	})
	return got, h, key
}

func TestABrowserUploadsByPresignedURL(t *testing.T) {
	chrome := chromePath(t)
	body := "uploaded by a browser, from a page on another origin"

	got, h, key := browserUpload(t, chrome, true, body)
	status, etag, _ := strings.Cut(got, " ")
	if status != "200" {
		t.Fatalf("the page saw %q, want 200", got)
	}
	if etag == "no-etag" || etag == "" {
		t.Fatalf("the page could not read the ETag: %q", got)
	}
	if read := getOK(t, h, key); read != body {
		t.Fatalf("read back %q", read)
	}
}

func TestABrowserOnAnUnlistedOriginCannotUpload(t *testing.T) {
	chrome := chromePath(t)
	got, h, key := browserUpload(t, chrome, false, "must not land")
	if !strings.HasPrefix(got, "error ") {
		t.Fatalf("the page saw %q, want a refusal by the browser", got)
	}
	wantAbsent(t, h, key)
}

// TestABrowserUploadsInParts is the multipart case: the backend opens the
// upload and completes it with its credential, and the browser uploads the
// parts by URL, reading each ETag -- which carries the part's salt to the
// completion (ADR-014) -- across origins.
func TestABrowserUploadsInParts(t *testing.T) {
	chrome := chromePath(t)
	var h *proxytest.Harness
	key := proxytest.TestKey(t, "browser-parts")
	var token string
	tail := "and the tail of the file"
	got := runInChrome(t, chrome, func(origin string) []byte {
		h = proxytest.New(t, withPresign(), withUploads(proxytest.TestPart), withCORS(origin))
		h.CleanupStored(t, key)
		token = h.MpuStart(t, key, nil)
		part := func(n int) string {
			return presignPut(t, h.URL(key)+"?partNumber="+strconv.Itoa(n)+"&uploadId="+
				proxytest.URLQueryEscape(token), 15*time.Minute, time.Now(), 0, nil, nil)
		}
		return render(t, partsPage, struct {
			First, Second, Tail string
			FirstSize           int
		}{part(1), part(2), tail, proxytest.TestPart})
	})

	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("the page saw %q, want two parts", got)
	}
	completed := make([]proxytest.CompletedPart, 0, 2)
	for i, line := range lines {
		status, etag, _ := strings.Cut(line, " ")
		if status != "200" || etag == "no-etag" || etag == "" {
			t.Fatalf("part %d: the page saw %q", i+1, line)
		}
		completed = append(completed, proxytest.CompletedPart{PartNumber: i + 1, ETag: etag})
	}
	resp := h.MpuComplete(t, key, token, completed)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completing with the ETags the browser read: %d %s", resp.StatusCode, proxytest.ReadBody(t, resp))
	}
	want := strings.Repeat("\x01", proxytest.TestPart) + tail
	if read := getOK(t, h, key); read != want {
		t.Fatalf("the object does not read back as its two parts (%d bytes, want %d)", len(read), len(want))
	}
}
