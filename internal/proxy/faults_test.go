package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// faultyProvider sits between the gateway and the real provider and fails the
// requests a test picks: with an S3 error, by dropping the connection before
// answering, or by cutting a response off partway through its body.
//
// It is the transport of the gateway's upstream client rather than a server in
// front of the provider, so every request it lets through goes to the
// provider's own address, signed for it. A proxy in front would have to be
// reached under a host of its own -- which a provider addressed by virtual
// host, AWS among them, cannot be. The harness keeps its own direct client,
// which is how a test sees what the provider really holds after the gateway was
// told something failed.
type faultyProvider struct {
	base http.RoundTripper

	mu    sync.Mutex
	rules []*fault
}

// fault is one injected failure.
type fault struct {
	match func(*http.Request) bool
	// times is how many matching requests fail; later ones pass. Zero means all.
	times int

	status   int    // answer with this status and an S3 error document
	code     string // the error code in that document; InjectedFault if empty
	drop     bool   // fail without an answer, as a dropped connection does
	cutAfter int64  // forward, but end the response body after this many bytes
	// setHeader forwards the request and adds these to the provider's answer,
	// for what a real provider would send and MinIO does not.
	setHeader map[string]string

	hits int
}

func newFaultyProvider(t *testing.T) *faultyProvider {
	t.Helper()
	return &faultyProvider{base: http.DefaultTransport}
}

// RoundTrip sends what no rule matches to the provider, and fails the rest.
// A failed request's body is read to the end first, as a provider would have
// received it before answering.
func (f *faultyProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	rule := f.take(r)
	switch {
	case rule == nil:
		return f.base.RoundTrip(r)
	case rule.drop:
		drainBody(r)
		return nil, errors.New("connection dropped by the test")
	case rule.status != 0:
		drainBody(r)
		code := rule.code
		if code == "" {
			code = "InjectedFault"
		}
		body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
			`<Error><Code>%s</Code><Message>injected by the test</Message></Error>`, code)
		return &http.Response{
			Status:     fmt.Sprintf("%d %s", rule.status, http.StatusText(rule.status)),
			StatusCode: rule.status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"Content-Type": {"application/xml"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       r,
		}, nil
	default:
		resp, err := f.base.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		// The headers are out by the time a body is cut, so the gateway sees
		// a read that fails partway, as it would on a broken connection.
		if rule.cutAfter > 0 {
			resp.Body = &cutBody{r: resp.Body, left: rule.cutAfter}
		}
		for name, value := range rule.setHeader {
			resp.Header.Set(name, value)
		}
		return resp, nil
	}
}

func drainBody(r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
}

// fail adds a fault and returns it, so a test can check that it was reached.
func (f *faultyProvider) fail(rule *fault) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule)
	return rule
}

func (f *faultyProvider) take(r *http.Request) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rule := range f.rules {
		if (rule.times == 0 || rule.hits < rule.times) && rule.match(r) {
			rule.hits++
			return rule
		}
	}
	return nil
}

func (f *faultyProvider) hits(rule *fault) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return rule.hits
}

// option gives a harness's gateway the faulty provider as its transport, with
// retries off so that one injected failure is one failure the gateway sees.
func (f *faultyProvider) option(t *testing.T) func(*Config) {
	t.Helper()
	cfg := upstreamConfig(t)
	cfg.HTTPClient = &http.Client{Transport: f}
	cfg.MaxRetries = 1
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return func(c *Config) { c.Upstream = client }
}

// cutBody ends a response body early with an error.
type cutBody struct {
	r    io.ReadCloser
	left int64
}

func (c *cutBody) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errors.New("connection cut by the test")
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func (c *cutBody) Close() error { return c.r.Close() }

// Request matchers. Keys are matched by substring of the path, which is enough
// to tell an object from its manifest under the reserved prefix.

func isManifest(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/"+s3api.ReservedPrefix)
}

func objectRequest(method, keyPart string, query ...string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		if r.Method != method || isManifest(r) || !strings.Contains(r.URL.Path, keyPart) {
			return false
		}
		for _, q := range query {
			if !r.URL.Query().Has(q) {
				return false
			}
		}
		return true
	}
}

func manifestRequest(method string) func(*http.Request) bool {
	return func(r *http.Request) bool { return r.Method == method && isManifest(r) }
}
