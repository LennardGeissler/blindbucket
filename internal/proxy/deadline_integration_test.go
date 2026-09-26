package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

// Deadlines are renewed as bytes move rather than set once as a global
// WriteTimeout. The two tests below are the two halves of that rule, and the
// second is the one that matters: a guard that also kills healthy transfers
// would be worse than no guard at all.

// withStall shortens the stall timeout so a test does not have to wait out the
// real one.
func withStall(d time.Duration) func(*Config) {
	return func(c *Config) { c.StallTimeout = d }
}

// A client that stops reading must not hold its connection for ever. There is
// deliberately no WriteTimeout, so without the renewed deadline nothing would
// ever close this.
//
// The guard fires on a write that blocks, and a write only blocks once the
// socket buffers between gateway and client are full. So this test is only
// about the guard if those buffers fill quickly, and on their own they do not
// always: Linux grows loopback buffers to several MiB, and against a provider
// that delivers slowly -- AWS, from a runner an ocean away -- the object
// trickles into them for longer than the client pauses. No write ever blocks,
// the client resumes, and the download completes. That is the guard working as
// specified, and the test failing. The client's receive buffer is therefore
// pinned small, which makes the buffers fill in a fraction of a second on any
// system and against any provider.
func TestIntegrationStalledDownloadIsDropped(t *testing.T) {
	const stall = 2 * time.Second
	h := newHarness(t, withStall(stall))
	key := testKey(t, "stalled.bin")

	// Larger than the buffers, so the server's writes block once the client
	// stops reading. A small object would be handed to the kernel whole and the
	// stall would never be observable.
	h.store(t, key, randomBytes(t, 8<<20))

	rcvbuf := 64 << 10
	if v, err := strconv.Atoi(os.Getenv("BLINDBUCKET_TEST_STALL_RCVBUF")); err == nil {
		rcvbuf = v // to reproduce the failure this pins against
	}
	client := &http.Client{Transport: &signingTransport{base: &http.Transport{
		DialContext: (&net.Dialer{Control: receiveBuffer(rcvbuf)}).DialContext,
	}}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d", resp.StatusCode)
	}

	// Read a little, proving the transfer started, then stop.
	first := make([]byte, 1024)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("reading the first bytes: %v", err)
	}

	time.Sleep(stall + time.Second)

	// The connection must be gone. Draining it has to end in an error rather
	// than in the rest of the object.
	start := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil {
		t.Fatalf("the stalled download completed anyway: %d further bytes", n)
	}
	if elapsed := time.Since(start); elapsed > stall {
		t.Errorf("the connection took %s to report the drop; the deadline had "+
			"already expired before the read began", elapsed.Round(time.Millisecond))
	}
}

// The half that is easy to get wrong: a client that reads slowly but keeps
// making progress must not be cut off, however long it takes in total. This one
// takes several times the stall timeout to finish and must still succeed.
func TestIntegrationSlowButProgressingDownloadSurvives(t *testing.T) {
	const stall = 500 * time.Millisecond
	h := newHarness(t, withStall(stall))
	key := testKey(t, "slow.bin")

	payload := randomBytes(t, 512<<10)
	h.store(t, key, payload)

	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()

	// Read in small pieces with a pause between them. Each pause is shorter
	// than the stall timeout, but the transfer as a whole runs well past it.
	var got bytes.Buffer
	buf := make([]byte, 16<<10)
	started := time.Now()
	for {
		n, err := resp.Body.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("a progressing download was cut off after %s and %d bytes: %v",
				time.Since(started).Round(time.Millisecond), got.Len(), err)
		}
		time.Sleep(stall / 4)
	}

	if total := time.Since(started); total < stall {
		t.Fatalf("the transfer finished in %s, faster than the stall timeout; it "+
			"never exercised a renewal", total)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("got %d bytes, want %d", got.Len(), len(payload))
	}
}
