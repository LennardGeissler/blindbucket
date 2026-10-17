package proxy

import (
	"io"
	"net/http"
	"time"
)

// defaultStallTimeout is how long a transfer may make no progress at all.
//
// Deadlines are renewed as bytes move rather than set once as a global
// WriteTimeout, and the distinction is the point: a 5 TiB download is a
// legitimate request that may run for hours, while a connection that has moved
// no bytes for a minute is not slow, it is stuck. A fixed WriteTimeout cannot
// tell those apart; a renewed one does not have to.
//
// The floor this implies is worth stating. The deadline covers one Write, which
// carries up to a chunk -- 64 KiB by default -- so a client reading more slowly
// than roughly 1 KiB/s will be cut off. That is well below any link worth
// serving, and far enough below it that a legitimately slow reader is not at
// risk.
const defaultStallTimeout = 60 * time.Second

// stallGuard renews a connection's deadlines as data moves.
//
// It degrades rather than fails: a ResponseWriter that cannot set deadlines --
// httptest's recorder, or a wrapper that does not unwrap -- disables the guard
// for that request instead of breaking it. The gateway's own wrapper implements
// Unwrap so that http.ResponseController can reach the connection through it.
type stallGuard struct {
	rc          *http.ResponseController
	timeout     time.Duration
	unsupported bool
}

func newStallGuard(w http.ResponseWriter, timeout time.Duration) *stallGuard {
	if timeout <= 0 {
		timeout = defaultStallTimeout
	}
	return &stallGuard{rc: http.NewResponseController(w), timeout: timeout}
}

// renewWrite pushes the write deadline out by one timeout.
func (g *stallGuard) renewWrite() {
	if g == nil || g.unsupported {
		return
	}
	if err := g.rc.SetWriteDeadline(time.Now().Add(g.timeout)); err != nil {
		g.unsupported = true
	}
}

// renewRead pushes the read deadline out by one timeout.
func (g *stallGuard) renewRead() {
	if g == nil || g.unsupported {
		return
	}
	if err := g.rc.SetReadDeadline(time.Now().Add(g.timeout)); err != nil {
		g.unsupported = true
	}
}

// clear removes the deadlines, so that a connection handed back to the server
// for reuse does not inherit this request's.
func (g *stallGuard) clear() {
	if g == nil || g.unsupported {
		return
	}
	_ = g.rc.SetWriteDeadline(time.Time{})
	_ = g.rc.SetReadDeadline(time.Time{})
}

// guardedWriter renews the write deadline before each write.
//
// Wrapping the writer rather than sampling on a timer is what makes the rule
// exactly "no progress for this long": every write that completes buys the next
// one a full timeout, and a write that blocks is the only thing the deadline
// ever fires on.
//
// It also remembers the first write that failed. A copy into the response can
// end with an error from either side, and only the side tells what happened:
// a failed read is the provider or the stored data, a failed write is the
// client -- gone, or cut off by this guard for not reading (#150).
type guardedWriter struct {
	dst   io.Writer
	guard *stallGuard
	err   error
}

func (g *guardedWriter) Write(p []byte) (int, error) {
	g.guard.renewWrite()
	n, err := g.dst.Write(p)
	if err != nil && g.err == nil {
		g.err = err
	}
	return n, err
}

// guardedReader is the same for a request body being read from a client.
type guardedReader struct {
	src   io.Reader
	guard *stallGuard
}

func (g guardedReader) Read(p []byte) (int, error) {
	g.guard.renewRead()
	return g.src.Read(p)
}
