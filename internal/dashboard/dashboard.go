// Package dashboard serves a read-only status page for one gateway instance
// (ADR-035): whether it is ready, which keys it holds and what seals them, and
// whether its audit log is being written, signed and still verifies.
//
// The page is served on a listener of its own, which the configuration allows
// only on loopback. It has no authentication; what keeps others out is that it
// is reached through kubectl port-forward or an SSH tunnel, whose
// authentication is already in front of it. Every request must name a loopback
// host, which turns a DNS-rebinding page away, and nothing on the page writes
// anything, runs a script or loads anything from elsewhere.
//
// What the page shows comes from narrow interfaces -- key IDs, the audit
// writer's status, a verification summary -- never from the keyring or the
// configuration as a whole, so that a field added to either cannot reach the
// page by accident.
package dashboard

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
)

// DefaultVerifyEvery is how often the audit log is verified in the background.
const DefaultVerifyEvery = 10 * time.Minute

// readyEvery bounds how often the page asks whether the gateway is ready: the
// check calls the provider, and reloading the page must not make the gateway do
// that once per reload.
const readyEvery = 10 * time.Second

// readyTimeout bounds one readiness check, as /readyz's does.
const readyTimeout = 3 * time.Second

//go:embed page.html
var pageHTML string

//go:embed style.css
var styleCSS []byte

var page = template.Must(template.New("page").Funcs(template.FuncMap{
	"when": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
}).Parse(pageHTML))

// Keyring is what the page may know about the keyring: key IDs, which is
// active, and when each was made. obs.KeyringInfo satisfies it.
type Keyring interface {
	KIDs() []string
	ActiveKID() string
	Created(kid string) (time.Time, bool)
}

// AuditLog is what the page may know about the audit writer.
type AuditLog interface {
	Status() audit.Status
}

// Verification is the outcome of verifying the audit log's files.
type Verification struct {
	At    time.Time
	OK    bool
	Files int
	// Entries and SignedThrough describe the last file of the chain: how many
	// entries it holds, and the last one a verified signature covers.
	Entries       uint64
	SignedThrough uint64
	// Error says why the log did not verify. It is the verifier's own message,
	// which names a file and a line, never an entry's contents.
	Error string
}

// Config describes one dashboard.
type Config struct {
	// Listen is the address to serve on. The configuration has already
	// refused anything but loopback.
	Listen  string
	Version string
	Started time.Time
	// Ready is the readiness check /readyz runs. Nil means ready.
	Ready   func(context.Context) error
	Keyring Keyring
	// Sealing says what seals the keyring, in words: "a passphrase", or which
	// Vault, OpenBao or KMS key. It names no credential.
	Sealing string
	// Audit and Verify are nil when no audit log is configured.
	Audit       AuditLog
	Verify      func(context.Context) Verification
	VerifyEvery time.Duration
	Logger      *slog.Logger
}

// Server is the dashboard's listener.
type Server struct {
	cfg    Config
	server *http.Server

	mu         sync.Mutex
	readyAt    time.Time
	readyErr   error
	verified   *Verification
	stopVerify context.CancelFunc
	verifyDone chan struct{}
}

// New builds a dashboard without starting it.
func New(cfg Config) *Server {
	if cfg.VerifyEvery <= 0 {
		cfg.VerifyEvery = DefaultVerifyEvery
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Started.IsZero() {
		cfg.Started = time.Now()
	}
	s := &Server{cfg: cfg}
	s.server = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// Start binds the listener, serves in the background, and starts verifying
// the audit log.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.cfg.Logger.Error("the dashboard stopped serving", "err", err)
		}
	}()
	if s.cfg.Verify != nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.stopVerify, s.verifyDone = cancel, make(chan struct{})
		go s.verifyLoop(ctx)
	}
	s.cfg.Logger.Info("dashboard listening", "addr", listener.Addr().String())
	return nil
}

// Shutdown stops the listener and the verification.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.stopVerify != nil {
		s.stopVerify()
		<-s.verifyDone
	}
	return s.server.Shutdown(ctx)
}

// verifyLoop verifies the audit log at start and then every VerifyEvery, never
// on a request: verifying reads every file of the chain, and a request must not
// be able to make the gateway do that.
func (s *Server) verifyLoop(ctx context.Context) {
	defer close(s.verifyDone)
	ticker := time.NewTicker(s.cfg.VerifyEvery)
	defer ticker.Stop()
	for {
		result := s.cfg.Verify(ctx)
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.verified = &result
		s.mu.Unlock()
		if !result.OK {
			s.cfg.Logger.Warn("the audit log did not verify", "err", result.Error)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Handler serves the page and its stylesheet, to loopback hosts only.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; "+
			"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")

		// A DNS-rebinding page reaches loopback under its own name, and that
		// name is what arrives here. A tunnel arrives as localhost.
		if !loopbackHost(r.Host) {
			http.Error(w, "this dashboard answers only to localhost", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "the dashboard is read-only", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/":
			s.servePage(w, r)
		case "/style.css":
			h.Set("Content-Type", "text/css; charset=utf-8")
			_, _ = w.Write(styleCSS)
		default:
			http.NotFound(w, r)
		}
	})
}

// loopbackHost reports whether a Host header names this machine's loopback.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// view is everything the template sees.
type view struct {
	Version, GoVersion string
	Started            time.Time
	Uptime             string
	Ready              bool
	NotReady           string
	ReadyAt            time.Time

	Keys    []keyView
	Sealing string

	Audit    *audit.Status
	Broken   string
	Verified *Verification
}

type keyView struct {
	ID      string
	Active  bool
	Created time.Time
}

func (s *Server) servePage(w http.ResponseWriter, r *http.Request) {
	v := view{
		Version: s.cfg.Version, GoVersion: runtime.Version(), Started: s.cfg.Started,
		Uptime:  time.Since(s.cfg.Started).Round(time.Second).String(),
		Sealing: s.cfg.Sealing,
	}
	readyAt, readyErr := s.ready(r.Context())
	v.Ready, v.ReadyAt = readyErr == nil, readyAt
	if readyErr != nil {
		v.NotReady = readyErr.Error()
	}
	if s.cfg.Keyring != nil {
		active := s.cfg.Keyring.ActiveKID()
		for _, id := range s.cfg.Keyring.KIDs() {
			created, _ := s.cfg.Keyring.Created(id)
			v.Keys = append(v.Keys, keyView{ID: id, Active: id == active, Created: created})
		}
		sort.Slice(v.Keys, func(i, j int) bool { return v.Keys[i].ID < v.Keys[j].ID })
	}
	if s.cfg.Audit != nil {
		status := s.cfg.Audit.Status()
		v.Audit = &status
		if status.Broken != nil {
			v.Broken = status.Broken.Error()
		}
		s.mu.Lock()
		if s.verified != nil {
			copied := *s.verified
			v.Verified = &copied
		}
		s.mu.Unlock()
	}

	var buf bytes.Buffer
	if err := page.Execute(&buf, v); err != nil {
		s.cfg.Logger.Error("rendering the dashboard", "err", err)
		http.Error(w, "the page could not be rendered; see the log", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// ready runs the readiness check at most once every readyEvery.
func (s *Server) ready(ctx context.Context) (time.Time, error) {
	if s.cfg.Ready == nil {
		return time.Now(), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readyAt.IsZero() && time.Since(s.readyAt) < readyEvery {
		return s.readyAt, s.readyErr
	}
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	s.readyErr, s.readyAt = s.cfg.Ready(ctx), time.Now()
	return s.readyAt, s.readyErr
}
