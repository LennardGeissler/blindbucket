package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/freshness"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// shutdownGrace is how long in-flight requests may finish after a signal.
// Aborted uploads leave nothing behind upstream, because a segment is only
// valid once its final chunk is written.
const shutdownGrace = 30 * time.Second

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket serve --config <file>

Runs the S3 gateway. Clients point at this endpoint instead of the storage
provider; the provider only ever sees ciphertext.

Clients are authenticated with SigV4 against the credentials in the config file.
Between client and proxy the body is plaintext, so use TLS or keep the listener
on loopback.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		verbose = fs.Bool("v", false, "log at debug level")
		pass    passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	ring, err := loadServerKeyring(ctx, cfg, &pass)
	if err != nil {
		return err
	}

	// The registry is built before the upstream client so that the client can
	// report how long the provider takes without knowing what a metric is.
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{}))
	metrics := obs.NewMetrics(registry)
	metrics.KeyringLoaded(ring)

	client, err := upstream.New(upstream.Config{
		Endpoint:        cfg.Upstream.Endpoint,
		Region:          cfg.Upstream.Region,
		PathStyle:       cfg.Upstream.PathStyle,
		AccessKeyID:     cfg.Upstream.AccessKeyID,
		SecretAccessKey: cfg.Upstream.SecretAccessKey,
		SessionToken:    cfg.Upstream.SessionToken,
		ObserveRequest:  metrics.Upstream,
	})
	if err != nil {
		return err
	}

	clients := make([]auth.Client, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients = append(clients, auth.Client{
			Name: c.Name, AccessKeyID: c.AccessKeyID,
			SecretAccessKey: c.SecretAccessKey, Buckets: c.Buckets,
		})
	}
	presignExpiry, err := cfg.Server.Presign.Expiry()
	if err != nil {
		return err
	}
	if presignExpiry == 0 {
		presignExpiry = auth.MaxPresignExpiry
	}
	verifier, err := auth.NewVerifier(auth.Config{
		Clients:              clients,
		AllowUnsignedPayload: cfg.Server.AllowUnsignedPayload,
		AllowPresign:         cfg.Server.Presign.Enabled,
		MaxPresignExpiry:     presignExpiry,
	})
	if err != nil {
		return err
	}

	auditLog, err := openAuditLog(cfg, ring, log)
	if err != nil {
		return err
	}
	if auditLog != nil {
		// Closed before the process exits so that the final checkpoint is
		// written: without it the tail of the log is chained but unsigned, and
		// an orderly shutdown would leave behind exactly the window that a
		// checkpoint exists to close.
		defer func() {
			if err := auditLog.Close(); err != nil {
				log.Error("the audit log did not close cleanly", "err", err)
			}
		}()
	}

	nameEnc, err := openNameEncrypter(cfg, ring, log)
	if err != nil {
		return err
	}

	freshIndex, err := openFreshnessIndex(cfg, ring, log)
	if err != nil {
		return err
	}
	if freshIndex != nil {
		// Closed before the process exits so the last records are on disk. A
		// lost tail costs detection for the objects in it, which is recoverable
		// -- they fall back to trust on first use -- but there is no reason to
		// lose it on an orderly shutdown.
		defer func() {
			if err := freshIndex.Close(); err != nil {
				log.Error("the freshness index did not close cleanly", "err", err)
			}
		}()
	}

	handler, err := proxy.New(proxy.Config{
		Upstream:              client,
		Keys:                  ring,
		Verifier:              verifier,
		BaseDomain:            cfg.Server.BaseDomain,
		Log2ChunkSize:         cfg.Crypto.Log2ChunkSize,
		Logger:                log,
		Metrics:               metrics,
		Names:                 nameEnc,
		MaxListingKeys:        cfg.Names.MaxListingKeys,
		MaxConcurrentListings: cfg.Names.MaxConcurrentListings,
		Audit:                 auditLog,
		AuditFailClosed:       cfg.Audit.FailClosed,
		Freshness:             freshnessStore(freshIndex),
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: handler,
		// Slowloris protection for the headers. There is deliberately no
		// WriteTimeout: it would cut off a large download after a fixed time
		// regardless of progress. What replaces it is per-transfer rather than
		// per-server -- the proxy renews the connection's deadlines as bytes
		// move, so a request may run as long as it likes but not stall as long
		// as it likes (internal/proxy/deadline.go).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	listener, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}

	// Metrics, health and profiles live on their own address. An empty
	// admin.listen turns the whole listener off rather than exporting nothing
	// on a port nobody asked for.
	var admin *obs.AdminServer
	if cfg.Admin.Listen != "" {
		admin = obs.NewAdminServer(obs.AdminConfig{
			Listen:      cfg.Admin.Listen,
			EnablePprof: cfg.Admin.Pprof,
			Registry:    registry,
			Ready:       readiness(client, ring, probeBucket(cfg)),
			Logger:      log,
		})
		if err := admin.Start(); err != nil {
			return err
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := admin.Shutdown(shutdownCtx); err != nil {
				log.Warn("the admin listener did not stop cleanly", "err", err)
			}
		}()
	}

	log.Info("blindbucket listening",
		"addr", listener.Addr().String(),
		"upstream", cfg.Upstream.Endpoint,
		"active_kid", ring.ActiveKID(),
		"log2_chunk_size", cfg.Crypto.Log2ChunkSize,
		"clients", len(cfg.Clients),
		"base_domain", cfg.Server.BaseDomain,
		"tls", cfg.Server.TLS.Enabled(),
		"audit", cfg.Audit.Log,
	)
	if cfg.ExposesPlaintextPublicly() {
		log.Warn("this listener carries plaintext beyond loopback without TLS; " +
			"clients and proxy must share a trust boundary")
	}
	if cfg.Server.AllowUnsignedPayload {
		log.Warn("UNSIGNED-PAYLOAD is enabled; request bodies are not covered by the signature")
	}
	if cfg.Server.Presign.Enabled && presignExpiry == auth.MaxPresignExpiry {
		log.Warn("presigned URLs may name a window of up to "+
			"S3's maximum; a URL is a bearer credential for as long as it lasts",
			// String, because slog renders a time.Duration as an integer count
			// of nanoseconds and "604800000000000" is not a number anyone reads.
			"setting", "server.presign.max_expiry", "max", auth.MaxPresignExpiry.String())
	}
	if auditLog != nil && !cfg.Audit.FailClosed {
		log.Warn("audit.fail_closed is off; the gateway will keep serving if it can no " +
			"longer record what it serves")
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.Server.TLS.Enabled() {
			serveErr <- srv.ServeTLS(listener, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			return
		}
		serveErr <- srv.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutting down", "grace", shutdownGrace.String())
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

// openAuditLog starts the audit log, if one was configured.
//
// The keyring must already hold an audit key. Generating one here instead would
// mean a gateway that silently starts signing with a key nobody has recorded,
// and a log nobody can verify -- so a keyring without one is a startup error
// naming the command that fixes it (ADR-016).
func openAuditLog(cfg *config.Config, ring *keys.Keyring, log *slog.Logger) (*audit.Writer, error) {
	if !cfg.Audit.Enabled() {
		return nil, nil
	}
	key, ok := ring.AuditKey()
	if !ok {
		return nil, fmt.Errorf("audit.log is configured, but %s has no audit key; "+
			"add one with `blindbucket keygen --out %s --add-audit-key`",
			cfg.Keys.Keyring, cfg.Keys.Keyring)
	}
	signer, err := key.Signer()
	if err != nil {
		return nil, err
	}
	nameKey, err := key.NameKey()
	if err != nil {
		return nil, err
	}
	defer clear(nameKey)

	interval, err := cfg.Audit.Interval()
	if err != nil {
		return nil, err
	}
	writer, err := audit.Open(audit.Config{
		Path:               cfg.Audit.Log,
		Chain:              cfg.Audit.Chain,
		Signer:             signer,
		NameKey:            nameKey,
		CheckpointEvery:    cfg.Audit.CheckpointEvery,
		CheckpointInterval: interval,
		RotateBytes:        cfg.Audit.RotateBytes,
	})
	if err != nil {
		return nil, err
	}

	pub, err := key.Public()
	if err != nil {
		return nil, err
	}
	log.Info("audit log open",
		"path", cfg.Audit.Log,
		"chain", writer.Chain(),
		"fail_closed", cfg.Audit.FailClosed,
		"public_key", base64.StdEncoding.EncodeToString(pub))
	return writer, nil
}

// openNameEncrypter builds the object-name encrypter, or nil when names are to
// be stored in clear.
//
// The keyring must already hold a name key, for a harder reason than the audit
// key's: generating one here would give a gateway a fresh key on a restart that
// lost its keyring, and every object written before would become unfindable
// rather than merely unreadable. So a missing key is a startup error naming the
// command that fixes it (ADR-015).
func openNameEncrypter(
	cfg *config.Config, ring *keys.Keyring, log *slog.Logger,
) (*names.Encrypter, error) {
	if !cfg.Names.Encrypt {
		return nil, nil
	}
	key, ok := ring.NameKey()
	if !ok {
		return nil, fmt.Errorf("names.encrypt is on, but %s has no name key; "+
			"add one with `blindbucket keygen --out %s --add-name-key` -- and add it "+
			"before writing objects, because the key decides where every object is "+
			"stored and cannot be changed once objects exist under it",
			cfg.Keys.Keyring, cfg.Keys.Keyring)
	}
	secret := key.Secret()
	defer clear(secret)
	enc, err := names.New(secret)
	if err != nil {
		return nil, err
	}
	log.Info("object names are encrypted",
		"note", "objects written with this off are not visible with it on, and the reverse")
	return enc, nil
}

// openFreshnessIndex builds the rollback index, or nil when detection is off.
//
// The keyring must already hold a freshness key, for the reason the name key
// must: generating one here would make a restart that lost its keyring silently
// forget every object, and the gateway would report nothing wrong while
// detecting nothing. A missing key is a startup error naming the command that
// fixes it (ADR-018).
func openFreshnessIndex(
	cfg *config.Config, ring *keys.Keyring, log *slog.Logger,
) (*freshness.Local, error) {
	if !cfg.Freshness.Enabled() {
		return nil, nil
	}
	key, ok := ring.FreshnessKey()
	if !ok {
		return nil, fmt.Errorf("freshness.index is set, but %s has no freshness key; "+
			"add one with `blindbucket keygen --out %s --add-freshness-key`",
			cfg.Keys.Keyring, cfg.Keys.Keyring)
	}
	retention, err := cfg.Freshness.Retention()
	if err != nil {
		return nil, err
	}
	secret := key.Secret()
	defer clear(secret)

	index, err := freshness.Open(freshness.Options{
		Path:               cfg.Freshness.Index,
		Key:                secret,
		TombstoneRetention: retention,
		SyncEvery:          cfg.Freshness.SyncEvery,
		Logger:             log,
	})
	if err != nil {
		return nil, err
	}
	stats := index.Stats()
	log.Info("rollback detection is on",
		"index", cfg.Freshness.Index,
		"objects", stats.Objects, "tombstones", stats.Tombstones,
		"note", "objects this index has not seen are trusted the first time they are read")
	return index, nil
}

// freshnessStore avoids the typed-nil trap: a (*freshness.Local)(nil) assigned
// to a freshness.Store interface is not nil, and every guard in the proxy checks
// the interface against nil.
func freshnessStore(l *freshness.Local) freshness.Store {
	if l == nil {
		return nil
	}
	return l
}

func loadServerKeyring(ctx context.Context, cfg *config.Config, pass *passphraseFlags) (*keys.Keyring, error) {
	return openKeyring(ctx, cfg.Keys.Keyring, cfg.Keys, pass)
}

// probeBucket picks a bucket for the readiness check to look at.
//
// There is no "the" bucket in the configuration -- a client names one per
// request -- so the first concrete bucket a credential is scoped to is used. A
// deployment whose credentials are all wildcards gives nothing to probe, and
// readiness then reports on the keyring alone rather than inventing a name.
func probeBucket(cfg *config.Config) string {
	for _, client := range cfg.Clients {
		for _, bucket := range client.Buckets {
			if bucket != "" && bucket != auth.AllBuckets {
				return bucket
			}
		}
	}
	return ""
}

// readiness reports whether the gateway can actually serve.
//
// Liveness is "the process runs"; readiness is "the keyring is loaded and the
// provider answers" -- the pair an orchestrator needs to route traffic. The
// provider check is a bucket HEAD rather than a listing: it is the cheapest call
// that still proves credentials and connectivity, and it reads nothing.
func readiness(client *upstream.Client, ring *keys.Keyring, bucket string) func(context.Context) error {
	return func(ctx context.Context) error {
		if ring.ActiveKID() == "" {
			return errors.New("no active key in the keyring")
		}
		if bucket == "" {
			// Nothing concrete to probe against; the keyring check stands alone.
			return nil
		}
		if _, err := client.Passthrough(ctx, http.MethodHead, bucket, nil, nil); err != nil {
			return fmt.Errorf("upstream: %w", err)
		}
		return nil
	}
}
