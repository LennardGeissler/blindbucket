package dashboard

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// SignIn is the dashboard's sign-in through the organisation's identity
// provider: the authorization code flow with PKCE, and access decided by one
// claim (ADR-039).
type SignIn struct {
	Issuer       string
	ClientID     string
	ClientSecret string // empty for a public client, which relies on PKCE
	RedirectURL  string
	Claim        string
	Allowed      []string
	// Scopes are asked for besides openid, profile and email.
	Scopes []string
	// Session is how long a sign-in lasts at most; the ID token's expiry may
	// end it sooner.
	Session time.Duration
	// HTTPClient talks to the identity provider. Nil uses a client with
	// ProviderTimeout; one without a timeout would let a provider that never
	// answers hold sign-in until a restart.
	HTTPClient *http.Client
	// Now is the clock, for tests. Nil uses time.Now.
	Now func() time.Time
}

// The cookies sign-in sets. __Host- makes the browser refuse them unless they
// are Secure, have no Domain and have the path /, so no other host and no
// other path can set or shadow them.
const (
	stateCookie   = "__Host-bb-signin"
	sessionCookie = "__Host-bb-session"
	// stateTTL bounds the time between the redirect to the identity provider
	// and its answer.
	stateTTL = 10 * time.Minute
	// ProviderTimeout bounds every call to the identity provider: discovery, the
	// token endpoint, and the key set, which go-oidc fetches once for every
	// waiting caller, so a fetch that never ends would leave every later
	// sign-in waiting on it.
	ProviderTimeout = 10 * time.Second
)

// signingAlgs are the only signatures an ID token may carry (ADR-039). none
// and the HMAC algorithms are absent: an HMAC "signature" keyed with the
// client secret would be forgeable by whoever holds it.
var signingAlgs = []string{oidc.RS256, oidc.ES256}

// pendingSignIn is what the state cookie holds between the redirect and the
// callback.
type pendingSignIn struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// session is what the session cookie holds.
type session struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
	// Name is what the page shows: the email or preferred username if the
	// token carries one, the subject otherwise.
	Name string `json:"name"`
}

// signer runs sign-in for one dashboard.
type signer struct {
	cfg      SignIn
	seal     *sealer
	redirect *url.URL
	log      interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
	}

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newSigner(cfg SignIn, log interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}) (*signer, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: ProviderTimeout}
	}
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("dashboard: the redirect URL: %w", err)
	}
	seal, err := newSealer(cfg.Now)
	if err != nil {
		return nil, err
	}
	return &signer{cfg: cfg, seal: seal, redirect: redirect, log: log}, nil
}

// provider discovers the identity provider on first use, and again after a
// failure (ADR-039): a gateway starts and serves S3 whatever the identity
// provider is doing, and only the page waits for it.
func (s *signer) provider(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oauth != nil {
		return s.oauth, s.verifier, nil
	}
	// Discovery holds the lock, so every other sign-in waits for it: bounded,
	// whatever client the caller passed.
	ctx, cancel := context.WithTimeout(ctx, ProviderTimeout)
	defer cancel()
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, s.cfg.HTTPClient), s.cfg.Issuer)
	if err != nil {
		return nil, nil, err
	}
	s.oauth = &oauth2.Config{
		ClientID: s.cfg.ClientID, ClientSecret: s.cfg.ClientSecret, RedirectURL: s.cfg.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: append([]string{oidc.ScopeOpenID, "profile", "email"}, s.cfg.Scopes...),
	}
	if s.cfg.ClientSecret == "" {
		s.oauth.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	// The key set is fetched with the client the verifier is built with, and
	// fetched again whenever a token names a key it does not have: that is
	// how the issuer's key rotation is followed.
	s.verifier = p.VerifierContext(oidc.ClientContext(context.Background(), s.cfg.HTTPClient), &oidc.Config{
		ClientID: s.cfg.ClientID, SupportedSigningAlgs: signingAlgs, Now: s.cfg.Now,
	})
	return s.oauth, s.verifier, nil
}

// allowsHost reports whether a request names the dashboard by a name it
// answers to: a loopback name, for a tunnel, or the host people use, from the
// redirect URL. A DNS-rebinding page arrives under its own name.
func (s *signer) allowsHost(host string) bool {
	if loopbackHost(host) {
		return true
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return strings.EqualFold(h, s.redirect.Hostname())
}

// current returns the request's session, if it has one that opens.
func (s *signer) current(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	var sess session
	if s.seal.open(sessionCookie, c.Value, &sess) != nil {
		return session{}, false
	}
	return sess, true
}

// begin sends the browser to the identity provider, with a fresh state,
// nonce and PKCE verifier kept in a sealed cookie.
func (s *signer) begin(w http.ResponseWriter, r *http.Request) {
	conf, _, err := s.provider(r.Context())
	if err != nil {
		s.log.Warn("dashboard sign-in: the identity provider cannot be reached", "issuer", s.cfg.Issuer, "err", err)
		http.Error(w, "Sign-in is unavailable: the identity provider cannot be reached.", http.StatusServiceUnavailable)
		return
	}
	p := pendingSignIn{State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(), Verifier: oauth2.GenerateVerifier()}
	value, err := s.seal.seal(stateCookie, p, s.cfg.Now().Add(stateTTL))
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	setCookie(w, stateCookie, value, stateTTL)
	http.Redirect(w, r, conf.AuthCodeURL(p.State, oidc.Nonce(p.Nonce), oauth2.S256ChallengeOption(p.Verifier)),
		http.StatusFound)
}

// callback finishes a sign-in: the state matches, the code is redeemed with
// the PKCE verifier, the ID token verifies, its nonce is this browser's, and
// the claim allows it.
func (s *signer) callback(w http.ResponseWriter, r *http.Request) {
	refuse := func(status int, reason string, args ...any) {
		s.log.Warn("dashboard sign-in refused: "+reason, args...)
		clearCookie(w, stateCookie)
		http.Error(w, "Sign-in failed. Reload the page to try again.", status)
	}
	c, err := r.Cookie(stateCookie)
	if err != nil {
		refuse(http.StatusBadRequest, "no sign-in was started from this browser")
		return
	}
	var p pendingSignIn
	if s.seal.open(stateCookie, c.Value, &p) != nil {
		refuse(http.StatusBadRequest, "the sign-in cookie does not open")
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.State)) != 1 {
		refuse(http.StatusBadRequest, "the state does not match")
		return
	}
	if e := q.Get("error"); e != "" {
		refuse(http.StatusForbidden, "the identity provider answered with an error", "error", e)
		return
	}
	conf, verifier, err := s.provider(r.Context())
	if err != nil {
		refuse(http.StatusServiceUnavailable, "the identity provider cannot be reached", "err", err)
		return
	}
	ctx := oidc.ClientContext(r.Context(), s.cfg.HTTPClient)
	token, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(p.Verifier))
	if err != nil {
		refuse(http.StatusForbidden, "the code was not redeemed", "err", err)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		refuse(http.StatusForbidden, "the token response holds no ID token")
		return
	}
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		refuse(http.StatusForbidden, "the ID token does not verify", "err", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(p.Nonce)) != 1 {
		refuse(http.StatusForbidden, "the ID token's nonce is not this sign-in's", "subject", idToken.Subject)
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		refuse(http.StatusForbidden, "the ID token's claims do not decode", "err", err)
		return
	}
	if !allowed(claims[s.cfg.Claim], s.cfg.Allowed) {
		refuse(http.StatusForbidden, "the claim allows no access", "subject", idToken.Subject,
			"issuer", idToken.Issuer, "claim", s.cfg.Claim)
		return
	}

	expires := s.cfg.Now().Add(s.cfg.Session)
	if idToken.Expiry.Before(expires) {
		expires = idToken.Expiry
	}
	sess := session{Subject: idToken.Subject, Issuer: idToken.Issuer, Name: displayName(claims, idToken.Subject)}
	value, err := s.seal.seal(sessionCookie, sess, expires)
	if err != nil {
		refuse(http.StatusInternalServerError, "the session could not be sealed", "err", err)
		return
	}
	clearCookie(w, stateCookie)
	setCookie(w, sessionCookie, value, expires.Sub(s.cfg.Now()))
	s.log.Info("dashboard sign-in", "subject", sess.Subject, "issuer", sess.Issuer, "until", expires.UTC())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout ends the browser's session. It is a POST, which a SameSite=Lax
// cookie does not accompany from another site, and only a request that
// carries the session ends it: a page on another site can still post here,
// and a response that cleared the cookie regardless would sign the person
// out, since a browser takes a top-level navigation's Set-Cookie.
func (s *signer) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.current(r); ok {
		s.log.Info("dashboard sign-out", "subject", sess.Subject, "issuer", sess.Issuer)
		clearCookie(w, sessionCookie)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Signed out</title><link rel="stylesheet" href="/style.css"></head>` +
		`<body><p>Signed out. <a href="/">Sign in again</a>.</p></body></html>`))
}

// allowed reports whether a claim's value, a string or a list of strings,
// holds one of the allowed values.
func allowed(claim any, values []string) bool {
	switch v := claim.(type) {
	case string:
		return slices.Contains(values, v)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && slices.Contains(values, s) {
				return true
			}
		}
	}
	return false
}

// displayName picks what the page shows for a person.
func displayName(claims map[string]any, subject string) string {
	for _, c := range []string{"email", "preferred_username", "name"} {
		if s, ok := claims[c].(string); ok && s != "" {
			return s
		}
	}
	return subject
}

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(maxAge / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
