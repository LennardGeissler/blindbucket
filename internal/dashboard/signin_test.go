package dashboard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// testIDP is an identity provider for the tests: discovery, a key set, and a
// token endpoint that hands out whatever ID token the test mints. It checks
// the PKCE verifier against the challenge the authorization request carried.
type testIDP struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	rsaKey    *rsa.PrivateKey
	ecKey     *ecdsa.PrivateKey
	published []jose.JSONWebKey
	// codes maps an authorization code to the PKCE challenge it was issued
	// for, and the ID token its redemption returns.
	codes map[string]issued
	// hangKeys, while set, makes the key set accept a request and never
	// answer it, until the request gives up.
	hangKeys bool
}

type issued struct {
	challenge string
	idToken   string
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIDP{t: t, rsaKey: rsaKey, ecKey: ecKey, codes: map[string]issued{}}
	p.published = []jose.JSONWebKey{
		{Key: rsaKey.Public(), KeyID: "rsa-1", Algorithm: "RS256", Use: "sig"},
		{Key: ecKey.Public(), KeyID: "ec-1", Algorithm: "ES256", Use: "sig"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.srv.URL,
			"authorization_endpoint":                p.srv.URL + "/auth",
			"token_endpoint":                        p.srv.URL + "/token",
			"jwks_uri":                              p.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256", "HS256", "none"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		hang := p.hangKeys
		p.mu.Unlock()
		if hang {
			<-r.Context().Done()
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: p.published})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		got, ok := p.codes[r.PostForm.Get("code")]
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != got.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "unused", "token_type": "Bearer", "id_token": got.idToken,
		})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// claims is a good ID token's claims for nonce; a test changes what it needs.
func (p *testIDP) claims(nonce string, now time.Time) map[string]any {
	return map[string]any{
		"iss": p.srv.URL, "aud": "blindbucket-dashboard", "sub": "user-1",
		"email": "ada@example.org", "groups": []string{"staff", "blindbucket-operators"},
		"nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
}

// sign signs claims with alg under key, named kid.
func (p *testIDP) sign(claims map[string]any, alg jose.SignatureAlgorithm, key any, kid string) string {
	p.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		p.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return out
}

// unsigned is claims as a JWT with alg none.
func unsigned(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

const (
	testRedirect = "https://dash.example:9101/callback"
	testHost     = "dash.example:9101"
	testSecret   = "a client secret of at least 32 bytes"
)

// signInServer is a dashboard with sign-in against p, on a clock the test
// moves.
func signInServer(t *testing.T, p *testIDP, now *time.Time) *Server {
	t.Helper()
	return New(Config{
		Version: "1.8.0", Keyring: keyring{}, Sealing: "a passphrase", Logger: quiet(),
		SignIn: &SignIn{
			Issuer: p.srv.URL, ClientID: "blindbucket-dashboard", ClientSecret: testSecret,
			RedirectURL: testRedirect, Claim: "groups", Allowed: []string{"blindbucket-operators"},
			Scopes: []string{"groups"}, Session: 8 * time.Hour, HTTPClient: p.srv.Client(), Now: func() time.Time { return *now },
		},
	})
}

// browser keeps cookies across requests to one dashboard handler.
type browser struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]*http.Cookie
}

func (b *browser) do(method, target string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = testHost
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

// start asks for the page without a session and returns where the dashboard
// sent the browser: the state, nonce and PKCE challenge it chose.
func (b *browser) start() url.Values {
	b.t.Helper()
	rec := b.do(http.MethodGet, "/")
	if rec.Code != http.StatusFound {
		b.t.Fatalf("GET / without a session: %d, want a redirect to the issuer\n%s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("scope") != "openid profile email groups" {
		b.t.Fatalf("the authorization request asks for the scopes %q", q.Get("scope"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" ||
		q.Get("state") == "" || q.Get("redirect_uri") != testRedirect || q.Get("client_id") != "blindbucket-dashboard" {
		b.t.Fatalf("the authorization request lacks something: %s", loc)
	}
	return q
}

// finish has the identity provider answer with idToken and returns the
// dashboard's answer to the callback.
func (b *browser) finish(p *testIDP, q url.Values, idToken string) *httptest.ResponseRecorder {
	b.t.Helper()
	code := "code-" + q.Get("state")[:8]
	p.mu.Lock()
	p.codes[code] = issued{challenge: q.Get("code_challenge"), idToken: idToken}
	p.mu.Unlock()
	return b.do(http.MethodGet, "/callback?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode())
}

// A good sign-in: redirect with PKCE, callback, the page, sign-out.
func TestSignIn(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	b := &browser{t: t, h: signInServer(t, p, &now).Handler(), cookies: map[string]*http.Cookie{}}

	q := b.start()
	state := b.cookies[stateCookie]
	if state == nil || !state.Secure || !state.HttpOnly || state.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the state cookie: %+v", state)
	}
	rec := b.finish(p, q, p.sign(p.claims(q.Get("nonce"), now), jose.RS256, p.rsaKey, "rsa-1"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	sess := b.cookies[sessionCookie]
	if sess == nil || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" {
		t.Fatalf("the session cookie: %+v", sess)
	}
	if _, ok := b.cookies[stateCookie]; ok {
		t.Error("the state cookie outlived the sign-in")
	}

	rec = b.do(http.MethodGet, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Signed in as ada@example.org") {
		t.Fatalf("the page after sign-in: %d\n%s", rec.Code, rec.Body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("the page's policy does not allow its sign-out form: %s", csp)
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := b.do(method, "/"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / with a session: %d, want 405", method, rec.Code)
		}
	}
	if rec := b.do(http.MethodGet, "/logout"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /logout: %d, want 405", rec.Code)
	}
	if rec := b.do(http.MethodPost, "/logout"); rec.Code != http.StatusOK {
		t.Errorf("POST /logout: %d", rec.Code)
	}
	if rec := b.do(http.MethodGet, "/"); rec.Code != http.StatusFound {
		t.Errorf("GET / after sign-out: %d, want a redirect to sign in again", rec.Code)
	}
}

// Every way an ID token can be wrong is refused, and leaves no session.
func TestSignInRefusals(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	strangerRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, mint := range map[string]func(nonce string) string{
		"expired": func(n string) string {
			c := p.claims(n, now)
			c["exp"] = now.Add(-time.Minute).Unix()
			return p.sign(c, jose.RS256, p.rsaKey, "rsa-1")
		},
		"for another audience": func(n string) string {
			c := p.claims(n, now)
			c["aud"] = "another-client"
			return p.sign(c, jose.RS256, p.rsaKey, "rsa-1")
		},
		"from another issuer": func(n string) string {
			c := p.claims(n, now)
			c["iss"] = "https://idp.attacker.example"
			return p.sign(c, jose.RS256, p.rsaKey, "rsa-1")
		},
		"without the claim": func(n string) string {
			c := p.claims(n, now)
			delete(c, "groups")
			return p.sign(c, jose.RS256, p.rsaKey, "rsa-1")
		},
		"without an allowed value": func(n string) string {
			c := p.claims(n, now)
			c["groups"] = []string{"staff"}
			return p.sign(c, jose.RS256, p.rsaKey, "rsa-1")
		},
		"with another nonce": func(string) string {
			return p.sign(p.claims("another-nonce", now), jose.RS256, p.rsaKey, "rsa-1")
		},
		"without a nonce": func(string) string {
			c := p.claims("", now)
			delete(c, "nonce")
			return p.sign(c, jose.RS256, p.rsaKey, "rsa-1")
		},
		"under a key the issuer does not publish": func(n string) string {
			return p.sign(p.claims(n, now), jose.RS256, strangerRSA, "rsa-stranger")
		},
		"under a published key id, signed by another key": func(n string) string {
			return p.sign(p.claims(n, now), jose.RS256, strangerRSA, "rsa-1")
		},
		"unsigned, alg none": func(n string) string { return unsigned(p.claims(n, now)) },
		"signed with HS256 and the client secret": func(n string) string {
			return p.sign(p.claims(n, now), jose.HS256, []byte(testSecret), "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := &browser{t: t, h: signInServer(t, p, &now).Handler(), cookies: map[string]*http.Cookie{}}
			q := b.start()
			rec := b.finish(p, q, mint(q.Get("nonce")))
			if rec.Code != http.StatusForbidden {
				t.Errorf("callback: %d, want 403\n%s", rec.Code, rec.Body)
			}
			if _, ok := b.cookies[sessionCookie]; ok {
				t.Error("a refused sign-in set a session")
			}
			if rec := b.do(http.MethodGet, "/"); rec.Code != http.StatusFound {
				t.Errorf("GET / after a refused sign-in: %d, want a redirect", rec.Code)
			}
		})
	}
}

// The callback itself is refused when it does not belong to a sign-in this
// browser started.
func TestSignInCallbackRefusals(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	good := func(q url.Values) string {
		return p.sign(p.claims(q.Get("nonce"), now), jose.RS256, p.rsaKey, "rsa-1")
	}
	newBrowser := func(t *testing.T) *browser {
		return &browser{t: t, h: signInServer(t, p, &now).Handler(), cookies: map[string]*http.Cookie{}}
	}

	t.Run("another state", func(t *testing.T) {
		b := newBrowser(t)
		q := b.start()
		q2 := url.Values{"state": {"x" + q.Get("state")}, "nonce": q["nonce"], "code_challenge": q["code_challenge"]}
		if rec := b.finish(p, q2, good(q)); rec.Code != http.StatusBadRequest {
			t.Errorf("%d, want 400", rec.Code)
		}
	})
	t.Run("no sign-in started here", func(t *testing.T) {
		b := newBrowser(t)
		q := b.start()
		delete(b.cookies, stateCookie)
		if rec := b.finish(p, q, good(q)); rec.Code != http.StatusBadRequest {
			t.Errorf("%d, want 400", rec.Code)
		}
	})
	t.Run("a sign-in started too long ago", func(t *testing.T) {
		b := newBrowser(t)
		q := b.start()
		later := now
		now = now.Add(stateTTL + time.Second)
		defer func() { now = later }()
		if rec := b.finish(p, q, good(q)); rec.Code != http.StatusBadRequest {
			t.Errorf("%d, want 400", rec.Code)
		}
	})
	t.Run("the identity provider refused", func(t *testing.T) {
		b := newBrowser(t)
		q := b.start()
		rec := b.do(http.MethodGet, "/callback?"+url.Values{"error": {"access_denied"}, "state": {q.Get("state")}}.Encode())
		if rec.Code != http.StatusForbidden {
			t.Errorf("%d, want 403", rec.Code)
		}
	})
	t.Run("a code redeemed without the PKCE verifier", func(t *testing.T) {
		b := newBrowser(t)
		q := b.start()
		q.Set("code_challenge", "not-the-challenge")
		if rec := b.finish(p, q, good(q)); rec.Code != http.StatusForbidden {
			t.Errorf("%d, want 403", rec.Code)
		}
	})
}

// The issuer's new key is fetched when a token names it, and a session ends
// with the ID token or the configured length, whichever is first.
func TestSignInFollowsKeyRotationAndEnds(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	srv := signInServer(t, p, &now)

	b := &browser{t: t, h: srv.Handler(), cookies: map[string]*http.Cookie{}}
	q := b.start()
	if rec := b.finish(p, q, p.sign(p.claims(q.Get("nonce"), now), jose.ES256, p.ecKey, "ec-1")); rec.Code != http.StatusSeeOther {
		t.Fatalf("an ES256 token: %d\n%s", rec.Code, rec.Body)
	}

	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.published = append(p.published, jose.JSONWebKey{Key: rotated.Public(), KeyID: "rsa-2", Algorithm: "RS256", Use: "sig"})
	p.mu.Unlock()
	b2 := &browser{t: t, h: srv.Handler(), cookies: map[string]*http.Cookie{}}
	q = b2.start()
	claims := p.claims(q.Get("nonce"), now)
	claims["exp"] = now.Add(30 * time.Minute).Unix()
	if rec := b2.finish(p, q, p.sign(claims, jose.RS256, rotated, "rsa-2")); rec.Code != http.StatusSeeOther {
		t.Fatalf("a token under the issuer's new key: %d\n%s", rec.Code, rec.Body)
	}

	now = now.Add(31 * time.Minute)
	if rec := b2.do(http.MethodGet, "/"); rec.Code != http.StatusFound {
		t.Errorf("after the ID token expired: %d, want a redirect", rec.Code)
	}
	if rec := b.do(http.MethodGet, "/"); rec.Code != http.StatusOK {
		t.Errorf("a session with time left: %d", rec.Code)
	}
}

// The page answers to its own address and to loopback, and to nothing else.
func TestSignInHosts(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	h := signInServer(t, p, &now).Handler()
	for host, want := range map[string]int{
		testHost: http.StatusFound, "DASH.example": http.StatusFound, "localhost:9101": http.StatusFound,
		"attacker.example": http.StatusMisdirectedRequest, "dash.example.attacker.example": http.StatusMisdirectedRequest,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: %d, want %d", host, rec.Code, want)
		}
	}
}

// An identity provider that cannot be reached makes the page answer 503, and
// the dashboard is built and served all the same.
func TestSignInWithoutTheIdentityProvider(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	issuer := p.srv.URL
	p.srv.Close()
	s := New(Config{Version: "1.8.0", Keyring: keyring{}, Logger: quiet(), SignIn: &SignIn{
		Issuer: issuer, ClientID: "blindbucket-dashboard", RedirectURL: testRedirect, Claim: "groups",
		Allowed: []string{"blindbucket-operators"}, Session: time.Hour, HTTPClient: p.srv.Client(),
		Now: func() time.Time { return now },
	}})
	b := &browser{t: t, h: s.Handler(), cookies: map[string]*http.Cookie{}}
	if rec := b.do(http.MethodGet, "/"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET / with the issuer down: %d, want 503", rec.Code)
	}
}

// A key set that never answers holds a sign-in only until the client's timeout,
// and once it answers again, the next sign-in works: go-oidc fetches it once
// for every waiting caller, so without a timeout one stuck fetch would hold
// every later sign-in until a restart. The default client has one.
func TestSignInRecoversFromAKeySetThatHangs(t *testing.T) {
	s, err := newSigner(SignIn{RedirectURL: testRedirect}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.HTTPClient.Timeout <= 0 {
		t.Error("the default client for the identity provider has no timeout")
	}

	p := newTestIDP(t)
	now := time.Now()
	srv := New(Config{
		Version: "1.8.0", Keyring: keyring{}, Logger: quiet(),
		SignIn: &SignIn{
			Issuer: p.srv.URL, ClientID: "blindbucket-dashboard", ClientSecret: testSecret,
			RedirectURL: testRedirect, Claim: "groups", Allowed: []string{"blindbucket-operators"},
			Scopes: []string{"groups"}, Session: time.Hour, Now: func() time.Time { return now },
			HTTPClient: &http.Client{Timeout: 300 * time.Millisecond, Transport: p.srv.Client().Transport},
		},
	})

	p.mu.Lock()
	p.hangKeys = true
	p.mu.Unlock()
	b := &browser{t: t, h: srv.Handler(), cookies: map[string]*http.Cookie{}}
	q := b.start()
	if rec := b.finish(p, q, p.sign(p.claims(q.Get("nonce"), now), jose.RS256, p.rsaKey, "rsa-1")); rec.Code != http.StatusForbidden {
		t.Fatalf("while the key set hangs: %d, want 403", rec.Code)
	}

	p.mu.Lock()
	p.hangKeys = false
	p.mu.Unlock()
	b = &browser{t: t, h: srv.Handler(), cookies: map[string]*http.Cookie{}}
	q = b.start()
	if rec := b.finish(p, q, p.sign(p.claims(q.Get("nonce"), now), jose.RS256, p.rsaKey, "rsa-1")); rec.Code != http.StatusSeeOther {
		t.Fatalf("after the key set answers again: %d, want a sign-in\n%s", rec.Code, rec.Body)
	}
}

// A sign-out posted from another site arrives without the session, as a
// SameSite=Lax cookie is not sent with it, and changes nothing.
func TestSignOutNeedsTheSession(t *testing.T) {
	p := newTestIDP(t)
	now := time.Now()
	h := signInServer(t, p, &now).Handler()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Host = testHost
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			t.Errorf("a sign-out without the session set %s: %+v", sessionCookie, c)
		}
	}
}
