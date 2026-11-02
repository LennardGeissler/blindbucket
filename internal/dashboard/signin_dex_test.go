package dashboard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

// selfSigned is a certificate for 127.0.0.1, and a pool that trusts it.
func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dashboard"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}, pool
}

// The whole sign-in against Dex (ADR-039): a browser that follows every
// redirect, from the page to Dex, through its mock connector, and back to
// /callback, gets the page if its groups claim holds an allowed value, and a
// refusal if not. test/services/dex.sh starts Dex with the client and the two
// redirect URIs used here.
func TestSignInWithDex(t *testing.T) {
	issuer := os.Getenv("BLINDBUCKET_TEST_DEX_ISSUER")
	if issuer == "" {
		t.Skip("set BLINDBUCKET_TEST_DEX_ISSUER to run against Dex (test/services/dex.sh)")
	}
	serverTLS, pool := selfSigned(t)

	for _, c := range []struct {
		name, addr string
		allowed    []string
		want       int
	}{
		{"in an allowed group", "127.0.0.1:19101", []string{"authors"}, http.StatusOK},
		{"in no allowed group", "127.0.0.1:19102", []string{"blindbucket-operators"}, http.StatusForbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := New(Config{
				Listen: c.addr, TLS: serverTLS, Version: "test", Keyring: keyring{}, Sealing: "a passphrase",
				Logger: quiet(),
				SignIn: &SignIn{
					Issuer: issuer, ClientID: "blindbucket-dashboard",
					ClientSecret: "dashboard-test-secret-of-thirty-two-bytes",
					RedirectURL:  "https://" + c.addr + "/callback", Claim: "groups", Allowed: c.allowed,
					Scopes: []string{"groups"}, Session: time.Hour,
				},
			})
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Shutdown(context.Background()) }()

			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			browser := &http.Client{Jar: jar, Timeout: 15 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			}}
			resp, err := browser.Get("https://" + c.addr + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Fatalf("after following the sign-in: %d at %s, want %d\n%s",
					resp.StatusCode, resp.Request.URL, c.want, body)
			}
			if c.want == http.StatusOK && !strings.Contains(string(body), "Signed in as kilgore@kilgore.trout") {
				t.Errorf("the page does not name who signed in:\n%s", body)
			}
		})
	}
}
