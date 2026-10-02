package awscreds

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each source against a stub of the service it speaks to. The stubs hold the
// protocol to what AWS documents, and to what this code must never do: ask
// IMDS without a session token, send a container token anywhere but where
// the platform said, or sign a request that is meant to be anonymous.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const stsCredentialsXML = `<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>secret</SecretAccessKey>` +
	`<SessionToken>session</SessionToken><Expiration>%s</Expiration></Credentials>`

// stsStub answers both actions, and records each request's form and headers.
type stsStub struct {
	*httptest.Server
	mu       sync.Mutex
	forms    []map[string]string
	auth     []string
	failWith string
}

func newSTSStub(t *testing.T) *stsStub {
	t.Helper()
	s := &stsStub{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		s.mu.Lock()
		s.forms = append(s.forms, form)
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		fail := s.failWith
		s.mu.Unlock()
		if fail != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code>`+
				`<Message>not authorized</Message></Error></ErrorResponse>`, fail)
			return
		}
		expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		creds := fmt.Sprintf(stsCredentialsXML, "ASIA"+strings.ToUpper(form["Action"][:6]), expires)
		_, _ = fmt.Fprintf(w, "<%sResponse><%sResult>%s</%sResult></%sResponse>",
			form["Action"], form["Action"], creds, form["Action"], form["Action"])
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *stsStub) last() (map[string]string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forms[len(s.forms)-1], s.auth[len(s.auth)-1]
}

func TestWebIdentityAsksSTSAnonymouslyWithTheCurrentToken(t *testing.T) {
	sts := newSTSStub(t)
	token := filepath.Join(t.TempDir(), "token")
	writeFile(t, token, "first-token\n")

	creds, err := New(Options{Source: SourceWebIdentity, Getenv: envOf(map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE": token,
		"AWS_ROLE_ARN":                "arn:aws:iam::123456789012:role/gateway",
		"AWS_ROLE_SESSION_NAME":       "pod-a",
		"AWS_ENDPOINT_URL_STS":        sts.URL,
	})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := creds.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.AccessKeyID != "ASIAASSUME" || !got.CanExpire || got.SessionToken != "session" {
		t.Errorf("credentials %+v", got)
	}
	form, auth := sts.last()
	for k, want := range map[string]string{
		"Action": "AssumeRoleWithWebIdentity", "RoleArn": "arn:aws:iam::123456789012:role/gateway",
		"RoleSessionName": "pod-a", "WebIdentityToken": "first-token", "Version": stsAPIVersion,
	} {
		if form[k] != want {
			t.Errorf("%s = %q, want %q", k, form[k], want)
		}
	}
	if auth != "" {
		t.Errorf("the web identity request was signed: %q", auth)
	}

	// The kubelet rotates the token; the next fetch must read the new one.
	writeFile(t, token, "rotated-token")
	if _, err := webIdentityFetchOnce(t, token, sts.URL); err != nil {
		t.Fatal(err)
	}
	if form, _ := sts.last(); form["WebIdentityToken"] != "rotated-token" {
		t.Errorf("the rotated token was not read: %q", form["WebIdentityToken"])
	}
}

func webIdentityFetchOnce(t *testing.T, token, endpoint string) (any, error) {
	t.Helper()
	fetch, _, err := webIdentity{tokenFile: token, roleARN: "arn:aws:iam::1:role/r"}.fetcher(
		&Options{Getenv: envOf(map[string]string{"AWS_ENDPOINT_URL_STS": endpoint})}, "test")
	if err != nil {
		return nil, err
	}
	return fetch(t.Context())
}

func TestSTSErrorsSayWhat(t *testing.T) {
	sts := newSTSStub(t)
	sts.failWith = "AccessDenied"
	token := filepath.Join(t.TempDir(), "token")
	writeFile(t, token, "t")
	_, err := webIdentityFetchOnce(t, token, sts.URL)
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("got %v, want the STS error code", err)
	}
}

func TestSTSEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		env    map[string]string
		region string
		want   string
	}{
		"regional": {nil, "eu-central-1", "https://sts.eu-central-1.amazonaws.com"},
		"china":    {nil, "cn-north-1", "https://sts.cn-north-1.amazonaws.com.cn"},
		"global":   {nil, "", "https://sts.amazonaws.com"},
		"STS override": {map[string]string{"AWS_ENDPOINT_URL_STS": "http://127.0.0.1:4566/"},
			"eu-central-1", "http://127.0.0.1:4566"},
		// The CLI pointed at this gateway with AWS_ENDPOINT_URL must not send
		// the gateway's own STS calls there.
		"the all-services override is ignored": {map[string]string{
			"AWS_ENDPOINT_URL": "http://127.0.0.1:9000"}, "eu-central-1",
			"https://sts.eu-central-1.amazonaws.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := stsEndpoint(&Options{Getenv: envOf(tc.env)}, tc.region); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProfiles(t *testing.T) {
	sts := newSTSStub(t)
	home := t.TempDir()
	token := filepath.Join(home, "token")
	writeFile(t, token, "profile-token")
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `
[default]
aws_access_key_id = AKIDDEFAULT
aws_secret_access_key = default-secret

# a comment
[base]
aws_access_key_id = AKIDBASE
aws_secret_access_key = base-secret
`)
	writeFile(t, filepath.Join(home, ".aws", "config"), `
[default]
region = eu-west-1
s3 =
  max_concurrent_requests = 20

[profile assumed]
role_arn = arn:aws:iam::123456789012:role/target
source_profile = base
external_id = ext-1
region = eu-central-1

[profile federated]
role_arn = arn:aws:iam::123456789012:role/fed
web_identity_token_file = `+token+`

[profile self]
role_arn = arn:aws:iam::123456789012:role/self
source_profile = self
aws_access_key_id = AKIDSELF
aws_secret_access_key = self-secret

[profile loop-a]
role_arn = arn:aws:iam::1:role/a
source_profile = loop-b
[profile loop-b]
role_arn = arn:aws:iam::1:role/b
source_profile = loop-a

[profile sso]
sso_session = corp
[profile process]
credential_process = /usr/bin/get-creds
[profile mfa]
role_arn = arn:aws:iam::1:role/m
source_profile = base
mfa_serial = arn:aws:iam::1:mfa/me

[sso-session corp]
sso_region = eu-central-1
`)
	opts := func(profile string) Options {
		return Options{Source: SourceProfile, Getenv: envOf(map[string]string{
			"HOME": home, "AWS_PROFILE": profile, "AWS_ENDPOINT_URL_STS": sts.URL,
		})}
	}

	t.Run("static keys in the default profile", func(t *testing.T) {
		creds, err := New(opts(""))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := creds.Retrieve(t.Context()); err != nil || got.AccessKeyID != "AKIDDEFAULT" {
			t.Errorf("got %+v, %v", got, err)
		}
	})

	t.Run("a role assumed with a source profile, signed with its keys", func(t *testing.T) {
		creds, err := New(opts("assumed"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := creds.Retrieve(t.Context())
		if err != nil || got.AccessKeyID != "ASIAASSUME" {
			t.Fatalf("got %+v, %v", got, err)
		}
		form, auth := sts.last()
		if form["Action"] != "AssumeRole" || form["RoleArn"] != "arn:aws:iam::123456789012:role/target" ||
			form["ExternalId"] != "ext-1" {
			t.Errorf("form %v", form)
		}
		if !strings.Contains(auth, "Credential=AKIDBASE/") || !strings.Contains(auth, "/eu-central-1/sts/") {
			t.Errorf("AssumeRole was not signed with the source profile's key in the profile's "+
				"region: %q", auth)
		}
	})

	t.Run("a role with a web identity token file", func(t *testing.T) {
		creds, err := New(opts("federated"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := creds.Retrieve(t.Context()); err != nil {
			t.Fatal(err)
		}
		if form, auth := sts.last(); form["WebIdentityToken"] != "profile-token" || auth != "" {
			t.Errorf("form %v, auth %q", form, auth)
		}
	})

	t.Run("a profile that is its own source", func(t *testing.T) {
		creds, err := New(opts("self"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := creds.Retrieve(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, auth := sts.last(); !strings.Contains(auth, "Credential=AKIDSELF/") {
			t.Errorf("auth %q", auth)
		}
	})

	for profile, want := range map[string]string{
		"loop-a":  "cycle",
		"sso":     "export-credentials",
		"process": "credential_process",
		"mfa":     "MFA",
		"missing": "in neither",
	} {
		t.Run("refused: "+profile, func(t *testing.T) {
			_, err := New(opts(profile))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("got %v, want an error mentioning %q", err, want)
			}
		})
	}
}

func TestContainerEndpoint(t *testing.T) {
	var auth atomic.Value
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		_, _ = fmt.Fprintf(w, `{"AccessKeyId":"ASIAPOD","SecretAccessKey":"s","Token":"t","Expiration":%q}`,
			time.Now().Add(6*time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(stub.Close)
	tokenFile := filepath.Join(t.TempDir(), "eks-pod-identity-token")
	writeFile(t, tokenFile, "pod-token-1")

	creds, err := New(Options{Source: SourceContainer, Getenv: envOf(map[string]string{
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":     stub.URL + "/v1/credentials",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": tokenFile,
	})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := creds.Retrieve(t.Context())
	if err != nil || got.AccessKeyID != "ASIAPOD" || !got.CanExpire {
		t.Fatalf("got %+v, %v", got, err)
	}
	if auth.Load() != "pod-token-1" {
		t.Errorf("Authorization %v", auth.Load())
	}

	for name, tc := range map[string]struct {
		env  map[string]string
		want string
		ok   bool
	}{
		"ECS relative URI": {map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/abc"},
			"http://169.254.170.2/v2/credentials/abc", true},
		"Pod Identity agent": {map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials"},
			"http://169.254.170.23/v1/credentials", true},
		"any host over TLS": {map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "https://creds.internal/x"},
			"https://creds.internal/x", true},
		"a remote host in clear": {map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://creds.example.com/x"},
			"", false},
		"another scheme": {map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "file:///etc/passwd"},
			"", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := containerEndpoint(&Options{Getenv: envOf(tc.env)})
			if (err == nil) != tc.ok || got != tc.want {
				t.Errorf("got %q, %v", got, err)
			}
		})
	}
}

// newIMDSStub is IMDS as version 2 answers it, and it fails the test if
// anything asks without a session token -- the version 1 request this code
// must never make.
func newIMDSStub(t *testing.T, asked *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if asked != nil {
			asked.Store(true)
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = fmt.Fprint(w, "session-token")
		case r.Header.Get("X-aws-ec2-metadata-token") != "session-token":
			t.Errorf("IMDS was asked %s %s without the session token", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == imdsCredentialsPath:
			_, _ = fmt.Fprint(w, "gateway-role\n")
		case r.URL.Path == imdsCredentialsPath+"gateway-role":
			_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"ASIAEC2","SecretAccessKey":"s",`+
				`"Token":"t","Expiration":%q}`, time.Now().Add(6*time.Hour).UTC().Format(time.RFC3339))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIMDSv2(t *testing.T) {
	imds := newIMDSStub(t, nil)
	creds, err := New(Options{Source: SourceIMDS, Getenv: envOf(map[string]string{
		"AWS_EC2_METADATA_SERVICE_ENDPOINT": imds.URL,
	})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := creds.Retrieve(t.Context())
	if err != nil || got.AccessKeyID != "ASIAEC2" || !got.CanExpire {
		t.Errorf("got %+v, %v", got, err)
	}
}

// TestIMDSHasNoVersion1Fallback: a refused session token is an error, and
// nothing is then asked without one.
func TestIMDSHasNoVersion1Fallback(t *testing.T) {
	var gets atomic.Int64
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(imds.Close)
	creds, err := New(Options{Source: SourceIMDS, Getenv: envOf(map[string]string{
		"AWS_EC2_METADATA_SERVICE_ENDPOINT": imds.URL,
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creds.Retrieve(t.Context()); err == nil || !strings.Contains(err.Error(), "fallback") {
		t.Errorf("got %v", err)
	}
	if gets.Load() != 0 {
		t.Errorf("%d GETs after the token was refused: a version 1 fallback", gets.Load())
	}
}
