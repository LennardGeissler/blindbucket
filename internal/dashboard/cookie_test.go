package dashboard

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

type testSession struct {
	Subject string `json:"sub"`
}

// A sealed cookie opens for the cookie it was sealed for, until it expires,
// in the process that sealed it, and in no other case.
func TestSealedCookies(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	s, err := newSealer(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	value, err := s.seal("session", testSession{Subject: "ada"}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var got testSession
	if err := s.open("session", value, &got); err != nil || got.Subject != "ada" {
		t.Fatalf("open = %+v, %v", got, err)
	}

	raw, _ := base64.RawURLEncoding.DecodeString(value)
	raw[len(raw)-1] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	other, err := newSealer(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	expired, err := s.seal("session", testSession{Subject: "ada"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, open := range map[string]func() error{
		"altered":                   func() error { return s.open("session", tampered, &got) },
		"sealed for another cookie": func() error { return s.open("state", value, &got) },
		"sealed by another process": func() error { return other.open("session", value, &got) },
		"expired":                   func() error { return s.open("session", expired, &got) },
		"not base64":                func() error { return s.open("session", "%%%", &got) },
		"too short":                 func() error { return s.open("session", "AAAA", &got) },
	} {
		if err := open(); !errors.Is(err, errCookie) {
			t.Errorf("%s: %v, want errCookie", name, err)
		}
	}
}
