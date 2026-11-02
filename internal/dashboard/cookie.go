package dashboard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// errCookie is any cookie that does not open: forged, altered, sealed for
// another cookie or by another process, or expired. The reasons are not told
// apart to a browser; each simply means signing in again.
var errCookie = errors.New("dashboard: the cookie does not open")

// cookieAADPrefix binds a sealed value to the cookie it was sealed for, so
// that one cookie's value cannot be presented as another's.
const cookieAADPrefix = "blindbucket/v1/dashboard-cookie/"

// sealer seals cookie values under a key the process generates when it starts
// and keeps in memory only (ADR-039). A restart ends every session, and each
// instance has its own key.
type sealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

func newSealer(now func() time.Time) (*sealer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &sealer{aead: aead, now: now}, nil
}

// sealed is what a cookie holds once opened: its value and when it ends.
type sealed struct {
	Expires int64           `json:"exp"`
	Value   json.RawMessage `json:"v"`
}

// seal returns v, sealed for the cookie called name until expires, as a
// cookie value: base64url of a random nonce and the AES-256-GCM ciphertext.
func (s *sealer) seal(name string, v any, expires time.Time) (string, error) {
	value, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(sealed{Expires: expires.Unix(), Value: value})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, []byte(cookieAADPrefix+name))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// open reads a value sealed for the cookie called name into v, and refuses
// one that does not open or has expired.
func (s *sealer) open(name, cookie string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(raw) < s.aead.NonceSize()+s.aead.Overhead() {
		return errCookie
	}
	nonce, ciphertext := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, []byte(cookieAADPrefix+name))
	if err != nil {
		return errCookie
	}
	var c sealed
	if err := json.Unmarshal(plain, &c); err != nil {
		return errCookie
	}
	if !s.now().Before(time.Unix(c.Expires, 0)) {
		return errCookie
	}
	if err := json.Unmarshal(c.Value, v); err != nil {
		return errCookie
	}
	return nil
}
