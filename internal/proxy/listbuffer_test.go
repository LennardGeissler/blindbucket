package proxy

import (
	"encoding/base64"
	"testing"
)

func TestCursorRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "ascii key",
			key:  "photos/2026/image.jpg",
		},
		{
			name: "multi-byte utf8 key with slash",
			key:  "dokumente/münchen/café/世界.png",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := encodeCursor(tc.key)
			gotKey, err := decodeCursor(token)
			if err != nil {
				t.Fatalf("decodeCursor(%q) failed: %v", token, err)
			}
			if gotKey != tc.key {
				t.Errorf("round trip mismatch: got %q, want %q", gotKey, tc.key)
			}
		})
	}
}

func TestCursorRefusal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{
			name:  "padded base64 with single padding char",
			token: base64.StdEncoding.EncodeToString([]byte("test")), // "dGVzdA==" has padding
		},
		{
			name:  "padded base64 with two padding chars",
			token: base64.StdEncoding.EncodeToString([]byte("a")), // "YQ==" has padding
		},
		{
			name:  "standard base64 using plus character",
			token: "abc+def",
		},
		{
			name:  "standard base64 using slash character",
			token: "abc/def",
		},
		{
			name:  "token with non-base64 characters",
			token: "invalid!token@value#",
		},
		{
			name:  "token with whitespace",
			token: "abc def",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := decodeCursor(tc.token)
			if err == nil {
				t.Fatalf("decodeCursor(%q) succeeded with %q, expected error", tc.token, gotKey)
			}
			if err.Code != "InvalidArgument" {
				t.Errorf("decodeCursor(%q) code = %q, want %q", tc.token, err.Code, "InvalidArgument")
			}
		})
	}
}
