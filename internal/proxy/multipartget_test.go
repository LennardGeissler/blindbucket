package proxy

import (
	"testing"
)

func TestPartCountFromETag(t *testing.T) {
	for _, tc := range []struct {
		name      string
		etag      string
		wantCount int64
		wantOK    bool
	}{
		{
			name:      "quoted multipart etag",
			etag:      `"abc-3"`,
			wantCount: 3,
			wantOK:    true,
		},
		{
			name:      "unquoted multipart etag",
			etag:      "abc-3",
			wantCount: 3,
			wantOK:    true,
		},
		{
			name:      "minimum valid part count",
			etag:      "-1",
			wantCount: 1,
			wantOK:    true,
		},
		{
			name:      "hash with part count 1",
			etag:      `"hash-1"`,
			wantCount: 1,
			wantOK:    true,
		},
		{
			name:      "maximum valid part count",
			etag:      "-10000",
			wantCount: 10000,
			wantOK:    true,
		},
		{
			name:      "hash with part count 10000",
			etag:      `"hash-10000"`,
			wantCount: 10000,
			wantOK:    true,
		},
		{
			name:      "zero part count is refused",
			etag:      "-0",
			wantCount: 0,
			wantOK:    false,
		},
		{
			name:      "part count past stream.MaxParts is refused",
			etag:      "-10001",
			wantCount: 0,
			wantOK:    false,
		},
		{
			name:      "non-numeric suffix is refused",
			etag:      "-x",
			wantCount: 0,
			wantOK:    false,
		},
		{
			name:      "empty suffix after dash is refused",
			etag:      "-",
			wantCount: 0,
			wantOK:    false,
		},
		{
			name:      "negative part count is refused",
			etag:      "hash--1",
			wantCount: 0,
			wantOK:    false,
		},
		{
			name:      "etag with no dash is not multipart",
			etag:      `"d41d8cd98f00b204e9800998ecf8427e"`,
			wantCount: 0,
			wantOK:    false,
		},
		{
			name:      "empty etag is not multipart",
			etag:      "",
			wantCount: 0,
			wantOK:    false,
		},
		{
			// The count is what follows the first dash. A real multipart
			// ETag's hash has no dash in it, so an ETag that does is not
			// read as multipart: a read of it fails rather than guessing.
			name:      "a hash with a dash in it is not read as multipart",
			etag:      `"abc-def-3"`,
			wantCount: 0,
			wantOK:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotCount, gotOK := partCountFromETag(tc.etag)
			if gotOK != tc.wantOK || gotCount != tc.wantCount {
				t.Errorf("partCountFromETag(%q) = (%d, %v), want (%d, %v)",
					tc.etag, gotCount, gotOK, tc.wantCount, tc.wantOK)
			}
		})
	}
}
