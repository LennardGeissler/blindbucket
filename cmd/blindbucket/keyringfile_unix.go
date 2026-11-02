//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// keepGroup gives a rewritten keyring the group of the file it replaces. It
// is best effort: a user who is not in that group cannot give a file to it,
// and is told so rather than stopped, since the keyring was written.
func keepGroup(tmp string, old os.FileInfo) {
	st, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if err := os.Chown(tmp, -1, int(st.Gid)); err != nil { //nolint:gosec // beside the operator's own keyring.
		fmt.Fprintf(os.Stderr, "warning: the keyring's group could not be kept (%v); check that the "+
			"gateway can still read it\n", err)
	}
}
