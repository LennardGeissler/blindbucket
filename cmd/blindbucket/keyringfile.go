package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A keyring file is the only copy of the keys that protect every object written
// under it, so the two ways it is written are held to what that means.
//
// Atomic: the new bytes go to a temporary file in the same directory and take
// the keyring's name in one rename or link, so a reader -- or a crash -- sees the
// old file or the new one and never half of either.
//
// Durable: the temporary file is synced before it takes the name, and the
// directory after. Without the first, a power cut just after the rename can
// leave a keyring of the right name and no content on filesystems that order
// metadata ahead of data; without the second, the rename itself may not
// survive one.
//
// And for a rewrite, unchanged since it was read. keygen --add, keys remove
// and reseal each open a keyring, change it in memory and write it back; two of
// them running at once would otherwise each write what they read, and the
// second would silently drop what the first added -- a KEK lost is every object
// wrapped under it. The check runs just before the rename, which narrows that
// window to the two calls between them rather than closing it; a lock would
// close it at the price of a lock file that a crash leaves behind, and that is
// a failure a keyring operation should not have.

// errKeyringChanged refuses to replace a keyring that changed since it was read.
var errKeyringChanged = errors.New("the keyring changed on disk since this command read it, " +
	"probably by another keygen, keys or reseal run; nothing was written -- run it again")

// createKeyringFile writes a new keyring, refusing to replace one that exists.
//
// The check is the link itself rather than a stat before it: a link onto an
// existing name fails, where a rename would replace it, so a keyring that
// appears between the caller's check and this write is still not clobbered.
func createKeyringFile(path string, data []byte) error {
	tmp, err := writeTemp(path, data)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (use --add to add a key to it)", path)
		}
		return err
	}
	return syncDir(path)
}

// replaceKeyring writes a rewritten keyring over the one that was read as
// opened, unless the file no longer holds exactly that.
func replaceKeyring(path string, opened, data []byte) error {
	tmp, err := writeTemp(path, data)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()

	//nolint:gosec // the path is the operator's own keyring.
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, opened) {
		return fmt.Errorf("%s: %w", path, errKeyringChanged)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	renamed = true
	return syncDir(path)
}

// writeTemp writes data to a new file beside path, mode 0600, synced.
//
// The name is unique per call, so two commands writing the same keyring never
// share a temporary file; and it starts with the keyring's own name, so one a
// crash leaves behind is recognisable as what it is.
func writeTemp(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	// CreateTemp already uses 0600; stated rather than relied on, because a
	// world-readable keyring defeats the passphrase.
	if err := f.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// syncDir makes a rename or link in path's directory durable.
func syncDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
