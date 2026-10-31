package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"golang.org/x/term"

	"github.com/LennardGeissler/blindbucket/internal/crypto/envelope"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// cryptFlags are shared by encrypt and decrypt.
type cryptFlags struct {
	keyring string
	conf    string
	in      string
	out     string
	pass    passphraseFlags
}

func (c *cryptFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.keyring, "keyring", "", "keyring file (required)")
	fs.StringVar(&c.conf, "config", "",
		"configuration file naming the root-key provider, for a keyring sealed by Vault or KMS")
	fs.StringVar(&c.in, "i", "-", "input file, or - for stdin")
	fs.StringVar(&c.out, "o", "-", "output file, or - for stdout")
	c.pass.register(fs)
}

// loadKeyring opens the keyring these commands were pointed at.
//
// It goes through openFile, as keys list and rotate do, so a keyring
// sealed by Vault Transit or AWS KMS opens here too. Until #46 this called
// keys.LoadKeyring directly with a passphrase, which made the offline commands
// unusable for an operator who had moved their root key to a service: there was
// no flag to name the provider with, and so no way to say how to reach it.
//
// The passphrase path is unchanged and still the default. Without --config,
// keysConfig yields the file provider, which is exactly what a passphrase
// keyring needs.
//
// With tenants (ADR-038) the file opens whole, with every tenant --config's
// keys.tenants can open without a prompt. encrypt wraps under the default
// tenant's active key, as there is no bucket to choose another by; decrypt
// finds the key a file names in whichever tenant holds it.
func (c *cryptFlags) loadKeyring(ctx context.Context) (keys.KeyProvider, error) {
	defer c.pass.wipe()
	if c.keyring == "" {
		return nil, errors.New("--keyring is required")
	}
	if err := c.requireConfigForAService(); err != nil {
		return nil, err
	}

	cfg, err := keysConfig(c.conf, &c.pass)
	if err != nil {
		return nil, err
	}
	// warnIfExposed is openFile's job; calling it here as well would warn
	// twice about the same file.
	f, _, err := openFile(ctx, c.keyring, cfg, &c.pass, openTenants(ctx, cfg))
	if err != nil {
		return nil, err
	}

	// Argon2id deliberately allocates 64 MiB, and that arena is dead the moment
	// the root key exists. Go does not hand freed pages back to the operating
	// system promptly on its own, so without this the process would sit at ~70
	// MiB of resident memory for the whole run and the streaming path's flat
	// memory profile would be invisible behind it. Returning it here is cheap:
	// it happens once, before any data moves.
	debug.FreeOSMemory()

	return fileKeys{Served: keys.NewServed(f), file: f}, nil
}

// fileKeys serves a whole keyring file to encrypt and decrypt, and says whose
// a key is when a file names one this process does not hold.
type fileKeys struct {
	*keys.Served
	file *keys.File
}

// Unwrap implements keys.KeyProvider.
func (k fileKeys) Unwrap(ctx context.Context, kid string, wrapped, aad []byte) ([]byte, error) {
	dek, err := k.Served.Unwrap(ctx, kid, wrapped, aad)
	if errors.Is(err, keys.ErrUnknownKID) {
		if owner, ok := k.file.KIDOwner(kid); ok {
			if t := k.file.Tenant(owner); t != nil {
				return nil, fmt.Errorf("%w: %q is tenant %s's, which did not open here (%v); "+
					"--config's keys.tenants.%s names its lock", err, kid, owner, t.Err, owner)
			}
			return nil, fmt.Errorf("%w: %q was tenant %s's, which is destroyed", err, kid, owner)
		}
	}
	return dek, err
}

// requireConfigForAService refuses a service-sealed keyring with no --config,
// naming the flag that is missing.
//
// Without it the operator in #46 is told `keys.provider is "file"`, which is
// true -- that is the default keysConfig returns -- and names neither the
// provider the keyring actually needs nor the flag that would supply it. These
// two commands are the only ones that can reach openFile with no
// configuration behind them, which is why the check sits here rather than in
// unlock, where it would be dead code for every other caller.
//
// The file is read a second time to do this. That is one small read once per
// invocation, before any data moves, and it buys an error the operator can act
// on; anything cheaper would mean threading the bytes through openFile's
// signature for this one caller.
func (c *cryptFlags) requireConfigForAService() error {
	if c.conf != "" {
		return nil
	}
	data, err := os.ReadFile(c.keyring)
	if err != nil {
		return keyringReadError(c.keyring, err)
	}
	ref, err := keys.ReadRootKeyRef(data)
	if err != nil {
		// Not a keyring this build can read. openFile says so in the words
		// every other command uses, so let it.
		return nil //nolint:nilerr // deliberate: the better message is downstream.
	}
	if ref.Source == keys.SourcePassphrase {
		return nil
	}
	return fmt.Errorf("%s is sealed by %s, not a passphrase; pass --config with a "+
		"configuration naming that provider (keys.provider), as `keys list` takes",
		c.keyring, ref.Source)
}

func runEncrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket encrypt --keyring <file> [flags] < plaintext > ciphertext

Encrypts a stream into a blindbucket file under the keyring's active key.
Memory stays proportional to the chunk size, not to the size of the input.

The keyring opens by whatever sealed it. A passphrase needs no configuration;
for one sealed by Vault Transit or AWS KMS, --config names the provider to ask.

Flags:
`)
		fs.PrintDefaults()
	}

	var c cryptFlags
	c.register(fs)
	log2C := fs.Uint("chunk-size-log2", stream.DefaultLog2ChunkSize,
		fmt.Sprintf("log2 of the chunk size in bytes (%d..%d)", stream.MinLog2ChunkSize, stream.MaxLog2ChunkSize))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *log2C > 255 {
		return fmt.Errorf("--chunk-size-log2 %d is out of range", *log2C)
	}
	if err := stream.ValidateLog2ChunkSize(uint8(*log2C)); err != nil {
		return err
	}

	ring, err := c.loadKeyring(ctx)
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(c.in)
	if err != nil {
		return err
	}
	defer closeSrc()

	dst, finish, err := openOutput(c.out, true)
	if err != nil {
		return err
	}
	if err := envelope.Encrypt(ctx, dst, src, ring, uint8(*log2C)); err != nil {
		return finish(err)
	}
	return finish(nil)
}

func runDecrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket decrypt --keyring <file> [flags] < ciphertext > plaintext

Decrypts a blindbucket file. Nothing is written until the first chunk has been
authenticated, so a wrong key or a damaged file leaves the output untouched.

The keyring opens by whatever sealed it. A passphrase needs no configuration;
for one sealed by Vault Transit or AWS KMS, --config names the provider to ask.

Flags:
`)
		fs.PrintDefaults()
	}

	var c cryptFlags
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ring, err := c.loadKeyring(ctx)
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(c.in)
	if err != nil {
		return err
	}
	defer closeSrc()

	dst, finish, err := openOutput(c.out, false)
	if err != nil {
		return err
	}
	if err := envelope.Decrypt(ctx, dst, src, ring); err != nil {
		return finish(err)
	}
	return finish(nil)
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	//nolint:gosec // the path is a command-line argument; opening it is the point.
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

// openOutput returns the destination and a finish function that must be called
// with the outcome.
//
// For a real file the output is written to a temporary path and only renamed
// into place on success, so a failed run cannot leave a plausible-looking
// truncated file behind.
func openOutput(path string, binaryOut bool) (io.Writer, func(error) error, error) {
	if path == "-" {
		if binaryOut && term.IsTerminal(int(os.Stdout.Fd())) {
			return nil, nil, errors.New("refusing to write binary output to a terminal; use -o or redirect")
		}
		return os.Stdout, func(err error) error { return err }, nil
	}

	// Write-then-rename only makes sense for a regular file. A device or a fifo
	// -- /dev/null being the common case -- has to be written to directly.
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		//nolint:gosec // the path is a command-line argument; opening it is the point.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, nil, err
		}
		return f, func(runErr error) error {
			closeErr := f.Close()
			if runErr != nil {
				return runErr
			}
			return closeErr
		}, nil
	}

	tmp := path + ".tmp"
	//nolint:gosec // the path is a command-line argument; creating it is the point.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	finish := func(runErr error) error {
		closeErr := f.Close()
		if runErr != nil {
			_ = os.Remove(tmp)
			return runErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		return os.Rename(tmp, path)
	}
	return f, finish, nil
}
