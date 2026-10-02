package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"
)

// passphraseEnv names the environment variable a passphrase may be supplied in.
// Secrets are referenced through the environment or a file, never written
// into configuration.
const passphraseEnv = "BLINDBUCKET_PASSPHRASE"

// passphraseFlags are the ways a command can be told where to find the
// passphrase that protects a keyring.
type passphraseFlags struct {
	file string
	// noEnv skips the environment variable. reseal's new passphrase sets it:
	// the variable is where the current one comes from, and taking the same
	// value for both would reseal a keyring under the passphrase it already has
	// while the operator believed it had changed.
	noEnv bool
	// resolved caches the first answer, so that a command asks at most once.
	// See resolve.
	resolved []byte
}

func (p *passphraseFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.file, "passphrase-file", "",
		"read the keyring passphrase from this file (default: $"+passphraseEnv+", else prompt)")
}

// registerNew registers the flag for a passphrase a keyring is about to be
// sealed under, which never comes from the environment.
func (p *passphraseFlags) registerNew(fs *flag.FlagSet) {
	p.noEnv = true
	fs.StringVar(&p.file, "new-passphrase-file", "",
		"read the new passphrase from this file (default: prompt, twice)")
}

// resolve returns the passphrase, asking the terminal only as a last resort.
//
// confirm re-prompts for verification, which matters when the passphrase is
// about to protect newly generated keys: a typo there is unrecoverable.
//
// The first answer is remembered for the rest of the command. A command that
// opens a keyring and then writes it back -- `keygen --add` is one -- would
// otherwise prompt twice, and the second answer, unconfirmed, would silently
// become the new passphrase: a typo there seals the keyring under something
// nobody knows, which loses every object encrypted under it.
//
// The caller gets a copy and may wipe it. The remembered one is wiped by wipe.
func (p *passphraseFlags) resolve(prompt string, confirm bool) ([]byte, error) {
	if p.resolved == nil {
		pass, err := p.read(prompt, confirm)
		if err != nil {
			return nil, err
		}
		p.resolved = pass
	}
	return bytes.Clone(p.resolved), nil
}

// wipe forgets the remembered passphrase. Commands defer it; as everywhere else
// in this program, it narrows the window rather than closing it (ADR-002).
func (p *passphraseFlags) wipe() {
	clear(p.resolved)
	p.resolved = nil
}

// read obtains the passphrase from the first source that has one.
func (p *passphraseFlags) read(prompt string, confirm bool) ([]byte, error) {
	if p.file != "" {
		warnIfExposed("passphrase file", p.file)
		data, err := os.ReadFile(p.file)
		if err != nil {
			return nil, fmt.Errorf("reading the passphrase file: %w", err)
		}
		pass := bytes.TrimRight(data, "\r\n")
		if len(pass) == 0 {
			return nil, fmt.Errorf("the passphrase file %s is empty", p.file)
		}
		return pass, nil
	}

	if !p.noEnv {
		if env := os.Getenv(passphraseEnv); env != "" {
			return []byte(env), nil
		}
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		if p.noEnv {
			return nil, errors.New("no new passphrase available: pass --new-passphrase-file, " +
				"or run on a terminal")
		}
		return nil, fmt.Errorf("no passphrase available: set $%s, pass --passphrase-file, or run on a terminal", passphraseEnv)
	}

	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}

	if confirm {
		fmt.Fprint(os.Stderr, "Repeat passphrase: ")
		again, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pass, again) {
			return nil, errors.New("the two passphrases do not match")
		}
	}
	return pass, nil
}
