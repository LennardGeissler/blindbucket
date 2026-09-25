// Command blindbucket is the CLI for the blindbucket S3 encryption gateway.
//
// It runs the gateway (serve), manages keyrings (keygen, rotate), removes
// orphaned multipart manifests (gc), measures what a provider does with
// conditional writes (probe), verifies the audit log (audit), and
// encrypts or decrypts a stream against a keyring with no provider in the way
// (encrypt, decrypt) -- exercising exactly the code the proxy uses for object
// bodies. The wire format and the decisions behind it are in docs/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is overwritten at release time via -ldflags.
var version = "dev"

// command is one subcommand of the CLI.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

func commands() []command {
	return []command{
		{"serve", "run the S3 gateway", runServe},
		{"keygen", "create a keyring, or add a key to an existing one", runKeygen},
		{"keys", "list the keys in a keyring, or retire one", runKeys},
		{"gc", "remove orphaned multipart manifests", runGC},
		{"rotate", "re-wrap data keys under a new KEK", runRotate},
		{"probe", "measure the provider's conditional writes", runProbe},
		{"audit", "verify the audit log, or print the key that verifies it", runAudit},
		{"encrypt", "encrypt a stream into a blindbucket file", runEncrypt},
		{"decrypt", "decrypt a blindbucket file", runDecrypt},
		{"version", "print the version and exit", runVersion},
	}
}

// errUsage asks main to print usage and exit with the conventional code 2.
var errUsage = errors.New("usage")

func main() { os.Exit(mainCode()) }

// mainCode holds every exit path, so that the signal handler's cleanup is not
// skipped by an os.Exit somewhere in the middle.
func mainCode() int {
	// Ctrl-C cancels the context, which aborts an in-flight stream. A partially
	// written output is never a valid file, because the final chunk is only
	// written on a clean close.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := run(ctx, os.Args[1:])
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		usage(os.Stderr)
		return 2
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "blindbucket: interrupted")
		return 130
	case errors.Is(err, flag.ErrHelp):
		return 2
	default:
		fmt.Fprintln(os.Stderr, "blindbucket:", err)
		return 1
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	case "-v", "--version":
		return runVersion(ctx, nil)
	}

	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(ctx, args[1:])
		}
	}
	return fmt.Errorf("unknown command %q (try `blindbucket help`)", args[0])
}

func runVersion(context.Context, []string) error {
	fmt.Println(version)
	return nil
}

func usage(w *os.File) {
	_, _ = fmt.Fprintf(w, "blindbucket %s - transparent S3 encryption gateway\n\n", version)
	_, _ = fmt.Fprintf(w, "Usage:\n  blindbucket <command> [flags]\n\nCommands:\n")
	for _, c := range commands() {
		_, _ = fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
	}
	_, _ = fmt.Fprintf(w, "\nRun `blindbucket <command> -h` for a command's flags.\n")
}
