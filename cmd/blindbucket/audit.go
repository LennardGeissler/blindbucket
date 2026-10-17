package main

import (
	"encoding/json"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

func runAudit(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return auditUsage()
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(ctx, args[1:])
	case "pubkey":
		return runAuditPubkey(ctx, args[1:])
	case "-h", "--help", "help":
		return auditUsage()
	}
	return fmt.Errorf("unknown audit subcommand %q (try `blindbucket audit help`)", args[0])
}

func auditUsage() error {
	_, _ = fmt.Fprint(os.Stderr, `Usage: blindbucket audit <subcommand> [flags]

Subcommands:
  verify    check a log's hash chain and checkpoint signatures
  pubkey    print the public key a verifier needs, so it can be recorded
            somewhere the gateway host cannot reach

Run "blindbucket audit <subcommand> -h" for a subcommand's flags.
`)
	return errUsage
}

func runAuditPubkey(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit pubkey", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket audit pubkey --keyring <file> [flags]

Prints the Ed25519 public key that verifies this keyring's audit log.

Record the value somewhere the gateway host does not control, and verify logs
against that copy rather than against the keyring on the same machine. A log
checked against a key taken from the file an attacker would also have edited
proves only that the two agree.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		keyring = fs.String("keyring", "", "keyring file (required)")
		conf    = fs.String("config", "", "configuration file naming the root-key provider")
		open    = fs.Bool("open", false,
			"open the keyring and derive the key, instead of reading the recorded one")
		pass passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	if *keyring == "" {
		fs.Usage()
		return errors.New("--keyring is required")
	}

	// Two ways to answer, and they are not equivalent. Reading the recorded key
	// needs no secret but trusts the file; opening the keyring re-derives the
	// key from the secret and proves the recorded one belongs to it.
	if *open {
		keysCfg, err := keysConfig(*conf, &pass)
		if err != nil {
			return err
		}
		ring, err := openKeyring(ctx, *keyring, keysCfg, &pass)
		if err != nil {
			return err
		}
		key, ok := ring.AuditKey()
		if !ok {
			return noAuditKey(*keyring)
		}
		pub, err := key.Public()
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	}

	//nolint:gosec // the path is a command-line argument.
	data, err := os.ReadFile(*keyring)
	if err != nil {
		return err
	}
	pub, err := keys.PublicAuditKey(data)
	if errors.Is(err, keys.ErrNoAuditKey) {
		return noAuditKey(*keyring)
	} else if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

func noAuditKey(path string) error {
	return fmt.Errorf("%s has no audit key; add one with "+
		"`blindbucket keygen --out %s --add-audit-key`", path, path)
}

func runAuditVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket audit verify <log> [<log> ...] [flags]

Checks that a log is the one that was written: every entry hashes onto the one
before it, and every checkpoint carries a signature from the audit key. Rotated
files given together are checked as one chain, in the order their heads say they
belong in.

A log verifies against a public key alone -- no keyring, no passphrase, nothing
that could also write one. Pass --keyring instead to additionally decrypt the
object names, which does need the keyring.

With neither, the chain is still checked but the signatures are not, and the
output says so. That answers "has this file been edited", not "did this gateway
write it".

What verification cannot see is entries removed from the end after the last
checkpoint. --expect pins a checkpoint recorded elsewhere and closes that gap.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		pubFlag = fs.String("public-key", "",
			"base64 Ed25519 public key, or a file containing one")
		keyring = fs.String("keyring", "",
			"keyring file: verifies, and decrypts the object names")
		conf   = fs.String("config", "", "configuration file naming the root-key provider")
		expect = fs.String("expect", "",
			"require the chain to reach at least this checkpoint, as <seq>:<hash>")
		list = fs.Bool("print", false, "print every entry")
		asJSON = fs.Bool("json", false, "print the result as JSON")
		pass passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	paths := fs.Args()
	if len(paths) == 0 {
		fs.Usage()
		return errors.New("name at least one log file")
	}

	pub, coder, err := auditVerifyKeys(ctx, *pubFlag, *keyring, *conf, &pass)
	if err != nil {
		return err
	}

	ordered, err := orderLogs(paths)
	if err != nil {
		return err
	}

	files := make([]audit.NamedReader, 0, len(ordered))
	for _, path := range ordered {
		//nolint:gosec // the path is a command-line argument.
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck // read-only.
		files = append(files, audit.NamedReader{Name: path, Reader: file})
	}

	var seen []seenCheckpoint
	results, err := audit.VerifyChain(files, audit.VerifyOptions{
		PublicKey: pub,
		OnEntry:   entryPrinter(*list, coder),
		OnCheckpoint: func(chain string, point *audit.Checkpoint) error {
			seen = append(seen, seenCheckpoint{chain: chain, seq: point.Seq, hash: point.Hash})
			return nil
		},
	})
	if err != nil {
		// What verified before the break is still worth printing -- it says
		// where the log stops being trustworthy -- but the verdict must not be.
		reportAudit(ordered, results, pub != nil, false, *asJSON)
		return err
	}
	reportAudit(ordered, results, pub != nil, true, *asJSON)

	if *expect != "" {
		if err := checkExpected(*expect, seen, pub != nil); err != nil {
			return err
		}
	}
	return nil
}

// seenCheckpoint is one verified checkpoint, kept so that --expect can be
// compared against every one of them rather than only the newest.
type seenCheckpoint struct {
	chain string
	seq   uint64
	hash  string
}

// auditVerifyKeys resolves what was asked for into a public key and, if the
// keyring was given, a decrypter for the names.
func auditVerifyKeys(
	ctx context.Context, pubFlag, keyring, conf string, pass *passphraseFlags,
) (ed25519.PublicKey, *names.Encrypter, error) {
	switch {
	case pubFlag != "" && keyring != "":
		return nil, nil, errors.New("pass either --public-key or --keyring, not both")

	case pubFlag != "":
		pub, err := parsePublicKey(pubFlag)
		return pub, nil, err

	case keyring != "":
		keysCfg := config.Keys{Provider: "file"}
		if conf != "" {
			cfg, err := config.Load(conf)
			if err != nil {
				return nil, nil, err
			}
			keysCfg = cfg.Keys
			if pass.file == "" {
				pass.file = keysCfg.PassphraseFile
			}
		}
		ring, err := openKeyring(ctx, keyring, keysCfg, pass)
		if err != nil {
			return nil, nil, err
		}
		key, ok := ring.AuditKey()
		if !ok {
			return nil, nil, noAuditKey(keyring)
		}
		pub, err := key.Public()
		if err != nil {
			return nil, nil, err
		}
		nameKey, err := key.NameKey()
		if err != nil {
			return nil, nil, err
		}
		coder, err := names.New(nameKey)
		if err != nil {
			return nil, nil, err
		}
		return pub, coder, nil
	}
	return nil, nil, nil
}

// parsePublicKey accepts the key itself or the path to a file holding it.
func parsePublicKey(value string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(value)
	if data, err := os.ReadFile(value); err == nil { //nolint:gosec // a command-line argument.
		raw = strings.TrimSpace(string(data))
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("--public-key is neither valid base64 nor a readable file: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--public-key is %d bytes, want %d",
			len(decoded), ed25519.PublicKeySize)
	}
	return decoded, nil
}

// orderLogs puts rotated files in the order their heads say they belong in.
//
// Filenames are a hint and nothing more: they can be renamed, and an operator
// passing a shell glob has no way to know that the live file sorts before its
// own archives. The head of each file records the chain it continues, and that
// is covered by the head's hash -- so the links are what the order is built
// from, and a set of files that does not form one chain is reported as such
// rather than silently verified in the wrong order.
func orderLogs(paths []string) ([]string, error) {
	if len(paths) == 1 {
		return paths, nil
	}

	type entry struct {
		path string
		head *audit.Head
	}
	byChain := make(map[string]entry, len(paths))
	for _, path := range paths {
		//nolint:gosec // the path is a command-line argument.
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		head, err := audit.ReadHead(file)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if existing, clash := byChain[head.Chain]; clash {
			return nil, fmt.Errorf("%s and %s are both chain %s",
				existing.path, path, head.Chain)
		}
		byChain[head.Chain] = entry{path: path, head: head}
	}

	// The first file of what was given is the one whose predecessor is not
	// among them, which covers both the true start of a chain and a verification
	// of only the recent part of one.
	var starts []string
	for chain, e := range byChain {
		if _, present := byChain[e.head.PrevChain]; !present {
			starts = append(starts, chain)
		}
	}
	sort.Strings(starts)
	if len(starts) != 1 {
		return nil, fmt.Errorf("the %d files given do not form one chain: %d of them "+
			"continue nothing that was given", len(paths), len(starts))
	}

	next := make(map[string]string, len(byChain))
	for chain, e := range byChain {
		if e.head.PrevChain != "" {
			next[e.head.PrevChain] = chain
		}
	}
	ordered := make([]string, 0, len(paths))
	for chain := starts[0]; chain != ""; chain = next[chain] {
		ordered = append(ordered, byChain[chain].path)
	}
	if len(ordered) != len(paths) {
		return nil, fmt.Errorf("the files given do not form one chain: %d of %d are reachable",
			len(ordered), len(paths))
	}
	return ordered, nil
}

// entryPrinter renders entries as they verify, decrypting names when it can.
func entryPrinter(enabled bool, coder *names.Encrypter) func(*audit.Entry) error {
	if !enabled {
		return nil
	}
	return func(e *audit.Entry) error {
		bucket, key := e.Bucket, e.Key
		if coder != nil {
			bucket, key = decodeName(coder, bucket), decodeName(coder, key)
		}
		who := e.Client
		if who == "" && e.Principal != "" {
			who = e.Principal + " (rejected)"
		}
		fmt.Printf("%6d  %s  %-24s %-3d %-16s %s/%s",
			e.Seq, e.Time, e.Op, e.Status, who, bucket, key)
		if e.Code != "" {
			fmt.Printf("  [%s]", e.Code)
		}
		if e.Bytes > 0 {
			fmt.Printf("  %d bytes", e.Bytes)
		}
		fmt.Println()
		return nil
	}
}

// decodeName reverses one encrypted name, leaving anything it cannot read as it
// stands rather than pretending to have read it.
func decodeName(coder *names.Encrypter, value string) string {
	if value == "" {
		return ""
	}
	plain, err := coder.DecryptKey(value)
	if err != nil {
		return value
	}
	return plain
}

// reportAudit prints what each file verified to, and the verdict.
//
// The verdict is passed in rather than inferred from the results, because the
// results of a failed run are the part that verified before the break. Printing
// "verified" under them would be the single most misleading thing this command
// could do.
func reportAudit(paths []string, results []*audit.Result, signaturesChecked, ok bool, asJSON bool) {
	if asJSON {
		type fileReport struct {
			File            string     `json:"file"`
			Chain           string     `json:"chain"`
			Entries         int        `json:"entries"`
			Checkpoints     int        `json:"checkpoints"`
			SignedThrough   int        `json:"signed_through"`
			EntriesPastLast int        `json:"entries_past_last_checkpoint"`
			TornTail        bool       `json:"torn_tail"`
			LastCheckpoint  any        `json:"last_checkpoint"`
			First           *time.Time `json:"first,omitempty"`
			Last            *time.Time `json:"last,omitempty"`
		}
		files := make([]fileReport, 0, len(results))
		signed := 0
		for i, result := range results {
			var last any
			if point := result.LastCheckpoint; point != nil {
				last = map[string]any{"seq": point.Seq, "hash": point.Hash}
			}
			past := 0
			if signaturesChecked && result.Entries-result.SignedThrough > 0 {
				past = result.Entries - result.SignedThrough
			}
			signed += result.Checkpoints
			files = append(files, fileReport{
				File:            filepath.Base(paths[i]),
				Chain:           result.Chain,
				Entries:         result.Entries,
				Checkpoints:     result.Checkpoints,
				SignedThrough:   result.SignedThrough,
				EntriesPastLast: past,
				TornTail:        result.TornTail,
				LastCheckpoint:  last,
				First:           result.First,
				Last:            result.Last,
			})
		}
		verdict := "verified"
		switch {
		case !ok:
			verdict = "not_verified"
		case !signaturesChecked:
			verdict = "chain_intact_signatures_not_checked"
		case signed == 0:
			verdict = "chain_intact_nothing_signed"
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":                 ok,
			"verdict":            verdict,
			"signatures_checked": signaturesChecked,
			"files":              files,
		})
		return
	}

	var signed int
	for i, result := range results {
		name := filepath.Base(paths[i])
		fmt.Printf("%s: chain %s, %d entries", name, result.Chain, result.Entries)
		if result.Entries > 0 {
			fmt.Printf(", %s to %s",
				result.First.Format(time.RFC3339), result.Last.Format(time.RFC3339))
		}
		fmt.Println()

		if result.TornTail {
			fmt.Printf("  the final record is cut off mid-write, which is what a crash " +
				"between checkpoints looks like\n")
		}
		signed += result.Checkpoints
		if point := result.LastCheckpoint; point != nil {
			fmt.Printf("  last checkpoint: %d:%s\n", point.Seq, point.Hash)
		}
		if unsigned := result.Entries - result.SignedThrough; signaturesChecked && unsigned > 0 {
			fmt.Printf("  %d entries past the last checkpoint are chained but not signed, "+
				"and could have been removed without trace\n", unsigned)
		}
	}

	fmt.Println()
	if !ok {
		fmt.Println("NOT VERIFIED. What is printed above is what held up to the point " +
			"the check failed; the reason follows.")
		return
	}
	switch {
	case !signaturesChecked:
		fmt.Println("SIGNATURES NOT CHECKED. The chain is intact, which means the file has " +
			"not been edited in place.")
		fmt.Println("It does not mean this gateway wrote it: without a public key, a log " +
			"forged end to end verifies too.")
		fmt.Println("Pass --public-key to check that as well.")
	case signed == 0:
		// A log with no checkpoint at all is chained and wholly unsigned. Saying
		// "signatures verified" of zero signatures would be true and useless.
		fmt.Println("CHAIN INTACT, BUT NOTHING IS SIGNED: this log contains no checkpoint, " +
			"so none of it")
		fmt.Println("is covered by the audit key. Entries could have been removed from the " +
			"end without trace.")
	default:
		fmt.Println("chain and signatures verified")
	}
}

// checkExpected compares the verified chain against a checkpoint recorded
// elsewhere.
//
// This is what closes the truncation window of ADR-016. A file cannot show that
// entries were cut from its end, but it cannot agree with a checkpoint it no
// longer reaches either -- so the comparison is with something the attacker did
// not hold.
func checkExpected(expect string, seen []seenCheckpoint, signaturesChecked bool) error {
	if !signaturesChecked {
		return errors.New("--expect needs --public-key or --keyring: comparing against a " +
			"checkpoint means nothing if the checkpoints in the file were never verified")
	}
	seqText, hash, ok := strings.Cut(expect, ":")
	if !ok {
		return fmt.Errorf("--expect must be <seq>:<hash>, got %q", expect)
	}
	var seq uint64
	if _, err := fmt.Sscanf(seqText, "%d", &seq); err != nil {
		return fmt.Errorf("--expect: %q is not a sequence number", seqText)
	}

	// Matched on the hash rather than on position. A chain hash is unique to the
	// exact sequence of entries that produced it, so finding one is proof the
	// log passed through that state -- across a rotation too, where sequence
	// numbers restart per file and would otherwise be ambiguous.
	for _, point := range seen {
		if point.seq != seq {
			continue
		}
		if point.hash == hash {
			fmt.Printf("matches the checkpoint recorded elsewhere: %s at %d:%s\n",
				point.chain, seq, hash)
			return nil
		}
		return fmt.Errorf("a checkpoint at entry %d exists in chain %s, but its hash is "+
			"%s where the one recorded elsewhere says %s: this is not the same log",
			seq, point.chain, point.hash, hash)
	}
	return fmt.Errorf("none of the files given contains the checkpoint recorded elsewhere "+
		"(entry %d); entries have been removed from the end, or a file is missing", seq)
}
