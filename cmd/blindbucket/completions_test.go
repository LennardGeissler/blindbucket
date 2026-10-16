package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The completion scripts are written by hand (#12), so nothing updates them
// when a command or a flag is added. These tests are what notices: they read
// the commands, subcommands and flags from the CLI itself -- commands() and
// each command's -h -- and require every script to offer exactly those.
//
// bash and fish are asked what they complete, the way a shell would on Tab.
// zsh's completion system cannot run outside an interactive shell, so its
// script is read instead, one command's branch at a time. A shell that is not
// installed is skipped; CI installs all three.

const completionsDir = "../../contrib/completions"

var (
	helpFlagLine   = regexp.MustCompile(`(?m)^  -([A-Za-z0-9-]+)`)
	subcommandLine = regexp.MustCompile(`^  ([a-z]+) {2,}\S`)
)

// commandPaths lists every command with its subcommand, if it has any: "init",
// "keys list". A command has subcommands when its -h says so.
func commandPaths(t *testing.T) [][]string {
	t.Helper()
	var paths [][]string
	for _, c := range commands() {
		subs := subcommandsOf(t, c.name)
		if len(subs) == 0 {
			paths = append(paths, []string{c.name})
		}
		for _, sub := range subs {
			paths = append(paths, []string{c.name, sub})
		}
	}
	return paths
}

// subcommandsOf reads the Subcommands section of a command's -h.
func subcommandsOf(t *testing.T, command string) []string {
	t.Helper()
	_, stderr, _ := runCLI(t, command, "-h")
	_, section, ok := strings.Cut(stderr, "\nSubcommands:\n")
	if !ok {
		return nil
	}
	var subs []string
	for _, line := range strings.Split(section, "\n") {
		if line == "" {
			break
		}
		if m := subcommandLine.FindStringSubmatch(line); m != nil {
			subs = append(subs, m[1])
		}
	}
	return subs
}

// helpFlags returns the flags a command's -h lists, spelled the way the
// scripts offer them: -i for a one-letter flag, --name for the rest. Go's flag
// package takes either spelling of either.
func helpFlags(t *testing.T, path []string) []string {
	t.Helper()
	_, stderr, _ := runCLI(t, append(slices.Clone(path), "-h")...)
	var flags []string
	for _, m := range helpFlagLine.FindAllStringSubmatch(stderr, -1) {
		if len(m[1]) == 1 {
			flags = append(flags, "-"+m[1])
		} else {
			flags = append(flags, "--"+m[1])
		}
	}
	return sorted(flags)
}

func commandNames() []string {
	names := []string{"help"}
	for _, c := range commands() {
		names = append(names, c.name)
	}
	return sorted(names)
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

func requireShell(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return path
}

func assertSame(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n  offered %v\n  but -h lists %v", what, got, want)
	}
}

// bashCompletes asks the bash script what it offers for words, the last of
// which is the word being completed.
func bashCompletes(t *testing.T, bash string, words ...string) []string {
	t.Helper()
	driver := filepath.Join(t.TempDir(), "driver.bash")
	script := `source "$1"; shift
COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
_blindbucket
printf '%s\n' "${COMPREPLY[@]}"
`
	if err := os.WriteFile(driver, []byte(script), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	args := append([]string{driver, filepath.Join(completionsDir, "blindbucket.bash"), "blindbucket"}, words...)
	out, err := exec.CommandContext(t.Context(), bash, args...).Output() //nolint:gosec // the test's own script.
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	return sorted(strings.Fields(string(out)))
}

func TestCompletionsBash(t *testing.T) {
	bash := requireShell(t, "bash")
	assertSame(t, "commands", bashCompletes(t, bash, ""), commandNames())
	for _, path := range commandPaths(t) {
		if len(path) == 2 {
			assertSame(t, path[0]+" subcommands", bashCompletes(t, bash, path[0], ""),
				sorted(subcommandsOf(t, path[0])))
		}
		words := append(slices.Clone(path), "-")
		assertSame(t, strings.Join(path, " ")+" flags", bashCompletes(t, bash, words...), helpFlags(t, path))
	}

	// Values, in either spelling of the flag.
	assertSame(t, "--keys-provider", bashCompletes(t, bash, "init", "--keys-provider", ""),
		sorted([]string{"file", "vault", "awskms"}))
	assertSame(t, "-credential-source", bashCompletes(t, bash, "init", "-credential-source", "w"),
		[]string{"web_identity"})
	// A path, from the files that are there.
	assertSame(t, "--config", bashCompletes(t, bash, "doctor", "--config", filepath.Join(completionsDir, "blindbucket.b")),
		[]string{filepath.Join(completionsDir, "blindbucket.bash")})
}

// fishCompletes asks fish what it offers for line, as Tab at its end would.
func fishCompletes(t *testing.T, fish, line string) []string {
	t.Helper()
	//nolint:gosec // a fixed script; line is the test's own.
	out, err := exec.CommandContext(t.Context(), fish, "--no-config", "-c",
		`source $argv[1]; complete -C $argv[2]`,
		filepath.Join(completionsDir, "blindbucket.fish"), line).Output()
	if err != nil {
		t.Fatalf("fish: %v", err)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if word, _, _ := strings.Cut(l, "\t"); word != "" {
			got = append(got, word)
		}
	}
	return sorted(got)
}

func TestCompletionsFish(t *testing.T) {
	fish := requireShell(t, "fish")
	assertSame(t, "commands", fishCompletes(t, fish, "blindbucket "), commandNames())
	for _, path := range commandPaths(t) {
		line := "blindbucket " + strings.Join(path, " ")
		if len(path) == 2 {
			assertSame(t, path[0]+" subcommands", fishCompletes(t, fish, "blindbucket "+path[0]+" "),
				sorted(subcommandsOf(t, path[0])))
		}
		assertSame(t, line+" flags", fishCompletes(t, fish, line+" -"), helpFlags(t, path))
	}
	assertSame(t, "--keys-provider", fishCompletes(t, fish, "blindbucket init --keys-provider "),
		sorted([]string{"file", "vault", "awskms"}))
}

var (
	zshSpecFlag  = regexp.MustCompile(`['"](--?[A-Za-z0-9-]+)\[`)
	zshListEntry = regexp.MustCompile(`^\s*['"]([a-z-]+):`)
)

// zshBranch returns the lines of the case branch for command in the zsh
// script, from its pattern line to the ;; that ends it, and whether there is
// one: a command without flags needs none.
func zshBranch(script, command string) (string, bool) {
	pattern := command + ")"
	if strings.Contains(command, " ") {
		pattern = "'" + command + "')"
	}
	var branch []string
	in := false
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !in && trimmed == pattern:
			in = true
		case in && trimmed == ";;":
			return strings.Join(branch, "\n"), true
		case in:
			branch = append(branch, line)
		}
	}
	return "", false
}

// zshListed returns the names in a zsh array of name:description entries,
// from the line that opens it to the one that closes it.
func zshListed(script, opener string) []string {
	var names []string
	_, rest, _ := strings.Cut(script, opener)
	for _, line := range strings.Split(rest, "\n") {
		if m := zshListEntry.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
		if strings.Contains(line, ")") && !strings.Contains(line, "'") && !strings.Contains(line, `"`) {
			break
		}
		if strings.HasSuffix(strings.TrimSpace(line), ") ;;") {
			break
		}
	}
	return sorted(names)
}

func TestCompletionsZsh(t *testing.T) {
	zsh := requireShell(t, "zsh")
	path := filepath.Join(completionsDir, "_blindbucket")
	if out, err := exec.CommandContext(t.Context(), zsh, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("zsh -n: %v\n%s", err, out)
	}
	data, err := os.ReadFile(path) //nolint:gosec // a file in this repository.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	script := string(data)

	assertSame(t, "commands", zshListed(script, "commands=("), commandNames())
	for _, p := range commandPaths(t) {
		if len(p) == 2 {
			assertSame(t, p[0]+" subcommands", zshListed(script, p[0]+") subcommands=("),
				sorted(subcommandsOf(t, p[0])))
		}
		branch, ok := zshBranch(script, strings.Join(p, " "))
		want := helpFlags(t, p)
		if !ok && len(want) > 0 {
			t.Errorf("the zsh script has no branch for %q, which has flags", strings.Join(p, " "))
			continue
		}
		var got []string
		for _, m := range zshSpecFlag.FindAllStringSubmatch(branch, -1) {
			got = append(got, m[1])
		}
		assertSame(t, strings.Join(p, " ")+" flags", sorted(got), want)
	}
}
