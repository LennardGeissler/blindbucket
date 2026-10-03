package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const repo = "https://github.com/o/r"

const sample = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n" +
	"## [1.1.0] — 2026-10-03\n\n" +
	"A paragraph wrapped\nacross three\nlines, with a [link](docs/adr/ADR-025.md), [another](https://example.com)\nand [a section](#fixed).\n\n" +
	"### Fixed\n\n" +
	"- **An item** that wraps\n  onto a second line, [here](./SECURITY.md).\n- A second item.\n\n" +
	"```sh\nkeep\n  as is\n```\n\n" +
	"| a | b |\n|---|---|\n\n" +
	"## [1.0.0] — 2026-09-27\n\nOlder,\nwrapped.\n\n" +
	"[1.1.0]: https://example.com/compare/v1.0.0...v1.1.0\n[1.0.0]: https://example.com/compare/v0.6.0...v1.0.0\n"

func TestNotes(t *testing.T) {
	got, err := Notes(sample, "v1.1.0", repo+"/")
	if err != nil {
		t.Fatal(err)
	}
	want := "A paragraph wrapped across three lines, with a " +
		"[link](https://github.com/o/r/blob/v1.1.0/docs/adr/ADR-025.md), " +
		"[another](https://example.com) and [a section](#fixed).\n\n" +
		"### Fixed\n\n" +
		"- **An item** that wraps onto a second line, [here](https://github.com/o/r/blob/v1.1.0/SECURITY.md).\n" +
		"- A second item.\n\n" +
		"```sh\nkeep\n  as is\n```\n\n" +
		"| a | b |\n|---|---|"
	if got != want {
		t.Errorf("got:\n%s\n\nwant:\n%s", got, want)
	}
}

// The last section ends at the link definitions, not at the end of the file.
func TestNotesOfTheLastSection(t *testing.T) {
	got, err := Notes(sample, "v1.0.0", repo)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Older, wrapped." {
		t.Errorf("got %q", got)
	}
}

// A tag without a section is an error, so that a release cannot go out with
// no text -- which is how every release before this command went out.
func TestNotesRefusesWhatIsNotThere(t *testing.T) {
	for _, tag := range []string{"v9.9.9", "v1.1", "vUnreleased"} {
		if _, err := Notes(sample, tag, repo); err == nil {
			t.Errorf("%s: rendered notes for a release the changelog does not describe", tag)
		}
	}
}

var (
	release      = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)
	anyLink      = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	standsAlone  = regexp.MustCompile(`^(#|\||>|\s*([-*+]|\d+[.)])\s)`)
	wrappedBreak = func(prev, line string) bool {
		return prev != "" && line != "" && !standsAlone.MatchString(prev) && !standsAlone.MatchString(line)
	}
)

// TestEveryReleaseInTheChangelog renders the real file: every release it
// describes has a section, no paragraph is left broken across lines, and no
// link is left relative to a root a release page does not have.
func TestEveryReleaseInTheChangelog(t *testing.T) {
	raw, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	versions := release.FindAllStringSubmatch(string(raw), -1)
	if len(versions) < 8 {
		t.Fatalf("found %d releases in CHANGELOG.md, want every one from 0.1.0", len(versions))
	}
	for _, v := range versions {
		tag := "v" + v[1]
		notes, err := Notes(string(raw), tag, repo)
		if err != nil {
			t.Errorf("%s: %v", tag, err)
			continue
		}
		lines := strings.Split(notes, "\n")
		for i := 1; i < len(lines); i++ {
			if wrappedBreak(lines[i-1], lines[i]) {
				t.Errorf("%s: a paragraph is still broken before %q", tag, lines[i])
			}
			if strings.HasPrefix(lines[i], "  ") {
				t.Errorf("%s: a list item is still continued on %q", tag, lines[i])
			}
		}
		for _, link := range anyLink.FindAllStringSubmatch(notes, -1) {
			target := link[1]
			if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "#") {
				t.Errorf("%s: relative link %q", tag, target)
			}
		}
	}
}
