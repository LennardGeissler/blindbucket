// Command releasenotes prints one release's section of CHANGELOG.md as the
// text of its GitHub release.
//
//	releasenotes [-changelog CHANGELOG.md] [-repo URL] v1.1.0 > notes.md
//
// CHANGELOG.md is the one place a release is described, and goreleaser's own
// changelog -- a list of commit subjects -- is not used; the release workflow
// passes this command's output to goreleaser as the release notes. Two things
// keep the section from going in as it stands. GitHub renders every newline in
// a release body as a line break, and the file is wrapped at eighty columns, so
// each paragraph and list item is joined back into one line. And its links are
// relative to the repository's root, which a release page is not, so each one
// becomes a link to the file as it was at the release's tag.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	changelog := flag.String("changelog", "CHANGELOG.md", "the changelog to read")
	repo := flag.String("repo", "https://github.com/LennardGeissler/blindbucket",
		"the repository relative links point into")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: releasenotes [-changelog FILE] [-repo URL] <tag>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*changelog)
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasenotes:", err)
		os.Exit(1)
	}
	notes, err := Notes(string(raw), flag.Arg(0), *repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasenotes:", err)
		os.Exit(1)
	}
	fmt.Println(notes)
}

// Notes renders the section of the release tagged tag.
func Notes(changelog, tag, repo string) (string, error) {
	body, err := section(changelog, strings.TrimPrefix(tag, "v"))
	if err != nil {
		return "", err
	}
	return absolute(unwrap(body), strings.TrimSuffix(repo, "/"), tag), nil
}

var (
	// linkDefinition is a reference-style link definition; the compare links
	// at the end of the file are these.
	linkDefinition = regexp.MustCompile(`^\[[^\]]+\]: \S`)
	listItem       = regexp.MustCompile(`^\s*([-*+]|\d+[.)])\s`)
	inlineLink     = regexp.MustCompile(`\]\(([^)\s]+)\)`)
)

// section returns what stands between the heading of version and the next
// release's heading, or the link definitions that end the file. The heading
// itself is left out: a release page has the tag for a title and its own date.
func section(changelog, version string) (string, error) {
	lines := strings.Split(changelog, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "## ["+version+"]") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", fmt.Errorf("CHANGELOG.md has no section for %s", version)
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## [") || linkDefinition.MatchString(lines[i]) {
			end = i
			break
		}
	}
	body := strings.TrimSpace(strings.Join(lines[start:end], "\n"))
	if body == "" {
		return "", fmt.Errorf("the CHANGELOG.md section for %s is empty", version)
	}
	return body, nil
}

// unwrap joins the lines of each paragraph and list item into one. What has a
// meaning line by line -- headings, table rows, quotes, fenced code -- is left
// as it is.
func unwrap(markdown string) string {
	var out []string
	fenced := false
	// open says whether the last line written is text a following line
	// continues: a paragraph's or a list item's.
	open := false
	for _, line := range strings.Split(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			fenced = !fenced
			out = append(out, line)
			open = false
		case fenced:
			out = append(out, line)
		case trimmed == "":
			out = append(out, "")
			open = false
		case strings.HasPrefix(trimmed, "#"), strings.HasPrefix(trimmed, "|"),
			strings.HasPrefix(trimmed, ">"):
			out = append(out, line)
			open = false
		case listItem.MatchString(line):
			out = append(out, strings.TrimRight(line, " "))
			open = true
		case open:
			out[len(out)-1] += " " + trimmed
		default:
			out = append(out, trimmed)
			open = true
		}
	}
	return strings.Join(out, "\n")
}

// absolute points every relative link at the file as it was at tag. Links
// with a scheme and links within the page stay as they are.
func absolute(markdown, repo, tag string) string {
	return inlineLink.ReplaceAllStringFunc(markdown, func(link string) string {
		target := link[2 : len(link)-1]
		if strings.Contains(target, "://") || strings.HasPrefix(target, "#") ||
			strings.HasPrefix(target, "mailto:") {
			return link
		}
		return "](" + repo + "/blob/" + tag + "/" + strings.TrimPrefix(target, "./") + ")"
	})
}
