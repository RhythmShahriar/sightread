// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// update rewrites golden files: go test ./report -update. A test package
// that imports coretest must not define its own -update flag.
var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

var (
	reTime     = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)`)
	reDurMS    = regexp.MustCompile(`("duration_ms":\s*)\d+`)
	reDur      = regexp.MustCompile(`\b\d+(\.\d+)?(ns|µs|us|ms|s|m)\b`)
	reToolVer  = regexp.MustCompile(`(rhythm[ -]sightread[ /])v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*|(rhythm[ -]sightread[ /])dev\b`)
	reEnvelope = regexp.MustCompile(`("tool":\s*"rhythm-sightread",\s*"version":\s*)"[^"]*"`)
)

// Normalise replaces what changes between runs and machines with
// placeholders: RFC 3339 times become <time>, durations <dur>, the tool's
// own version <version>, paths under the temp folder <tmp>/... with
// slashes. Package versions are left alone.
func Normalise(b []byte) []byte {
	s := string(b)
	for _, tmp := range tempRoots() {
		s = replacePaths(s, tmp)
	}
	s = reTime.ReplaceAllString(s, "<time>")
	s = reDurMS.ReplaceAllString(s, "${1}0")
	s = reEnvelope.ReplaceAllString(s, `${1}"<version>"`)
	s = reToolVer.ReplaceAllStringFunc(s, func(m string) string {
		return m[:len("rhythm sightread ")] + "<version>"
	})
	s = reDur.ReplaceAllString(s, "<dur>")
	return []byte(s)
}

// tempRoots are the temp folder as written and with symlinks resolved
// (macOS /var is /private/var), plus its JSON-escaped form on Windows.
func tempRoots() []string {
	tmp := filepath.Clean(os.TempDir())
	roots := []string{tmp}
	if r, err := filepath.EvalSymlinks(tmp); err == nil && r != tmp {
		roots = append(roots, r)
	}
	if filepath.Separator == '\\' {
		for _, r := range roots {
			roots = append(roots, strings.ReplaceAll(r, `\`, `\\`))
		}
	}
	return roots
}

// replacePaths turns every path under root into <tmp>/rest-with-slashes.
func replacePaths(s, root string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, root)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		s = s[i+len(root):]
		end := strings.IndexFunc(s, func(r rune) bool {
			return r == '"' || r == '\'' || r == ' ' || r == '\n' || r == '\t' || r == ')' || r == '<' || r == '>'
		})
		if end < 0 {
			end = len(s)
		}
		rest := strings.ReplaceAll(strings.ReplaceAll(s[:end], `\\`, "/"), `\`, "/")
		b.WriteString("<tmp>" + rest)
		s = s[end:]
	}
}

// Golden compares got, normalised, with testdata/golden/<name> in the
// test's package. With -update it writes the file instead.
func Golden(t testing.TB, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", filepath.FromSlash(name))
	got = Normalise(got)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // a golden file of the test's own package
	if err != nil {
		t.Fatalf("%v (run the test with -update to write it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file (run with -update to accept):\n%s", path, firstDiff(want, got))
	}
}

// firstDiff shows the first line that differs, with its number.
func firstDiff(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + strconv.Itoa(i+1) + "\n  want: " + wl + "\n  got:  " + gl
		}
	}
	return "(only line endings differ)"
}
