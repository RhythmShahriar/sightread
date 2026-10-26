// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"path"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/RhythmShahriar/sightread/core"
)

func TestValidateName(t *testing.T) {
	long := strings.Repeat("a", MaxName+1)
	cases := []struct {
		raw, clean string
		issue      core.ArchiveIssueKind
	}{
		{"ok.php", "ok.php", ""},
		{"plugin/includes/loader.php", "plugin/includes/loader.php", ""},
		{`plugin\includes\loader.php`, "plugin/includes/loader.php", ""},
		{"caf\u0065\u0301.php", "caf\u00e9.php", ""}, // NFD in, NFC out
		{".hidden/.htaccess", ".hidden/.htaccess", ""},
		{"a..b/c..d.php", "a..b/c..d.php", ""},
		{"console.php", "console.php", ""},
		{"com10.txt", "com10.txt", ""},
		{"lpt.php", "lpt.php", ""},
		{strings.Repeat("a", MaxName), strings.Repeat("a", MaxName), ""},
		{"../evil.php", "", core.IssuePathEscape},
		{"/abs.php", "", core.IssuePathEscape},
		{`..\win.php`, "", core.IssuePathEscape},
		{"C:/x.php", "", core.IssuePathEscape},
		{`C:\x.php`, "", core.IssuePathEscape},
		{"c:x.php", "", core.IssuePathEscape},
		{`\\host\share\x`, "", core.IssuePathEscape},
		{"//host/share/x", "", core.IssuePathEscape},
		{"plugin/../../x.php", "", core.IssuePathEscape},
		{"plugin/..", "", core.IssuePathEscape},
		{"a/./b", "", core.IssuePathEscape},
		{"./a", "", core.IssuePathEscape},
		{"a//b", "", core.IssuePathEscape},
		{"plugin/", "", core.IssuePathEscape},
		{"plugin/.../x.php", "", core.IssuePathEscape},
		{"plugin/.. /x.php", "", core.IssuePathEscape},
		{".\u200c./x.php", "", core.IssuePathEscape},
		{"\ufeff../x.php", "", core.IssuePathEscape},
		{"plugin/file.php:stream", "", core.IssuePathEscape},
		{"plugin/NUL", "", core.IssuePathEscape},
		{"plugin/con.php", "", core.IssuePathEscape},
		{"aux .txt", "", core.IssuePathEscape},
		{"COM1", "", core.IssuePathEscape},
		{"lpt\u00b9.log", "", core.IssuePathEscape},
		{"conin$", "", core.IssuePathEscape},
		{"", "", core.IssueMalformed},
		{"evil\x00.php", "", core.IssueMalformed},
		{"evil\n.php", "", core.IssueMalformed},
		{"evil\x7f.php", "", core.IssueMalformed},
		{"evil\u0085.php", "", core.IssueMalformed},
		{"bad\xff.php", "", core.IssueMalformed},
		{long, "", core.IssueMalformed},
	}
	for _, tc := range cases {
		clean, issue, ok := ValidateName(tc.raw)
		if ok != (tc.issue == "") || issue != tc.issue || clean != tc.clean {
			t.Errorf("ValidateName(%q) = %q, %q, %v; want %q, %q", tc.raw, clean, issue, ok, tc.clean, tc.issue)
		}
	}
}

func TestCaseKey(t *testing.T) {
	if CaseKey("Foo.php") != CaseKey("foo.php") {
		t.Error("case differs")
	}
	if CaseKey("caf\u0065\u0301.php") != CaseKey("CAF\u00c9.php") {
		t.Error("NFD and NFC differ")
	}
	if CaseKey("a.php") == CaseKey("b.php") {
		t.Error("different names collide")
	}
}

// windowsLocal is filepath.IsLocal with Windows rules, so the fuzz
// target checks them on any OS: no root, no colon, no reserved device
// name and no climbing out with "..".
func windowsLocal(p string) bool {
	if p == "" || p[0] == '\\' || p[0] == '/' || strings.ContainsRune(p, ':') {
		return false
	}
	depth := 0
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' }) {
		if reservedWindows(part) {
			return false
		}
		switch part {
		case ".":
		case "..":
			depth--
			if depth < 0 {
				return false
			}
		default:
			depth++
		}
	}
	return true
}

func FuzzSafePath(f *testing.F) {
	for _, s := range []string{
		"ok.php", "../evil.php", "/abs.php", `..\win.php`, `C:\x.php`, `\\host\share\x`,
		"plugin/../../x.php", "a/./b", "evil\x00.php", "caf\u0065\u0301.php", ".\u200c./x",
		"plugin/con.php", "a:b", "...", "plugin/.. /x", strings.Repeat("x/", 600),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		clean, issue, ok := ValidateName(raw)
		if !ok {
			if issue != core.IssuePathEscape && issue != core.IssueMalformed {
				t.Fatalf("%q refused with issue %q", raw, issue)
			}
			return
		}
		if issue != "" {
			t.Fatalf("%q accepted with issue %q", raw, issue)
		}
		if !utf8.ValidString(clean) || !norm.NFC.IsNormalString(clean) || len(clean) > MaxName {
			t.Fatalf("%q gave %q: not valid NFC within the length cap", raw, clean)
		}
		if strings.ContainsAny(clean, "\\\x00") || strings.ContainsFunc(clean, isControl) {
			t.Fatalf("%q gave %q with a backslash or control character", raw, clean)
		}
		// Linux and macOS: joined to a root it stays under the root.
		if j := path.Join("/root", clean); !strings.HasPrefix(j, "/root/") {
			t.Fatalf("%q joins to %q", raw, j)
		}
		if !filepath.IsLocal(filepath.FromSlash(clean)) {
			t.Fatalf("%q gave %q, which filepath.IsLocal refuses here", raw, clean)
		}
		// Windows.
		win := strings.ReplaceAll(clean, "/", `\`)
		if !windowsLocal(win) {
			t.Fatalf("%q gave %q, which is not local on Windows", raw, win)
		}
		// Accepting is stable: a clean name validates to itself.
		if again, _, ok := ValidateName(clean); !ok || again != clean {
			t.Fatalf("%q gave %q, which validates to %q, %v", raw, clean, again, ok)
		}
	})
}
