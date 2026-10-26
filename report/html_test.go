// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func writeHTML(t testing.TB, r *core.Report) string {
	t.Helper()
	return string(writeWith(t, core.FormatHTML, r, testOpts))
}

func TestHTMLGolden(t *testing.T) {
	out := writeHTML(t, coretest.SampleReport())
	checkHTML(t, []byte(out))
	coretest.Golden(t, "sample.html", []byte(out))
}

// htmlBanned are elements that load, embed or submit something. A
// report needs none of them.
var htmlBanned = map[string]bool{
	"iframe": true, "frame": true, "object": true, "embed": true, "img": true, "link": true, "form": true,
	"base": true, "audio": true, "video": true, "source": true, "svg": true, "math": true, "textarea": true, "input": true,
}

// checkHTML parses a page (SR-51): one script, inline and hashed into
// the CSP; no external src or href; no event handler attributes; none of
// the loading elements; the CSP meta exactly as PRD 9.5.
func checkHTML(t *testing.T, out []byte) {
	t.Helper()
	for _, p := range htmlProblems(out) {
		t.Error(p)
	}
}

// htmlProblems lists what checkHTML reports.
func htmlProblems(out []byte) []string {
	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	doc, err := html.Parse(bytes.NewReader(out))
	if err != nil {
		return []string{"html does not parse: " + err.Error()}
	}
	var scripts []string
	csp := ""
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if htmlBanned[n.Data] {
				fail("html: a <%s> element is in the page", n.Data)
			}
			for _, a := range n.Attr {
				key, val := strings.ToLower(a.Key), strings.ToLower(strings.TrimSpace(a.Val))
				switch {
				case strings.HasPrefix(key, "on"):
					fail("html: event handler %s=%q on <%s>", a.Key, a.Val, n.Data)
				case key == "src" || key == "srcset" || key == "action" || key == "formaction" || key == "poster":
					fail("html: %s=%q on <%s>", a.Key, a.Val, n.Data)
				case key == "href" && !strings.HasPrefix(val, "#"):
					fail("html: href %q is not an anchor on the page", a.Val)
				case key == "style" && (strings.Contains(val, "url(") || strings.Contains(val, "expression")):
					fail("html: style %q loads something", a.Val)
				}
			}
			if n.Data == "meta" && attr(n, "http-equiv") == "Content-Security-Policy" {
				csp = attr(n, "content")
			}
			if n.Data == "script" {
				var b strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					b.WriteString(c.Data)
				}
				scripts = append(scripts, b.String())
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if len(scripts) != 1 {
		fail("html: %d script elements, want 1", len(scripts))
		return problems
	}
	sum := sha256.Sum256([]byte(scripts[0]))
	want := "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if csp != want {
		fail("html: CSP is %q, want %q", csp, want)
	}
	return problems
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// TestHTMLChecksCatchMistakes: the checker itself fails on each thing it
// must catch, so a green run means something.
func TestHTMLChecksCatchMistakes(t *testing.T) {
	good := writeHTML(t, smallReport())
	for name, bad := range map[string]string{
		"second script":  strings.Replace(good, "</body>", "<script>alert(1)</script></body>", 1),
		"external src":   strings.Replace(good, "</main>", `<img src="https://evil.test/x.png"></main>`, 1),
		"external href":  strings.Replace(good, "</main>", `<a href="https://evil.test">x</a></main>`, 1),
		"handler":        strings.Replace(good, "<main>", `<main onclick="x()">`, 1),
		"changed script": strings.Replace(good, `"use strict";`, `"use strict"; fetch("x");`, 1),
		"no csp":         strings.Replace(good, `http-equiv="Content-Security-Policy"`, `http-equiv="x"`, 1),
	} {
		if len(htmlProblems([]byte(bad))) == 0 {
			t.Errorf("%s: checkHTML passed a bad page", name)
		}
	}
	checkHTML(t, []byte(good))
}

// TestHTMLHostileText is the static part of T-51: markup in file names,
// changelogs and names is shown as text.
func TestHTMLHostileText(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	u.Name = `<script>alert(1)</script>`
	u.To.URL = "javascript:alert(1)"
	u.To.Publisher = []string{`</textarea><img src=x onerror=alert(1)>`}
	u.Changelog = []core.ChangelogEntry{{Version: "1.3.1", Text: `</textarea><script>alert(2)</script> <a href="javascript:alert(3)">x</a>`}}
	file := `lib/</textarea><img src=x onerror=alert(1)>.js`
	u.Findings = []core.Finding{{ID: "outbound-new-domain", Title: "Contacts a new domain", Severity: cli.SeverityMedium,
		File: file, Line: 2, Evidence: core.NewSnippet(`fetch("https://evil.test/x")</pre><script>alert(4)</script>`),
		Domains: []string{"evil.test"}, Advice: `<b onmouseover=alert(5)>`}}
	u.Hunks = []core.Hunk{{Path: file, NewStart: 1, NewLines: 2, Lines: []string{`+</textarea><script>alert(6)</script>`, `+javascript:alert(7)`}}}
	r.NotChecked = []core.NotChecked{{Name: "<svg onload=alert(8)>", Text: "x"}}
	r.Warnings = []string{"<iframe src=//evil.test>"}
	out := writeHTML(t, r)
	checkHTML(t, []byte(out))
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;/textarea&gt;&lt;img src=x onerror=alert(1)&gt;", "hxxps://evil[.]test/x"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing escaped %q", want)
		}
	}
	if strings.Contains(out, "https://evil.test") {
		t.Error("a live package URL is in the page")
	}
}

func TestHTMLLayout(t *testing.T) {
	out := writeHTML(t, coretest.SampleReport())
	for _, want := range []string{
		`<h1>Sightread review: /var/www/shop</h1>`,
		`<li class="hold"><b>1</b> hold</li>`, `<li class="review"><b>1</b> review</li>`,
		`<li class="routine"><b>2</b> routine</li>`, `<li class="allowed"><b>1</b> allowed</li>`,
		`<table class="sortable">`, `<a href="#u1">countdown-timer-ultimate</a>`,
		`<h3>What the diff adds</h3>`, `<li>network</li><li>1</li>`,
		`<span class="muted">Size from</span> 412 KB`,
		`<button type="button" id="view">Show side by side</button>`,
		`<details open><summary class="file">includes/class-wpos-analytics.php</summary>`,
		`<p class="muted">Raised by owner-change.</p>`, `<p class="muted">Demoted: vendored path.</p>`,
		`<p>Static diff of official releases; Sightread never ran this code. Not proof an update is safe.</p>`,
		`<p>Sightread reports what changed. It does not judge intent.</p>`,
		`rhythm sightread allow wp-plugin:countdown-timer-ultimate@2.6.8 --reason &#34;...&#34;`,
		`It records this archive by its sha256 <code>` + strings.Repeat("2", 64) + `</code>`,
		`<h2>Not checked</h2>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestHTMLFleet(t *testing.T) {
	r := smallReport()
	if out := writeHTML(t, r); strings.Contains(out, `<th data-col="5">Sites</th>`) {
		t.Error("a single-site run has a Sites column")
	}
	r.Target.Sites = []string{"shop", "blog"}
	r.Updates[0].Sites = []string{"shop", "blog"}
	out := writeHTML(t, r)
	for _, want := range []string{`<th data-col="5">Sites</th>`, `· on 2 sites`, `<li>shop</li>`, `<li>blog</li>`, " · 2 sites</p>"} {
		if !strings.Contains(out, want) {
			t.Errorf("fleet page misses %q", want)
		}
	}
}

func TestHTMLDiffViewer(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	u.Findings = []core.Finding{{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh, File: "src/a.js", Line: 11,
		Domains: []string{"cdn.example"}}}
	long := strings.Repeat("x", 1200)
	u.Hunks = []core.Hunk{
		{Path: "src/a.js", OldStart: 10, OldLines: 2, NewStart: 10, NewLines: 2, Lines: []string{" keep", "-old", "+new"}},
		{Path: "src/b.js", NewStart: 1, NewLines: 1, Lines: []string{"+other"}},
		{Path: "lib/c.min.js", NewStart: 1, NewLines: 1, Lines: []string{"+" + long}},
	}
	u.Findings = append(u.Findings, core.Finding{ID: "outbound-new-domain", Title: "t", Severity: cli.SeverityInfo, File: "lib/c.min.js",
		Domains: []string{"a.example", "b.example"}, Baselined: true})
	out := writeHTML(t, r)
	checkHTML(t, []byte(out))
	for _, want := range []string{
		`<details open><summary class="file">src/a.js</summary>`,
		`<tr class="ctx" data-k=" "><td class="ln">10</td><td class="ln">10</td><td class="code">keep</td></tr>`,
		`<tr class="del" data-k="-"><td class="ln">11</td><td class="ln"></td><td class="code">old</td></tr>`,
		`<tr class="add" data-k="&#43;"><td class="ln"></td><td class="ln">11</td><td class="code">new</td></tr>`,
		`<details><summary>Other changed files (2)</summary>`,
		`<details><summary class="file">src/</summary>`, `<details><summary class="file">lib/</summary>`,
		`<p class="muted">minified, 1 KB, not shown; 2 new domains in it</p>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, long) {
		t.Error("the minified line is in the page")
	}
	if strings.Contains(out, `<details open><summary class="file">src/b.js`) {
		t.Error("an unflagged file is open")
	}
}

func TestHTMLExplainAndSoundcheck(t *testing.T) {
	restore := core.SwapExplain("eval-dynamic", core.Explain{Why: "Code built from strings can run anything.", HowToReview: "Find where the string comes from."})
	defer restore()
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict = core.Review
	u.Findings = []core.Finding{{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh}}
	u.Soundcheck = &core.SoundcheckResult{Staging: "https://staging.example", Broke: 1, New: 2, Changed: 3, RolledBack: true, Report: "soundcheck/report.html"}
	out := writeHTML(t, r)
	checkHTML(t, []byte(out))
	for _, want := range []string{
		`<p><strong>Why it matters.</strong> Code built from strings can run anything.</p>`,
		`<p><strong>How to review.</strong> Find where the string comes from.</p>`,
		`<h2>Soundcheck</h2>`, `1 broke, 2 new, 3 changed; rolled back`, `<code>soundcheck/report.html</code>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(writeHTML(t, smallReport()), "Soundcheck") {
		t.Error("a run without --soundcheck has a Soundcheck section")
	}
}

func TestHTMLUnverifiedCantBeAllowed(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	u.Verdict, u.To.Verified, u.To.SHA256 = core.Unverified, core.ByNone, strings.Repeat("c", 64)
	out := writeHTML(t, r)
	if !strings.Contains(out, "This version isn't verified, so it can't be allowed yet.") {
		t.Errorf("no refusal line:\n%s", out)
	}
	if strings.Contains(out, "It records this archive") || strings.Contains(out, "allow npm:left-pad") {
		t.Error("an unverified archive is offered for allowing")
	}
	if clean := writeHTML(t, smallReport()); strings.Contains(clean, "Record your review") {
		t.Error("a routine update offers an allow command")
	}
}

func TestHTMLRedactPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home folder")
	}
	r := smallReport()
	r.Target.Path = filepath.Join(home, "sites", "shop")
	r.Warnings = []string{"can't read " + filepath.Join(home, "other", "x.php")}
	o := testOpts
	o.RedactPaths = true
	out := string(writeWith(t, core.FormatHTML, r, o))
	if strings.Contains(out, home) {
		t.Errorf("the home path is in the page")
	}
	if !strings.Contains(out, "can&#39;t read ~/other/x.php") {
		t.Errorf("the warning path is not redacted")
	}
}

func TestHTMLSignedFooter(t *testing.T) {
	o := testOpts
	o.Signed = strings.Repeat("ab", 32)
	out := string(writeWith(t, core.FormatHTML, smallReport(), o))
	if !strings.Contains(out, "<p>Signed JSON report sha256: <code>"+o.Signed+"</code></p>") {
		t.Error("no signed hash in the footer")
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1 KB", 49152: "48 KB", 1572864: "1.5 MB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestScriptHashMatchesEmbedded(t *testing.T) {
	sum := sha256.Sum256([]byte(htmlScript))
	if !strings.Contains(htmlCSP, base64.StdEncoding.EncodeToString(sum[:])) {
		t.Error("the CSP does not hold the embedded script's hash")
	}
	if strings.Contains(strings.ToLower(htmlScript), "</script") || strings.Contains(htmlScript, "innerHTML") {
		t.Error("the script can close its element or write markup")
	}
}
