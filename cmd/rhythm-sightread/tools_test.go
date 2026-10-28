// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

// docWriter is a JSON writer that also writes the other document kinds:
// the envelope as plain JSON.
type docWriter struct{ *coretest.FakeWriter }

func (d docWriter) WriteDocument(w io.Writer, env core.Envelope, _ core.WriteOptions) error {
	env.Schema, env.Tool = core.Schema, "rhythm-sightread"
	return json.NewEncoder(w).Encode(env)
}

// installDocs registers docWriter for JSON.
func installDocs(t *testing.T) {
	t.Helper()
	t.Cleanup(core.SwapWriter(docWriter{&coretest.FakeWriter{Name: core.FormatJSON}}))
}

// jsonReports makes core.ReadReport read reports the test saved with
// saveReport (encoding/json of core.Report).
func jsonReports(t *testing.T) {
	t.Helper()
	t.Cleanup(core.SwapReportReader(func(r io.Reader) (*core.Report, error) {
		var rep core.Report
		if err := json.NewDecoder(r).Decode(&rep); err != nil {
			return nil, err
		}
		return &rep, nil
	}))
}

func saveReport(t *testing.T, rep *core.Report) string {
	t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSignalsGolden(t *testing.T) {
	code, out, _ := execute(t, "signals")
	if code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	coretest.Golden(t, "signals.txt", []byte(out))
	if !strings.HasPrefix(out, "ID  ") || strings.Count(out, "\n") != len(core.Catalog)+1 {
		t.Errorf("table:\n%s", out)
	}
}

func TestSignalsJSON(t *testing.T) {
	installDocs(t)
	code, out, _ := execute(t, "signals", "--json")
	var env struct {
		Kind string
		Data core.SignalsData
	}
	if err := json.Unmarshal([]byte(out), &env); code != cli.ExitOK || err != nil || env.Kind != core.KindSignals ||
		len(env.Data.Signals) != len(core.Catalog) {
		t.Errorf("exit %d (%v) %.200s", code, err, out)
	}
}

func TestExplain(t *testing.T) {
	coretest.FakeExplainRenderer{}.Install(t)
	code, out, _ := execute(t, "explain", "remote-fetch-exec")
	if code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	coretest.Golden(t, "explain-signal.txt", []byte(out))

	code, _, errOut := execute(t, "explain", "eval-dynamik")
	want := "rhythm-sightread explain: no signal \"eval-dynamik\" (did you mean eval-dynamic?)\n  list them: rhythm-sightread signals\n"
	if code != cli.ExitUsage || errOut != want {
		t.Errorf("unknown signal: exit %d %q", code, errOut)
	}
	// A word close to a part of an ID gets that ID, as the changes
	// notes say: "evil" is not two edits from any ID.
	code, _, errOut = execute(t, "explain", "evil")
	want = "rhythm-sightread explain: no signal \"evil\" (did you mean eval-dynamic?)\n  list them: rhythm-sightread signals\n"
	if code != cli.ExitUsage || errOut != want {
		t.Errorf("explain evil: exit %d %q", code, errOut)
	}
	code, _, errOut = execute(t, "explain", "zzzzzzzzzz")
	if code != cli.ExitUsage || strings.Contains(errOut, "did you mean") {
		t.Errorf("explain zzzzzzzzzz: exit %d %q", code, errOut)
	}
}

// TestExplainFinding picks a finding by number and by fingerprint and
// diffs it from the cached archives.
func TestExplainFinding(t *testing.T) {
	w := world(t)
	coretest.FakeExplainRenderer{}.Install(t)
	routineAndHold(w)
	report := filepath.Join(t.TempDir(), "r.json")
	if code, _, errOut := execute(t, "all", "-o", report); code != cli.ExitOK {
		t.Fatal(errOut)
	}
	rep := w.Writers[core.FormatTerminal].Got()[0]
	jsonReports(t)
	path := saveReport(t, rep)
	hunks := &hunkDiffer{}
	t.Cleanup(core.SwapDiffer(hunks))

	code, out, errOut := execute(t, "explain", path, "1")
	if code != cli.ExitOK || out != "explain finding 1 (1 hunks)\n" {
		t.Errorf("by number: exit %d %q %q", code, out, errOut)
	}
	if got := hunks.asked; len(got) != 1 || got[0] != "main.php 6" {
		t.Errorf("hunks asked %q, want main.php with 6 lines of context", got)
	}
	fp := rep.Updates[0].Findings[0].Fingerprint // the HOLD update comes first
	if code, out, _ := execute(t, "explain", path, fp); code != cli.ExitOK || out != "explain finding "+fp+" (1 hunks)\n" {
		t.Errorf("by fingerprint: exit %d %q", code, out)
	}
	code, _, errOut = execute(t, "explain", path, "9")
	if code != cli.ExitUsage || !strings.HasSuffix(errOut, "review.json has no finding 9 (it has 1)\n") {
		t.Errorf("no such finding: exit %d %q", code, errOut)
	}

	// A cached tree that isn't the release the report names (another
	// sha256) is not used: the report's own hunk of the file is.
	other := *rep
	other.Updates = slices.Clone(rep.Updates)
	u := &other.Updates[0]
	u.To.SHA256 = strings.Repeat("0", 64)
	u.Hunks = []core.Hunk{{Path: "main.php", Lines: []string{"+saved"}}, {Path: "other.php", Lines: []string{"+no"}}}
	saved := saveReport(t, &other)
	asked := len(hunks.asked)
	if code, out, _ := execute(t, "explain", saved, "1"); code != cli.ExitOK || out != "explain finding 1 (1 hunks)\n" || len(hunks.asked) != asked {
		t.Errorf("other sha256: exit %d %q, differ asked %q", code, out, hunks.asked[asked:])
	}

	// A --to-file side is never cached: the report's hunk, no diff.
	u.To.SHA256, u.To.Source = rep.Updates[0].To.SHA256, core.SourceLocalFile
	saved = saveReport(t, &other)
	if code, out, _ := execute(t, "explain", saved, "1"); code != cli.ExitOK || out != "explain finding 1 (1 hunks)\n" || len(hunks.asked) != asked {
		t.Errorf("local file: exit %d %q, differ asked %q", code, out, hunks.asked[asked:])
	}

	// Without the cached archives the renderer gets no hunks and says so.
	t.Setenv("RHYTHM_CACHE_DIR", t.TempDir())
	if code, out, _ := execute(t, "explain", path, "1"); code != cli.ExitOK || out != "explain finding 1 (0 hunks)\n" {
		t.Errorf("no cache: exit %d %q", code, out)
	}
	// ...unless the report saved the hunk.
	if code, out, _ := execute(t, "explain", saved, "1"); code != cli.ExitOK || out != "explain finding 1 (1 hunks)\n" {
		t.Errorf("no cache, saved hunk: exit %d %q", code, out)
	}
}

// hunkDiffer is the fake differ with one hunk per path asked for.
type hunkDiffer struct {
	coretest.FakeDiffer
	asked []string
}

func (h *hunkDiffer) Hunks(_ context.Context, _ *core.Diff, path string, n int) ([]core.Hunk, error) {
	h.asked = append(h.asked, fmt.Sprintf("%s %d", path, n))
	return []core.Hunk{{Path: path, Lines: []string{"+x"}}}, nil
}

// listPolicy is FakePolicy with an allow set that lists its entries, as
// policy.AllowSet does.
type listPolicy struct{ *coretest.FakePolicy }

type listSet struct{ coretest.AllowList }

func (l listSet) Entries() []core.AllowEntry { return l.AllowList }

func (p listPolicy) LoadAllow(c *core.Config, path, base string) (core.AllowSet, error) {
	s, err := p.FakePolicy.LoadAllow(c, path, base)
	if err != nil {
		return nil, err
	}
	return listSet{s.(coretest.AllowList)}, nil //nolint:forcetypeassert // FakePolicy returns an AllowList
}

func installAllow(t *testing.T, w *runtest.World) *coretest.FakePolicy {
	t.Helper()
	t.Cleanup(core.SwapPolicy(listPolicy{w.Policy}))
	installDocs(t)
	t.Setenv("USER", "Ann Reviewer")
	t.Setenv("PATH", t.TempDir()) // no git: --by comes from $USER
	return w.Policy
}

// TestAllowRoundTrip adds, lists and removes an entry.
func TestAllowRoundTrip(t *testing.T) {
	w := world(t)
	p := installAllow(t, w)
	w.Publish(core.NPM, "sharp", "0.33.5")
	code, out, errOut := execute(t, "allow", "npm:sharp@0.33.5", "--reason", "known install script", "--signals", "npm-install-script-new")
	if code != cli.ExitOK || !strings.HasPrefix(out, "allowed npm:sharp@0.33.5 (sha256 ") {
		t.Fatalf("add: exit %d %q %q", code, out, errOut)
	}
	if len(p.Allow) != 1 {
		t.Fatalf("entries %+v", p.Allow)
	}
	e := p.Allow[0]
	if e.Package != "npm:sharp" || e.Version != "0.33.5" || len(e.SHA256) != 64 || e.By != "Ann Reviewer" ||
		e.Date != time.Now().Format(time.DateOnly) || !slices.Equal(e.Signals, []string{"npm-install-script-new"}) {
		t.Errorf("entry %+v", e)
	}
	code, out, _ = execute(t, "allow", "list")
	if code != cli.ExitOK || !strings.Contains(out, "npm:sharp@0.33.5  "+e.SHA256[:12]) {
		t.Errorf("list: exit %d\n%s", code, out)
	}
	code, out, _ = execute(t, "allow", "list", "--json")
	if code != cli.ExitOK || !strings.Contains(out, `"kind":"allowed"`) || !strings.Contains(out, e.SHA256) {
		t.Errorf("list --json: exit %d %s", code, out)
	}
	if code, out, _ := execute(t, "allow", "remove", "npm:sharp@0.33.5"); code != cli.ExitOK || !strings.HasPrefix(out, "removed npm:sharp@0.33.5 from ") {
		t.Errorf("remove: exit %d %q", code, out)
	}
	if code, out, _ := execute(t, "allow", "list"); code != cli.ExitOK || !strings.HasSuffix(out, "allows nothing yet\n") {
		t.Errorf("list after remove: exit %d %q", code, out)
	}
}

// TestAllowUntil: --until before today is refused (E12) and writes
// nothing; allow list marks an expired entry; adding the version again
// replaces the expired entry without --force.
func TestAllowUntil(t *testing.T) {
	w := world(t)
	p := installAllow(t, w)
	w.Publish(core.NPM, "leftpadplus", "1.0.1")
	code, out, errOut := execute(t, "allow", "npm:leftpadplus@1.0.1", "--reason", "ok", "--until", "2020-01-01")
	if code != cli.ExitUsage || out != "" || errOut != "rhythm-sightread allow: --until 2020-01-01 is in the past, so the entry would never count\n"+
		"  give today or a later date, or leave --until out\n" || len(p.Allow) != 0 {
		t.Fatalf("past --until: exit %d %q %q, entries %d", code, out, errOut, len(p.Allow))
	}
	today := time.Now().Format(time.DateOnly)
	if code, _, errOut := execute(t, "allow", "npm:leftpadplus@1.0.1", "--reason", "ok", "--until", today); code != cli.ExitOK {
		t.Fatalf("--until today: exit %d %q", code, errOut)
	}
	// An entry from an older run that has run out since.
	p.Allow[0].Until = "2020-01-01"
	code, out, _ = execute(t, "allow", "list")
	if code != cli.ExitOK || !strings.Contains(out, "2020-01-01 (expired)") {
		t.Errorf("list: exit %d\n%s", code, out)
	}
	code, out, errOut = execute(t, "allow", "npm:leftpadplus@1.0.1", "--reason", "looked again")
	if code != cli.ExitOK || !strings.HasPrefix(out, "allowed npm:leftpadplus@1.0.1 (sha256 ") {
		t.Fatalf("again: exit %d %q %q", code, out, errOut)
	}
	if len(p.Allow) != 1 || p.Allow[0].Until != "" || p.Allow[0].Reason != "looked again" {
		t.Errorf("entries %+v", p.Allow)
	}
	if code, out, _ := execute(t, "allow", "list"); code != cli.ExitOK || strings.Contains(out, "expired") {
		t.Errorf("list after replace: exit %d\n%s", code, out)
	}
}

// TestAllowOtherHash: allowing a version already allowed with other
// bytes is refused with a pointer to --force; --force replaces the old
// entry with a warning, so the file never holds two entries for one
// version. A report side with no hash (an archive limit hit) is refused.
func TestAllowOtherHash(t *testing.T) {
	w := world(t)
	p := installAllow(t, w)
	old := strings.Repeat("cd", 32)
	p.Allow = append(p.Allow, core.AllowEntry{Package: "npm:sharp", Version: "0.33.5", SHA256: old, Reason: "earlier",
		By: "Bob", Date: "2026-10-01"})
	w.Publish(core.NPM, "sharp", "0.33.5")
	code, out, errOut := execute(t, "allow", "npm:sharp@0.33.5", "--reason", "looked again")
	if code != cli.ExitUsage || out != "" || !strings.Contains(errOut, "npm:sharp@0.33.5 is already allowed with sha256 cdcdcdcdcdcd") ||
		!strings.Contains(errOut, "add --force to replace that entry") || len(p.Allow) != 1 {
		t.Fatalf("without --force: exit %d %q %q, entries %d", code, out, errOut, len(p.Allow))
	}
	code, out, errOut = execute(t, "allow", "npm:sharp@0.33.5", "--reason", "looked again", "--force")
	if code != cli.ExitOK || !strings.HasPrefix(out, "allowed npm:sharp@0.33.5 (sha256 ") ||
		errOut != "warning: replaced the entry that allowed npm:sharp@0.33.5 with sha256 cdcdcdcdcdcd (by Bob, 2026-10-01)\n" {
		t.Fatalf("--force: exit %d %q %q", code, out, errOut)
	}
	if len(p.Allow) != 1 || p.Allow[0].SHA256 == old || p.Allow[0].Reason != "looked again" {
		t.Errorf("entries %+v", p.Allow)
	}

	jsonReports(t)
	rep := &core.Report{Kind: core.KindReview, Updates: []core.Update{
		{Eco: core.WPPlugin, Name: "e04-bomb", To: core.Side{Version: "1.0.1", HashKind: core.HashManifest, Verified: core.ByChecksums}},
		{Eco: core.NPM, Name: "sharp", To: core.Side{Version: "0.33.5", SHA256: old, Verified: core.BySignature}},
	}}
	code, _, errOut = execute(t, "allow", "--from", saveReport(t, rep), "--reason", "r")
	if code != cli.ExitUsage || !strings.Contains(errOut, "wp-plugin:e04-bomb@1.0.1 has no complete archive hash, so it can't be allowed") ||
		!strings.Contains(errOut, "npm:sharp@0.33.5 is already allowed with sha256 ") || len(p.Allow) != 1 {
		t.Errorf("--from: exit %d %q, entries %+v", code, errOut, p.Allow)
	}
}

// TestAllowRefuses: E12 without a reason, E18 for an unverified or
// mismatched version, through a fetch and through --from.
func TestAllowRefuses(t *testing.T) {
	w := world(t)
	p := installAllow(t, w)
	w.Publish(core.NPM, "left-pad", "1.4.0")
	w.Publish(core.NPM, "evil", "2.0.0")
	w.Sources[core.NPM].Integrity[core.Ref{Eco: core.NPM, Name: "left-pad", Version: "1.4.0"}] = core.Integrity{By: core.ByNone}
	w.Sources[core.NPM].Integrity[core.Ref{Eco: core.NPM, Name: "evil", Version: "2.0.0"}] = core.Integrity{By: core.ByFailed,
		Mismatch: []string{"sha512"}}

	code, _, errOut := execute(t, "allow", "npm:left-pad@1.4.0")
	if code != cli.ExitUsage || errOut != "rhythm-sightread allow: --reason is required, so the next person knows why it is allowed\n"+
		"  add --reason \"<what you checked>\"\n" {
		t.Errorf("E12: exit %d %q", code, errOut)
	}
	unverified := "rhythm-sightread allow: npm:left-pad@1.4.0 couldn't be verified, so it can't be allowed\n" +
		"  allow records a reviewed archive by its hash; review it first with rhythm-sightread npm left-pad --to 1.4.0\n"
	code, _, errOut = execute(t, "allow", "npm:left-pad@1.4.0", "--reason", "ok")
	if code != cli.ExitUsage || errOut != unverified {
		t.Errorf("E18 unverified: exit %d %q", code, errOut)
	}
	mismatch := "rhythm-sightread allow: npm:evil@2.0.0 doesn't match its published hash, so it can't be allowed\n" +
		"  someone between you and the registry changed it, or the release was edited; don't install this copy\n"
	code, _, errOut = execute(t, "allow", "npm:evil@2.0.0", "--reason", "ok")
	if code != cli.ExitUsage || errOut != mismatch {
		t.Errorf("E18 mismatch: exit %d %q", code, errOut)
	}

	jsonReports(t)
	sum := strings.Repeat("ab", 32)
	rep := &core.Report{Kind: core.KindReview, Updates: []core.Update{
		{Eco: core.NPM, Name: "left-pad", To: core.Side{Version: "1.4.0", SHA256: sum, Verified: core.ByNone}},
		{Eco: core.NPM, Name: "evil", To: core.Side{Version: "2.0.0", SHA256: sum, Verified: core.BySignature},
			Findings: []core.Finding{{ID: "integrity-mismatch"}}},
		{Eco: core.WPPlugin, Name: "akismet", To: core.Side{Version: "5.3.5", SHA256: sum, HashKind: core.HashManifest, Verified: core.ByChecksums}},
	}}
	code, out, errOut := execute(t, "allow", "--from", saveReport(t, rep), "--reason", "reviewed in PR 412")
	if code != cli.ExitUsage || errOut != unverified+mismatch {
		t.Errorf("--from: exit %d %q", code, errOut)
	}
	if len(p.Allow) != 1 || p.Allow[0].Package != "wp-plugin:akismet" || p.Allow[0].Hash != core.HashManifest ||
		!strings.HasPrefix(out, "allowed wp-plugin:akismet@5.3.5 (sha256 abababababab)") {
		t.Errorf("--from added %+v, printed %q", p.Allow, out)
	}
	// A report made after that allow lists akismet as ALLOWED: it is
	// skipped and the new update after it is still recorded.
	rep.Updates = append(rep.Updates[2:], core.Update{Eco: core.NPM, Name: "right-pad", To: core.Side{Version: "2.0.0", SHA256: sum, Verified: core.BySignature}})
	rep.Updates[0].Verdict = core.Allowed
	code, out, errOut = execute(t, "allow", "--from", saveReport(t, rep), "--reason", "reviewed in PR 413")
	if code != cli.ExitOK || errOut != "" || len(p.Allow) != 2 || p.Allow[1].Package != "npm:right-pad" ||
		!strings.HasPrefix(out, "already allowed wp-plugin:akismet@5.3.5 (sha256 abababababab)") ||
		!strings.Contains(out, "\nallowed npm:right-pad@2.0.0 (sha256 abababababab)") {
		t.Errorf("--from again: exit %d %q %q, entries %+v", code, out, errOut, p.Allow)
	}
	// A local copy has no published archive: refused before any fetch.
	code, _, errOut = execute(t, "allow", "wp-plugin:acme-i@local", "--reason", "ok")
	if code != cli.ExitUsage || !strings.HasPrefix(errOut, "rhythm-sightread: wp-plugin:acme-i@local is a local copy, which can't be allowed; allow records a published version: wp-plugin:acme-i@<version>\n") {
		t.Errorf("@local: exit %d %q", code, errOut)
	}
	if code, _, _ := execute(t, "allow", "npm:x@1", "--until", "soon", "--reason", "r"); code != cli.ExitUsage {
		t.Errorf("bad --until: exit %d", code)
	}
}

// TestReportMerges renders two saved reports as one Markdown file.
func TestReportMerges(t *testing.T) {
	w := world(t)
	jsonReports(t)
	a := saveReport(t, &core.Report{Kind: core.KindReview, Target: core.Target{Path: "/srv/a"}, Updates: []core.Update{{Name: "x"}}})
	b := saveReport(t, &core.Report{Kind: core.KindReview, Target: core.Target{Path: "/srv/b"}, Updates: []core.Update{{Name: "y"}},
		NotChecked: []core.NotChecked{{Name: "z"}}})
	out := filepath.Join(t.TempDir(), "all.md")
	code, stdout, errOut := execute(t, "report", a, b, "-o", out)
	if code != cli.ExitOK || stdout != "wrote "+filepath.ToSlash(out)+"\n" {
		t.Fatalf("exit %d %q %q", code, stdout, errOut)
	}
	got := w.Writers[core.FormatMarkdown].Got()
	if len(got) != 1 || len(got[0].Updates) != 2 || len(got[0].NotChecked) != 1 || got[0].Summary.Updates != 2 ||
		!slices.Equal(got[0].Target.Sites, []string{"/srv/a", "/srv/b"}) {
		t.Errorf("merged %+v", got)
	}
	if b, _ := os.ReadFile(out); string(b) != "fake md: 2 updates\n" { //nolint:gosec // the test's own file
		t.Errorf("file %q", b)
	}
	if code, _, _ := execute(t, "report", a); code != cli.ExitUsage {
		t.Errorf("no -o: exit %d", code)
	}
	if code, _, errOut := execute(t, "report", a, "-o", "x.txt"); code != cli.ExitUsage || !strings.Contains(errOut, `-o "x.txt"`) {
		t.Errorf("bad -o: exit %d %q", code, errOut)
	}
}

// TestReportRedactsInCI: report redacts paths when CI is set unless
// --redact-paths says otherwise; --help reads the same either way.
func TestReportRedactsInCI(t *testing.T) {
	w := world(t)
	jsonReports(t)
	a := saveReport(t, &core.Report{Kind: core.KindReview, Target: core.Target{Path: "/srv/a"}, Updates: []core.Update{{Name: "x"}}})
	for _, c := range []struct {
		ci   string
		args []string
		want bool
	}{
		{"", nil, false},
		{"true", nil, true},
		{"true", []string{"--redact-paths=false"}, false},
		{"", []string{"--redact-paths"}, true},
	} {
		t.Setenv("CI", c.ci)
		before := len(w.Writers[core.FormatMarkdown].Options())
		args := append([]string{"report", a, "--md"}, c.args...)
		if code, _, errOut := execute(t, args...); code != cli.ExitOK {
			t.Fatalf("CI=%q %v: exit %d %q", c.ci, c.args, code, errOut)
		}
		opts := w.Writers[core.FormatMarkdown].Options()
		if len(opts) != before+1 || opts[before].RedactPaths != c.want {
			t.Errorf("CI=%q %v: RedactPaths %+v, want %v", c.ci, c.args, opts[before:], c.want)
		}
	}
	var help [2]string
	for i, ci := range []string{"", "true"} {
		t.Setenv("CI", ci)
		_, help[i], _ = execute(t, "report", "--help")
	}
	if help[0] != help[1] || help[0] == "" {
		t.Errorf("report --help differs with CI set:\n%s\nwithout:\n%s", help[1], help[0])
	}
}

// TestMergeKeepsLocations: merged reports keep what SARIF needs to
// find their files. One target is kept as it is; targets in one
// repository get paths relative to its root; a target outside a
// repository leaves the paths alone.
func TestMergeKeepsLocations(t *testing.T) {
	up := func(path, lock string) []core.Update {
		return []core.Update{{Name: "x", Installed: core.InstalledInfo{Path: path, Lockfile: lock}}}
	}
	site := core.Target{Path: ".", RepoPath: "projects/wp", Kind: "mixed"}
	m := mergeReports([]*core.Report{{Target: site, Updates: up("wp-content/plugins/a", "")}, {Target: site, Updates: up("", "composer.lock")}})
	if m.Target.Path != "." || m.Target.RepoPath != "projects/wp" || m.Target.Kind != "mixed" ||
		m.Updates[0].Installed.Path != "wp-content/plugins/a" || m.Updates[1].Installed.Lockfile != "composer.lock" {
		t.Errorf("one target: %+v %+v", m.Target, m.Updates)
	}

	m = mergeReports([]*core.Report{
		{Target: core.Target{Path: ".", RepoPath: "projects/wp"}, Updates: up("wp-content/plugins/a", "")},
		{Target: core.Target{Path: ".", RepoPath: "."}, Updates: up("", "web/package-lock.json")},
	})
	if m.Target.RepoPath != "." || m.Target.Kind != "merged" ||
		m.Updates[0].Installed.Path != "projects/wp/wp-content/plugins/a" || m.Updates[1].Installed.Lockfile != "web/package-lock.json" {
		t.Errorf("one repository: %+v %+v", m.Target, m.Updates)
	}

	m = mergeReports([]*core.Report{
		{Target: core.Target{Path: ".", RepoPath: "projects/wp"}, Updates: up("wp-content/plugins/a", "")},
		{Target: core.Target{Path: "/srv/b"}, Updates: up("", "composer.lock")},
	})
	if m.Target.RepoPath != "" || m.Updates[0].Installed.Path != "wp-content/plugins/a" || m.Updates[1].Installed.Lockfile != "composer.lock" {
		t.Errorf("outside a repository: %+v %+v", m.Target, m.Updates)
	}
}

// keySigner verifies like FakeSigner and also wants "trusted-key"
// among the trusted keys.
type keySigner struct{ coretest.FakeSigner }

func (k keySigner) Verify(j, s []byte, trusted [][]byte) (string, error) {
	id, err := k.FakeSigner.Verify(j, s, trusted)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(trusted, func(b []byte) bool { return bytes.Equal(b, []byte("trusted-key")) }) {
		return "", errors.New("untrusted key")
	}
	return id, nil
}

// TestVerifyReport: exit 0 for a good signature from a trusted key, 1
// for a changed report or an untrusted key, 2 for a missing file.
func TestVerifyReport(t *testing.T) {
	w := world(t)
	installDocs(t)
	t.Cleanup(core.SwapSigner(keySigner{}))
	dir := t.TempDir()
	report := filepath.Join(dir, "r.json")
	if err := os.WriteFile(report, []byte(`{"kind":"review"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (coretest.FakeSigner{}).Sign(report, ""); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "verify-report", report); code != cli.ExitFindings || !strings.Contains(errOut, "untrusted key") {
		t.Errorf("untrusted: exit %d %q", code, errOut)
	}
	w.Policy.Config = &core.Config{TrustedKeys: []string{"trusted-key"}}
	if code, out, _ := execute(t, "verify-report", report); code != cli.ExitOK || !strings.HasSuffix(out, "r.json: signature good, signed by fake\n") {
		t.Errorf("trusted_keys: exit %d %q", code, out)
	}
	if code, out, _ := execute(t, "verify-report", report, "--json"); code != cli.ExitOK || !strings.Contains(out, `"valid":true`) {
		t.Errorf("--json: exit %d %q", code, out)
	}
	if err := os.WriteFile(report, []byte(`{"kind":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "verify-report", report); code != cli.ExitFindings || !strings.Contains(errOut, "signature doesn't check out") {
		t.Errorf("changed: exit %d %q", code, errOut)
	}
	if code, _, errOut := execute(t, "verify-report", filepath.Join(dir, "none.json")); code != cli.ExitUsage || !strings.HasSuffix(errOut, "none.json: no such file\n") {
		t.Errorf("missing: exit %d %q", code, errOut)
	}
	_ = os.Remove(report + ".sig")
	if code, _, _ := execute(t, "verify-report", report); code != cli.ExitUsage {
		t.Errorf("missing signature: exit %d", code)
	}
}

// pruneBlobs is a blob store that records what Prune keeps.
type pruneBlobs struct {
	core.BlobStore
	kept map[[32]byte]bool
}

func (p *pruneBlobs) Prune(referenced map[[32]byte]bool, _ time.Duration) (int, int64, error) {
	p.kept = referenced
	return 2, 3 << 20, nil
}

// TestCachePrune: prune keeps every blob a live index names and drops
// old indexes.
func TestCachePrune(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	if code, _, errOut := execute(t, "all"); code != cli.ExitOK {
		t.Fatal(errOut)
	}
	pb := &pruneBlobs{BlobStore: w.Blobs}
	t.Cleanup(core.SwapBlobStore(func(string) (core.BlobStore, error) { return pb, nil }))
	code, out, _ := execute(t, "cache", "prune")
	if code != cli.ExitOK || out != "removed 0 archive indexes older than 30 days and 2 cached files nothing uses (3.0 MiB)\n" {
		t.Errorf("prune: exit %d %q", code, out)
	}
	tree := coretest.Tree(map[string]string{"main.php": "<?php // akismet 5.3.5\n"})
	if !pb.kept[tree.Files[0].SHA256] || len(pb.kept) != 2 {
		t.Errorf("kept %d blobs, want both versions' files", len(pb.kept))
	}
	code, out, _ = execute(t, "cache", "prune", "--older", "0s")
	if code != cli.ExitOK || !strings.HasPrefix(out, "removed 2 archive indexes (all of them) and ") || len(pb.kept) != 0 {
		t.Errorf("--older 0s: exit %d %q, kept %d", code, out, len(pb.kept))
	}
	if code, _, _ := execute(t, "cache"); code != cli.ExitUsage {
		t.Errorf("cache with no action: exit %d", code)
	}
}

// TestOlderText words --older for any age, never Go's duration form
// or "less than an hour".
func TestOlderText(t *testing.T) {
	for age, want := range map[time.Duration]string{
		0:                   "(all of them)",
		time.Second:         "older than 1 second",
		45 * time.Second:    "older than 45 seconds",
		time.Minute:         "older than 1 minute",
		30 * time.Minute:    "older than 30 minutes",
		30 * 24 * time.Hour: "older than 30 days",
	} {
		if got := olderText(age); got != want {
			t.Errorf("%v: %q, want %q", age, got, want)
		}
	}
}

// TestAllowListSanitises: an imported entry's fields reach the terminal
// escaped, never as raw control bytes (SR-10).
func TestAllowListSanitises(t *testing.T) {
	w := world(t)
	p := installAllow(t, w)
	esc := string(rune(0x1b))
	p.Allow = append(p.Allow, core.AllowEntry{Package: "npm:sh" + esc + "]0;x", Version: "1.0.0", SHA256: strings.Repeat("a", 64),
		By: "eve" + esc + "[2J", Date: "2026-10-01", Reason: "x" + esc + "[31mred\tcol\nrow"})
	code, out, errOut := execute(t, "allow", "list")
	if code != cli.ExitOK || strings.Contains(out, esc) {
		t.Fatalf("exit %d %q %q", code, out, errOut)
	}
	if strings.Count(out, "\n") != 2 {
		t.Errorf("a field broke a row:\n%s", out)
	}
	for _, want := range []string{`x\x1b[31mred\tcol\nrow`, `eve\x1b[2J`, `npm:sh\x1b]0;x@1.0.0`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
