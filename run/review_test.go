// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/run"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

func request(t *testing.T, command string) run.Request {
	t.Helper()
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	return run.Request{Command: command, Version: "test", CacheDir: t.TempDir(), Jobs: 4,
		Inventory: core.InventoryRequest{Root: t.TempDir()}}
}

func review(t *testing.T, req run.Request) *core.Report {
	t.Helper()
	rep, err := run.Review(context.Background(), req)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	return rep
}

func names(rep *core.Report) []string {
	var out []string
	for _, u := range rep.Updates {
		out = append(out, u.Name+" "+u.From.Version+"→"+u.To.Version+" "+string(u.Verdict))
	}
	return out
}

// TestReviewAll: every installed package with a newer version is
// reviewed once, up-to-date ones are left out and findings set the
// verdict.
func TestReviewAll(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Publish(core.WPPlugin, "hello", "1.7.2")
	w.Publish(core.WPPlugin, "countdown", "2.6.7", "2.6.8")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	w.Install(core.WPPlugin, "hello", "1.7.2")
	w.Install(core.WPPlugin, "countdown", "2.6.7")
	w.Detector.Set("countdown", "remote-fetch-exec")
	req := request(t, "all")
	rep := review(t, req)
	want := []string{"akismet 5.3.3→5.3.5 routine", "countdown 2.6.7→2.6.8 hold"}
	if got := names(rep); !reflect.DeepEqual(got, want) {
		t.Fatalf("updates %q, want %q", got, want)
	}
	if rep.Summary.Hold != 1 || rep.Summary.Routine != 1 || !rep.Complete {
		t.Errorf("summary %+v complete %v", rep.Summary, rep.Complete)
	}
	if rep.Target.Path != req.Inventory.Root || rep.MinConfidence != "likely" {
		t.Errorf("target %+v, min confidence %q", rep.Target, rep.MinConfidence)
	}
	if u := rep.Updates[1]; !u.To.Latest || u.To.Verified != core.ByChecksums || u.To.SHA256 == "" {
		t.Errorf("candidate side %+v", u.To)
	}
}

// TestCandidateSelection is PRD 5.3: the default per ecosystem, the
// keywords, dist-tags, prereleases, E3, E19 and the up-to-date note.
func TestCandidateSelection(t *testing.T) {
	cases := []struct {
		name, eco, to, from, constraint, want, err string
		tags                                       map[string]string
		pre, downgrade                             bool
	}{
		{name: "wp default is latest", eco: "wp-plugin", from: "1.0.0", want: "2.1.0"},
		{name: "wp latest is the info API version", eco: "wp-plugin", from: "1.0.0", tags: map[string]string{"latest": "2.0.0"}, want: "2.0.0"},
		{name: "composer default is wanted", eco: "composer", from: "1.0.0", constraint: "^1.0.0", want: "1.2.0"},
		{name: "composer latest", eco: "composer", from: "1.0.0", constraint: "^1.0.0", to: "latest", want: "2.1.0"},
		{name: "npm wanted takes a lower latest tag", eco: "npm", from: "1.0.0", constraint: "^1.0.0", tags: map[string]string{"latest": "1.1.0"}, want: "1.1.0"},
		{name: "npm wanted ignores a latest tag outside the range", eco: "npm", from: "1.0.0", constraint: "^1.0.0", tags: map[string]string{"latest": "2.1.0"}, want: "1.2.0"},
		{name: "dist-tag", eco: "npm", from: "1.0.0", to: "next", tags: map[string]string{"next": "3.0.0-beta.1"}, want: "3.0.0-beta.1"},
		{name: "exact", eco: "wp-plugin", from: "1.0.0", to: "1.2.0", want: "1.2.0"},
		{name: "pre lets latest pick a prerelease", eco: "wp-plugin", from: "1.0.0", pre: true, want: "3.0.0-beta.1"},
		{name: "installed", eco: "wp-plugin", from: "1.2.0", to: "installed", want: "up to date"},
		{name: "same version", eco: "wp-plugin", from: "2.1.0", want: "up to date"},
		{name: "unknown version is E3", eco: "wp-plugin", from: "1.0.0", to: "9.9.9",
			err: "rhythm sightread plugin: pkg has no version 9.9.9 on wordpress.org\n  newest: 2.1.0 · see them all: rhythm sightread plugin pkg --to list"},
		{name: "downgrade is E19", eco: "wp-plugin", from: "2.1.0", to: "1.0.0",
			err: "rhythm sightread plugin: --to 1.0.0 is older than the installed 2.1.0\n  add --allow-downgrade to review a downgrade"},
		{name: "allowed downgrade", eco: "wp-plugin", from: "2.1.0", to: "1.0.0", downgrade: true, want: "1.0.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := runtest.Install(t)
			eco := core.Ecosystem(c.eco)
			pkg := "pkg"
			if eco == core.Composer {
				pkg = "acme/pkg"
			}
			w.Publish(eco, pkg, "1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0", "3.0.0-beta.1")
			w.Sources[eco].TagMap[pkg] = c.tags
			inst := w.Install(eco, pkg, c.from)
			inst.Constraint = c.constraint
			req := request(t, "plugin")
			req.Eco, req.Names, req.To, req.Pre, req.AllowDowngrade = eco, []string{pkg}, c.to, c.pre, c.downgrade
			rep, err := run.Review(context.Background(), req)
			switch {
			case c.err != "":
				if err == nil || err.Error() != c.err {
					t.Fatalf("error %v, want %q", err, c.err)
				}
				return
			case err != nil:
				t.Fatal(err)
			case c.want == "up to date":
				if len(rep.Updates) != 0 || len(rep.Notes) != 1 || !strings.HasSuffix(rep.Notes[0], run.NothingToCompare) {
					t.Fatalf("updates %v notes %q", names(rep), rep.Notes)
				}
				return
			}
			if len(rep.Updates) != 1 || rep.Updates[0].To.Version != c.want {
				t.Fatalf("updates %v, want → %s", names(rep), c.want)
			}
		})
	}
}

// TestAlreadyLatestText is PRD 6.1's exact text.
func TestAlreadyLatestText(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.5")
	req := request(t, "plugin")
	req.Eco, req.Names = core.WPPlugin, []string{"akismet"}
	rep := review(t, req)
	if want := []string{"akismet 5.3.5 is already the latest: nothing to compare"}; !reflect.DeepEqual(rep.Notes, want) {
		t.Errorf("notes %q, want %q", rep.Notes, want)
	}
}

// TestMissingSlugIsE1: a named plugin the site doesn't have, without
// --from.
func TestMissingSlugIsE1(t *testing.T) {
	runtest.Install(t)
	req := request(t, "plugin")
	req.Eco, req.Names = core.WPPlugin, []string{"countdown-timer-ultimate"}
	_, err := run.Review(context.Background(), req)
	want := "rhythm sightread plugin: no installed countdown-timer-ultimate under " + req.Inventory.Root + "\n" +
		`  name the site with --path /var/www/site, read it with --wp "wp --path=..." or give the version: --from <version>`
	if err == nil || err.Error() != want || core.CodeOf(err) != core.ENothingInstalled {
		t.Fatalf("error %v, want %q", err, want)
	}
	var e *core.Error
	if !errors.As(err, &e) || e.ExitCode() != cli.ExitUsage {
		t.Errorf("exit code of %v", err)
	}
}

// TestFromNeedsNoSite: --from reviews a version without any inventory.
func TestFromNeedsNoSite(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Inventory.Err = errors.New("the inventory must not be read")
	req := request(t, "plugin")
	req.Eco, req.Names, req.From = core.WPPlugin, []string{"akismet"}, "5.3.3"
	if got := names(review(t, req)); !reflect.DeepEqual(got, []string{"akismet 5.3.3→5.3.5 routine"}) {
		t.Errorf("updates %q", got)
	}
}

// TestPrivateNamesStayLocal is SR-8: a private package no configured
// registry serves never reaches a source or OSV; it is Not checked.
func TestPrivateNamesStayLocal(t *testing.T) {
	w := runtest.Install(t)
	w.Inventory.Site.Kind = "npm"
	w.Publish(core.NPM, "left-pad", "1.0.0", "1.1.0")
	w.Publish(core.NPM, "@acme/billing", "1.0.0", "9.0.0")
	w.Install(core.NPM, "left-pad", "1.0.0")
	w.Install(core.NPM, "@acme/billing", "1.0.0").Private = true
	w.Inventory.Site.Installed = append(w.Inventory.Site.Installed, core.Installed{
		Ref: core.Ref{Eco: core.WPPlugin, Name: "acme-internal", Version: "1.0.0"}, Private: true})
	w.Inventory.Site.NotChecked = []core.NotChecked{{Eco: core.WPPlugin, Name: "acme-internal", Reason: core.NotWPOrg}}
	w.Publish(core.WPPlugin, "acme-internal", "1.0.0", "2.0.0")
	rep := review(t, request(t, "all"))
	for eco, s := range w.Sources {
		for _, n := range s.Names() {
			if n == "@acme/billing" || n == "acme-internal" {
				t.Errorf("%s source was asked about private %s", eco, n)
			}
		}
	}
	for _, ref := range w.Advisories.Asked() {
		if ref.Name == "@acme/billing" {
			t.Errorf("OSV was asked about %s", ref)
		}
	}
	if got := names(rep); !reflect.DeepEqual(got, []string{"left-pad 1.0.0→1.1.0 routine"}) {
		t.Errorf("updates %q", got)
	}
	reasons := map[string]core.NotCheckedReason{}
	for _, n := range rep.NotChecked {
		reasons[n.Name] = n.Reason
	}
	if reasons["@acme/billing"] != core.Private || reasons["acme-internal"] != core.NotWPOrg {
		t.Errorf("not checked %+v", rep.NotChecked)
	}
	if slices.Contains(rep.Warnings, "dependency-confusion") {
		t.Errorf("warnings %q", rep.Warnings)
	}
}

// TestCheckConfusion: with --check-confusion a private package served by
// its configured registry is also looked up publicly and a higher public
// version lands in Meta.PublicShadow.
func TestCheckConfusion(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[on], func(t *testing.T) {
			w := runtest.Install(t)
			w.Policy.Config = &core.Config{Sources: core.SourcesConfig{NPM: core.NPMSourceConfig{
				Scopes: map[string]string{"@acme": "https://npm.acme.example"}}}}
			w.Publish(core.NPM, "@acme/billing", "1.0.0", "1.1.0", "9.0.0")
			inst := w.Install(core.NPM, "@acme/billing", "1.0.0")
			inst.Private, inst.Constraint = true, "^1.0.0"
			req := request(t, "npm")
			req.Eco, req.Options.CheckConfusion = core.NPM, on
			rep := review(t, req)
			if got := names(rep); !reflect.DeepEqual(got, []string{"@acme/billing 1.0.0→1.1.0 routine"}) {
				t.Fatalf("updates %q", got)
			}
			subj := w.Detector.Subjects()
			if len(subj) != 1 {
				t.Fatalf("%d subjects", len(subj))
			}
			want := map[bool]string{false: "", true: "9.0.0"}[on]
			if subj[0].New.PublicShadow != want {
				t.Errorf("PublicShadow %q, want %q", subj[0].New.PublicShadow, want)
			}
			if asked := w.Advisories.Asked(); len(asked) != 0 {
				t.Errorf("OSV asked about private %v", asked)
			}
		})
	}
}

// TestFleetDedupe: a plugin at the same version on three sites is
// fetched and analysed once and lists all three sites.
func TestFleetDedupe(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "wpforms-lite", "1.9.1", "1.9.2")
	w.Install(core.WPPlugin, "wpforms-lite", "1.9.1")
	req := request(t, "all")
	for _, s := range []string{"shop", "brochure", "blog"} {
		req.Sites = append(req.Sites, run.Site{Name: s, Inventory: core.InventoryRequest{Root: t.TempDir()}})
	}
	rep := review(t, req)
	if len(rep.Updates) != 1 {
		t.Fatalf("updates %q", names(rep))
	}
	if got := rep.Updates[0].Sites; !reflect.DeepEqual(got, []string{"shop", "brochure", "blog"}) {
		t.Errorf("sites %q", got)
	}
	if n := w.Sources[core.WPPlugin].Fetches(); n != 2 {
		t.Errorf("%d fetches, want 2 (one per version)", n)
	}
	if n := len(w.Detector.Subjects()); n != 1 {
		t.Errorf("analysed %d times, want once", n)
	}
	if !reflect.DeepEqual(rep.Target.Sites, []string{"shop", "brochure", "blog"}) || rep.Target.Kind != "fleet" {
		t.Errorf("target %+v", rep.Target)
	}
}

// TestArchiveIndexReuse: a second run of the same pair downloads
// nothing and says it came from the cache.
func TestArchiveIndexReuse(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	req := request(t, "all")
	first := review(t, req)
	if n := w.Sources[core.WPPlugin].Fetches(); n != 2 || first.Updates[0].FromCache {
		t.Fatalf("first run: %d fetches, from cache %v", n, first.Updates[0].FromCache)
	}
	second := review(t, req)
	if n := w.Sources[core.WPPlugin].Fetches(); n != 2 {
		t.Errorf("second run fetched %d more", n-2)
	}
	if u := second.Updates[0]; !u.FromCache || second.Summary.FromCache != 1 || u.To.SHA256 != first.Updates[0].To.SHA256 {
		t.Errorf("second run: %+v", u)
	}
}

// TestSVNCheckSkipsTLSCache: a theme cached by TLS alone is fetched and
// checked again for --svn-check, the svn result is cached and reused,
// and a run without --svn-check still reuses the TLS entry of a plugin.
func TestSVNCheckSkipsTLSCache(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPTheme, "astra", "4.8.0", "4.8.1")
	w.Install(core.WPTheme, "astra", "4.8.0")
	src := w.Sources[core.WPTheme]
	refs := []core.Ref{{Eco: core.WPTheme, Name: "astra", Version: "4.8.0"}, {Eco: core.WPTheme, Name: "astra", Version: "4.8.1"}}
	set := func(in core.Integrity) {
		for _, r := range refs {
			src.Integrity[r] = in
		}
	}
	set(core.Integrity{By: core.ByTLS, Method: "TLS only"})
	req := request(t, "all")
	if u := review(t, req).Updates[0]; u.To.Verified != core.ByTLS || src.Fetches() != 2 {
		t.Fatalf("first run: verified %s, %d fetches", u.To.Verified, src.Fetches())
	}
	// Without --svn-check the TLS entry is enough.
	if u := review(t, req).Updates[0]; !u.FromCache || src.Fetches() != 2 {
		t.Fatalf("second run: from cache %v, %d fetches", u.FromCache, src.Fetches())
	}
	// A check that could not finish is not cached.
	req.Options.SVNCheck = true
	set(core.Integrity{By: core.ByTLS, Method: "TLS only", Detail: "--svn-check could not finish: timeout"})
	if u := review(t, req).Updates[0]; u.FromCache || src.Fetches() != 4 {
		t.Fatalf("svn run that could not finish: from cache %v, %d fetches", u.FromCache, src.Fetches())
	}
	set(core.Integrity{By: core.BySVN, Method: "svn"})
	if u := review(t, req).Updates[0]; u.FromCache || u.To.Verified != core.BySVN || src.Fetches() != 6 {
		t.Fatalf("svn run: from cache %v, verified %s, %d fetches", u.FromCache, u.To.Verified, src.Fetches())
	}
	if u := review(t, req).Updates[0]; !u.FromCache || u.To.Verified != core.BySVN || src.Fetches() != 6 {
		t.Fatalf("second svn run: from cache %v, verified %s, %d fetches", u.FromCache, u.To.Verified, src.Fetches())
	}
	// The svn entry serves a run without --svn-check too.
	req.Options.SVNCheck = false
	if u := review(t, req).Updates[0]; !u.FromCache || u.To.Verified != core.BySVN {
		t.Fatalf("plain run after svn: from cache %v, verified %s", u.FromCache, u.To.Verified)
	}
}

// TestSignalDirsCheckedFirst: the --signals folders reach the detectors'
// config check, and its error stops the run before any download.
func TestSignalDirsCheckedFirst(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	req := request(t, "all")
	req.SignalDirs = []string{"/rules"}
	review(t, req)
	if got := w.Detector.Checked(); len(got) != 1 || !slices.Equal(got[0], []string{"/rules"}) {
		t.Fatalf("checked %q", got)
	}
	w.Detector.ConfigErr = &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: "bad rule"}
	before := w.Sources[core.WPPlugin].Fetches()
	_, err := run.Review(context.Background(), req)
	if core.CodeOf(err) != core.EBadConfig {
		t.Fatalf("error %v, want E12", err)
	}
	if n := w.Sources[core.WPPlugin].Fetches(); n != before {
		t.Errorf("%d fetches after a bad --signals folder", n-before)
	}
}

// TestTreeMetaFromCache: what a source reads from the release's files
// is filled again for a cached tree, so a second run reports the same;
// the changelog keeps only the entries newer than the installed side.
func TestTreeMetaFromCache(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.4", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	w.Sources[core.WPPlugin].TreeMeta = func(m *core.Meta, _ *core.Tree) {
		m.Changelog = []core.ChangelogEntry{{Version: "5.3.5", Text: "c"}, {Version: "5.3.4", Text: "b"}, {Version: "5.3.3", Text: "a"}}
	}
	req := request(t, "all")
	for i := range 2 {
		u := review(t, req).Updates[0]
		var got []string
		for _, e := range u.Changelog {
			got = append(got, e.Version)
		}
		if u.FromCache != (i == 1) || !slices.Equal(got, []string{"5.3.5", "5.3.4"}) {
			t.Errorf("run %d: from cache %v, changelog %v", i+1, u.FromCache, got)
		}
	}
}

// TestTLSDetail: a theme verified by TLS because --svn-check could not
// finish says why next to the method; one verified by TLS alone, or by
// the check, shows the method only.
func TestTLSDetail(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPTheme, "astra", "4.8.0", "4.8.1")
	src := w.Sources[core.WPTheme]
	src.Integrity[core.Ref{Eco: core.WPTheme, Name: "astra", Version: "4.8.1"}] =
		core.Integrity{By: core.ByTLS, Method: "TLS only", Detail: "--svn-check could not finish: timeout"}
	src.Integrity[core.Ref{Eco: core.WPTheme, Name: "astra", Version: "4.8.0"}] = core.Integrity{By: core.ByTLS, Method: "TLS only"}
	w.Install(core.WPTheme, "astra", "4.8.0")
	u := review(t, request(t, "all")).Updates[0]
	if u.To.Method != "TLS only (--svn-check could not finish: timeout)" || u.From.Method != "TLS only" {
		t.Errorf("to %q from %q", u.To.Method, u.From.Method)
	}
}

// TestUnverified: a side with no integrity check is UNVERIFIED and not
// diffed, unless --allow-unverified, when it is diffed and still marked.
func TestUnverified(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "allow-unverified"}[allow], func(t *testing.T) {
			w := runtest.Install(t)
			w.Publish(core.WPTheme, "astra", "4.8.0", "4.8.1")
			w.Sources[core.WPTheme].Integrity[core.Ref{Eco: core.WPTheme, Name: "astra", Version: "4.8.1"}] =
				core.Integrity{By: core.ByNone, Detail: "wordpress.org checksums answered 503"}
			w.Install(core.WPTheme, "astra", "4.8.0")
			w.Detector.Set("astra", "eval-dynamic", "unanalysed")
			req := request(t, "all")
			req.AllowUnverified = allow
			rep := review(t, req)
			if len(rep.Updates) != 1 {
				t.Fatalf("updates %q", names(rep))
			}
			u := rep.Updates[0]
			if u.Verdict != core.Unverified || u.To.Verified != core.ByNone {
				t.Errorf("verdict %s verified %s", u.Verdict, u.To.Verified)
			}
			subs := w.Detector.Subjects()
			diffed := len(subs) == 1 && subs[0].Diff != nil
			if diffed != allow {
				t.Errorf("diffed %v with --allow-unverified %v", diffed, allow)
			}
			// Not diffed, the archive's own findings stay and the code
			// findings, which need the diff, are left out.
			var ids []string
			for _, f := range u.Findings {
				ids = append(ids, f.ID)
			}
			if want := map[bool][]string{false: {"unanalysed"}, true: {"eval-dynamic", "unanalysed"}}[allow]; !reflect.DeepEqual(ids, want) {
				t.Errorf("findings %q, want %q", ids, want)
			}
			if !allow && (len(u.Errors) != 1 || u.Errors[0].Code != core.EUnverifiable ||
				u.Errors[0].Message != "couldn't verify astra 4.8.1: wordpress.org checksums answered 503") {
				t.Errorf("errors %+v", u.Errors)
			}
		})
	}
}

// TestDriftNotWPOrg: an installed copy that shares a slug but not the
// files becomes Not checked not-wporg instead of being diffed; a copy
// with a few local edits is reviewed with its drift recorded.
func TestDriftNotWPOrg(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "gravityforms", "2.9.0", "2.9.1")
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	gf := w.Install(core.WPPlugin, "gravityforms", "2.9.0")
	gf.Path = "wp-content/plugins/gravityforms"
	ak := w.Install(core.WPPlugin, "akismet", "5.3.3")
	ak.Path = "wp-content/plugins/akismet"
	req := request(t, "all")
	root := req.Inventory.Root
	w.Inventory.Dirs = map[string]map[string]string{
		filepath.Join(root, "wp-content", "plugins", "gravityforms"): {"gravityforms.php": "<?php // the vendor's own plugin\n", "a.php": "x"},
		filepath.Join(root, "wp-content", "plugins", "akismet"):      {"main.php": "<?php // edited on the server\n"},
	}
	w.Sources[core.WPPlugin].Trees[core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.3"}] =
		map[string]string{"main.php": "<?php // akismet 5.3.3\n", "readme.txt": "r", "class.php": "c"}
	w.Inventory.Dirs[filepath.Join(root, "wp-content", "plugins", "akismet")]["readme.txt"] = "r"
	w.Inventory.Dirs[filepath.Join(root, "wp-content", "plugins", "akismet")]["class.php"] = "c"
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"akismet 5.3.3→5.3.5 routine"}) {
		t.Fatalf("updates %q", got)
	}
	if u := rep.Updates[0]; !u.Installed.Drift || !reflect.DeepEqual(u.Installed.DriftFiles, []string{"main.php"}) {
		t.Errorf("installed %+v", u.Installed)
	}
	if len(rep.NotChecked) != 1 || rep.NotChecked[0].Name != "gravityforms" || rep.NotChecked[0].Reason != core.NotWPOrg {
		t.Errorf("not checked %+v", rep.NotChecked)
	}
	for _, s := range w.Detector.Subjects() {
		if s.Update.Name == "akismet" && (s.Drift == nil || len(s.Drift.Differ) != 1) {
			t.Errorf("subject drift %+v", s.Drift)
		}
	}
}

// TestDeterministicOrder: random latencies never change the report.
func TestDeterministicOrder(t *testing.T) {
	w := runtest.Install(t)
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		w.Publish(core.WPPlugin, n, "1.0.0", "1.1.0")
		w.Install(core.WPPlugin, n, "1.0.0")
		if n < "d" {
			w.Detector.Set(n, "outbound-new-domain", "eval-dynamic")
		}
	}
	w.Sources[core.WPPlugin].Delay = func() time.Duration { return time.Duration(rand.IntN(400)) * time.Microsecond }
	req := request(t, "all")
	req.Jobs = 8
	var first []string
	for i := range 20 {
		req.CacheDir = t.TempDir()
		got := names(review(t, req))
		if i == 0 {
			first = got
			continue
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d: %q, first %q", i, got, first)
		}
	}
}

// TestInterrupt: the first stop lets the packages under way finish and
// lists the rest as not reviewed; the hard stop returns at once.
func TestInterrupt(t *testing.T) {
	setup := func(t *testing.T, delay time.Duration) (*runtest.World, run.Request) {
		w := runtest.Install(t)
		for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
			w.Publish(core.WPPlugin, n, "1.0.0", "1.1.0")
			w.Install(core.WPPlugin, n, "1.0.0")
		}
		req := request(t, "all")
		req.Jobs = 1
		w.Sources[core.WPPlugin].Delay = func() time.Duration { return delay }
		return w, req
	}
	t.Run("soft", func(t *testing.T) {
		_, req := setup(t, 5*time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		var once bool
		req.Progress = writerFunc(func(p []byte) {
			if !once && strings.HasPrefix(string(p), "reviewing 2 of 6") {
				once = true
				cancel()
			}
		})
		rep, err := run.Review(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if rep.StoppedBy != run.StoppedInterrupted || rep.Complete {
			t.Errorf("stopped by %q complete %v", rep.StoppedBy, rep.Complete)
		}
		if len(rep.Updates) != 2 || len(rep.NotChecked) != 4 {
			t.Fatalf("updates %q not checked %+v", names(rep), rep.NotChecked)
		}
		if nc := rep.NotChecked[0]; nc.Text != "the run was interrupted before it was reviewed" || nc.Reason != core.FetchFailed {
			t.Errorf("not checked %+v", nc)
		}
	})
	t.Run("hard", func(t *testing.T) {
		_, req := setup(t, 2*time.Second)
		stop := make(chan struct{})
		req.HardStop = stop
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
			close(stop)
		}()
		start := time.Now()
		rep, err := run.Review(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("the hard stop took %v", d)
		}
		if rep.StoppedBy != run.StoppedInterrupted || len(rep.Updates) != 0 || len(rep.NotChecked) != 6 {
			t.Errorf("stopped by %q, updates %q, not checked %d", rep.StoppedBy, names(rep), len(rep.NotChecked))
		}
	})
}

// TestDeadline: --deadline ends the run and says so.
func TestDeadline(t *testing.T) {
	w := runtest.Install(t)
	for _, n := range []string{"a", "b", "c"} {
		w.Publish(core.WPPlugin, n, "1.0.0", "1.1.0")
		w.Install(core.WPPlugin, n, "1.0.0")
	}
	w.Sources[core.WPPlugin].Delay = func() time.Duration { return 30 * time.Millisecond }
	req := request(t, "all")
	req.Jobs, req.Deadline = 1, 100*time.Millisecond
	rep := review(t, req)
	if rep.StoppedBy != run.StoppedDeadline || len(rep.NotChecked) == 0 {
		t.Fatalf("stopped by %q, updates %q, not checked %+v", rep.StoppedBy, names(rep), rep.NotChecked)
	}
	if nc := rep.NotChecked[len(rep.NotChecked)-1]; nc.Text != "--deadline 100ms passed before it was reviewed" {
		t.Errorf("not checked %+v", nc)
	}
}

// TestLocalFiles: config local_files picks the newest vendor zip above
// the installed version and reviews it as --to-file; no match leaves
// the plugin not checked.
func TestLocalFiles(t *testing.T) {
	w := runtest.Install(t)
	zips := t.TempDir()
	for _, v := range []string{"2.8.0", "2.9.1", "2.9.10", "2.9.2"} {
		if err := os.WriteFile(filepath.Join(zips, "gravityforms-"+v+".zip"), []byte("zip "+v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.Policy.Config = &core.Config{LocalFiles: map[string]string{
		"gravityforms": filepath.ToSlash(zips) + "/gravityforms-{version}.zip",
		"acf-pro":      filepath.ToSlash(zips) + "/acf-pro-{version}.zip",
	}}
	var read []string
	t.Cleanup(core.SwapLocalArchive(func(_ context.Context, path string, _ core.BlobStore, _ core.Limits) (*core.Tree, error) {
		read = append(read, filepath.Base(path))
		return runtestTree(path), nil
	}))
	w.Inventory.Site.NotChecked = []core.NotChecked{
		{Eco: core.WPPlugin, Name: "gravityforms", Version: "2.9.0", Reason: core.NotWPOrg},
		{Eco: core.WPPlugin, Name: "acf-pro", Version: "6.0.0", Reason: core.NotWPOrg},
	}
	req := request(t, "all")
	w.Inventory.Dirs = map[string]map[string]string{
		filepath.Join(req.Inventory.Root, "wp-content", "plugins", "gravityforms"): {"gravityforms.php": "<?php // 2.9.0\n"},
	}
	req.AllowUnverified = true
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"gravityforms 2.9.0→2.9.10 unverified"}) {
		t.Fatalf("updates %q, not checked %+v", got, rep.NotChecked)
	}
	if !reflect.DeepEqual(read, []string{"gravityforms-2.9.10.zip"}) {
		t.Errorf("read %q", read)
	}
	if u := rep.Updates[0]; u.To.Source != "local file" || u.From.Source != "installed copy" {
		t.Errorf("sides %+v %+v", u.From, u.To)
	}
	if len(rep.NotChecked) != 1 || rep.NotChecked[0].Name != "acf-pro" {
		t.Errorf("not checked %+v", rep.NotChecked)
	}
	if n := len(w.Sources[core.WPPlugin].Names()); n != 0 {
		t.Errorf("the WordPress.org source was asked %d times", n)
	}
}

func runtestTree(path string) *core.Tree {
	b, _ := os.ReadFile(path) //nolint:gosec // the test's own file
	t := coretest.Tree(map[string]string{"gravityforms.php": string(b)})
	t.HashKind = core.HashArchive
	return t
}

// TestTooLarge: a download over --max-size is Not checked too-large with
// the hint to raise it.
func TestTooLarge(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.NPM, "huge-pkg", "1.3.0", "1.4.0")
	w.Install(core.NPM, "huge-pkg", "1.3.0")
	t.Cleanup(core.SwapSource(core.NPM, func(*core.Env) core.Source {
		return tooLarge{w.Sources[core.NPM]}
	}))
	req := request(t, "npm")
	req.Eco = core.NPM
	rep := review(t, req)
	want := core.NotChecked{Eco: core.NPM, Name: "huge-pkg", Version: "1.3.0", Reason: core.TooLarge,
		Text: "the 1.4.0 tarball of huge-pkg is over 256 MiB", Hint: "raise --max-size"}
	if len(rep.NotChecked) != 1 || !reflect.DeepEqual(rep.NotChecked[0], want) {
		t.Errorf("not checked %+v", rep.NotChecked)
	}
}

type tooLarge struct{ *runtest.Source }

func (s tooLarge) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	if m.Ref.Version == "1.4.0" {
		return nil, core.Integrity{}, &core.Error{Code: core.ETooLarge, Exit: cli.ExitUnavailable,
			What: "the 1.4.0 tarball of huge-pkg is over 256 MiB", Err: core.ErrTooLarge}
	}
	return s.Source.Fetch(ctx, m)
}

// TestRunsKept: every review is saved under runs/ and only the newest
// 20 stay.
func TestRunsKept(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	req := request(t, "all")
	start := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	i := 0
	req.Now = func() time.Time { return start.Add(time.Duration(i) * time.Minute) }
	for i = range 23 {
		review(t, req)
	}
	entries, err := os.ReadDir(run.RunsDir(req.CacheDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != run.RunsKept {
		t.Fatalf("%d saved runs, want %d", len(entries), run.RunsKept)
	}
	if entries[0].Name() != "20261026T090300.000Z.json" {
		t.Errorf("oldest kept %s", entries[0].Name())
	}
	if fi, err := entries[0].Info(); err == nil && fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if n := len(w.Writers[core.FormatJSON].Got()); n != 23 {
		t.Errorf("json writer called %d times", n)
	}
}

// TestFilters: --exclude-id and --severity drop findings after scoring
// and the verdict follows; integrity-mismatch can never be dropped.
func TestFilters(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "a", "1.0.0", "1.1.0")
	w.Publish(core.WPPlugin, "b", "1.0.0", "1.1.0")
	w.Install(core.WPPlugin, "a", "1.0.0")
	w.Install(core.WPPlugin, "b", "1.0.0")
	w.Detector.Set("a", "remote-fetch-exec", "cron-new-hook")
	w.Detector.Set("b", "integrity-mismatch")
	req := request(t, "all")
	req.ExcludeIDs, req.Severity = []string{"remote-*", "integrity-mismatch"}, cli.SeverityMedium
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"a 1.0.0→1.1.0 routine", "b 1.0.0→1.1.0 hold"}) {
		t.Fatalf("updates %q", got)
	}
	if n := len(rep.Updates[0].Findings); n != 0 {
		t.Errorf("a kept %d findings", n)
	}
	if f := rep.Updates[1].Findings; len(f) != 1 || f[0].ID != "integrity-mismatch" {
		t.Errorf("b findings %+v", f)
	}
}

// TestChanges: a lockfile change reviews moved and added packages, an
// added one with no from side.
func TestChanges(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.NPM, "axios", "1.14.0", "1.14.1")
	w.Publish(core.NPM, "plain-crypto-js", "4.2.1")
	from := core.Installed{Ref: core.Ref{Eco: core.NPM, Name: "axios", Version: "1.14.0"}, Lockfile: "package-lock.json"}
	w.Inventory.Bumps = []core.Bump{
		{From: &from, To: core.Installed{Ref: core.Ref{Eco: core.NPM, Name: "axios", Version: "1.14.1"}, Lockfile: "package-lock.json"}},
		{To: core.Installed{Ref: core.Ref{Eco: core.NPM, Name: "plain-crypto-js", Version: "4.2.1"}}},
	}
	w.Detector.Set("plain-crypto-js", "npm-install-script-new")
	req := request(t, "changes")
	req.Changes = &core.ChangesRequest{Before: "a.json", After: "b.json"}
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"axios 1.14.0→1.14.1 routine", "plain-crypto-js →4.2.1 review"}) {
		t.Fatalf("updates %q", got)
	}
	for _, s := range w.Detector.Subjects() {
		if s.Update.Name == "plain-crypto-js" && (s.Old != nil || s.OldTree != nil || s.NewLock == nil) {
			t.Errorf("added package subject %+v", s)
		}
	}
}

// TestOSVBatch: advisories are asked once for both sides of every
// public update and reach the subject.
func TestOSVBatch(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.NPM, "left-pad", "1.0.0", "1.1.0")
	w.Install(core.NPM, "left-pad", "1.0.0")
	to := core.Ref{Eco: core.NPM, Name: "left-pad", Version: "1.1.0"}
	w.Advisories.By = map[core.Ref][]core.Advisory{to: {{ID: "MAL-2026-1", Malicious: true}}}
	req := request(t, "npm")
	req.Eco = core.NPM
	review(t, req)
	asked := w.Advisories.Asked()
	if len(asked) != 2 {
		t.Errorf("asked %v", asked)
	}
	if s := w.Detector.Subjects(); len(s) != 1 || len(s[0].New.Advisories) != 1 {
		t.Errorf("advisories did not reach the subject")
	}
	req.NoOSV = true
	review(t, req)
	if n := len(w.Advisories.Asked()); n != 2 {
		t.Errorf("--no-osv still asked (%d)", n)
	}
}

// TestListVersions is --to list: newest first.
func TestListVersions(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.10.0", "5.3.5")
	req := request(t, "plugin")
	req.Eco, req.Names = core.WPPlugin, []string{"akismet"}
	got, err := run.ListVersions(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Versions, []string{"5.10.0", "5.3.5", "5.3.3"}) {
		t.Errorf("versions %+v", got)
	}
}

type writerFunc func(p []byte)

func (f writerFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

// unpubSource is a fake npm source that says which versions were
// unpublished.
type unpubSource struct {
	*runtest.Source
	gone map[string]bool
}

func (u unpubSource) Unpublished(_ context.Context, _, v string) bool { return u.gone[v] }

// TestToUnpublished: --to naming a version that was taken down says so;
// one that never existed keeps the usual E3.
func TestToUnpublished(t *testing.T) {
	for to, want := range map[string]string{
		"1.0.1": "rhythm sightread npm: lib 1.0.1 was unpublished from registry.npmjs.org\n  newest: 1.0.0 · see them all: rhythm sightread npm lib --to list",
		"9.9.9": "rhythm sightread npm: lib has no version 9.9.9 on registry.npmjs.org\n  newest: 1.0.0 · see them all: rhythm sightread npm lib --to list",
	} {
		w := runtest.Install(t)
		w.Publish(core.NPM, "lib", "1.0.0")
		w.Install(core.NPM, "lib", "1.0.0")
		src := unpubSource{Source: w.Sources[core.NPM], gone: map[string]bool{"1.0.1": true}}
		t.Cleanup(core.SwapSource(core.NPM, func(*core.Env) core.Source { return src }))
		req := request(t, "npm")
		req.Eco, req.Names, req.To = core.NPM, []string{"lib"}, to
		_, err := run.Review(context.Background(), req)
		if err == nil || err.Error() != want || core.CodeOf(err) != core.EVersionMissing {
			t.Errorf("--to %s: %v, want %q", to, err, want)
		}
	}
}
