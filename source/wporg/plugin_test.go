// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	_ "github.com/RhythmShahriar/sightread/diff" // the one drift rule VerifyLocal uses
	"github.com/RhythmShahriar/sightread/fetch"
)

// akismetInfo is a plugin info answer in the shape api.wordpress.org
// serves (fields copied by hand, values made up, sections cut short).
const akismetInfo = `{
  "name": "Akismet Anti-spam: Spam Protection",
  "slug": "akismet",
  "version": "5.3.5",
  "author": "<a href=\"https://automattic.com/wordpress-plugins/\">Automattic &#8211; Anti-spam Team</a>",
  "author_profile": "https://profiles.wordpress.org/automattic/",
  "contributors": {
    "automattic": {"profile": "https://profiles.wordpress.org/automattic/", "avatar": "https://secure.gravatar.com/avatar/x", "display_name": "Automattic"},
    "kbrownkd": {"profile": "https://profiles.wordpress.org/kbrownkd/", "avatar": "https://secure.gravatar.com/avatar/y", "display_name": "kbrownkd"}
  },
  "requires": "5.8",
  "tested": "6.6.2",
  "requires_php": "5.6.20",
  "requires_plugins": [],
  "rating": 92,
  "ratings": {"5": 900, "4": 40},
  "num_ratings": 1000,
  "active_installs": 6000000,
  "last_updated": "2024-10-01 3:52pm GMT",
  "added": "2005-10-24",
  "homepage": "https://akismet.com/",
  "sections": {"description": "<p>Akismet checks your comments.</p>", "changelog": "<h4>5.3.5</h4>"},
  "download_link": "https://downloads.wordpress.org/plugin/akismet.5.3.5.zip",
  "upgrade_notice": [],
  "screenshots": [],
  "tags": {"spam": "spam"},
  "versions": {
    "5.3.3": "https://downloads.wordpress.org/plugin/akismet.5.3.3.zip",
    "5.3.4": "https://downloads.wordpress.org/plugin/akismet.5.3.4.zip",
    "5.3.5": "https://downloads.wordpress.org/plugin/akismet.5.3.5.zip",
    "trunk": "https://downloads.wordpress.org/plugin/akismet.zip"
  },
  "business_model": false,
  "banners": {"low": "https://ps.w.org/akismet/assets/banner-772x250.png", "high": false},
  "a_field_from_next_year": {"nested": [1, 2, 3]}
}`

// closedInfo is the 404 body of a closed plugin.
const closedInfo = `{"error": "closed", "name": "Countdown Timer Ultimate", "slug": "countdown-timer-ultimate",
  "description": "This plugin has been closed as of June 3, 2025 and is not available for download. Reason: Security Issue.",
  "closed": true, "closed_date": "2025-06-03", "reason": "security-issue", "reason_text": "Security Issue"}`

var akismetFiles = map[string]string{
	"akismet.php":             "<?php /* Plugin Name: Akismet */",
	"class.akismet.php":       "<?php class Akismet {}",
	"views/config.php":        "<?php // settings",
	"readme.txt":              "=== Akismet ===\nStable tag: 5.3.5\n",
	"_inc/akismet-admin.js":   "jQuery(function(){});",
	"_inc/img/logo-a-2x.png":  "\x89PNG",
	"languages/akismet.pot":   "msgid \"\"",
	"wrapper.php":             "<?php // wrapper",
	"changelog.txt":           "= 5.3.5 =\n* Fix",
	"class.akismet-admin.php": "<?php class Akismet_Admin {}",
}

// akismet sets up the registry for akismet 5.3.5 with files in the zip
// and sums in the checksums.
func akismet(t *testing.T, r *registry, files, sums map[string]string) {
	t.Helper()
	r.info["plugins/akismet"] = akismetInfo
	r.zips["plugin/akismet.5.3.5.zip"] = makeZip(t, "akismet", files)
	r.checksums["akismet/5.3.5"] = checksumsJSON(t, "akismet", "5.3.5", sums)
	r.dav["/akismet/tags/5.3.5/"] = davOne("/akismet/tags/5.3.5/", "automattic", "2024-10-01T15:52:01.123456Z")
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestPluginRegistered(t *testing.T) {
	src := core.SourceFor(core.WPPlugin, &core.Env{})
	if _, ok := src.(*Plugin); !ok || src.Eco() != core.WPPlugin {
		t.Fatalf("wp-plugin source is %T", src)
	}
}

func TestPluginVerified(t *testing.T) {
	r := newRegistry()
	akismet(t, r, akismetFiles, akismetFiles)
	env := start(t, r, core.SourceOptions{})
	p := NewPlugin(env)
	ctx := context.Background()

	vs, err := p.Versions(ctx, "akismet")
	if err != nil || strings.Join(vs, " ") != "5.3.3 5.3.4 5.3.5" {
		t.Fatalf("Versions = %v, %v", vs, err)
	}
	m, err := p.Meta(ctx, core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Contributors, ",") != "automattic,kbrownkd" || m.Author != "Automattic – Anti-spam Team" ||
		m.AuthorProfile != "https://profiles.wordpress.org/automattic/" || m.RequiresPHP != "5.6.20" ||
		m.Homepage != "https://akismet.com/" || m.Latest != "5.3.5" || m.Closed {
		t.Errorf("meta %+v", m)
	}
	if m.Publisher == nil || m.Publisher.Login != "automattic" {
		t.Errorf("publisher %+v", m.Publisher)
	}
	if want := time.Date(2024, 10, 1, 15, 52, 1, 123456000, time.UTC); !m.Published.Equal(want) {
		t.Errorf("published %v, want the SVN tag's date %v", m.Published, want)
	}
	if len(m.History) != 2 || m.History[0].Version != "5.3.4" || m.History[1].Version != "5.3.3" {
		t.Errorf("history %+v", m.History)
	}
	if !strings.HasSuffix(m.Archive.URL, "/plugin/akismet.5.3.5.zip") {
		t.Errorf("archive %s", m.Archive.URL)
	}

	tree, in, err := p.Fetch(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if in.By != core.ByChecksums || in.Method != MethodChecksums || len(in.Mismatch) != 0 {
		t.Errorf("integrity %+v", in)
	}
	if tree.Root != "akismet/" || len(tree.Files) != len(akismetFiles) || tree.HashKind != core.HashManifest ||
		tree.SHA256 != core.ManifestHash(tree.Files) {
		t.Errorf("tree root %q, %d files, hash %s", tree.Root, len(tree.Files), tree.HashKind)
	}
	if len(m.Changelog) != 1 || m.Changelog[0].Version != "5.3.5" || m.Changelog[0].Text != "* Fix" {
		t.Errorf("changelog from changelog.txt: %+v", m.Changelog)
	}
	if got := coretest.Read(tree, "akismet.php"); got != akismetFiles["akismet.php"] {
		t.Errorf("akismet.php = %q", got)
	}
	// One info request serves Versions and Meta.
	if n := r.count("GET /plugins/info/1.2/"); n != 1 {
		t.Errorf("%d info requests", n)
	}
	if d := r.headers["/akismet/tags/5.3.5/"].Get("Depth"); d != "0" {
		t.Errorf("PROPFIND depth %q", d)
	}
	want := []string{
		"GET /plugins/info/1.2/", "PROPFIND /akismet/tags/5.3.5/",
		"GET /plugin/akismet.5.3.5.zip", "GET /plugin-checksums/akismet/5.3.5.json",
	}
	if got := r.requests(); !slices.Equal(got, want) {
		t.Errorf("requests\n%v\nwant\n%v", got, want)
	}
}

func TestPluginMismatch(t *testing.T) {
	files := clone(akismetFiles)
	files["class.akismet.php"] = "<?php class Akismet {} eval($_POST['x']);"
	files["wp-load-extra.php"] = "<?php // not in the release"
	sums := clone(akismetFiles)
	sums["gone.php"] = "<?php // in the release, not in the zip"
	r := newRegistry()
	akismet(t, r, files, sums)
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	m, err := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
	if err != nil {
		t.Fatal(err)
	}
	_, in, err := p.Fetch(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"class.akismet.php", "gone.php", "wp-load-extra.php"}
	if in.By != core.ByFailed || in.Method != MethodChecksumsFailed || !slices.Equal(in.Mismatch, want) ||
		in.Detail != "3 files differ from WordPress.org's checksums" {
		t.Errorf("integrity %+v, want failed listing %v", in, want)
	}
}

func TestPluginReadmeChangeIsNotAMismatch(t *testing.T) {
	files := clone(akismetFiles)
	files["readme.txt"] = "=== Akismet ===\nStable tag: 5.3.5\nTested up to: 6.7\n"
	r := newRegistry()
	akismet(t, r, files, akismetFiles)
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	m, _ := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
	_, in, err := p.Fetch(context.Background(), m)
	if err != nil || in.By != core.ByChecksums {
		t.Errorf("readme.txt change: %+v %v, want checksums", in, err)
	}
}

func TestPluginChecksumsUnavailable(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	for _, tc := range []struct {
		name   string
		set    func(r *registry)
		reason string
	}{
		{"503", func(r *registry) { r.status["/plugin-checksums/akismet/5.3.5.json"] = 503 }, "wordpress.org checksums answered 503"},
		{"404", func(r *registry) { delete(r.checksums, "akismet/5.3.5") }, "wordpress.org has no checksums for this version"},
		{"empty", func(r *registry) { r.checksums["akismet/5.3.5"] = `{"files": []}` }, "wordpress.org has no checksums for this version"},
		{"bad hash", func(r *registry) {
			r.checksums["akismet/5.3.5"] = `{"files": {"akismet.php": {"sha256": "nope"}}}`
		}, "wordpress.org checksums could not be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry()
			akismet(t, r, akismetFiles, akismetFiles)
			tc.set(r)
			p := NewPlugin(start(t, r, core.SourceOptions{}))
			m, _ := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
			tree, in, err := p.Fetch(context.Background(), m)
			if err != nil || tree == nil {
				t.Fatal(err)
			}
			if in.By != core.ByNone || in.Method != MethodChecksumsNone || in.Detail != tc.reason || !in.Partial() {
				t.Errorf("integrity %+v", in)
			}
		})
	}
	got := fetch.Unverified("plugin", "countdown-timer-ultimate", "2.6.8", "wordpress.org checksums answered 503").Error()
	want := "rhythm sightread plugin: couldn't verify countdown-timer-ultimate 2.6.8: wordpress.org checksums answered 503\n" +
		"  not diffed; run again later, or --allow-unverified to review it anyway (the report marks it unverified)"
	if got != want {
		t.Errorf("E5\n%s\nwant\n%s", got, want)
	}
}

func TestPluginClosed(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry()
	// The closed answer is a 404 with a JSON body.
	r.closed["plugins/countdown-timer-ultimate"] = closedInfo
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	ctx := context.Background()
	vs, err := p.Versions(ctx, "countdown-timer-ultimate")
	if err != nil || len(vs) != 0 {
		t.Fatalf("Versions of a closed plugin = %v, %v", vs, err)
	}
	m, err := p.Meta(ctx, core.Ref{Eco: core.WPPlugin, Name: "countdown-timer-ultimate", Version: "2.6.8"})
	if err != nil || !m.Closed || m.ClosedReason != "Security Issue" {
		t.Fatalf("Meta = %+v, %v", m, err)
	}
	_, _, err = p.Fetch(ctx, m)
	want := "rhythm sightread plugin: countdown-timer-ultimate is closed on wordpress.org (Security Issue); there is nothing to download\n" +
		"  the wporg-closed finding says why; give a copy you trust with --to-file <zip>"
	if err == nil || err.Error() != want {
		t.Errorf("Fetch of a closed plugin\n%v\nwant\n%s", err, want)
	}
	tags, err := p.Tags(ctx, "countdown-timer-ultimate")
	if err != nil || len(tags) != 0 {
		t.Errorf("Tags = %v, %v", tags, err)
	}
}

func TestPluginUnknownSlug(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry()
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	_, err := p.Versions(context.Background(), "contact-form7")
	want := "rhythm sightread plugin: wordpress.org has no plugin \"contact-form7\"\n" +
		"  A premium plugin has no official source: use --to-file <zip>"
	if err == nil || err.Error() != want || core.CodeOf(err) != core.EUnknownPackage {
		t.Errorf("without a names pack\n%v\nwant\n%s", err, want)
	}

	(&coretest.FakeDataPacks{PopularNames: map[core.Ecosystem][]string{
		core.WPPlugin: {"contact-form-7", "akismet"},
	}}).Install(t)
	p = NewPlugin(start(t, r, core.SourceOptions{}))
	_, err = p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "contact-form7", Version: "1.0"})
	want = "rhythm sightread plugin: wordpress.org has no plugin \"contact-form7\"\n" +
		"  did you mean contact-form-7? A premium plugin has no official source: use --to-file <zip>"
	var ce *core.Error
	if !errors.As(err, &ce) || err.Error() != want || ce.ExitCode() != 2 {
		t.Errorf("with a names pack\n%v\nwant\n%s", err, want)
	}
}

func TestPluginNoVersion(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry()
	akismet(t, r, akismetFiles, akismetFiles)
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	_, err := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "9.9.9"})
	want := "rhythm sightread plugin: akismet has no version 9.9.9 on wordpress.org\n" +
		"  newest: 5.3.5 · see them all: rhythm sightread plugin akismet --to list"
	if err == nil || err.Error() != want || core.CodeOf(err) != core.EVersionMissing {
		t.Errorf("E3\n%v\nwant\n%s", err, want)
	}
	if _, err := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "trunk"}); core.CodeOf(err) != core.EVersionMissing {
		t.Errorf("trunk is not a version: %v", err)
	}
}

func TestPluginPublisherUnknown(t *testing.T) {
	r := newRegistry()
	akismet(t, r, akismetFiles, akismetFiles)
	r.status["/akismet/tags/5.3.5/"] = 404
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	m, err := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
	if err != nil || m.Publisher != nil {
		t.Fatalf("Meta = %+v, %v; want no publisher", m, err)
	}
	// Without the SVN date the current version falls back to last_updated.
	if want := time.Date(2024, 10, 1, 15, 52, 0, 0, time.UTC); !m.Published.Equal(want) {
		t.Errorf("published %v, want %v", m.Published, want)
	}
}

func TestPluginStableTagTrunk(t *testing.T) {
	// The readme says Stable tag: trunk, so 2.0 has no tag and no
	// versioned zip: WordPress.org lists it only as the version field.
	info := `{"slug": "trunky", "version": "2.0", "download_link": "https://downloads.wordpress.org/plugin/trunky.zip",
	  "versions": {"1.0": "https://downloads.wordpress.org/plugin/trunky.1.0.zip", "trunk": "https://downloads.wordpress.org/plugin/trunky.zip"},
	  "contributors": [], "author": "Trunky", "author_profile": "https://profiles.wordpress.org/trunky/",
	  "requires_php": false, "last_updated": "2025-01-02 1:00am GMT"}`
	r := newRegistry()
	r.info["plugins/trunky"] = info
	files := map[string]string{"trunky.php": "<?php // 2.0", "readme.txt": "Stable tag: trunk"}
	r.zips["plugin/trunky.zip"] = makeZip(t, "trunky", files)
	r.checksums["trunky/2.0"] = checksumsJSON(t, "trunky", "2.0", files)
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	ctx := context.Background()
	tags, err := p.Tags(ctx, "trunky")
	if err != nil || tags["latest"] != "2.0" || len(tags) != 1 {
		t.Fatalf("Tags = %v, %v", tags, err)
	}
	vs, _ := p.Versions(ctx, "trunky")
	if strings.Join(vs, " ") != "1.0 2.0" {
		t.Errorf("Versions = %v", vs)
	}
	m, err := p.Meta(ctx, core.Ref{Eco: core.WPPlugin, Name: "trunky"})
	if err != nil || m.Ref.Version != "2.0" || !strings.HasSuffix(m.Archive.URL, "/plugin/trunky.zip") || m.RequiresPHP != "" {
		t.Fatalf("Meta = %+v, %v", m, err)
	}
	if _, in, err := p.Fetch(ctx, m); err != nil || in.By != core.ByChecksums {
		t.Errorf("Fetch: %+v %v", in, err)
	}
}

func TestPluginDownloadTooLarge(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry()
	akismet(t, r, akismetFiles, akismetFiles)
	env := start(t, r, core.SourceOptions{})
	env.Limits = core.Limits{Download: 64}
	p := NewPlugin(env)
	m, _ := p.Meta(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
	_, _, err := p.Fetch(context.Background(), m)
	want := "rhythm sightread plugin: the 5.3.5 zip of akismet is over 64 bytes\n" +
		"  raise --max-size if you expect that; a size jump this big is worth a look on its own"
	if err == nil || err.Error() != want || !errors.Is(err, core.ErrTooLarge) {
		t.Errorf("E11\n%v\nwant\n%s", err, want)
	}
}

func TestVerifyLocal(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry()
	akismet(t, r, akismetFiles, akismetFiles)
	ref := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"}
	local := clone(akismetFiles)
	local["class.akismet.php"] = "<?php // edited on the site"
	local["languages/akismet-de_DE.po"] = "msgid \"\""
	local["languages/akismet-de_DE.mo"] = "\x00"
	local["readme.txt"] = "changed"
	local["cache/extra.php"] = "<?php"
	delete(local, "wrapper.php")

	check := func(t *testing.T, d core.Drift) {
		t.Helper()
		if !d.Official || !slices.Equal(d.Differ, []string{"class.akismet.php"}) ||
			!slices.Equal(d.Missing, []string{"wrapper.php"}) || !slices.Equal(d.Extra, []string{"cache/extra.php"}) {
			t.Errorf("drift %+v", d)
		}
	}
	t.Run("diff", func(t *testing.T) {
		p := NewPlugin(start(t, r, core.SourceOptions{}))
		d, err := p.VerifyLocal(context.Background(), ref, coretest.Tree(local))
		if err != nil {
			t.Fatal(err)
		}
		check(t, d)
	})
	t.Run("differ", func(t *testing.T) {
		coretest.FakeDiffer{}.Install(t)
		p := NewPlugin(start(t, r, core.SourceOptions{}))
		d, err := p.VerifyLocal(context.Background(), ref, coretest.Tree(local))
		if err != nil {
			t.Fatal(err)
		}
		// The fake differ ignores nothing, so it also lists readme.txt.
		if !d.Official || !slices.Contains(d.Differ, "class.akismet.php") || !slices.Contains(d.Missing, "wrapper.php") {
			t.Errorf("drift through the differ %+v", d)
		}
	})
	t.Run("namesake", func(t *testing.T) {
		p := NewPlugin(start(t, r, core.SourceOptions{}))
		other := map[string]string{"akismet.php": "<?php /* Plugin Name: Someone else */", "inc/a.php": "<?php", "readme.txt": "x"}
		d, err := p.VerifyLocal(context.Background(), ref, coretest.Tree(other))
		if err != nil || d.Official {
			t.Errorf("a namesake is official: %+v %v", d, err)
		}
	})
	t.Run("no checksums", func(t *testing.T) {
		p := NewPlugin(start(t, r, core.SourceOptions{}))
		d, err := p.VerifyLocal(context.Background(), core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "0.1"}, coretest.Tree(local))
		if err != nil || d.Official {
			t.Errorf("a version without checksums: %+v %v", d, err)
		}
	})
	t.Run("no differ", func(t *testing.T) {
		t.Cleanup(core.SwapDiffer(nil))
		p := NewPlugin(start(t, r, core.SourceOptions{}))
		if _, err := p.VerifyLocal(context.Background(), ref, coretest.Tree(local)); !errors.Is(err, core.ErrNotLinked) {
			t.Errorf("without a differ: %v", err)
		}
	})
	t.Run("503", func(t *testing.T) {
		r2 := newRegistry()
		akismet(t, r2, akismetFiles, akismetFiles)
		r2.status["/plugin-checksums/akismet/5.3.5.json"] = 503
		p := NewPlugin(start(t, r2, core.SourceOptions{}))
		_, err := p.VerifyLocal(context.Background(), ref, coretest.Tree(local))
		if core.CodeOf(err) != core.EUnverifiable ||
			!strings.HasPrefix(err.Error(), "rhythm sightread plugin: couldn't verify akismet 5.3.5: wordpress.org checksums answered 503") {
			t.Errorf("E5: %v", err)
		}
	})
}

func TestVerifyTreeLimitCut(t *testing.T) {
	tree := coretest.TreeWith(map[string]string{"a.php": "a"},
		[]core.ArchiveIssue{{Kind: core.IssueLimit, Detail: "more than 100000 entries; the rest were not read"}})
	want := sums{"a.php": {sha("a")}, "b.php": {sha("b")}}
	if in := verifyTree(tree, want); in.By != core.ByNone || in.Detail == "" {
		t.Errorf("cut tree: %+v, want none", in)
	}
	tree = coretest.TreeWith(map[string]string{"a.php": "changed"},
		[]core.ArchiveIssue{{Kind: core.IssueLimit}})
	if in := verifyTree(tree, want); in.By != core.ByFailed || !slices.Equal(in.Mismatch, []string{"a.php"}) {
		t.Errorf("cut tree with a changed file: %+v, want failed", in)
	}
	// A rebuilt release lists two hashes; either matches.
	tree = coretest.Tree(map[string]string{"a.php": "new"})
	if in := verifyTree(tree, sums{"a.php": {sha("old"), sha("new")}}); in.By != core.ByChecksums {
		t.Errorf("second hash: %+v", in)
	}
}

func TestDecodeInfo(t *testing.T) {
	in, err := decodeInfo([]byte(akismetInfo))
	if err != nil || in.Version != "5.3.5" || len(in.Versions) != 4 {
		t.Fatalf("akismet: %+v %v", in, err)
	}
	for name, body := range map[string]string{
		"versions a string":     `{"version": "1.0", "versions": "1.0", "download_link": "x"}`,
		"version a number":      `{"version": 1.0, "versions": {}, "download_link": "x"}`,
		"no version":            `{"versions": {}, "download_link": "x"}`,
		"no versions":           `{"version": "1.0", "download_link": "x"}`,
		"no download_link":      `{"version": "1.0", "versions": {}}`,
		"contributors a string": `{"version": "1.0", "versions": {}, "download_link": "x", "contributors": "me"}`,
		"requires_php a number": `{"version": "1.0", "versions": {}, "download_link": "x", "requires_php": 7}`,
		"author an array":       `{"version": "1.0", "versions": {}, "download_link": "x", "author": []}`,
		"closed a string":       `{"error": "gone", "closed": "yes"}`,
		"version trunk":         `{"version": "trunk", "versions": {}, "download_link": "x"}`,
		"not an object":         `[1, 2]`,
		"null":                  `null`,
	} {
		if _, err := decodeInfo([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	in, err = decodeInfo([]byte(`{"error": "Plugin not found."}`))
	if err != nil || !in.NotFound {
		t.Errorf("not found: %+v %v", in, err)
	}
	in, err = decodeInfo([]byte(closedInfo))
	if err != nil || !in.Closed || in.ClosedReason != "Security Issue" {
		t.Errorf("closed: %+v %v", in, err)
	}
	in, err = decodeInfo([]byte(`{"version": "1.0", "versions": [], "download_link": "x", "requires_php": false,
	  "author": {"user_nicename": "wordpressdotorg", "profile": "https://profiles.wordpress.org/wordpressdotorg/", "display_name": "WordPress.org"},
	  "last_updated": "2024-04-02", "last_updated_time": "2024-04-02 14:08:51"}`))
	if err != nil || in.Author != "WordPress.org" || !slices.Equal(in.Contributors, []string{"wordpressdotorg"}) ||
		!in.LastUpdated.Equal(time.Date(2024, 4, 2, 14, 8, 51, 0, time.UTC)) || len(in.Versions) != 0 {
		t.Errorf("theme shape: %+v %v", in, err)
	}
	long := strings.Repeat("a", 5000)
	in, err = decodeInfo([]byte(fmt.Sprintf(`{"version": "1.0", "versions": {}, "download_link": "x", "author": %q}`, long)))
	if err != nil || len(in.Author) != maxField {
		t.Errorf("long author kept %d bytes, %v", len(in.Author), err)
	}
}

func TestParseMultistatus(t *testing.T) {
	es, err := parseMultistatus([]byte(davOne("/akismet/tags/5.3.5/", "automattic", "2024-10-01T15:52:01Z")))
	if err != nil || len(es) != 1 || !es[0].Dir || es[0].Creator != "automattic" {
		t.Fatalf("%+v %v", es, err)
	}
	for name, body := range map[string]string{
		"not xml":     "{}",
		"unclosed":    "<D:multistatus xmlns:D=\"DAV:\"><D:response>",
		"entity bomb": `<!DOCTYPE x [<!ENTITY a "aaaa">]><multistatus><response><href>&a;</href></response></multistatus>`,
		"bad href":    `<multistatus><response><href>%zz</href></response></multistatus>`,
	} {
		if _, err := parseMultistatus([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A propstat that is not 200 gives nothing.
	es, err = parseMultistatus([]byte(`<multistatus><response><href>/x/</href><propstat><prop><creator-displayname>eve</creator-displayname></prop><status>HTTP/1.1 404 Not Found</status></propstat></response></multistatus>`))
	if err != nil || len(es) != 1 || es[0].Creator != "" {
		t.Errorf("404 propstat: %+v %v", es, err)
	}
}

func FuzzWPInfo(f *testing.F) {
	f.Add([]byte(akismetInfo))
	f.Add([]byte(closedInfo))
	f.Add([]byte(`{"error": "Plugin not found."}`))
	f.Add([]byte(`{"version": "1.0", "versions": [], "download_link": "x", "author": {"display_name": "a"}}`))
	f.Add([]byte(`{"version": "1", "versions": {"1": null}, "download_link": "", "contributors": {"b": 1, "a": "x"}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		in, err := decodeInfo(body)
		if err != nil {
			return
		}
		if in.NotFound || in.Closed {
			if in.Closed && in.ClosedReason == "" {
				t.Error("closed without a reason")
			}
			return
		}
		if in.Version == "" || in.Version == "trunk" || in.Versions == nil {
			t.Errorf("accepted %+v", in)
		}
		if !slices.IsSorted(in.Contributors) {
			t.Error("contributors not sorted")
		}
		for _, s := range append([]string{in.Version, in.Author, in.AuthorProfile, in.Homepage, in.RequiresPHP}, in.Contributors...) {
			if len(s) > maxField {
				t.Errorf("field of %d bytes kept", len(s))
			}
		}
		_ = versions(in)
	})
}

// TestPluginOlderVersionOwners: the info API's contributors and author
// describe the current release only, so an older version gets none of
// them and takes its contributors from its own readme. Given the
// current list, a new committer would count as an old owner and
// owner-change would never fire.
func TestPluginOlderVersionOwners(t *testing.T) {
	r := newRegistry()
	akismet(t, r, akismetFiles, akismetFiles)
	p := NewPlugin(start(t, r, core.SourceOptions{}))
	ctx := context.Background()
	old, err := p.Meta(ctx, core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Contributors) != 0 || old.Author != "" || old.AuthorProfile != "" {
		t.Errorf("5.3.4 got the current release's owners: %q, %q, %q", old.Contributors, old.Author, old.AuthorProfile)
	}
	if old.Latest != "5.3.5" {
		t.Errorf("latest %q", old.Latest)
	}
	cur, err := p.Meta(ctx, core.Ref{Eco: core.WPPlugin, Name: "akismet"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cur.Contributors, ",") != "automattic,kbrownkd" || cur.AuthorProfile == "" {
		t.Errorf("current release lost its owners: %q, %q", cur.Contributors, cur.AuthorProfile)
	}
	// The readme of the older release names its own contributors.
	metaFromTree(old, coretest.Tree(map[string]string{"readme.txt": "=== Akismet ===\nContributors: automattic\n\n== Description ==\n"}))
	if strings.Join(old.Contributors, ",") != "automattic" {
		t.Errorf("readme contributors %q", old.Contributors)
	}
}
