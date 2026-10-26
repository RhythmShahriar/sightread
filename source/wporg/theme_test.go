// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// themeInfo is a theme info answer in the shape api.wordpress.org
// serves (fields copied by hand, values made up).
const themeInfo = `{
  "name": "Twenty Twenty-Four",
  "slug": "twentytwentyfour",
  "version": "1.2",
  "preview_url": "https://wp-themes.com/twentytwentyfour/",
  "author": {"user_nicename": "wordpressdotorg", "profile": "https://profiles.wordpress.org/wordpressdotorg/",
    "avatar": "https://secure.gravatar.com/avatar/x", "display_name": "WordPress.org",
    "author": "the WordPress team", "author_url": "https://wordpress.org/"},
  "screenshot_url": "//ts.w.org/wp-content/themes/twentytwentyfour/screenshot.png",
  "rating": 88,
  "num_ratings": 50,
  "downloaded": 1000000,
  "last_updated": "2024-07-16",
  "last_updated_time": "2024-07-16 18:22:31",
  "creation_time": "2023-11-07 23:26:47",
  "homepage": "https://wordpress.org/themes/twentytwentyfour/",
  "download_link": "https://downloads.wordpress.org/theme/twentytwentyfour.1.2.zip",
  "tags": {"blog": "Blog"},
  "requires": "6.4",
  "requires_php": "7.0",
  "is_commercial": false,
  "external_support_url": false,
  "is_community": false,
  "external_repository_url": "",
  "versions": {
    "1.0": "https://downloads.wordpress.org/theme/twentytwentyfour.1.0.zip",
    "1.1": "https://downloads.wordpress.org/theme/twentytwentyfour.1.1.zip",
    "1.2": "https://downloads.wordpress.org/theme/twentytwentyfour.1.2.zip"
  }
}`

var themeFiles = map[string]string{
	"style.css":            "/* Theme Name: Twenty Twenty-Four */",
	"functions.php":        "<?php // setup",
	"theme.json":           `{"version": 3}`,
	"templates/index.html": "<!-- wp:query /-->",
	"parts/footer.html":    "<!-- wp:group /-->",
	"readme.txt":           "=== Twenty Twenty-Four ===",
}

const svnRoot = "/twentytwentyfour/1.2/"

// davList is a depth 1 answer for folder: the folder itself, then each
// child by name (a trailing slash marks a folder) with its size.
func davList(folder string, children map[string]int) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n" + `<D:multistatus xmlns:D="DAV:">`)
	entry := func(href string, dir bool, size int) {
		b.WriteString(`<D:response xmlns:lp1="DAV:"><D:href>` + href + `</D:href><D:propstat><D:prop>`)
		if dir {
			b.WriteString(`<lp1:resourcetype><D:collection/></lp1:resourcetype>`)
		} else {
			b.WriteString(`<lp1:resourcetype/><lp1:getcontentlength>` + fmt.Sprint(size) + `</lp1:getcontentlength>`)
		}
		b.WriteString(`<lp1:creator-displayname>wordpressdotorg</lp1:creator-displayname>` +
			`<lp1:creationdate>2024-07-16T18:22:31.000000Z</lp1:creationdate>` +
			`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
	}
	entry(folder, true, 0)
	names := make([]string, 0, len(children))
	for n := range children {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		href := n
		if !strings.HasPrefix(n, "/") {
			href = folder + n
		}
		entry(href, strings.HasSuffix(n, "/"), children[n])
	}
	b.WriteString(`</D:multistatus>`)
	return b.String()
}

// svnTheme serves files as the SVN copy of twentytwentyfour 1.2.
func svnTheme(r *registry, files map[string]string) {
	dirs := map[string]map[string]int{"": {}}
	for p, body := range files {
		dir, name := "", p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			dir, name = p[:i+1], p[i+1:]
			if dirs[dir] == nil {
				dirs[dir] = map[string]int{}
				dirs[""][dir] = 0
			}
		}
		dirs[dir][name] = len(body)
		r.svnFiles[svnRoot+p] = body
	}
	for dir, children := range dirs {
		r.dav[svnRoot+dir] = davList(svnRoot+dir, children)
	}
}

func twentyTwentyFour(t *testing.T, r *registry, zipFiles map[string]string) {
	t.Helper()
	r.info["themes/twentytwentyfour"] = themeInfo
	r.zips["theme/twentytwentyfour.1.2.zip"] = makeZip(t, "twentytwentyfour", zipFiles)
}

func fetchTheme(t *testing.T, r *registry, svnCheck bool) (*core.Tree, core.Integrity) {
	t.Helper()
	th := NewTheme(start(t, r, core.SourceOptions{SVNCheck: svnCheck}))
	m, err := th.Meta(context.Background(), core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour", Version: "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	tree, in, err := th.Fetch(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return tree, in
}

func TestThemeRegistered(t *testing.T) {
	src := core.SourceFor(core.WPTheme, &core.Env{})
	if _, ok := src.(*Theme); !ok || src.Eco() != core.WPTheme {
		t.Fatalf("wp-theme source is %T", src)
	}
}

func TestThemeTLS(t *testing.T) {
	r := newRegistry()
	twentyTwentyFour(t, r, themeFiles)
	svnTheme(r, themeFiles)
	th := NewTheme(start(t, r, core.SourceOptions{}))
	ctx := context.Background()
	vs, err := th.Versions(ctx, "twentytwentyfour")
	if err != nil || strings.Join(vs, " ") != "1.0 1.1 1.2" {
		t.Fatalf("Versions = %v, %v", vs, err)
	}
	m, err := th.Meta(ctx, core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Ref.Version != "1.2" || m.Author != "WordPress.org" || !slices.Equal(m.Contributors, []string{"wordpressdotorg"}) ||
		m.RequiresPHP != "7.0" || m.Publisher == nil || m.Publisher.Login != "wordpressdotorg" ||
		!strings.HasSuffix(m.Archive.URL, "/theme/twentytwentyfour.1.2.zip") {
		t.Errorf("meta %+v publisher %+v", m, m.Publisher)
	}
	tree, in, err := th.Fetch(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if in.By != core.ByTLS || in.Method != MethodTLS || in.Partial() {
		t.Errorf("integrity %+v", in)
	}
	if tree.Root != "twentytwentyfour/" || len(tree.Files) != len(themeFiles) || tree.HashKind != core.HashManifest {
		t.Errorf("tree root %q with %d files", tree.Root, len(tree.Files))
	}
	// Without --svn-check only the tag folder's properties are asked for.
	for _, req := range r.requests() {
		if strings.HasPrefix(req, "GET "+svnRoot) || req == "PROPFIND "+svnRoot+"templates/" {
			t.Errorf("SVN request without --svn-check: %s", req)
		}
	}
	tags, err := th.Tags(ctx, "twentytwentyfour")
	if err != nil || tags["latest"] != "1.2" {
		t.Errorf("Tags = %v, %v", tags, err)
	}
}

func TestThemeSVNMatch(t *testing.T) {
	r := newRegistry()
	twentyTwentyFour(t, r, themeFiles)
	svnTheme(r, themeFiles)
	_, in := fetchTheme(t, r, true)
	if in.By != core.BySVN || in.Method != MethodSVN || len(in.Mismatch) != 0 {
		t.Errorf("integrity %+v", in)
	}
	if d := r.headers[svnRoot+"templates/"].Get("Depth"); d != "1" {
		t.Errorf("listing depth %q", d)
	}
	for p := range themeFiles {
		if r.count("GET "+svnRoot+p) != 1 {
			t.Errorf("%s fetched %d times", p, r.count("GET "+svnRoot+p))
		}
	}
}

func TestThemeSVNDiffer(t *testing.T) {
	zipFiles := clone(themeFiles)
	zipFiles["functions.php"] = "<?php // setup\nadd_action('wp_footer', 'spam_links');"
	zipFiles["inc/extra.php"] = "<?php // only in the zip"
	svn := clone(themeFiles)
	svn["patterns/hero.php"] = "<?php // only in SVN"
	r := newRegistry()
	twentyTwentyFour(t, r, zipFiles)
	svnTheme(r, svn)
	_, in := fetchTheme(t, r, true)
	want := []string{"functions.php", "inc/extra.php", "patterns/hero.php"}
	if in.By != core.ByFailed || in.Method != MethodSVNFailed || !slices.Equal(in.Mismatch, want) ||
		in.Detail != "3 files differ from themes.svn.wordpress.org" {
		t.Errorf("integrity %+v, want failed listing %v", in, want)
	}
}

func TestThemeSVNRefusesEscapes(t *testing.T) {
	for name, child := range map[string]string{
		"dot dot":      "../evil.php",
		"encoded":      "%2e%2e%2fevil.php",
		"other folder": "/other-theme/1.0/evil.php",
		"nested":       "a/b.php",
		"dot":          ".",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRegistry()
			twentyTwentyFour(t, r, themeFiles)
			svnTheme(r, themeFiles)
			children := map[string]int{"style.css": 10, child: 10}
			r.dav[svnRoot] = davList(svnRoot, children)
			_, in := fetchTheme(t, r, true)
			if in.By != core.ByFailed || len(in.Mismatch) != 1 ||
				in.Detail != "the SVN listing names a path outside the theme folder; nothing was fetched from it" {
				t.Errorf("integrity %+v", in)
			}
			for _, req := range r.requests() {
				if strings.HasPrefix(req, "GET ") && !strings.HasPrefix(req, "GET /theme") && !strings.HasPrefix(req, "GET /themes/") {
					t.Errorf("fetched %s after a refused listing", req)
				}
			}
		})
	}
}

func TestThemeSVNCannotFinish(t *testing.T) {
	t.Run("listing 404", func(t *testing.T) {
		r := newRegistry()
		twentyTwentyFour(t, r, themeFiles)
		r.dav[svnRoot] = davList(svnRoot, map[string]int{"templates/": 0})
		r.status[svnRoot+"templates/"] = 404
		_, in := fetchTheme(t, r, true)
		if in.By != core.ByTLS || !strings.HasPrefix(in.Detail, "--svn-check could not finish: ") {
			t.Errorf("integrity %+v", in)
		}
	})
	t.Run("entry cap", func(t *testing.T) {
		r := newRegistry()
		twentyTwentyFour(t, r, themeFiles)
		svnTheme(r, themeFiles)
		env := start(t, r, core.SourceOptions{SVNCheck: true})
		env.Limits = core.Limits{Entries: 3}
		th := NewTheme(env)
		m, err := th.Meta(context.Background(), core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour", Version: "1.2"})
		if err != nil {
			t.Fatal(err)
		}
		// The zip itself is over 3 entries too, so its tree is cut short.
		_, in, err := th.Fetch(context.Background(), m)
		if err != nil || in.By != core.ByTLS || !strings.Contains(in.Detail, "could not finish") {
			t.Errorf("integrity %+v %v", in, err)
		}
	})
	t.Run("file over the entry limit", func(t *testing.T) {
		r := newRegistry()
		big := clone(themeFiles)
		big["functions.php"] = strings.Repeat("x", 4096)
		twentyTwentyFour(t, r, themeFiles)
		svnTheme(r, big)
		env := start(t, r, core.SourceOptions{SVNCheck: true})
		env.Limits = core.Limits{EntryStored: 1024}
		th := NewTheme(env)
		m, _ := th.Meta(context.Background(), core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour", Version: "1.2"})
		_, in, err := th.Fetch(context.Background(), m)
		if err != nil || in.By != core.ByTLS || !strings.Contains(in.Detail, "over 1 KiB") {
			t.Errorf("integrity %+v %v", in, err)
		}
	})
}

func TestThemeUnknown(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	th := NewTheme(start(t, newRegistry(), core.SourceOptions{}))
	_, err := th.Versions(context.Background(), "twentytwentyfive-pro")
	want := "rhythm sightread theme: wordpress.org has no theme \"twentytwentyfive-pro\"\n" +
		"  A premium theme has no official source: use --to-file <zip>"
	if err == nil || err.Error() != want || core.CodeOf(err) != core.EUnknownPackage {
		t.Errorf("E2\n%v\nwant\n%s", err, want)
	}
}

func TestEscapePath(t *testing.T) {
	if got := escapePath("assets/a b#1.css"); got != "assets/a%20b%231.css" {
		t.Errorf("escapePath = %q", got)
	}
}

// TestThemeVerifyLocal: an installed theme is compared with the zip of
// its version; an edited file is drift, an untouched copy has none and a
// namesake with other files is not the WordPress.org theme.
func TestThemeVerifyLocal(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry()
	twentyTwentyFour(t, r, themeFiles)
	ref := core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour", Version: "1.2"}
	ctx := context.Background()
	t.Run("edited", func(t *testing.T) {
		local := clone(themeFiles)
		local["functions.php"] = "<?php // edited on the site"
		local["cache/extra.php"] = "<?php"
		d, err := NewTheme(start(t, r, core.SourceOptions{})).VerifyLocal(ctx, ref, coretest.Tree(local))
		if err != nil || !d.Official || !slices.Equal(d.Differ, []string{"functions.php"}) || !slices.Equal(d.Extra, []string{"cache/extra.php"}) {
			t.Errorf("drift %+v, %v", d, err)
		}
	})
	t.Run("untouched", func(t *testing.T) {
		d, err := NewTheme(start(t, r, core.SourceOptions{})).VerifyLocal(ctx, ref, coretest.Tree(clone(themeFiles)))
		if err != nil || !d.Official || len(d.Differ)+len(d.Missing)+len(d.Extra) != 0 {
			t.Errorf("drift %+v, %v", d, err)
		}
	})
	t.Run("namesake", func(t *testing.T) {
		other := map[string]string{"style.css": "/* Theme Name: Someone else */", "index.php": "<?php", "inc/a.php": "<?php"}
		d, err := NewTheme(start(t, r, core.SourceOptions{})).VerifyLocal(ctx, ref, coretest.Tree(other))
		if err != nil || d.Official {
			t.Errorf("a namesake is official: %+v %v", d, err)
		}
	})
	t.Run("unknown version", func(t *testing.T) {
		_, err := NewTheme(start(t, r, core.SourceOptions{})).VerifyLocal(ctx, core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour", Version: "9.9"}, coretest.Tree(themeFiles))
		if core.CodeOf(err) != core.EVersionMissing {
			t.Errorf("unknown version: %v", err)
		}
	})
	t.Run("no differ", func(t *testing.T) {
		t.Cleanup(core.SwapDiffer(nil))
		if _, err := NewTheme(start(t, r, core.SourceOptions{})).VerifyLocal(ctx, ref, coretest.Tree(themeFiles)); !errors.Is(err, core.ErrNotLinked) {
			t.Errorf("without a differ: %v", err)
		}
	})
}
