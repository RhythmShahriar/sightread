// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// installedBy indexes a site's Installed entries by "<eco>:<name>".
func installedBy(s *core.Site) map[string]core.Installed {
	m := map[string]core.Installed{}
	for _, in := range s.Installed {
		m[in.Ref.Unversioned().String()] = in
	}
	return m
}

// notCheckedBy indexes Not checked entries by "<eco>:<name>".
func notCheckedBy(ncs []core.NotChecked) map[string]core.NotChecked {
	m := map[string]core.NotChecked{}
	for _, nc := range ncs {
		m[string(nc.Eco)+":"+nc.Name] = nc
	}
	return m
}

func TestReadWordPress(t *testing.T) {
	root := copyTree(t, "testdata/wp/site")
	// CRLF and a byte order mark are written here: .gitattributes keeps
	// every fixture LF in git.
	writeFiles(t, root, map[string]string{
		"wp-content/plugins/crlf-plugin/crlf-plugin.php": "<?php\r\n/*\r\n * Plugin Name: CRLF Plugin\r\n * Version: 3.0.1\r\n */\r\n",
		"wp-content/plugins/bom-plugin/main.php":         "\ufeff<?php\n/*\nPlugin Name: BOM Plugin\nVersion: 0.9.0 beta\n*/\n",
		"wp-content/themes/crlf-theme/style.css":         "\ufeff/*\r\nTheme Name: CRLF Theme\r\nVersion: 2.0\r\nUpdate URI: false\r\n*/\r\n",
	})
	site, err := ReadWordPress(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if site.WordPress != "6.8.3" || site.Kind != "wordpress" || site.Root != root {
		t.Errorf("site = %q %q %q, want 6.8.3 wordpress %q", site.WordPress, site.Kind, site.Root, root)
	}
	got := installedBy(site)
	for key, want := range map[string]core.Installed{
		"wp-plugin:akismet": {Ref: core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"},
			Path: "wp-content/plugins/akismet", Lockfile: "wp-content/plugins/akismet/akismet.php", LockLine: 9},
		"wp-plugin:contact-form-7": {Ref: core.Ref{Eco: core.WPPlugin, Name: "contact-form-7", Version: "6.0.6"},
			Path: "wp-content/plugins/contact-form-7", Lockfile: "wp-content/plugins/contact-form-7/wp-contact-form-7.php", LockLine: 10},
		"wp-plugin:hello": {Ref: core.Ref{Eco: core.WPPlugin, Name: "hello", Version: "1.7.2"},
			Path: "wp-content/plugins/hello.php", Lockfile: "wp-content/plugins/hello.php", LockLine: 11},
		"wp-plugin:acme-internal": {Ref: core.Ref{Eco: core.WPPlugin, Name: "acme-internal", Version: "2.1.0"},
			Path: "wp-content/plugins/acme-internal", Lockfile: "wp-content/plugins/acme-internal/acme-internal.php", LockLine: 4,
			UpdateURI: "https://updates.acme.example/acme-internal", Private: true},
		"wp-plugin:crlf-plugin": {Ref: core.Ref{Eco: core.WPPlugin, Name: "crlf-plugin", Version: "3.0.1"},
			Path: "wp-content/plugins/crlf-plugin", Lockfile: "wp-content/plugins/crlf-plugin/crlf-plugin.php", LockLine: 4},
		"wp-plugin:bom-plugin": {Ref: core.Ref{Eco: core.WPPlugin, Name: "bom-plugin", Version: "0.9.0"},
			Path: "wp-content/plugins/bom-plugin", Lockfile: "wp-content/plugins/bom-plugin/main.php", LockLine: 4},
		"wp-theme:twentytwentyfour": {Ref: core.Ref{Eco: core.WPTheme, Name: "twentytwentyfour", Version: "1.3"},
			Path: "wp-content/themes/twentytwentyfour", Lockfile: "wp-content/themes/twentytwentyfour/style.css", LockLine: 7},
		"wp-theme:crlf-theme": {Ref: core.Ref{Eco: core.WPTheme, Name: "crlf-theme", Version: "2.0"},
			Path: "wp-content/themes/crlf-theme", Lockfile: "wp-content/themes/crlf-theme/style.css", LockLine: 3,
			UpdateURI: "false", Private: true},
	} {
		if got[key] != want {
			t.Errorf("%s:\n got %+v\nwant %+v", key, got[key], want)
		}
	}
	if len(got) != 8 {
		t.Errorf("installed = %d entries, want 8: %v", len(got), site.Installed)
	}
	nc := notCheckedBy(site.NotChecked)
	for key, want := range map[string]core.NotCheckedReason{
		"wp-plugin:headerless":       core.NoHeader,
		"wp-plugin:acme-internal":    core.NotWPOrg,
		"wp-plugin:loader":           core.MUPlugin,
		"wp-plugin:object-cache.php": core.MUPlugin,
		"wp-theme:broken":            core.NoHeader,
		"wp-theme:crlf-theme":        core.NotWPOrg,
		":wordpress":                 core.Core,
	} {
		if nc[key].Reason != want {
			t.Errorf("not checked %s = %q, want %q", key, nc[key].Reason, want)
		}
	}
	if len(nc) != 7 {
		t.Errorf("not checked = %v, want 7 entries", site.NotChecked)
	}
	if h := nc["wp-plugin:acme-internal"]; h.Hint != "give the vendor's zip with --to-file" || h.Text != "not on WordPress.org" {
		t.Errorf("not-wporg = %+v", h)
	}
	if h := nc["wp-plugin:headerless"]; h.Text != "plugin folder has no Plugin Name header" || h.Hint != "check the folder by hand or remove it" {
		t.Errorf("no-header = %+v", h)
	}
	if h := nc[":wordpress"]; h.Version != "6.8.3" || h.Hint != "WordPress core updates come signed from WordPress.org" {
		t.Errorf("core = %+v", h)
	}
	if v := nc["wp-plugin:loader"].Version; v != "1.0" {
		t.Errorf("mu-plugin version = %q, want 1.0", v)
	}
	if len(site.Warnings) != 0 {
		t.Errorf("warnings = %q, want none", site.Warnings)
	}
}

// Negative: a folder that is not a WordPress root is refused; an
// install with no plugins or themes folder reads as just core.
func TestReadWordPressNotARoot(t *testing.T) {
	if _, err := ReadWordPress(context.Background(), t.TempDir()); err == nil {
		t.Error("an empty folder read as WordPress")
	}
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"wp-includes/version.php": "<?php\n$wp_version = '6.7-RC1';\n", "wp-content/index.php": "<?php\n"})
	site, err := ReadWordPress(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if site.WordPress != "6.7-RC1" || len(site.Installed) != 0 || len(site.NotChecked) != 1 || len(site.Warnings) != 0 {
		t.Errorf("bare site = %+v", site)
	}
}

func TestReadWordPressLinkedPlugin(t *testing.T) {
	root := copyTree(t, "testdata/wp/site")
	elsewhere := t.TempDir()
	writeFiles(t, elsewhere, map[string]string{"linked/linked.php": "<?php\n/* Plugin Name: Linked\nVersion: 1.0.0 */\n"})
	if err := os.Symlink(filepath.Join(elsewhere, "linked"), filepath.Join(root, "wp-content/plugins/linked")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("creating links needs a privilege on Windows:", err)
		}
		t.Fatal(err)
	}
	site, err := ReadWordPress(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if in := installedBy(site)["wp-plugin:linked"]; in.Ref.Version != "1.0.0" {
		t.Errorf("linked plugin = %+v", in)
	}
	want := "wp-content/plugins/linked is a link to a folder elsewhere; read through the link"
	if !slices.Contains(site.Warnings, want) {
		t.Errorf("warnings = %q, want %q", site.Warnings, want)
	}
}

func TestParseWPHeader(t *testing.T) {
	for _, c := range []struct {
		name, in, key string
		want          WPHeader
		ok            bool
	}{
		{"block comment", "<?php\n/*\nPlugin Name: A\nVersion: 1.2.3\nUpdate URI: w.org\nAuthor: Ann\nAuthor URI: https://ann.example\nRequires PHP: 8.1\n*/", "Plugin Name",
			WPHeader{Name: "A", Version: "1.2.3", UpdateURI: "w.org", Author: "Ann", AuthorURI: "https://ann.example", RequiresPHP: "8.1", Line: 4}, true},
		{"docblock", "<?php\n/**\n * Plugin Name: B\n * Version: 2.0-beta1\n */", "Plugin Name", WPHeader{Name: "B", Version: "2.0-beta1", Line: 4}, true},
		{"on the php line", "<?php /* Plugin Name: C */", "Plugin Name", WPHeader{Name: "C", Line: 1}, true},
		{"comment end on the line", "/*\nTheme Name: D\nVersion: 4.1 */", "Theme Name", WPHeader{Name: "D", Version: "4.1", Line: 3}, true},
		{"hash comment", "<?php\n# Plugin Name: E\n# Version: 5", "Plugin Name", WPHeader{Name: "E", Version: "5", Line: 3}, true},
		{"case", "/*\nplugin name: F\nversion: 6.0\n*/", "Plugin Name", WPHeader{Name: "F", Version: "6.0", Line: 3}, true},
		{"old mac", "<?php\r/*\rPlugin Name: G\rVersion: 7\r*/", "Plugin Name", WPHeader{Name: "G", Version: "7", Line: 4}, true},
		{"version words", "/*\nPlugin Name: H\nVersion: 1.0 (stable)\n*/", "Plugin Name", WPHeader{Name: "H", Version: "1.0", Line: 3}, true},
		// Negative cases that look close.
		{"no name", "<?php\n/*\nVersion: 1.0\n*/", "Plugin Name", WPHeader{}, false},
		{"theme header for a plugin", "/*\nTheme Name: I\n*/", "Plugin Name", WPHeader{}, false},
		{"name mid-line", "<?php\n$x = 'Plugin Name: J';", "Plugin Name", WPHeader{}, false},
		{"past 8 KiB", "<?php\n" + strings.Repeat("/", 9000) + "\nPlugin Name: K\n", "Plugin Name", WPHeader{}, false},
		{"stable version", "/*\nPlugin Name: L\nStable Version: 9\n*/", "Plugin Name", WPHeader{Name: "L", Line: 2}, true},
	} {
		got, ok := ParseWPHeader([]byte(c.in), c.key)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v, %v; want %+v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestOfficialUpdateURI(t *testing.T) {
	for _, uri := range []string{"", " ", "w.org", "wordpress.org", "https://wordpress.org", "https://wordpress.org/",
		"https://wordpress.org/plugins/akismet/", "https://wordpress.org/plugins/akismet", "http://W.org/", "https://www.wordpress.org/plugins/akismet/"} {
		if !OfficialUpdateURI(uri, "akismet", core.WPPlugin) {
			t.Errorf("OfficialUpdateURI(%q) = false, want true", uri)
		}
	}
	for _, uri := range []string{"false", "https://updates.acme.example/akismet", "https://wordpress.org/plugins/other/",
		"https://wordpress.org/themes/akismet/", "https://wordpress.org.evil.example/", "https://user@wordpress.org/",
		"ftp://wordpress.org/", "https://wordpress.org/plugins/akismet/?x=1", "my-plugin", "https://downloads.wordpress.org/plugin/akismet.zip"} {
		if OfficialUpdateURI(uri, "akismet", core.WPPlugin) {
			t.Errorf("OfficialUpdateURI(%q) = true, want false", uri)
		}
	}
	if !OfficialUpdateURI("https://wordpress.org/themes/astra/", "astra", core.WPTheme) {
		t.Error("a theme's own wordpress.org URI is not official")
	}
}

func TestFolderNameNotASlug(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"wp-includes/version.php":                 "<?php $wp_version = '6.8';",
		"wp-content/plugins/My Plugin/plugin.php": "<?php\n/* Plugin Name: Mine\nVersion: 1 */",
	})
	site, err := ReadWordPress(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if in := installedBy(site)["wp-plugin:My Plugin"]; !in.Private {
		t.Errorf("a folder name with a space can't be a WordPress.org slug: %+v", in)
	}
}

func TestFindWordPress(t *testing.T) {
	root := t.TempDir()
	site := map[string]string{"wp-includes/version.php": "<?php $wp_version = '6.8';", "wp-content/index.php": "<?php"}
	for _, dir := range []string{"a", "b/c", "node_modules/x", "vendor/y", ".git/z", "d/e/f/g/h/i/j/k", "a/nested"} {
		for p, data := range site {
			writeFiles(t, root, map[string]string{dir + "/" + p: data})
		}
	}
	got, err := FindWordPress(context.Background(), root, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i], _ = filepath.Rel(root, got[i])
		got[i] = filepath.ToSlash(got[i])
	}
	// a/nested is inside a root, so it is not searched; d/e/... is 8
	// folders down, past the default depth.
	if want := []string{"a", "b/c"}; !slices.Equal(got, want) {
		t.Errorf("FindWordPress = %q, want %q", got, want)
	}
	if got, _ := FindWordPress(context.Background(), root, 1); len(got) != 1 {
		t.Errorf("depth 1 = %q, want just a", got)
	}
	if got, _ := FindWordPress(context.Background(), filepath.Join(root, "a"), 3); len(got) != 1 || got[0] != filepath.Join(root, "a") {
		t.Errorf("root itself = %q", got)
	}
	if _, err := FindWordPress(context.Background(), filepath.Join(root, "missing"), 3); err == nil {
		t.Error("a missing folder gave no error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FindWordPress(ctx, root, 3); err == nil {
		t.Error("a canceled search gave no error")
	}
}

// FuzzWPHeader: never panics; every value is a substring of the
// input.
func FuzzWPHeader(f *testing.F) {
	for _, s := range []string{
		"<?php\n/*\nPlugin Name: A\nVersion: 1.2.3\nUpdate URI: w.org\n*/",
		"\ufeff/*\r\nTheme Name: T\r\nVersion: 2\r\n*/",
		"<?php /* Plugin Name: C ?> */",
		"Plugin Name:\nVersion:",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, key := range []string{"Plugin Name", "Theme Name"} {
			h, ok := ParseWPHeader(b, key)
			if !ok {
				continue
			}
			for _, v := range []string{h.Name, h.Version, h.UpdateURI, h.Author, h.AuthorURI, h.RequiresPHP} {
				if !strings.Contains(string(b), v) {
					t.Fatalf("value %q is not in the input", v)
				}
			}
			if h.Line < 1 || h.Line > strings.Count(string(b), "\n")+strings.Count(string(b), "\r")+1 {
				t.Fatalf("line %d out of range", h.Line)
			}
		}
	})
}
