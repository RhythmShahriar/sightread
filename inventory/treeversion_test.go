// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// TestTreeVersion reads the version a local copy declares, the way the
// platform would after installing it, and refuses anything that is not a
// plain version token.
func TestTreeVersion(t *testing.T) {
	plugin := "<?php\n/*\n * Plugin Name: Premium\n * Version: 2.8.1\n */\n"
	cases := []struct {
		name  string
		eco   core.Ecosystem
		files map[string]string
		want  string
	}{
		{"plugin main file", core.WPPlugin, map[string]string{"premium.php": plugin, "inc/a.php": "<?php"}, "2.8.1"},
		{"plugin in its folder", core.WPPlugin, map[string]string{"premium/premium.php": plugin, "premium/readme.txt": "x"}, "2.8.1"},
		{"plugin main file by another name", core.WPPlugin, map[string]string{"loader.php": plugin, "a.php": "<?php // no header"}, "2.8.1"},
		{"plugin header in a subfolder only", core.WPPlugin, map[string]string{"inc/premium.php": plugin, "a.php": "<?php"}, ""},
		{"plugin without a version", core.WPPlugin, map[string]string{"premium.php": "<?php\n/* Plugin Name: Premium */\n"}, ""},
		{"theme", core.WPTheme, map[string]string{"style.css": "/*\nTheme Name: Shop\nVersion: 3.1\n*/", "index.php": "<?php"}, "3.1"},
		{"theme without a header", core.WPTheme, map[string]string{"style.css": "body{}", "index.php": "<?php"}, ""},
		{"npm", core.NPM, map[string]string{"package/package.json": `{"name":"x","version":"1.4.0"}`, "package/index.js": ""}, "1.4.0"},
		{"npm hostile version", core.NPM, map[string]string{"package.json": `{"version":"1.0.0\u001b[31m"}`}, ""},
		{"npm version with spaces", core.NPM, map[string]string{"package.json": `{"version":"1.0 rm -rf"}`}, ""},
		{"npm bad JSON", core.NPM, map[string]string{"package.json": `{"version":`}, ""},
		{"composer", core.Composer, map[string]string{"composer.json": `{"name":"acme/x","version":"2.0.0"}`}, "2.0.0"},
		{"composer without a version", core.Composer, map[string]string{"composer.json": `{"name":"acme/x"}`}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (&Reader{}).TreeVersion(c.eco, "premium", coretest.Tree(c.files)); got != c.want {
				t.Errorf("TreeVersion = %q, want %q", got, c.want)
			}
		})
	}
	if got := (&Reader{}).TreeVersion(core.WPPlugin, "premium", nil); got != "" {
		t.Errorf("nil tree: %q", got)
	}
}

// FuzzTreeVersion: any style.css or package.json gives a short plain
// version token or nothing, and never panics.
func FuzzTreeVersion(f *testing.F) {
	f.Add("/*\nTheme Name: Shop\nVersion: 3.1\n*/")
	f.Add(`{"version":"1.4.0"}`)
	f.Add("Theme Name: x\nVersion: \x00\x1b]8;;")
	f.Fuzz(func(t *testing.T, data string) {
		for _, eco := range []core.Ecosystem{core.WPTheme, core.NPM} {
			v := (&Reader{}).TreeVersion(eco, "x", coretest.Tree(map[string]string{"style.css": data, "package.json": data}))
			if len(v) > maxVersionLen || (v != "" && versionToken.FindString(v) != v) {
				t.Fatalf("%s: version %q", eco, v)
			}
		}
	})
}
