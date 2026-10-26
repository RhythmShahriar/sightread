// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// plugin is an official copy of a small plugin.
var plugin = map[string]string{
	"akismet.php":                    "<?php\n// Plugin Name: Akismet\n",
	"class.akismet.php":              "<?php\nclass Akismet {}\n",
	"class.akismet-admin.php":        "<?php\nclass Akismet_Admin {}\n",
	"views/config.php":               "<?php\n",
	"views/notice.php":               "<?php\n// notice\n",
	"views/stats.php":                "<?php\n// stats\n",
	"views/start.php":                "<?php\n// start\n",
	"_inc/akismet.js":                "jQuery(function(){});\n",
	"readme.txt":                     "=== Akismet ===\nStable tag: 5.3\n",
	"languages/akismet-de_DE.po":     "msgid \"\"\n",
	"languages/akismet-de_DE.mo":     "\xde\x12\x04\x95",
	"languages/akismet-de_DE-1.json": "{}",
}

// code is the files of plugin that Drift compares, sorted, less the
// ones named.
func code(except ...string) []string {
	var out []string
	for _, p := range slices.Sorted(maps.Keys(plugin)) {
		if !DriftIgnored(p) && !slices.Contains(except, p) {
			out = append(out, p)
		}
	}
	return out
}

// with returns a copy of base with changes applied; an empty value
// deletes the path.
func with(base map[string]string, changes map[string]string) map[string]string {
	m := maps.Clone(base)
	for k, v := range changes {
		if v == "" {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return m
}

func TestDrift(t *testing.T) {
	tests := []struct {
		name  string
		local map[string]string
		want  core.Drift
	}{
		{
			name:  "identical copy",
			local: plugin,
			want: core.Drift{
				Matched:  code(),
				Official: true,
			},
		},
		{
			name: "readme and translations changed count as identical",
			local: with(plugin, map[string]string{
				"readme.txt":                     "=== Akismet ===\nStable tag: 5.4\n",
				"languages/akismet-de_DE.po":     "",
				"languages/akismet-fr_FR.mo":     "\xde\x12",
				"languages/akismet-de_DE-1.json": `{"x":1}`,
				".DS_Store":                      "\x00\x00\x00\x01Bud1",
				"views/.DS_Store":                "\x00\x00\x00\x01Bud1",
			}),
			want: core.Drift{
				Matched:  code(),
				Official: true,
			},
		},
		{
			name: "three edited files",
			local: with(plugin, map[string]string{
				"akismet.php":       "<?php\n// Plugin Name: Akismet\n@eval($_POST['x']);\n",
				"class.akismet.php": "<?php\nclass Akismet { }\n",
				"views/config.php":  "<?php\necho 1;\n",
			}),
			want: core.Drift{
				Matched:  code("akismet.php", "class.akismet.php", "views/config.php"),
				Differ:   []string{"akismet.php", "class.akismet.php", "views/config.php"},
				Official: true,
			},
		},
		{
			name: "extra and missing files",
			local: with(plugin, map[string]string{
				"wp-tmp.php":                  "<?php\n",
				"languages/akismet.l10n.php":  "<?php\nreturn [];\n",
				"views/config.php":            "",
				"_inc/img/logo.json":          "{}",
				"languages/akismet-de_DE.pot": "",
			}),
			want: core.Drift{
				Matched:  code("views/config.php"),
				Missing:  []string{"views/config.php"},
				Extra:    []string{"_inc/img/logo.json", "languages/akismet.l10n.php", "wp-tmp.php"},
				Official: true,
			},
		},
		{
			name: "unrelated namesake",
			local: map[string]string{
				"akismet.php": "<?php\n// Plugin Name: My Akismet\n",
				"index.php":   "<?php\n",
				"readme.txt":  "=== Akismet ===\nStable tag: 5.3\n",
			},
			want: core.Drift{
				Differ:   []string{"akismet.php"},
				Missing:  code("akismet.php"),
				Extra:    []string{"index.php"},
				Official: false,
			},
		},
		{
			name:  "nothing installed",
			local: nil,
			want: core.Drift{
				Missing:  code(),
				Official: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Differ{}.Drift(context.Background(), coretest.Tree(tt.local), coretest.Tree(plugin))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("drift = %+v\nwant    %+v", got, tt.want)
			}
		})
	}
}

func TestDriftHalfMatching(t *testing.T) {
	official := coretest.Tree(map[string]string{"a.php": "a", "b.php": "b", "c.php": "c", "d.php": "d"})
	half := coretest.Tree(map[string]string{"a.php": "a", "b.php": "b", "c.php": "x", "d.php": "y"})
	if d := (Differ{}).Drift(context.Background(), half, official); !d.Official {
		t.Error("half the files matching: Official false, want true")
	}
	under := coretest.Tree(map[string]string{"a.php": "a", "b.php": "x", "c.php": "x", "d.php": "y"})
	if d := (Differ{}).Drift(context.Background(), under, official); d.Official {
		t.Error("a quarter matching: Official true, want false")
	}
	if d := (Differ{}).Drift(context.Background(), half, nil); d.Official || len(d.Extra) != 4 {
		t.Errorf("no official tree: %+v", d)
	}
}

func TestDriftIgnoresModes(t *testing.T) {
	official := coretest.Tree(map[string]string{"a.php": "a"})
	local := coretest.Tree(map[string]string{"a.php": "a"})
	local.Files[0].Mode = 0o755
	if d := (Differ{}).Drift(context.Background(), local, official); len(d.Matched) != 1 {
		t.Errorf("drift = %+v, want a match", d)
	}
}

func TestDriftIgnored(t *testing.T) {
	for p, want := range map[string]bool{
		"readme.txt":                   true,
		"README.TXT":                   true,
		"sub/readme.txt":               true,
		".DS_Store":                    true,
		"a/b/.ds_store":                true,
		"languages/x-de_DE.mo":         true,
		"lang/x.mo":                    true,
		"languages/x-de_DE.po":         true,
		"languages/x.pot":              true,
		"languages/x-de_DE-abc.json":   true,
		"inc/languages/x.po":           true,
		"Languages/x.json":             true,
		"readme.md":                    false,
		"readme.txt.php":               false,
		"languages/x-de_DE.l10n.php":   false,
		"languages/x.php":              false,
		"lang/x.po":                    false,
		"assets/data.json":             false,
		"languages.json":               false,
		"mylanguages/x.json":           false,
		"vendor/composer/package.json": false,
	} {
		if got := DriftIgnored(p); got != want {
			t.Errorf("DriftIgnored(%q) = %v, want %v", p, got, want)
		}
	}
}
