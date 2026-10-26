// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A large flat YAML lockfile under the byte cap is turned away before
// yaml.Unmarshal builds its tree, within a time and memory bound.
func TestYAMLFlatListFailsFast(t *testing.T) {
	cases := map[string]string{
		"block list":  "packages:\n" + strings.Repeat("- a\n", 8<<20),
		"nested dash": "packages:\n" + strings.Repeat("- - a\n", 4<<20),
		"flow list":   "packages: [" + strings.Repeat("a,", 8<<20) + "a]\n",
		"stray quote": "packages: [x'y," + strings.Repeat("a,", 8<<20) + "a]\n",
		"flow map":    "packages: {" + strings.Repeat("a: b, ", 3<<20) + "a: b}\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			_, err := ParseNPMLock("pnpm-lock.yaml", []byte(doc), nil, Options{})
			d := time.Since(start)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, errYAMLBomb) {
				t.Fatalf("err = %v, want the YAML bomb error", err)
			}
			if d > 2*time.Second {
				t.Errorf("took %s", d)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
				t.Errorf("allocated %d MiB", alloc>>20)
			}
		})
	}
}

// Negative: the count stays under the cap for every real lockfile
// fixture and for marks inside quotes and comments.
func TestYAMLNodeFloor(t *testing.T) {
	for doc, want := range map[string]int{
		"a: b\n":                    1,
		"- a\n- b\n":                2,
		"- - a\n":                   2,
		"a-b: c-d\n":                1,
		"x: 'a, b: c, - d'\n":       1,
		"x: \"[a, {b\"\n":           1,
		"x: y # a, b, c: d\n":       1,
		"x: [a, b]\n":               3,
		"x: it's, a: b\n":           3,
		"url: https://x.test/a:b\n": 1,
	} {
		if got := yamlNodeFloor([]byte(doc)); got != want {
			t.Errorf("yamlNodeFloor(%q) = %d, want %d", doc, got, want)
		}
	}
	files, _ := filepath.Glob("testdata/npm/*/*.yaml")
	more, _ := filepath.Glob("testdata/npm/*/yarn.lock")
	for _, f := range append(files, more...) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if n := yamlNodeFloor(b); n > len(b) || n > maxYAMLNodes {
			t.Errorf("%s: floor %d over the file", f, n)
		}
	}
}

func FuzzYAMLNodeFloor(f *testing.F) {
	f.Add([]byte("packages:\n  a@1.0.0:\n    resolution: {integrity: x}\n"))
	f.Add([]byte("- 'a\n- b"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if n := yamlNodeFloor(data); n < 0 || n > len(data) {
			t.Fatalf("floor %d for %d bytes", n, len(data))
		}
		_, _ = parseYAML(data)
	})
}
