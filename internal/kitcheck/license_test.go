// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package kitcheck

import (
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// licenses is every module the build or its tests link, with its
// license. A new dependency fails TestLicenses until someone reads its
// license and adds it here; THIRD_PARTY/ lists the same modules for the
// release.
var licenses = map[string]string{
	"github.com/RhythmShahriar/sightread":    "MIT",
	"github.com/RhythmShahriar/rhythm":       "AGPL-3.0-only", // the kit, Rhythm's own
	"github.com/atotto/clipboard":            "BSD-3-Clause",
	"github.com/aymanbagabas/go-osc52/v2":    "MIT",
	"github.com/catppuccin/go":               "MIT",
	"github.com/charmbracelet/bubbles":       "MIT",
	"github.com/charmbracelet/bubbletea":     "MIT",
	"github.com/charmbracelet/colorprofile":  "MIT",
	"github.com/charmbracelet/huh":           "MIT",
	"github.com/charmbracelet/lipgloss":      "MIT",
	"github.com/charmbracelet/x/ansi":        "MIT",
	"github.com/charmbracelet/x/cellbuf":     "MIT",
	"github.com/charmbracelet/x/exp/strings": "MIT",
	"github.com/charmbracelet/x/term":        "MIT",
	"github.com/dustin/go-humanize":          "MIT",
	"github.com/erikgeiser/coninput":         "MIT",
	"github.com/lucasb-eyer/go-colorful":     "MIT",
	"github.com/mattn/go-isatty":             "MIT",
	"github.com/mattn/go-localereader":       "MIT",
	"github.com/mattn/go-runewidth":          "MIT",
	"github.com/mitchellh/hashstructure/v2":  "MIT",
	"github.com/muesli/ansi":                 "MIT",
	"github.com/muesli/cancelreader":         "MIT",
	"github.com/muesli/termenv":              "MIT",
	"github.com/rivo/uniseg":                 "MIT",
	"github.com/xo/terminfo":                 "MIT",
	"golang.org/x/net":                       "BSD-3-Clause", // publicsuffix's table is MPL-2.0 data
	"golang.org/x/sync":                      "BSD-3-Clause",
	"golang.org/x/sys":                       "BSD-3-Clause",
	"golang.org/x/text":                      "BSD-3-Clause",
	"gopkg.in/yaml.v3":                       "MIT and Apache-2.0",
}

// TestLicenses lists the modules of every package the module builds,
// tests included, on each OS. It fails on one missing from licenses.
// It reads the build graph rather than go list -m all: the full module
// graph also names modules of the kit's own tools (sigstore and the
// like) that no Sightread package compiles.
func TestLicenses(t *testing.T) {
	seen := map[string]bool{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command("go", "list", "-deps", "-test", "-f", "{{with .Module}}{{.Path}}{{end}}", "./...")
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOWORK=off", "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (%s): %v", goos, err)
		}
		for _, m := range strings.Fields(string(out)) {
			seen[m] = true
		}
	}
	var unknown []string
	for m := range seen {
		if _, ok := licenses[m]; !ok {
			unknown = append(unknown, m)
		}
	}
	sort.Strings(unknown)
	for _, m := range unknown {
		t.Errorf("module %s has no known license: read it and add it to licenses (and THIRD_PARTY/)", m)
	}
	if !seen["github.com/RhythmShahriar/rhythm"] {
		t.Error("the kit isn't in the build graph: is go list reading the right module?")
	}
}
