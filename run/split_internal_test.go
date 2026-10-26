// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"runtime"
	"slices"
	"testing"
)

// TestSplitCommandWindows: on Windows a backslash is a path separator,
// literal unless it escapes a double quote.
func TestSplitCommandWindows(t *testing.T) {
	for in, want := range map[string][]string{
		`C:\tools\wp.bat --path=C:\site`:      {`C:\tools\wp.bat`, `--path=C:\site`},
		`"C:\Program Files\wp\wp.bat" plugin`: {`C:\Program Files\wp\wp.bat`, "plugin"},
		`wp --title=\"x\"`:                    {"wp", `--title="x"`},
		`"\\server\share\wp.bat"`:             {`\\server\share\wp.bat`},
		`wp x\`:                               {"wp", `x\`},
	} {
		got, err := splitCommand(in, true)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("windows %q = %q, %v; want %q", in, got, err, want)
		}
	}
	// The POSIX rule still escapes.
	if got, err := splitCommand(`C:\\tools\\wp.bat d\ e`, false); err != nil || !slices.Equal(got, []string{`C:\tools\wp.bat`, "d e"}) {
		t.Errorf("posix: %q, %v", got, err)
	}
}

// TestSplitCommandOnWindows runs SplitCommand itself on a Windows host.
func TestSplitCommandOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	got, err := SplitCommand(`C:\tools\wp.bat --path=C:\site`)
	if err != nil || !slices.Equal(got, []string{`C:\tools\wp.bat`, `--path=C:\site`}) {
		t.Errorf("got %q, %v", got, err)
	}
}
