// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRooted(t *testing.T) {
	cases := map[string]bool{
		"site":                         false,
		"sites/shop":                   false,
		filepath.FromSlash("/var/www"): true,
	}
	if runtime.GOOS == "windows" {
		cases[`C:\sites\shop`] = true
		cases[`\var\www`] = true
		cases[`C:www`] = true
	}
	for p, want := range cases {
		if got := rooted(p); got != want {
			t.Errorf("rooted(%q) = %v, want %v", p, got, want)
		}
	}
}
