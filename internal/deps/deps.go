// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package deps holds blank imports of every dependency the lanes build
// with, so go.mod requires them from the first commit and no lane has to
// edit go.mod or go.sum. Nothing imports this package; go mod tidy keeps
// a requirement any package of the module uses.
package deps

import (
	_ "github.com/charmbracelet/huh"      // the picker
	_ "github.com/charmbracelet/lipgloss" // terminal layout
	_ "github.com/charmbracelet/x/term"   // terminal width
	_ "github.com/muesli/termenv"         // color profile
	_ "golang.org/x/net/idna"             // punycode hosts
	_ "golang.org/x/net/publicsuffix"     // eTLD+1 of hosts in code
	_ "golang.org/x/sync/errgroup"        // the review worker pool
	_ "golang.org/x/text/unicode/norm"    // NFC of archive entry names
	_ "gopkg.in/yaml.v3"                  // config, allow and rule files
)
