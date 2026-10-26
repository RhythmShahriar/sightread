// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package staging describes the --soundcheck end to end scenario (e15)
// against the Docker WordPress of testbed/docker-compose.yml: the cases
// (one that applies the update and one per refusal), how each is judged
// and the zip that puts the old version back between cases. It starts no
// process; the benchmark (testbed/bench) runs the cases through the real
// binary, testbed/bin/wp and the Roadie stub and hands the results here.
package staging

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// URL is the staging site the cases point --soundcheck at.
var URL = fmt.Sprintf("http://127.0.0.1:%d", ports.WPDocker)

// Case is one --soundcheck run of e15.
type Case struct {
	// Name identifies the case in the benchmark.
	Name string
	// Slug is the plugin the case reviews and would update.
	Slug string
	// From and To are the installed and candidate versions.
	From, To string
	// Roadie is the stub's outcome (see testbed/stubs/roadie); empty
	// leaves rhythm-roadie off PATH.
	Roadie string
	// WP replaces the --wp command; empty uses testbed/bin/wp.
	WP string
	// WantExit is the exit code Sightread must give.
	WantExit int
	// Says is text the output must contain (case-insensitive).
	Says string
	// Applies says the update must land in the container. Every other
	// case is a refusal that must stop before any change.
	Applies bool
	// NeedsSoundcheck marks the case that runs the real rhythm-soundcheck;
	// it is "not run" when Soundcheck is not on PATH.
	NeedsSoundcheck bool
}

// Cases are the e15 cases, the applying one first. The remote --wp case
// names an ssh prefix to a loopback port where nothing listens, so even
// a Sightread that wrongly ran it would reach nothing.
func Cases() []Case {
	const slug, from, to = "e15-soundcheck", "1.0.0", "1.1.0"
	remote := fmt.Sprintf("ssh -p %d 127.0.0.1 wp", ports.ProbeUnconfigured)
	return []Case{
		{Name: "applies", Slug: slug, From: from, To: to, Roadie: "ok", WantExit: 0, Says: "Sightread did not", Applies: true, NeedsSoundcheck: true},
		{Name: "hold", Slug: "b01-widget", From: "2.6.7", To: "2.6.8", Roadie: "ok", WantExit: 1, Says: "HOLD"},
		{Name: "production", Slug: slug, From: from, To: to, Roadie: "production", WantExit: 2, Says: "production"},
		{Name: "roadie-failed", Slug: slug, From: from, To: to, Roadie: "failed", WantExit: 3, Says: "roadie verify"},
		{Name: "roadie-stale", Slug: slug, From: from, To: to, Roadie: "stale", WantExit: 3, Says: "roadie verify"},
		{Name: "roadie-unsealed", Slug: slug, From: from, To: to, Roadie: "unsealed", WantExit: 3, Says: "roadie verify"},
		{Name: "roadie-missing", Slug: slug, From: from, To: to, WantExit: 3, Says: "rhythm-roadie"},
		{Name: "remote-wp", Slug: slug, From: from, To: to, Roadie: "ok", WP: remote, WantExit: 2, Says: "--apply"},
	}
}

// Args is the command line of a case after rhythm-sightread. wp is the
// --wp command the case uses by default (testbed/bin/wp).
func (c Case) Args(wp string) []string {
	if c.WP != "" {
		wp = c.WP
	}
	return []string{"plugin", c.Slug, "--soundcheck", URL, "--wp", wp, "--fail-on", "high", "--plain"}
}

// Result is what the benchmark observed for one case.
type Result struct {
	// Exit is Sightread's exit code; Output its stdout and stderr.
	Exit   int
	Output string
	// Before and After are the plugin's version in the container.
	Before, After string
	// HostChanged lists files of the host project fixtures that changed.
	HostChanged []string
	// Elapsed is how long the run took.
	Elapsed time.Duration
}

// Judge lists what a case got wrong; an empty list is a pass.
func Judge(c Case, r Result) []string {
	var bad []string
	if r.Exit != c.WantExit {
		bad = append(bad, fmt.Sprintf("exit %d, want %d", r.Exit, c.WantExit))
	}
	if c.Says != "" && !strings.Contains(strings.ToLower(r.Output), strings.ToLower(c.Says)) {
		bad = append(bad, fmt.Sprintf("output does not say %q", c.Says))
	}
	if r.Before != c.From {
		bad = append(bad, fmt.Sprintf("the container had %s %s before the run, want %s", c.Slug, r.Before, c.From))
	}
	switch {
	case c.Applies && r.After != c.To:
		bad = append(bad, fmt.Sprintf("the container has %s %s after the run, want %s", c.Slug, r.After, c.To))
	case !c.Applies && r.After != r.Before:
		bad = append(bad, fmt.Sprintf("a refusal changed the container: %s %s became %s", c.Slug, r.Before, r.After))
	}
	if len(r.HostChanged) > 0 {
		bad = append(bad, "the host project changed: "+strings.Join(r.HostChanged, ", "))
	}
	return bad
}

// WriteZip writes the tree at dir as a WordPress plugin zip whose entries
// sit under top/, in a fixed order with fixed times so the bytes are the
// same on every run. The benchmark installs it to put the old version
// back between cases.
func WriteZip(w io.Writer, dir, top string) error {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	zw := zip.NewWriter(w)
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, rel := range files {
		hdr := &zip.FileHeader{Name: path.Join(top, rel), Method: zip.Deflate, Modified: stamp}
		hdr.SetMode(0o644)
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))) //nolint:gosec // the testbed's own fixtures
		if err != nil {
			return err
		}
		if _, err := fw.Write(b); err != nil {
			return err
		}
	}
	return zw.Close()
}
