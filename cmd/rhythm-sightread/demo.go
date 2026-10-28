// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/demo"
	"github.com/RhythmShahriar/sightread/run"
)

// demoAddr is where the demo server listens: any free 127.0.0.1 port.
// Tests pin it to a port of their own.
var demoAddr = "127.0.0.1:0"

// demoTimeout bounds one request to the demo server.
const demoTimeout = 10 * time.Second

// demoCommand is `demo` (PRD 6.9): three built-in updates reviewed by
// the normal pipeline against a server on 127.0.0.1.
var demoCommand = &simpleCommand{
	name: "demo", args: "[--keep] [-o <file>]... [--open] [--json] [-q] [--fail-on <level>]", brief: "[--keep]", summary: "try it on built-in packages, no network",
	long: "Reviews three updates of built-in example packages: a routine plugin update, a plugin update in the pattern " +
		"of the 2025 Essential Plugin takeover and an npm update that adds an install script and a typosquatted " +
		"dependency. A server on 127.0.0.1 publishes them the way WordPress.org and npm do, so the demo runs the real " +
		"review with no network. Nothing is installed and no package code runs. --keep keeps the archives, the cache " +
		"and the example site in a folder under TMPDIR and prints where and what to run on them. -o writes the report " +
		"to a file as a review does; --open opens the HTML one. --json, -q and --fail-on work as in a review, so " +
		"\"demo --fail-on high\" shows the CI path: it exits 1 because two updates are on HOLD. The other review flags " +
		"(--path, --offline, --to and the rest) don't apply to the built-in packages.",
	examples: []string{"demo", "demo --keep", "demo -o review.html --open", "demo --fail-on high -q"},
	flags: func(fs *flag.FlagSet, sf *simpleFlags) runFunc {
		keep := fs.Bool("keep", false, "keep the generated archives, cache and site and print their folder")
		var outputs cli.RepeatFlag
		fs.Var(&outputs, "output", "also write the report to this `file` (repeatable; .json, .md, .html or .sarif)")
		sf.short(fs, "o", "output")
		open := fs.Bool("open", false, "open the HTML report in the browser when done")
		asJSON := fs.Bool("json", false, "print the rhythm-sightread/v1 JSON report instead of the terminal one")
		quiet := fs.Bool("quiet", false, "verdicts and findings only")
		sf.short(fs, "q", "quiet")
		failOn := fs.String("fail-on", "", "exit 1 on a finding at or above this `level`: none, info, low, medium, high or critical")
		plain := fs.Bool("plain", false, "no color or symbols (also when stdout is not a terminal)")
		noColor := fs.Bool("no-color", false, "no color (NO_COLOR does the same)")
		return func(ctx context.Context, pos []string, stdout, stderr io.Writer) error {
			if len(pos) > 0 {
				return cli.Usagef("demo takes no arguments, got %q", pos[0])
			}
			if *failOn != "" {
				if _, err := cli.ParseFailOn(*failOn); err != nil {
					return badFlag("%s", err.Error())
				}
			}
			var files []output
			for _, path := range outputs {
				format, ok := formatOf(path)
				if !ok || format == core.FormatJSONL {
					return badFlag("-o %q: want a file ending in .json, .md, .html or .sarif", path)
				}
				files = append(files, output{path: path, format: format})
			}
			if *open && !slices.ContainsFunc(files, func(o output) bool { return o.format == core.FormatHTML }) {
				return badFlag("--open opens the HTML report, so write one with -o <file>.html")
			}
			terminal := cli.IsTerminal(stdout)
			o := core.WriteOptions{Program: cli.Name(), Version: version, MaxFindings: defaultMaxFindings,
				Plain: *plain || !terminal, Demo: true, HTMLReport: firstHTML(files), Quiet: *quiet}
			o.Color = !o.Plain && !*noColor && os.Getenv("NO_COLOR") == ""
			rep, err := runDemo(ctx, demoRun{keep: *keep, files: files, json: *asJSON, failOn: strings.ToLower(*failOn)}, o, stdout, stderr)
			if err != nil {
				return err
			}
			if *open {
				openFirstHTML(ctx, files, nil, stderr)
			}
			return gate(rep, core.GateOptions{}, "demo")
		}
	},
}

// demoRun is what the demo flags ask for besides the output options.
type demoRun struct {
	keep   bool
	files  []output // -o
	json   bool     // --json: the JSON report on stdout
	failOn string   // --fail-on
}

// runDemo serves the demo packages, reviews the demo site against them
// and prints the report and the two next steps. Each -o file gets the
// report in its format. It returns the report for the --fail-on gate.
func runDemo(ctx context.Context, d demoRun, o core.WriteOptions, stdout, stderr io.Writer) (_ *core.Report, err error) {
	keep := d.keep
	dir, err := os.MkdirTemp("", "sightread-demo-*") // under TMPDIR when it is set
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			err = errors.Join(err, os.RemoveAll(dir))
		}
	}()
	srv, err := demo.Start(demoAddr, time.Now())
	if err != nil {
		return nil, err
	}
	defer func() { _ = srv.Close() }()

	site, cache, keys := filepath.Join(dir, "site"), filepath.Join(dir, "cache"), filepath.Join(dir, "npm-keys.json")
	if err := demo.WriteSite(site); err != nil {
		return nil, err
	}
	b, err := srv.KeysJSON()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keys, b, 0o600); err != nil {
		return nil, err
	}
	// The npm source trusts a key outside its pinned set only for a
	// loopback mirror, which the demo server is. The cache variable keeps
	// every stage, kit's metadata cache included, inside the folder.
	restore := setenv(map[string]string{"SIGHTREAD_NPM_EXTRA_KEYS": keys, "RHYTHM_CACHE_DIR": cache})
	defer restore()

	rep, err := run.Review(ctx, run.Request{
		Command: "demo", Version: version, NoConfig: true, NoSignalUpdates: true, CacheDir: cache,
		AllHunks:  slices.ContainsFunc(d.files, func(o output) bool { return o.format == core.FormatHTML }),
		Inventory: core.InventoryRequest{Root: site, MaxDepth: 6}, Set: map[string]bool{"path": true}, FailOn: d.failOn,
		Getter: core.GetterConfig{Bases: srv.Bases(), Proxy: srv.Proxy(), Timeout: demoTimeout, Retries: -1,
			UserAgent: "rhythm-sightread/" + version + " (+https://github.com/RhythmShahriar/sightread)"},
	})
	if err != nil {
		return nil, err
	}
	if refused := srv.Refused(); len(refused) > 0 {
		return nil, fmt.Errorf("demo: something tried to leave the machine (%s); please report it", strings.Join(refused, ", "))
	}
	w := core.WriterFor(core.FormatTerminal)
	if w == nil {
		return nil, fmt.Errorf("terminal writer %w", core.ErrNotLinked)
	}
	for _, f := range d.files {
		b, err := render(f.format, rep, o)
		if err != nil {
			return nil, err
		}
		if err := run.WriteFile(f.path, b); err != nil {
			return nil, fmt.Errorf("-o %s: %w", f.path, err)
		}
	}
	switch {
	case d.json:
		b, err := render(core.FormatJSON, rep, o)
		if err != nil {
			return nil, err
		}
		if _, err := stdout.Write(b); err != nil {
			return nil, err
		}
	case o.Quiet:
		if err := w.Write(stdout, rep, o); err != nil {
			return nil, err
		}
	case !o.Plain:
		if err := w.Write(stdout, rep, o); err != nil {
			return nil, err
		}
		fmt.Fprintf(stdout, "\n→ on your site: %s all /path/to/wordpress\n→ in CI: %s init ci\n", cli.Name(), cli.Name())
	default:
		// Plain output has no glyphs: the two lines join the report's
		// own "next:" lines, with no blank line between.
		var buf bytes.Buffer
		if err := w.Write(&buf, rep, o); err != nil {
			return nil, err
		}
		fmt.Fprintf(stdout, "%s\nnext: on your site: %s all /path/to/wordpress\nnext: in CI: %s init ci\n",
			strings.TrimRight(buf.String(), "\n"), cli.Name(), cli.Name())
	}
	if keep {
		if err := keepArchives(srv, filepath.Join(dir, "archives")); err != nil {
			return nil, err
		}
		fmt.Fprintf(stderr, "kept the demo archives, cache and site in %s\n", dir)
		if line := keptNext(dir); line != "" {
			fmt.Fprintf(stderr, "review two of them as local files: %s\n", line)
		}
	}
	return rep, nil
}

// keptNext is the command that reviews the kept takeover plugin as two
// local zips, or "" when the demo has no such plugin.
func keptNext(dir string) string {
	for _, p := range demo.Packages() {
		if p.Eco != core.WPPlugin || p.Expect != core.Hold || p.Old == nil || p.New == nil {
			continue
		}
		zip := func(v string) string { return shellQuote(filepath.Join(dir, "archives", p.Name+"."+v+".zip")) }
		return fmt.Sprintf("%s plugin %s --from-file %s --to-file %s --allow-unverified --no-osv",
			cli.Name(), p.Name, zip(p.Old.Version), zip(p.New.Version))
	}
	return ""
}

// shellQuote quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	safe := func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@%", r)
	}
	if s != "" && strings.IndexFunc(s, func(r rune) bool { return !safe(r) }) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// keepArchives writes every demo archive into dir for --keep.
func keepArchives(srv *demo.Server, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, p := range demo.Packages() {
		for _, v := range []*demo.Version{p.Old, p.New} {
			if v == nil {
				continue
			}
			b, name, ok := srv.Archive(p.Eco, p.Name, v.Version)
			if !ok {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// setenv sets variables for the rest of the command and returns what
// puts the old values back.
func setenv(vars map[string]string) (restore func()) {
	type old struct {
		v  string
		ok bool
	}
	saved := map[string]old{}
	for k, v := range vars {
		ov, ok := os.LookupEnv(k)
		saved[k] = old{ov, ok}
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, o := range saved {
			if o.ok {
				_ = os.Setenv(k, o.v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}
}
