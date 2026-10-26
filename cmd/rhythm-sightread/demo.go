// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	name: "demo", args: "[--keep]", summary: "try it on built-in packages, no network",
	long: "Reviews three updates of built-in example packages: a routine plugin update, a plugin update in the pattern " +
		"of the 2025 Essential Plugin takeover and an npm update that adds an install script and a typosquatted " +
		"dependency. A server on 127.0.0.1 publishes them the way WordPress.org and npm do, so the demo runs the real " +
		"review with no network. Nothing is installed and no package code runs. --keep keeps the archives, the cache " +
		"and the example site in a temporary folder and prints where.",
	examples: []string{"demo", "demo --keep"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		keep := fs.Bool("keep", false, "keep the generated archives, cache and site and print their folder")
		plain := fs.Bool("plain", false, "no colour or symbols (also when stdout is not a terminal)")
		noColor := fs.Bool("no-color", false, "no colour (also NO_COLOR)")
		return func(ctx context.Context, pos []string, stdout, stderr io.Writer) error {
			if len(pos) > 0 {
				return cli.Usagef("demo takes no arguments, got %q", pos[0])
			}
			terminal := cli.IsTerminal(stdout)
			o := core.WriteOptions{Program: cli.Name(), Version: version, MaxFindings: defaultMaxFindings,
				Plain: *plain || !terminal}
			o.Color = !o.Plain && !*noColor && os.Getenv("NO_COLOR") == ""
			return runDemo(ctx, *keep, o, stdout, stderr)
		}
	},
}

// runDemo serves the demo packages, reviews the demo site against them
// and prints the report and the two next steps.
func runDemo(ctx context.Context, keep bool, o core.WriteOptions, stdout, stderr io.Writer) (err error) {
	dir, err := os.MkdirTemp("", "sightread-demo-*")
	if err != nil {
		return err
	}
	defer func() {
		if !keep {
			err = errors.Join(err, os.RemoveAll(dir))
		}
	}()
	srv, err := demo.Start(demoAddr, time.Now())
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	site, cache, keys := filepath.Join(dir, "site"), filepath.Join(dir, "cache"), filepath.Join(dir, "npm-keys.json")
	if err := demo.WriteSite(site); err != nil {
		return err
	}
	b, err := srv.KeysJSON()
	if err != nil {
		return err
	}
	if err := os.WriteFile(keys, b, 0o600); err != nil {
		return err
	}
	// The npm source trusts a key outside its pinned set only for a
	// loopback mirror, which the demo server is. The cache variable keeps
	// every stage, kit's metadata cache included, inside the folder.
	restore := setenv(map[string]string{"SIGHTREAD_NPM_EXTRA_KEYS": keys, "RHYTHM_CACHE_DIR": cache})
	defer restore()

	rep, err := run.Review(ctx, run.Request{
		Command: "demo", Version: version, NoConfig: true, NoSignalUpdates: true, CacheDir: cache,
		Inventory: core.InventoryRequest{Root: site, MaxDepth: 6}, Set: map[string]bool{"path": true},
		Getter: core.GetterConfig{Bases: srv.Bases(), Proxy: srv.Proxy(), Timeout: demoTimeout, Retries: -1,
			UserAgent: "rhythm-sightread/" + version + " (+https://github.com/RhythmShahriar/sightread)"},
	})
	if err != nil {
		return err
	}
	if refused := srv.Refused(); len(refused) > 0 {
		return fmt.Errorf("demo: something tried to leave the machine (%s); please report it", strings.Join(refused, ", "))
	}
	w := core.WriterFor(core.FormatTerminal)
	if w == nil {
		return fmt.Errorf("terminal writer %w", core.ErrNotLinked)
	}
	if err := w.Write(stdout, rep, o); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\n→ on your site: %s all /path/to/wordpress\n→ in CI: %s init ci\n", cli.Name(), cli.Name())
	if keep {
		if err := keepArchives(srv, filepath.Join(dir, "archives")); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "kept the demo archives, cache and site in %s\n", dir)
	}
	return nil
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
