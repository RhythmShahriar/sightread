// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

// Command bench runs Sightread's public benchmark: it builds
// bin/rhythm-sightread from this checkout, starts the fixture registry,
// the canary, the webhook receiver, the probes, the misbehaving fronts
// and the proxy guard on loopback, runs every scenario of
// testbed/scenarios.yaml through the real binary with every SIGHTREAD_*
// base pointed at the registry, checks each review against its
// expectation and writes docs/benchmark.md (see testbed/benchdoc). It
// exits non-zero when a 1.0 target is not met.
//
// Run from the module root:
//
//	go run -tags testbed ./testbed/bench [-only b01,g05,env] [-tools auto|none|all|"npm composer guarddog soundcheck"]
//	go run -tags testbed ./testbed/bench -diff first.json second.json
//	go run -tags testbed ./testbed/bench -only e13 -plain-http   (Windows)
//
// Go reads SSL_CERT_FILE only on Unix, so on Windows the registry
// serves plain HTTP on loopback (-plain-http, the default there), which
// Sightread accepts for a loopback mirror only.
//
// The e15 cases and the Soundcheck column need the Docker WordPress
// (make -C testbed up-wp); without it they are reported as not run.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
)

// options are the command-line flags.
type options struct {
	bin, out, work, results string
	build                   bool
	only                    []string
	tools                   string
	rounds                  int
	timeout                 time.Duration
	large                   bool
	// plainHTTP serves the registry and the fronts without TLS.
	plainHTTP bool
}

func main() {
	var o options
	var only, diff string
	flag.StringVar(&o.bin, "bin", "bin/rhythm-sightread", "the binary to benchmark (built there first unless -build=false)")
	flag.BoolVar(&o.build, "build", true, "build the binary from this checkout before the run")
	flag.StringVar(&o.out, "out", "docs/benchmark.md", "where to write the page")
	flag.StringVar(&o.work, "work", "", "working folder (default testbed/bench/work)")
	flag.StringVar(&o.results, "results", "", "where to write results.json (default <work>/results.json)")
	flag.StringVar(&only, "only", "", "comma-separated scenario ids to run; bad, good and env pick a kind (default all)")
	flag.StringVar(&o.tools, "tools", "auto", `compared tools: auto (npm, composer, guarddog when installed), none, all (auto plus soundcheck) or names`)
	flag.IntVar(&o.rounds, "rounds", 10, "control pass rounds over the good scenarios")
	flag.DurationVar(&o.timeout, "timeout", 2*time.Minute, "time limit for each command")
	flag.BoolVar(&o.large, "large", true, "run the p01-large performance check")
	flag.BoolVar(&o.plainHTTP, "plain-http", runtime.GOOS == "windows", "serve the registry over plain HTTP on loopback (no compared tools); the default on Windows, where Go ignores SSL_CERT_FILE")
	flag.StringVar(&diff, "diff", "", "compare the outcomes of two results.json files (this flag and one argument); exit 1 if they differ")
	flag.Parse()

	if diff != "" {
		if flag.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "bench: -diff takes two files: -diff first.json second.json")
			os.Exit(2)
		}
		a, err := benchdoc.Read(diff)
		if err == nil {
			var b *benchdoc.Results
			if b, err = benchdoc.Read(flag.Arg(0)); err == nil {
				if !benchdoc.Diff(a, b, os.Stdout) {
					os.Exit(1)
				}
				return
			}
		}
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(2)
	}
	if only != "" {
		o.only = strings.Split(only, ",")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := run(ctx, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(2)
	}
	if res.Partial {
		// A partial run never claims the targets; it passes when every
		// scenario that ran did.
		if failed := res.PartialFailures(); len(failed) > 0 {
			fmt.Fprintf(os.Stderr, "bench: partial run (-only): failed: %s\n", strings.Join(failed, ", "))
			os.Exit(1)
		}
		fmt.Println("bench: partial run (-only): every scenario that ran passed; the 1.0 targets are not claimed")
		return
	}
	if !res.Met() {
		for _, t := range res.Targets() {
			if !t.Met {
				fmt.Fprintf(os.Stderr, "bench: NOT MET: %s (%s)\n", t.Name, t.Detail)
			}
		}
		os.Exit(1)
	}
	fmt.Println("bench: every 1.0 target met")
}

// moduleRoot finds the Sightread module root from the current folder.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // looking for our own go.mod
		if err == nil && strings.Contains(string(b), "module github.com/RhythmShahriar/sightread\n") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run from the Sightread checkout (no go.mod of github.com/RhythmShahriar/sightread above here)")
		}
		dir = parent
	}
}

// scrub makes the checkout's absolute path relative in every free-text
// field, so the committed page names no folder of the machine it ran on.
func scrub(r *benchdoc.Results, root string) {
	prefix := root + string(filepath.Separator)
	fix := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, prefix, ""), root, ".") }
	fixAll := func(ss []string) {
		for i := range ss {
			ss[i] = fix(ss[i])
		}
	}
	r.BinErr = fix(r.BinErr)
	for i := range r.Scenarios {
		r.Scenarios[i].Problem = fix(r.Scenarios[i].Problem)
	}
	for _, list := range [][]benchdoc.EnvResult{r.Env, r.Staging} {
		for i := range list {
			fixAll(list[i].Notes)
		}
	}
	fixAll(r.Safety.CanaryFiles)
	fixAll(r.Safety.Egress)
	fixAll(r.Safety.OutsideWrites)
	r.Large.Note = fix(r.Large.Note)
	for i := range r.Tools {
		r.Tools[i].NotRun = fix(r.Tools[i].NotRun)
	}
}

// run is the whole benchmark.
func run(ctx context.Context, o options) (*benchdoc.Results, error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, err
	}
	h, err := newHarness(ctx, root, o)
	if err != nil {
		return nil, err
	}
	defer h.Close()

	res := h.res
	pick, err := h.pick(o.only)
	if err != nil {
		return nil, err
	}
	res.Partial = len(o.only) > 0

	if res.BinErr == "" {
		for _, s := range pick.scored {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			fmt.Printf("bench: %s %s\n", s.ID, s.Title)
			res.Scenarios = append(res.Scenarios, h.scored(ctx, s))
		}
		res.Control = h.control(ctx, pick.scored, o.rounds)
		for _, s := range pick.env {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			fmt.Printf("bench: %s %s\n", s.ID, s.Title)
			if s.ID == "e15" {
				res.Staging = h.staging(ctx)
				res.Env = append(res.Env, summarizeStaging(s, res.Staging))
				continue
			}
			res.Env = append(res.Env, h.environment(ctx, s))
		}
		if o.large && !res.Partial {
			fmt.Println("bench: p01-large")
			res.Large = h.large(ctx)
		} else {
			res.Large.Note = "skipped for a partial run or with -large=false"
		}
		h.compare(ctx, res)
	}

	res.Safety = h.safety()
	res.Seconds = time.Since(res.Started).Seconds()
	scrub(res, root)

	resultsPath := o.results
	if resultsPath == "" {
		resultsPath = filepath.Join(h.work, "results.json")
	}
	if err := res.Write(resultsPath); err != nil {
		return nil, err
	}
	out := o.out
	if !filepath.IsAbs(out) {
		out = filepath.Join(root, out)
	}
	old, _ := os.ReadFile(out) //nolint:gosec // our own page, kept for its corpus block
	page := benchdoc.Render(res, benchdoc.CorpusBlock(string(old)))
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil { //nolint:gosec // docs folder
		return nil, err
	}
	if err := os.WriteFile(out, []byte(page), 0o644); err != nil { //nolint:gosec // a public page
		return nil, err
	}
	fmt.Printf("bench: wrote %s and %s\n", out, resultsPath)
	return res, nil
}
