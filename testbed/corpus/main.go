// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build corpus

// Command corpus measures Sightread on real releases, the optional
// owner-run section of docs/benchmark.md. It needs network, so it is
// never part of make bench or CI.
//
//	go run -tags corpus ./testbed/corpus fetch [-pin]   download and verify every archive of corpus.lock
//	go run -tags corpus ./testbed/corpus run            review each pair, time the PRD 17 cases, write the section
//
// fetch reaches downloads.wordpress.org and registry.npmjs.org only. It
// checks each archive against the SHA-256 in corpus.lock; -pin records
// the hash of entries still marked - and rewrites the lock. run reviews
// the cached pairs with --from-file and --to-file, then times the real
// network cases of PRD 17 with Sightread's normal sources.
package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec" //nolint:depguard // the corpus run starts the binary it measures
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/corpus/release"
	"github.com/RhythmShahriar/sightread/testbed/scenario"
)

// maxArchive caps one download, as Sightread's own --max-size default.
const maxArchive = 256 << 20

type options struct {
	lock, cache, bin, out string
	pin, build, timings   bool
	timeout               time.Duration
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "fetch" && os.Args[1] != "run") {
		fmt.Fprintln(os.Stderr, "usage: go run -tags corpus ./testbed/corpus fetch [-pin] | run")
		os.Exit(2)
	}
	cmd := os.Args[1]
	var o options
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.StringVar(&o.lock, "lock", "testbed/corpus/corpus.lock", "the corpus lock")
	fs.StringVar(&o.cache, "cache", "testbed/corpus/cache", "where archives and results are kept")
	fs.StringVar(&o.bin, "bin", "bin/rhythm-sightread", "the binary to run")
	fs.BoolVar(&o.build, "build", true, "build the binary from this checkout first (run)")
	fs.StringVar(&o.out, "out", "docs/benchmark.md", "the page whose real-release section is replaced (run)")
	fs.BoolVar(&o.pin, "pin", false, "record the hash of every entry still marked - (fetch)")
	fs.BoolVar(&o.timings, "timings", true, "time the PRD 17 real-network cases (run)")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Minute, "time limit for each command (run)")
	_ = fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	if cmd == "fetch" {
		err = fetch(ctx, o)
	} else {
		err = run(ctx, o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus:", err)
		os.Exit(1)
	}
}

// readLock parses the lock and returns it with its raw text.
func readLock(path string) ([]release.Entry, string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the lock the owner named
	if err != nil {
		return nil, "", err
	}
	entries, err := release.ParseLock(strings.NewReader(string(b)))
	return entries, string(b), err
}

// fetch downloads every archive and checks it against the lock.
func fetch(ctx context.Context, o options) error {
	entries, raw, err := readLock(o.lock)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	var failed []string
	pinned := 0
	for i := range entries {
		e := &entries[i]
		for _, side := range []struct {
			version string
			sha     *string
		}{{e.From, &e.FromSHA}, {e.To, &e.ToSHA}} {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			got, err := fetchOne(ctx, client, o.cache, *e, side.version, *side.sha)
			switch {
			case err != nil:
				failed = append(failed, fmt.Sprintf("%s %s: %v", e.Ref(), side.version, err))
			case *side.sha == release.Unpinned && o.pin:
				*side.sha = got
				pinned++
			case *side.sha == release.Unpinned:
				failed = append(failed, fmt.Sprintf("%s %s: not pinned yet (run make -C testbed corpus PIN=1 once)", e.Ref(), side.version))
			}
		}
		fmt.Printf("fetched %s %s and %s\n", e.Ref(), e.From, e.To)
	}
	if pinned > 0 {
		if err := os.WriteFile(o.lock, []byte(release.FormatLock(release.Header(raw), entries)), 0o644); err != nil { //nolint:gosec // the lock is committed
			return err
		}
		fmt.Printf("pinned %d archives in %s; commit it\n", pinned, o.lock)
	}
	stamp, _ := json.Marshal(map[string]string{"fetched": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(o.cache, "fetched.json"), stamp, 0o644); err != nil { //nolint:gosec // not a secret
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d archives failed:\n  %s", len(failed), strings.Join(failed, "\n  "))
	}
	return nil
}

// fetchOne makes sure the archive of v is cached and matches want (when
// pinned) and returns its SHA-256.
func fetchOne(ctx context.Context, client *http.Client, cache string, e release.Entry, v, want string) (string, error) {
	dest := release.CachePath(cache, e, v)
	if have, err := fileSHA(dest); err == nil && (want == release.Unpinned || have == want) {
		return have, nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL(e, v), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "rhythm-sightread-corpus (+https://github.com/RhythmShahriar/sightread)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp) //nolint:gosec // under the corpus cache
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchive+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxArchive {
		err = fmt.Errorf("larger than %d MB", maxArchive>>20)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if err == nil && want != release.Unpinned && got != want {
		err = fmt.Errorf("sha256 %s, the lock pins %s", got, want)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return got, os.Rename(tmp, dest)
}

// fileSHA hashes a file.
func fileSHA(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // under the corpus cache
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runner starts the binary for the corpus.
type runner struct {
	bin, work string
	timeout   time.Duration
}

// sightread runs the binary with the owner's environment (real network),
// its own cache and no update check; it returns the exit code.
func (r runner) sightread(ctx context.Context, cache string, args ...string) (int, []byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.bin, args...) //nolint:gosec // the binary under test
	cmd.Dir = r.work
	cmd.Env = append(os.Environ(), "RHYTHM_NO_UPDATE_CHECK=1", "NO_COLOR=1", "RHYTHM_CACHE_DIR="+cache)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	took := time.Since(start)
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return code, out, took, err
	}
	return code, out, took, nil
}

// run reviews every cached pair and times the PRD 17 cases.
func run(ctx context.Context, o options) error {
	entries, _, err := readLock(o.lock)
	if err != nil {
		return err
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	cache, err := filepath.Abs(o.cache)
	if err != nil {
		return err
	}
	bin, err := filepath.Abs(o.bin)
	if err != nil {
		return err
	}
	if o.build {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/rhythm-sightread") //nolint:gosec // building this checkout
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build: %w\n%s", err, out)
		}
	}
	work := filepath.Join(cache, "run")
	if err := os.RemoveAll(work); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(work, "out"), 0o750); err != nil {
		return err
	}
	r := runner{bin: bin, work: work, timeout: o.timeout}

	res := release.Run{Ran: time.Now().UTC(), Machine: fmt.Sprintf("%s/%s, %d CPUs", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())}
	if b, err := os.ReadFile(filepath.Join(cache, "fetched.json")); err == nil { //nolint:gosec // our own cache
		var f struct{ Fetched time.Time }
		_ = json.Unmarshal(b, &f)
		res.Fetched = f.Fetched
	}
	if code, out, _, err := r.sightread(ctx, filepath.Join(work, "c-version"), "--version"); err == nil && code == 0 {
		res.Version = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	}

	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rv := reviewPair(ctx, r, cache, e)
		fmt.Printf("%s %s to %s: %s %s\n", e.Ref(), e.From, e.To, rv.Verdict, rv.Error)
		res.Reviews = append(res.Reviews, rv)
	}
	if o.timings {
		res.Timings = timings(ctx, r, cache, entries)
	}

	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.WriteFile(filepath.Join(cache, "run.json"), b, 0o644); err != nil { //nolint:gosec // results
		return err
	}
	out := o.out
	if !filepath.IsAbs(out) {
		out = filepath.Join(root, out)
	}
	page, err := os.ReadFile(out) //nolint:gosec // our own page
	if err != nil {
		return fmt.Errorf("%w (run the benchmark once first: make bench)", err)
	}
	updated := benchdoc.SpliceCorpus(string(page), release.RenderSection(res))
	if err := os.WriteFile(out, []byte(updated), 0o644); err != nil { //nolint:gosec // a public page
		return err
	}
	c := res.Count()
	fmt.Printf("corpus: %d HOLD, %d REVIEW, %d ROUTINE of %d; wrote %s\n", c.Hold, c.Review, c.Routine, c.Total, out)
	return nil
}

// reviewPair reviews one cached pair with --from-file and --to-file.
func reviewPair(ctx context.Context, r runner, cache string, e release.Entry) release.Review {
	rv := release.Review{Entry: e, Verdict: "ERROR"}
	from, to := release.CachePath(cache, e, e.From), release.CachePath(cache, e, e.To)
	for _, p := range []string{from, to} {
		if _, err := os.Stat(p); err != nil {
			rv.Error = "not fetched: run make -C testbed corpus"
			return rv
		}
	}
	cmd := "plugin"
	if e.Ecosystem == release.EcoNPM {
		cmd = "npm"
	}
	report := filepath.Join(r.work, "out", strings.ReplaceAll(e.Ref(), "/", "__")+".json")
	code, out, took, err := r.sightread(ctx, filepath.Join(r.work, "cache"), cmd, e.Name, "--from-file", from, "--to-file", to,
		"--allow-unverified", "--fail-on", "none", "-o", report, "--no-color")
	rv.Seconds = took.Seconds()
	if err != nil {
		rv.Error = err.Error()
		return rv
	}
	f, err := os.Open(report) //nolint:gosec // the report this run wrote
	if err != nil {
		rv.Error = fmt.Sprintf("exit %d, no report: %s", code, firstLine(out))
		return rv
	}
	defer func() { _ = f.Close() }()
	rep, err := scenario.ReadReport(f)
	if err != nil {
		rv.Error = err.Error()
		return rv
	}
	rv.Verdict = rep.OverallVerdict()
	for _, fd := range rep.CountedFindings() {
		rv.Findings = append(rv.Findings, release.Finding{ID: fd.ID, Severity: fd.Severity})
	}
	return rv
}

// firstLine is the first line of out.
func firstLine(out []byte) string {
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

// timings runs the PRD 17 real-network cases.
func timings(ctx context.Context, r runner, cache string, entries []release.Entry) []release.Timing {
	var wp, npm []release.Entry
	for _, e := range entries {
		if e.Ecosystem == release.EcoWPPlugin {
			wp = append(wp, e)
		} else {
			npm = append(npm, e)
		}
	}
	var out []release.Timing
	add := func(name, target string, limit float64, secs float64, note string) {
		out = append(out, release.Timing{Case: name, Target: target, Limit: limit, Seconds: secs, Note: note})
	}
	timed := func(cacheName string, args ...string) (float64, string) {
		code, o, took, err := r.sightread(ctx, filepath.Join(r.work, cacheName), args...)
		switch {
		case err != nil:
			return -1, err.Error()
		case code == 2 || code == 3:
			return took.Seconds(), fmt.Sprintf("exit %d: %s", code, firstLine(o))
		}
		return took.Seconds(), ""
	}

	// One plugin of about 5 MB, two versions: cold, then from cache.
	if big, ok := nearest5MB(cache, wp); ok {
		s, note := timed("t-plugin", "plugin", big.Name, "--from", big.From, "--to", big.To, "--fail-on", "none", "--no-color")
		add(fmt.Sprintf("one 5 MB plugin (%s), cold", big.Name), "under 10 s", 10, s, note)
		s, note = timed("t-plugin", "plugin", big.Name, "--from", big.From, "--to", big.To, "--fail-on", "none", "--no-color")
		add(fmt.Sprintf("one 5 MB plugin (%s), from cache", big.Name), "under 1 s", 1, s, note)
	} else {
		add("one 5 MB plugin", "under 10 s cold, 1 s cached", 10, -1, "no plugin fetched")
	}

	// all on a site with 30 plugins, 8 of them reviewed.
	if len(wp) >= 30 {
		site := filepath.Join(r.work, "site30")
		if err := buildSite(site, cache, wp[:30]); err != nil {
			add("all, 30 plugins and 8 updates, cold", "under 60 s", 60, -1, err.Error())
		} else {
			only := make([]string, 0, 8)
			for _, e := range wp[:8] {
				only = append(only, "wp-plugin:"+e.Name)
			}
			args := []string{"all", site, "--only", strings.Join(only, ","), "--fail-on", "none", "--no-color"}
			s, note := timed("t-all", args...)
			add("all, 30 plugins and 8 updates, cold", "under 60 s", 60, s, note)
		}
	}

	// changes with 40 moved npm packages: cold, then warm.
	if len(npm) >= 40 {
		base, head := filepath.Join(r.work, "base-lock.json"), filepath.Join(r.work, "head-lock.json")
		if err := writeLocks(base, head, npm[:40]); err != nil {
			add("changes, 40 npm packages", "under 60 s cold", 60, -1, err.Error())
		} else {
			args := []string{"changes", "--before", base, "--after", head, "--fail-on", "none", "--no-color"}
			s, note := timed("t-changes", args...)
			add("changes, 40 moved npm packages, cold", "under 60 s", 60, s, note)
			s, note = timed("t-changes", args...)
			add("changes, 40 moved npm packages, warm", "under 5 s", 5, s, note)
		}
	}

	// watch over 50 sites that share most plugins.
	if len(wp) >= 10 {
		list, err := buildFleet(filepath.Join(r.work, "fleet"), cache, wp[:10])
		if err != nil {
			add("watch, 50 sites, cold", "under 10 min", 600, -1, err.Error())
		} else {
			s, note := timed("t-watch", "watch", "-l", list, "--once", "--now", "--dir", filepath.Join(r.work, "watch"))
			add("watch, 50 sites with heavy overlap, cold", "under 10 min", 600, s, note)
		}
	}
	return out
}

// nearest5MB picks the plugin whose new zip is closest to 5 MB.
func nearest5MB(cache string, wp []release.Entry) (release.Entry, bool) {
	var best release.Entry
	bestDiff := int64(-1)
	for _, e := range wp {
		st, err := os.Stat(release.CachePath(cache, e, e.To))
		if err != nil {
			continue
		}
		d := st.Size() - 5<<20
		if d < 0 {
			d = -d
		}
		if bestDiff < 0 || d < bestDiff {
			best, bestDiff = e, d
		}
	}
	return best, bestDiff >= 0
}

// buildSite makes a WordPress tree with each plugin's old version
// unpacked under wp-content/plugins. Sightread reads it; nothing runs.
func buildSite(site, cache string, plugins []release.Entry) error {
	if err := os.MkdirAll(filepath.Join(site, "wp-includes"), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(site, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '6.8.3';\n"), 0o644); err != nil { //nolint:gosec // fixture
		return err
	}
	for _, e := range plugins {
		if err := unzip(release.CachePath(cache, e, e.From), filepath.Join(site, "wp-content", "plugins")); err != nil {
			return fmt.Errorf("%s: %w", e.Name, err)
		}
	}
	return nil
}

// buildFleet makes 50 sites (each with 6 of the 10 plugins) and their
// sites.yaml.
func buildFleet(dir, cache string, pool []release.Entry) (string, error) {
	var list strings.Builder
	list.WriteString("sites:\n")
	for i := 0; i < 50; i++ {
		var pick []release.Entry
		for k := 0; k < 6; k++ {
			pick = append(pick, pool[(i+k)%len(pool)])
		}
		site := filepath.Join(dir, fmt.Sprintf("site%02d", i))
		if err := buildSite(site, cache, pick); err != nil {
			return "", err
		}
		fmt.Fprintf(&list, "  - name: site%02d\n    path: %q\n", i, site)
	}
	path := filepath.Join(dir, "sites.yaml")
	return path, os.WriteFile(path, []byte(list.String()), 0o644) //nolint:gosec // fixture
}

// writeLocks writes a base and a head package-lock.json (v3) that move
// every package from its old to its new version.
func writeLocks(base, head string, pkgs []release.Entry) error {
	for _, side := range []struct {
		path string
		old  bool
	}{{base, true}, {head, false}} {
		deps := map[string]string{}
		packages := map[string]any{}
		for _, e := range pkgs {
			v := e.To
			if side.old {
				v = e.From
			}
			deps[e.Name] = v
			packages["node_modules/"+e.Name] = map[string]any{"version": v, "resolved": release.URL(e, v)}
		}
		packages[""] = map[string]any{"name": "corpus", "version": "1.0.0", "dependencies": deps}
		b, err := json.MarshalIndent(map[string]any{"name": "corpus", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": packages}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(side.path, b, 0o644); err != nil { //nolint:gosec // fixture
			return err
		}
	}
	return nil
}

// unzip unpacks a plugin zip under dest, refusing any entry that would
// land outside it and skipping links: these are real archives from the
// internet.
func unzip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if !f.Mode().IsRegular() && !f.FileInfo().IsDir() {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(f.Name)) //nolint:gosec // checked against root below
		if rel, err := filepath.Rel(root, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("entry %q leaves the folder", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		if err := copyEntry(f, target); err != nil {
			return err
		}
	}
	return nil
}

// copyEntry writes one zip entry, capped at maxArchive.
func copyEntry(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	w, err := os.Create(target) //nolint:gosec // checked against the root by unzip
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, io.LimitReader(rc, maxArchive)); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}
