// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the benchmark starts the binary it measures and the compared tools
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/canary"
	"github.com/RhythmShahriar/sightread/testbed/fsnap"
	"github.com/RhythmShahriar/sightread/testbed/ports"
	"github.com/RhythmShahriar/sightread/testbed/probes"
	"github.com/RhythmShahriar/sightread/testbed/registry"
	"github.com/RhythmShahriar/sightread/testbed/scenario"
	"github.com/RhythmShahriar/sightread/testbed/webhook"
)

// harness is everything a run needs: the paths, the servers on
// loopback and the results being filled.
type harness struct {
	root, tb, state, work string
	bin                   string
	stubBin               string
	home                  string
	timeout               time.Duration
	tools                 string

	manifest *scenario.Manifest
	reg      *registry.Registry
	can      *canary.Canary
	hook     *webhook.Receiver
	probes   *probes.Set
	retry    *probes.Front
	stall    *probes.Front
	guard    *probes.Guard

	res     *benchdoc.Results
	outside []string
	// egress are the proxy guard lines seen while Sightread ran. The
	// compared tools reach the guard too (a browser's background calls),
	// which is not counted against Sightread.
	egress  []string
	closers []func() error
}

// newHarness builds the binary and the Roadie stub and starts every
// loopback server. A binary that does not build is recorded, not fatal,
// so the page still says why nothing ran.
func newHarness(ctx context.Context, root string, o options) (*harness, error) {
	h := &harness{
		root:    root,
		tb:      filepath.Join(root, "testbed"),
		state:   filepath.Join(root, "testbed", "state"),
		timeout: o.timeout,
		tools:   o.tools,
		res:     &benchdoc.Results{Schema: benchdoc.Schema, Started: time.Now().UTC(), Machine: machine()},
	}
	h.work = o.work
	if h.work == "" {
		h.work = filepath.Join(h.tb, "bench", "work")
	}
	var err error
	if h.work, err = filepath.Abs(h.work); err != nil {
		return nil, err
	}
	// A fresh work folder each run: caches, homes and reports start empty.
	if err := os.RemoveAll(h.work); err != nil {
		return nil, err
	}
	for _, d := range []string{h.work, h.state, filepath.Join(h.work, "out")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	if h.manifest, err = scenario.Load(filepath.Join(h.tb, "scenarios.yaml")); err != nil {
		return nil, err
	}

	h.bin = o.bin
	if !filepath.IsAbs(h.bin) {
		h.bin = filepath.Join(root, h.bin)
	}
	if exe := runtime.GOOS == "windows" && !strings.HasSuffix(h.bin, ".exe"); exe {
		h.bin += ".exe"
	}
	if o.build {
		if out, err := h.goBuild(ctx, h.bin, "./cmd/rhythm-sightread"); err != nil {
			h.res.BinErr = "go build ./cmd/rhythm-sightread: " + firstLine(out, err)
		}
	}
	if h.res.BinErr == "" {
		h.res.Version = h.version(ctx)
	}
	h.stubBin = filepath.Join(h.work, "stubbin")
	roadie := filepath.Join(h.stubBin, "rhythm-roadie")
	if runtime.GOOS == "windows" {
		roadie += ".exe"
	}
	if out, err := h.goBuild(ctx, roadie, "./testbed/stubs/roadie"); err != nil {
		return nil, fmt.Errorf("build the Roadie stub: %s", firstLine(out, err))
	}

	// HOME is shared by every run and walked before and after each.
	h.home = filepath.Join(h.work, "home")
	if err := os.MkdirAll(h.home, 0o750); err != nil {
		return nil, err
	}

	if err := h.start(); err != nil {
		h.Close()
		return nil, err
	}
	if err := h.writeFromFileZips(); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// start brings up the registry, canary, webhook, probes, fronts and
// guard. A port already taken (a testbed left up with make up) is an
// error that names it.
func (h *harness) start() error {
	_ = os.RemoveAll(filepath.Join(h.state, "canary"))
	_ = os.Remove(filepath.Join(h.state, "canary.log"))
	_ = os.Remove(filepath.Join(h.state, "roadie"))
	_ = os.Remove(filepath.Join(h.state, "roadie.log"))
	var err error
	if h.reg, err = registry.New(registry.Options{PackagesDir: filepath.Join(h.tb, "packages"), StateDir: h.state, Now: h.res.Started}); err != nil {
		return err
	}
	if err := h.reg.Start(); err != nil {
		return fmt.Errorf("%w (is make -C testbed up still running? make -C testbed down stops it)", err)
	}
	h.closers = append(h.closers, h.reg.Close)
	if h.can, err = canary.New(h.state); err != nil {
		return err
	}
	if err := h.can.Start(); err != nil {
		return err
	}
	h.closers = append(h.closers, h.can.Close)
	if h.hook, err = webhook.New(); err != nil {
		return err
	}
	h.hook.Start()
	h.closers = append(h.closers, h.hook.Close)
	if h.probes, err = probes.Start(); err != nil {
		return err
	}
	h.closers = append(h.closers, h.probes.Close)
	npm := fmt.Sprintf("https://127.0.0.1:%d", ports.NPM)
	ca := h.reg.CACertPEM()
	if h.retry, err = probes.StartFront(ports.FrontRetry, probes.FrontModeRetry, npm, h.reg.TLSConfig(), ca); err != nil {
		return err
	}
	h.closers = append(h.closers, h.retry.Close)
	if h.stall, err = probes.StartFront(ports.FrontStall, probes.FrontModeStall, npm, h.reg.TLSConfig(), ca); err != nil {
		return err
	}
	h.closers = append(h.closers, h.stall.Close)
	if h.guard, err = probes.StartGuard(ports.ClosedProxy); err != nil {
		return err
	}
	h.closers = append(h.closers, h.guard.Close)
	return nil
}

// Close stops every server that started, last first; errors are
// ignored, the run is over.
func (h *harness) Close() {
	for i := len(h.closers) - 1; i >= 0; i-- {
		_ = h.closers[i]()
	}
	h.closers = nil
	_ = os.Remove(filepath.Join(h.state, "roadie"))
}

// goBuild builds pkg into out from the module root.
func (h *harness) goBuild(ctx context.Context, out, pkg string) ([]byte, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		// go run does not put go on PATH; the toolchain's usual home.
		goBin = filepath.Join("/usr/local/go/bin", "go")
	}
	cmd := exec.CommandContext(ctx, goBin, "build", "-o", out, pkg) //nolint:gosec // building this checkout
	cmd.Dir = h.root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	return cmd.CombinedOutput()
}

// version asks the binary for its version line.
func (h *harness) version(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, h.bin, "--version").CombinedOutput() //nolint:gosec // the binary under test
	if err != nil {
		return "unknown (" + firstLine(out, err) + ")"
	}
	return strings.TrimSpace(firstLine(out, nil))
}

// writeFromFileZips writes the archives b22 reviews with --from-file and
// --to-file. They are built from the fixture trees at start and never
// committed.
func (h *harness) writeFromFileZips() error {
	m, ok := h.reg.Meta("b22-premium")
	if !ok {
		return nil
	}
	for side, pick := range map[string]func() (registry.VersionMeta, bool){"old": m.InstalledVersion, "new": m.CandidateVersion} {
		v, ok := pick()
		if !ok {
			continue
		}
		b, ok := h.reg.Archive("b22-premium", v.Version)
		if !ok {
			return fmt.Errorf("no archive for b22-premium %s", v.Version)
		}
		if err := os.WriteFile(filepath.Join(h.state, "b22-"+side+".zip"), b, 0o644); err != nil { //nolint:gosec // fixture archive
			return err
		}
	}
	return nil
}

// picked are the scenarios a run covers.
type picked struct {
	scored []scenario.Scenario // bad and good
	env    []scenario.Scenario
}

// pick filters the manifest by -only: ids, or bad, good and env.
func (h *harness) pick(only []string) (picked, error) {
	var p picked
	known := map[string]bool{"bad": true, "good": true, "env": true}
	for _, s := range h.manifest.Scenarios {
		known[s.ID] = true
	}
	for _, o := range only {
		if !known[o] {
			return p, fmt.Errorf("-only %s: no such scenario or kind", o)
		}
	}
	for _, s := range h.manifest.Scenarios {
		if len(only) > 0 && !slices.Contains(only, s.ID) && !slices.Contains(only, s.Kind) {
			continue
		}
		if s.Kind == scenario.KindEnv {
			p.env = append(p.env, s)
		} else {
			p.scored = append(p.scored, s)
		}
	}
	return p, nil
}

// setStates publishes the candidates of the named folders and withholds
// every other one, so a run sees exactly its scenario's update.
func (h *harness) setStates(published []string) error {
	for _, id := range h.reg.IDs() {
		st := registry.StateGood
		if slices.Contains(published, id) {
			st = registry.StateBad
		}
		if err := registry.WriteState(h.state, id, st); err != nil {
			return err
		}
	}
	return nil
}

// expand fills {testbed} in a manifest command.
func (h *harness) expand(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, "{testbed}", h.tb)
	}
	return out
}

// watched are the trees walked for outside writes, relative to the
// testbed, plus HOME.
func (h *harness) watched() map[string]string {
	return map[string]string{
		"HOME":     h.home,
		"projects": filepath.Join(h.tb, "projects"),
		"packages": filepath.Join(h.tb, "packages"),
	}
}

// snapshotAll records every watched tree.
func (h *harness) snapshotAll() map[string]fsnap.Snapshot {
	out := map[string]fsnap.Snapshot{}
	for name, dir := range h.watched() {
		s, err := fsnap.Take(dir)
		if err != nil {
			s = fsnap.Snapshot{"(unreadable: " + err.Error() + ")": {}}
		}
		out[name] = s
	}
	return out
}

// noteOutside records what changed in the watched trees during a run.
func (h *harness) noteOutside(id string, before map[string]fsnap.Snapshot) []string {
	var found []string
	for name, after := range h.snapshotAll() {
		for _, c := range fsnap.Diff(before[name], after) {
			found = append(found, fmt.Sprintf("%s: %s: %s/%s", id, c.What, name, c.Path))
		}
	}
	slices.Sort(found)
	h.outside = append(h.outside, found...)
	return found
}

// machine names the OS, architecture and CPU count.
func machine() string {
	return fmt.Sprintf("%s/%s, %d CPUs, %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
}

// firstLine is the first non-empty line of out, or err's text.
func firstLine(out []byte, err error) string {
	for _, l := range bytes.Split(out, []byte("\n")) {
		if s := strings.TrimSpace(string(l)); s != "" {
			return s
		}
	}
	if err != nil {
		return err.Error()
	}
	return ""
}
