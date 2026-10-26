// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the benchmark starts the binary it measures
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// runOpts adjust one run of the binary.
type runOpts struct {
	// id names the run's TMPDIR and, unless cache is set, its cache.
	id string
	// cache is RHYTHM_CACHE_DIR; "-" leaves it unset so the cache goes
	// under HOME.
	cache string
	// home replaces the shared HOME.
	home string
	// env overrides variables; an empty value removes one.
	env map[string]string
	// noStub leaves the Roadie stub off PATH.
	noStub bool
	// interruptAfter sends Ctrl-C (SIGINT) that long after the start.
	interruptAfter time.Duration
	// noWatch skips the outside-write walk (a run that is meant to write
	// HOME, or one that runs beside another).
	noWatch bool
}

// execResult is what one run gave.
type execResult struct {
	exit     int
	stdout   []byte
	stderr   []byte
	elapsed  time.Duration
	rssMB    float64
	timedOut bool
	err      error // the binary could not be started
}

// output is stdout and stderr together, for text assertions.
func (r execResult) output() string { return string(r.stdout) + "\n" + string(r.stderr) }

// bases are the SIGHTREAD_* variables of PRD 8.4, all on the registry,
// with scheme http or https.
func bases(scheme string) map[string]string {
	at := func(port int, path string) string { return fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, port, path) }
	return map[string]string{
		"SIGHTREAD_WPORG_API":       at(ports.WPOrg, ""),
		"SIGHTREAD_WPDL_API":        at(ports.WPOrg, ""),
		"SIGHTREAD_WPSVN":           at(ports.WPOrg, "/svn/plugins"),
		"SIGHTREAD_WPTHEMESVN":      at(ports.WPOrg, "/svn/themes"),
		"SIGHTREAD_PACKAGIST":       at(ports.Packagist, ""),
		"SIGHTREAD_PACKAGIST_META":  at(ports.Packagist, ""),
		"SIGHTREAD_GITHUB_API":      at(ports.GitHub, ""),
		"SIGHTREAD_GITHUB_CODELOAD": at(ports.Codeload, ""),
		"SIGHTREAD_NPM_REGISTRY":    at(ports.NPM, ""),
		"SIGHTREAD_OSV_API":         at(ports.OSV, ""),
	}
}

// proxyEnv points every proxy variable at the guard and lets loopback
// through, for Sightread and the compared tools alike.
func proxyEnv() map[string]string {
	guard := fmt.Sprintf("http://127.0.0.1:%d", ports.ClosedProxy)
	loop := "127.0.0.1,localhost,::1"
	return map[string]string{
		"HTTPS_PROXY": guard, "HTTP_PROXY": guard, "https_proxy": guard, "http_proxy": guard,
		"ALL_PROXY": guard, "all_proxy": guard, "NO_PROXY": loop, "no_proxy": loop,
	}
}

// environ builds a run's environment from scratch: nothing of the
// caller's leaks in (no tokens, no proxies, no RHYTHM_OFFLINE) except
// PATH and the few variables Windows needs to start a process.
func (h *harness) environ(o runOpts) ([]string, error) {
	env := map[string]string{}
	// DOCKER_* reach testbed/bin/wp, which e15 hands Sightread as --wp.
	for _, k := range []string{"SYSTEMROOT", "SystemRoot", "COMSPEC", "PATHEXT", "LANG", "TZ", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"} {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	path := os.Getenv("PATH")
	if !o.noStub {
		path = h.stubBin + string(os.PathListSeparator) + path
	} else {
		path = withoutRoadie(path)
	}
	env["PATH"] = path

	home := h.home
	if o.home != "" {
		home = o.home
	}
	env["HOME"] = home
	if runtime.GOOS == "windows" {
		env["USERPROFILE"], env["APPDATA"], env["LOCALAPPDATA"] = home, filepath.Join(home, "AppData", "Roaming"), filepath.Join(home, "AppData", "Local")
	}
	tmp := filepath.Join(h.work, "tmp", o.id)
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		return nil, err
	}
	env["TMPDIR"], env["TMP"], env["TEMP"] = tmp, tmp, tmp
	switch o.cache {
	case "-":
	case "":
		env["RHYTHM_CACHE_DIR"] = filepath.Join(h.work, "cache", o.id)
	default:
		env["RHYTHM_CACHE_DIR"] = o.cache
	}

	// Kit's config folder (report keys, first-run notes) is a work
	// folder too; anything else written under HOME counts as outside.
	env["RHYTHM_CONFIG_DIR"] = filepath.Join(h.work, "config")
	env["RHYTHM_NO_UPDATE_CHECK"] = "1"
	env["NO_COLOR"] = "1"
	if !h.plain {
		env["SSL_CERT_FILE"] = filepath.Join(h.state, "ca.pem")
	}
	env["SIGHTREAD_NPM_EXTRA_KEYS"] = filepath.Join(h.state, "npm-keys.json")
	env["SIGHTREAD_CANARY_DIR"] = filepath.Join(h.state, "canary")
	env["TESTBED_STATE"] = h.state
	for k, v := range bases(h.scheme()) {
		env[k] = v
	}
	for k, v := range proxyEnv() {
		env[k] = v
	}
	for k, v := range o.env {
		if v == "" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

// withoutRoadie drops PATH entries that hold a rhythm-roadie, so the
// missing-Roadie case really has none.
func withoutRoadie(path string) string {
	var keep []string
	for _, dir := range filepath.SplitList(path) {
		found := false
		for _, name := range []string{"rhythm-roadie", "rhythm-roadie.exe"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil { //nolint:gosec // PATH entries, only checked for a file
				found = true
			}
		}
		if !found {
			keep = append(keep, dir)
		}
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// run starts rhythm-sightread with args from the testbed folder (so the
// manifest's relative paths resolve) and waits for it.
func (h *harness) run(ctx context.Context, args []string, o runOpts) execResult {
	env, err := h.environ(o)
	if err != nil {
		return execResult{exit: -1, err: err}
	}
	var before = h.snapshotAll()
	if o.noWatch {
		before = nil
	}

	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.bin, args...) //nolint:gosec // the binary under test with the manifest's arguments
	cmd.Dir = h.tb
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second

	mark := h.guard.Count()
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return execResult{exit: -1, err: err}
	}
	if o.interruptAfter > 0 {
		timer := time.AfterFunc(o.interruptAfter, func() { interrupt(cmd) })
		defer timer.Stop()
	}
	werr := cmd.Wait()
	r := execResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), elapsed: time.Since(start)}
	r.timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmd.ProcessState != nil {
		r.exit = cmd.ProcessState.ExitCode()
		r.rssMB = maxRSSMB(cmd.ProcessState)
	} else {
		r.exit = -1
	}
	var exitErr *exec.ExitError
	if werr != nil && !errors.As(werr, &exitErr) {
		r.err = werr
	}
	if before != nil {
		h.noteOutside(o.id, before)
	}
	h.checkMasked(o.id, "stdout", r.stdout)
	h.checkMasked(o.id, "stderr", r.stderr)
	for _, a := range h.guard.Attempts()[mark:] {
		h.egress = append(h.egress, o.id+": proxy guard: "+a)
	}
	return r
}
