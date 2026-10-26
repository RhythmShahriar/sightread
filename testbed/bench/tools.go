// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the benchmark runs the compared tools
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/ports"
	"github.com/RhythmShahriar/sightread/testbed/registry"
	"github.com/RhythmShahriar/sightread/testbed/staging"
)

// The compared tools, in column order.
const (
	toolNPM        = "npm audit"
	toolComposer   = "composer audit"
	toolGuardDog   = "GuardDog"
	toolSoundcheck = "Soundcheck"
)

// comparedTool knows how to judge one scenario's update.
type comparedTool struct {
	info benchdoc.Tool
	// sees reports whether the tool can look at an ecosystem.
	sees func(eco string) bool
	// flagged runs the tool on the update and reports whether it raised
	// anything.
	flagged func(ctx context.Context, h *harness, id string, m *registry.PackageMeta, from, to string) (bool, error)
}

// pickTools resolves -tools to the tools to run.
func pickTools(spec string) []string {
	all := []string{toolNPM, toolComposer, toolGuardDog, toolSoundcheck}
	switch spec {
	case "none", "":
		return nil
	case "auto":
		return all[:3]
	case "all":
		return all
	}
	var out []string
	for _, f := range strings.Fields(strings.ToLower(spec)) {
		switch f {
		case "npm":
			out = append(out, toolNPM)
		case "composer":
			out = append(out, toolComposer)
		case "guarddog":
			out = append(out, toolGuardDog)
		case "soundcheck":
			out = append(out, toolSoundcheck)
		}
	}
	return out
}

// toolVersion runs `<bin> --version` and returns its first line, or an
// error when the tool is missing.
func toolVersion(ctx context.Context, bin string, args ...string) (string, error) {
	if _, err := exec.LookPath(bin); err != nil {
		return "", fmt.Errorf("not installed")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if len(args) == 0 {
		args = []string{"--version"}
	}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput() //nolint:gosec // a compared tool's version
	if err != nil {
		return "", fmt.Errorf("--version failed: %s", firstLine(out, err))
	}
	line := firstLine(out, nil)
	if v := versionRE.FindString(line); v != "" {
		return v, nil
	}
	return line, nil
}

// versionRE finds a version number in a --version line ("Composer
// version 2.9.5 2026-01-29" gives 2.9.5).
var versionRE = regexp.MustCompile(`\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.]+)?`)

// toolEnv is a compared tool's environment: its own HOME and caches in
// the work folder, the testbed CA and the proxy guard.
func (h *harness) toolEnv(name string) []string {
	home := filepath.Join(h.work, "tools", "home-"+strings.ReplaceAll(name, " ", "-"))
	_ = os.MkdirAll(home, 0o750)
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NO_COLOR=1", "RHYTHM_NO_UPDATE_CHECK=1",
		"NODE_EXTRA_CA_CERTS=" + filepath.Join(h.state, "ca.pem"), "SSL_CERT_FILE=" + filepath.Join(h.state, "ca.pem"),
		"COMPOSER_HOME=" + filepath.Join(home, "composer"), "COMPOSER_CACHE_DIR=" + filepath.Join(home, "composer-cache"),
		"COMPOSER_NO_INTERACTION=1", "COMPOSER_DISABLE_XDEBUG_WARN=1",
		"npm_config_cache=" + filepath.Join(home, "npm-cache"), "npm_config_update_notifier=false", "npm_config_fund=false"}
	for k, v := range proxyEnv() {
		env = append(env, k+"="+v)
	}
	return env
}

// runTool runs a compared tool in dir and returns stdout and the exit.
func (h *harness) runTool(ctx context.Context, name, dir, bin string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // a compared tool on the fixture states
	cmd.Dir = dir
	cmd.Env = h.toolEnv(name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if code < 0 {
		return nil, code, fmt.Errorf("%s: %s", name, firstLine(stderr.Bytes(), err))
	}
	return stdout.Bytes(), code, nil
}

// tools builds the compared tools that answer here.
func (h *harness) comparedTools(ctx context.Context) []comparedTool {
	var out []comparedTool
	for _, name := range pickTools(h.tools) {
		t := comparedTool{info: benchdoc.Tool{Name: name}}
		var err error
		switch name {
		case toolNPM:
			t.info.Scope = "published advisories for npm lockfiles"
			t.info.Version, err = toolVersion(ctx, "npm")
			t.sees = func(eco string) bool { return eco == "npm" }
			t.flagged = npmAudit
		case toolComposer:
			t.info.Scope = "published advisories for Composer lockfiles"
			t.info.Version, err = toolVersion(ctx, "composer", "--version", "--no-ansi")
			t.sees = func(eco string) bool { return eco == "composer" }
			t.flagged = composerAudit
		case toolGuardDog:
			t.info.Scope = "heuristics on npm tarballs, offline"
			t.info.Version, err = toolVersion(ctx, "guarddog")
			t.sees = func(eco string) bool { return eco == "npm" }
			t.flagged = guardDog
		case toolSoundcheck:
			t.info.Scope = "what a WordPress site shows, before and after"
			t.info.Version, err = toolVersion(ctx, "rhythm-soundcheck")
			if err == nil && !wpUp(ctx) {
				err = fmt.Errorf("the Docker WordPress is not up")
			}
			t.sees = func(eco string) bool { return eco == "wp-plugin" || eco == "wp-theme" }
			t.flagged = soundcheckBeforeAfter
		}
		if err != nil {
			t.info.NotRun = err.Error()
		}
		out = append(out, t)
	}
	return out
}

// compare judges every scored scenario with every compared tool.
func (h *harness) compare(ctx context.Context, res *benchdoc.Results) {
	tools := h.comparedTools(ctx)
	for _, t := range tools {
		res.Tools = append(res.Tools, t.info)
	}
	for i := range res.Scenarios {
		s := &res.Scenarios[i]
		sc, _ := h.scenarioByID(s.ID)
		s.Tools = map[string]string{}
		m, ok := h.reg.Meta(sc.Package)
		for _, t := range tools {
			switch {
			case t.info.NotRun != "":
				s.Tools[t.info.Name] = benchdoc.ToolNotRun
			case !ok || !t.sees(m.Ecosystem):
				s.Tools[t.info.Name] = benchdoc.ToolCantSee
			default:
				from, _ := m.InstalledVersion()
				to, _ := m.CandidateVersion()
				_ = h.setStates(sc.Packages())
				hit, err := t.flagged(ctx, h, sc.Package, m, from.Version, to.Version)
				s.Tools[t.info.Name] = toolLabel(s.Kind, hit, err)
			}
		}
	}
}

// toolLabel turns a tool's answer into its cell.
func toolLabel(kind string, hit bool, err error) string {
	switch {
	case err != nil:
		return benchdoc.ToolError
	case kind == "bad" && hit:
		return benchdoc.ToolCaught
	case kind == "bad":
		return benchdoc.ToolMissed
	case hit:
		return benchdoc.ToolFalseAlarm
	}
	return benchdoc.ToolClean
}

// toolDir makes a fresh folder for one tool run.
func (h *harness) toolDir(tool, id string) (string, error) {
	dir := filepath.Join(h.work, "tools", strings.ReplaceAll(tool, " ", "-"), id)
	_ = os.RemoveAll(dir)
	return dir, os.MkdirAll(dir, 0o750)
}

// writeJSON writes v to dir/name.
func writeJSON(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), b, 0o644) //nolint:gosec // tool fixture
}

// npmAudit audits a lockfile that pins the candidate, against the
// registry's advisory endpoint.
func npmAudit(ctx context.Context, h *harness, id string, m *registry.PackageMeta, _, to string) (bool, error) {
	dir, err := h.toolDir(toolNPM, id)
	if err != nil {
		return false, err
	}
	reg := fmt.Sprintf("https://127.0.0.1:%d/", ports.NPM)
	deps := map[string]string{m.Name: to}
	if err := writeJSON(dir, "package.json", map[string]any{"name": "bench-" + id, "version": "1.0.0", "private": true, "dependencies": deps}); err != nil {
		return false, err
	}
	lock := map[string]any{
		"name": "bench-" + id, "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"":                       map[string]any{"name": "bench-" + id, "version": "1.0.0", "dependencies": deps},
			"node_modules/" + m.Name: map[string]any{"version": to, "resolved": reg + m.Name + "/-/" + tarballBase(m.Name) + "-" + to + ".tgz"},
		},
	}
	if err := writeJSON(dir, "package-lock.json", lock); err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry="+reg+"\n"), 0o644); err != nil { //nolint:gosec // tool fixture
		return false, err
	}
	out, _, err := h.runTool(ctx, toolNPM, dir, "npm", "audit", "--json", "--package-lock-only", "--registry="+reg, "--audit-level=info")
	if err != nil {
		return false, err
	}
	var doc struct {
		Error    any `json:"error"`
		Metadata struct {
			Vulnerabilities struct {
				Total int `json:"total"`
			} `json:"vulnerabilities"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || doc.Error != nil {
		return false, fmt.Errorf("npm audit: %s", firstLine(out, err))
	}
	return doc.Metadata.Vulnerabilities.Total > 0, nil
}

// tarballBase is the file name part npm uses for a (scoped) name.
func tarballBase(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// composerAudit audits a lockfile that pins the candidate, with
// Packagist switched off and the fixture registry as the repository.
func composerAudit(ctx context.Context, h *harness, id string, m *registry.PackageMeta, _, to string) (bool, error) {
	dir, err := h.toolDir(toolComposer, id)
	if err != nil {
		return false, err
	}
	repo := fmt.Sprintf("https://127.0.0.1:%d", ports.Packagist)
	composerJSON := map[string]any{
		"name":         "bench/" + strings.ReplaceAll(id, "_", "-"),
		"repositories": []any{map[string]any{"type": "composer", "url": repo}, map[string]any{"packagist.org": false}},
		"require":      map[string]string{m.Name: to},
		"config":       map[string]any{"cafile": filepath.Join(h.state, "ca.pem"), "allow-plugins": false},
	}
	if err := writeJSON(dir, "composer.json", composerJSON); err != nil {
		return false, err
	}
	lock := map[string]any{
		"_readme": []string{"testbed"}, "content-hash": "testbed",
		"packages":     []any{map[string]any{"name": m.Name, "version": to, "type": "library"}},
		"packages-dev": []any{}, "aliases": []any{}, "minimum-stability": "stable", "stability-flags": map[string]any{},
		"prefer-stable": false, "prefer-lowest": false, "platform": map[string]any{}, "platform-dev": map[string]any{},
		"plugin-api-version": "2.6.0",
	}
	if err := writeJSON(dir, "composer.lock", lock); err != nil {
		return false, err
	}
	out, _, err := h.runTool(ctx, toolComposer, dir, "composer", "audit", "--locked", "--format=json", "--no-interaction",
		"--no-plugins", "--no-scripts", "--abandoned=ignore")
	if err != nil {
		return false, err
	}
	var doc struct {
		Advisories json.RawMessage `json:"advisories"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || doc.Advisories == nil {
		return false, fmt.Errorf("composer audit: %s", firstLine(out, err))
	}
	var byName map[string]json.RawMessage
	if json.Unmarshal(doc.Advisories, &byName) != nil {
		return false, nil // an empty list ([]) is no advisories
	}
	return len(byName) > 0, nil
}

// guardDog scans the candidate tarball offline.
func guardDog(ctx context.Context, h *harness, id string, m *registry.PackageMeta, _, to string) (bool, error) {
	dir, err := h.toolDir(toolGuardDog, id)
	if err != nil {
		return false, err
	}
	b, ok := h.reg.Archive(id, to)
	if !ok {
		return false, fmt.Errorf("no tarball for %s %s", m.Name, to)
	}
	tgz := filepath.Join(dir, tarballBase(m.Name)+"-"+to+".tgz")
	if err := os.WriteFile(tgz, b, 0o644); err != nil { //nolint:gosec // tool fixture
		return false, err
	}
	out, _, err := h.runTool(ctx, toolGuardDog, dir, "guarddog", "npm", "scan", tgz, "--output-format=json")
	if err != nil {
		return false, err
	}
	var doc struct {
		Issues int `json:"issues"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return false, fmt.Errorf("guarddog: %s", firstLine(out, err))
	}
	return doc.Issues > 0, nil
}

// soundcheckBeforeAfter installs the old version in the Docker WordPress,
// takes a Soundcheck snapshot, installs the new one and compares. The
// update's code runs in the sealed container, as it would on a real
// site; that is what a visual-only check does.
func soundcheckBeforeAfter(ctx context.Context, h *harness, id string, m *registry.PackageMeta, from, to string) (bool, error) {
	dir, err := h.toolDir(toolSoundcheck, id)
	if err != nil {
		return false, err
	}
	kind := "plugin"
	if m.Ecosystem == "wp-theme" {
		kind = "theme"
	}
	zips := map[string]string{}
	for side, v := range map[string]string{"old": from, "new": to} {
		b, ok := h.reg.Archive(id, v)
		if !ok {
			return false, fmt.Errorf("no zip for %s %s", m.Name, v)
		}
		zips[side] = filepath.Join(dir, m.Name+"-"+side+".zip")
		if err := os.WriteFile(zips[side], b, 0o644); err != nil { //nolint:gosec // tool fixture
			return false, err
		}
	}
	defer func() { _ = h.seed(ctx) }()
	if err := h.seed(ctx); err != nil {
		return false, err
	}
	if _, err := h.wp(ctx, kind, "install", zips["old"], "--force", "--activate"); err != nil {
		return false, err
	}
	name := "sightread-bench-" + id
	// A desktop pass of the health and visual modules over a handful of
	// pages: enough to see what an update changes on screen.
	if _, _, err := h.runTool(ctx, toolSoundcheck, dir, "rhythm-soundcheck", "snapshot", staging.URL, "--name", name,
		"--modules", "health,visual", "--viewport", "desktop", "--limit", "10"); err != nil {
		return false, err
	}
	if _, err := h.wp(ctx, kind, "install", zips["new"], "--force", "--activate"); err != nil {
		return false, err
	}
	out, _, err := h.runTool(ctx, toolSoundcheck, dir, "rhythm-soundcheck", "compare", staging.URL, "--snapshot", name, "--json")
	if err != nil {
		return false, err
	}
	var doc struct {
		Summary struct {
			Verdict string `json:"verdict"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || doc.Summary.Verdict == "" {
		return false, fmt.Errorf("soundcheck compare: %s", firstLine(out, err))
	}
	return slices.Contains([]string{"broke", "changed"}, doc.Summary.Verdict), nil
}
