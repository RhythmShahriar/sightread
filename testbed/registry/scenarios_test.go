// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// packagesDir and projectsDir are the committed fixtures, relative to
// this package.
const (
	packagesDir = "../packages"
	projectsDir = "../projects"
)

var (
	scenarioOnce sync.Once
	scenarioReg  *Registry
	scenarioErr  error
)

// scenarioRegistry builds every committed scenario once for the package:
// the build is the slow part of these tests, the more so under -race.
// It is never started; TestMain closes it.
func scenarioRegistry(t *testing.T) *Registry {
	t.Helper()
	if _, err := os.Stat(packagesDir); err != nil {
		t.Skipf("no committed packages: %v", err)
	}
	scenarioOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sightread-registry-test-")
		if err != nil {
			scenarioErr = err
			return
		}
		scenarioDir = dir
		scenarioReg, scenarioErr = New(Options{PackagesDir: packagesDir, StateDir: dir})
	})
	if scenarioErr != nil {
		t.Fatalf("building the scenario packages: %v", scenarioErr)
	}
	return scenarioReg
}

// scenarioDir is scenarioRegistry's state folder, removed by TestMain.
var scenarioDir string

func TestMain(m *testing.M) {
	code := m.Run()
	if scenarioReg != nil {
		_ = scenarioReg.Close()
	}
	if scenarioDir != "" {
		_ = os.RemoveAll(scenarioDir)
	}
	os.Exit(code)
}

// TestScenarioPackagesBuild builds every committed scenario through the
// registry, which reads each meta.yaml, builds and hashes every archive
// and signs the npm versions. A broken fixture fails here.
func TestScenarioPackagesBuild(t *testing.T) {
	reg := scenarioRegistry(t)
	if len(reg.pkgs) == 0 {
		t.Fatal("no scenarios built")
	}
	for _, p := range reg.pkgs {
		if _, ok := p.CandidateVersionBuilt(); !ok {
			t.Errorf("%s: no candidate version built", p.id)
		}
	}
}

// CandidateVersionBuilt is a test helper: the built candidate version.
func (p *builtPkg) CandidateVersionBuilt() (*builtVersion, bool) {
	bv, ok := p.versions[p.candidate]
	return bv, ok
}

// noCodePayload names bad scenarios whose attack is in the bytes or the
// metadata, not in code that could run: there is nothing to trip a
// canary, so none is required.
var noCodePayload = map[string]bool{"b17": true}

// TestBadScenariosHaveCanary checks every bad scenario carries a canary
// tripwire (the port 18905) somewhere in its group (a scenario and its
// companion dependency share the group prefix, e.g. b13-app and b13-dep),
// the proof that if its payload ever ran it would be caught. Good
// scenarios must carry none.
func TestBadScenariosHaveCanary(t *testing.T) {
	ids, err := scenarioIDs(packagesDir)
	if err != nil {
		t.Skipf("no committed packages: %v", err)
	}
	groupHasCanary := map[string]bool{}
	for _, id := range ids {
		g, _, _ := strings.Cut(id, "-")
		if treeContains(t, filepath.Join(packagesDir, id, "new"), "18905") {
			groupHasCanary[g] = true
		}
	}
	for _, id := range ids {
		g, _, _ := strings.Cut(id, "-")
		switch {
		case strings.HasPrefix(id, "b"):
			if !noCodePayload[g] && !groupHasCanary[g] {
				t.Errorf("%s: a bad scenario must carry the canary tripwire (18905) in its group", id)
			}
		case strings.HasPrefix(id, "g"):
			if treeContains(t, filepath.Join(packagesDir, id, "new"), "18905") {
				t.Errorf("%s: a good scenario must not carry the canary tripwire", id)
			}
		}
	}
}

// literalKeyRE matches a real-format secret that must never be committed;
// fixtures assemble fake keys at build time from {{fakekey:...}} instead.
var literalKeyRE = regexp.MustCompile(`sk_live_|ghp_[A-Za-z0-9]|npm_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}|xox[baprs]-`)

// TestNoLiteralSecrets scans every committed fixture file for a literal
// real-format key. There must be none: GitHub push protection blocks
// them and only the fake assembled keys are allowed.
func TestNoLiteralSecrets(t *testing.T) {
	for _, root := range []string{packagesDir, projectsDir} {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			b, err := os.ReadFile(path) //nolint:gosec // our own fixtures
			if err != nil {
				return err
			}
			if literalKeyRE.Match(b) {
				t.Errorf("%s: holds a literal real-format secret; assemble a fake one at build time", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// treeContains reports whether any file under dir contains needle.
func treeContains(t *testing.T, dir, needle string) bool {
	t.Helper()
	found := false
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path) //nolint:gosec // our own fixtures
		if err != nil {
			return err
		}
		if strings.Contains(string(b), needle) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}
