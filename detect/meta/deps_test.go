// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// typoPacks are data packs whose names index is the real typo engine
// over a short list.
type typoPacks struct {
	coretest.FakeDataPacks
	idx map[core.Ecosystem]*TypoIndex
}

func (p *typoPacks) Names() core.NameIndex { return p }

func (p *typoPacks) Popular(eco core.Ecosystem, name string) bool { return p.idx[eco].Popular(name) }

func (p *typoPacks) Near(eco core.Ecosystem, name string) []string { return p.idx[eco].Near(name) }

func installTypoPacks(t *testing.T) {
	t.Helper()
	p := &typoPacks{idx: map[core.Ecosystem]*TypoIndex{
		core.NPM: NewTypoIndex(core.NPM, npmPopular), core.Composer: NewTypoIndex(core.Composer, composerPopular),
	}}
	t.Cleanup(core.SwapDataPacks(p))
}

func TestDependencyWording(t *testing.T) {
	installTypoPacks(t)
	s := subject(core.NPM)
	s.Now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s.New.Deps = map[string]string{"plain-crypto-js": "^4.2.1", "left-pad": "^1.3.0"}
	s.New.DevDeps = map[string]string{"vitest": "^2.0.0"}
	s.New.DepInfo = map[string]*core.DepInfo{
		"plain-crypto-js": {Published: s.Now.Add(-30 * time.Hour), HasInstallScript: true},
		"left-pad":        {Published: s.Now.Add(-400 * 24 * time.Hour), Downloads: 1200},
	}
	fs := run(t, depsDetector{}, s)
	want := map[string]cli.Severity{
		"adds left-pad ^1.3.0 (published 400 days ago, 1200 downloads)":               cli.SeverityMedium,
		"adds plain-crypto-js ^4.2.1 (published 1 day ago, has an install script)":    cli.SeverityHigh,
		"adds dev dependency vitest ^2.0.0":                                           cli.SeverityInfo,
		"plain-crypto-js is close to the popular crypto-js; it has an install script": cli.SeverityHigh,
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if sev, ok := want[f.Evidence.String()]; !ok || sev != f.Severity || f.File != "package.json" {
			t.Errorf("unexpected %s %s %q @%s", f.ID, f.Severity, f.Evidence, f.File)
		}
	}
}

func TestDependencyYoungIsHigh(t *testing.T) {
	s := subject(core.NPM)
	s.Now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s.New.Deps = map[string]string{"x": "1"}
	s.New.DepInfo = map[string]*core.DepInfo{"x": {Published: s.Now.Add(-6 * 24 * time.Hour)}}
	if f := only(t, run(t, depsDetector{}, s), SigDependencyNew); f.Severity != cli.SeverityHigh {
		t.Errorf("a 6 day old dependency is %s", f.Severity)
	}
	s.New.DepInfo["x"].Published = s.Now.Add(-8 * 24 * time.Hour)
	if f := only(t, run(t, depsDetector{}, s), SigDependencyNew); f.Severity != cli.SeverityMedium {
		t.Errorf("an 8 day old dependency is %s", f.Severity)
	}
}

func TestTyposquatOfAddedPackage(t *testing.T) {
	installTypoPacks(t)
	s := subject(core.Composer)
	s.Old = nil
	s.Update.Name, s.New.Ref.Name = "laravell/framework", "laravell/framework"
	s.New.Deps = map[string]string{"guzzlehtp/guzzle": "^7"} // an added package's deps are not checked
	f := only(t, run(t, depsDetector{}, s), SigTyposquat)
	if f.Evidence.String() != "laravell/framework is close to the popular laravel/framework" || f.File != "composer.json" {
		t.Errorf("finding = %q @%s", f.Evidence, f.File)
	}
}

func TestTyposquatWithoutPacksIsQuiet(t *testing.T) {
	t.Cleanup(core.SwapDataPacks(nil))
	s := subject(core.NPM)
	s.New.Deps = map[string]string{"plain-crypto-js": "1"}
	for _, f := range run(t, depsDetector{}, s) {
		if f.ID == SigTyposquat {
			t.Errorf("typosquat fired with no data packs: %+v", f)
		}
	}
}

// Negative: a new dependency the popular package's own maintainers
// publish is a sibling, not a typosquat; the same holds for an added
// package. Positive: the same name from someone else still fires.
func TestTyposquatSharedMaintainer(t *testing.T) {
	installTypoPacks(t)
	ann := []core.Person{{Name: "Ann", Login: "ann", Email: "ann@example.test"}}
	s := subject(core.NPM)
	s.New.Deps = map[string]string{"plain-crypto-js": "^4.2.1"}
	s.New.DepInfo = map[string]*core.DepInfo{
		"plain-crypto-js": {Maintainers: []core.Person{{Login: "ANN"}}},
		"crypto-js":       {Popular: true, Maintainers: ann},
	}
	for _, f := range run(t, depsDetector{}, s) {
		if f.ID == SigTyposquat {
			t.Errorf("sibling package fired: %+v", f)
		}
	}
	s.New.DepInfo["plain-crypto-js"].Maintainers = []core.Person{{Login: "mallory"}}
	only(t, run(t, depsDetector{}, s), SigTyposquat)

	s = subject(core.Composer)
	s.Old = nil
	s.Update.Name, s.New.Ref.Name = "laravell/framework", "laravell/framework"
	s.New.Maintainers = []core.Person{{Email: "ann@example.test"}}
	s.New.DepInfo = map[string]*core.DepInfo{"laravel/framework": {Popular: true, Maintainers: ann}}
	for _, f := range run(t, depsDetector{}, s) {
		if f.ID == SigTyposquat {
			t.Errorf("added sibling package fired: %+v", f)
		}
	}
}

// An added package is the new dependency: high with an install script,
// info as a development entry, and its own dependencies are not listed.
func TestAddedPackageIsNew(t *testing.T) {
	s := subject(core.NPM)
	s.Old = nil
	s.Update.Name, s.Update.Version = "expresss", "1.0.0"
	s.New.HasInstallScript = true
	s.New.Deps = map[string]string{"left-pad": "^1.3.0"}
	s.NewLock = &core.Installed{Lockfile: "package-lock.json", LockLine: 9}
	f := only(t, run(t, depsDetector{}, s), SigDependencyNew)
	if f.Severity != cli.SeverityHigh || f.Evidence.String() != "adds expresss 1.0.0 (has an install script)" ||
		f.File != "package-lock.json" || f.Line != 9 {
		t.Errorf("added package: %+v", f)
	}
	s.NewLock.Dev = true
	if f := only(t, run(t, depsDetector{}, s), SigDependencyNew); f.Severity != cli.SeverityInfo {
		t.Errorf("added dev package: %+v", f)
	}
}
