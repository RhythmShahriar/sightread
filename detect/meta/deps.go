// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the dependency detector.
const (
	SigDependencyNew = "dependency-new"
	SigTyposquat     = "typosquat"
)

// youngDependency is the age under which a new dependency is high: a
// package published days ago has had no time to be looked at (PRD 12.1).
const youngDependency = 7 * 24 * time.Hour

// maxNear caps the popular names one typosquat finding names.
const maxNear = 3

func init() { core.RegisterDetector(depsDetector{}) }

// depsDetector reports dependencies new in the candidate plus new names
// that look like a popular package's (PRD 12.1, qa.md b13, g11, the
// axios and plain-crypto-js incident).
type depsDetector struct{}

func (depsDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-deps", Signals: []string{SigDependencyNew, SigTyposquat}}
}

func (depsDetector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.New == nil {
		return
	}
	var names []string
	if s.Old != nil {
		runtime, dev := newDeps(s)
		for _, n := range runtime {
			out.send(depFinding(s, n, s.New.Deps[n], false))
		}
		for _, n := range dev {
			out.send(depFinding(s, n, s.New.DevDeps[n], true))
		}
		names = slices.Concat(runtime, dev)
	} else {
		// An added package (a lockfile gained it) is itself the new
		// dependency; its own name is the one to check. Its own
		// dependencies are new to no one yet, so they are not listed.
		out.send(addedFinding(s))
		names = []string{s.Update.Name}
	}
	for _, n := range names {
		if f, ok := typosquatFinding(s, n); ok {
			out.send(f)
		}
	}
}

// platformDep reports Composer requirements that are not packages:
// php, extensions, system libraries and Composer's own APIs.
func platformDep(eco core.Ecosystem, name string) bool {
	if eco != core.Composer {
		return false
	}
	switch name {
	case "php", "php-64bit", "php-ipv6", "php-zts", "php-debug", "hhvm", "composer", "composer-plugin-api", "composer-runtime-api":
		return true
	}
	return strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-")
}

// newDeps lists the runtime and dev dependencies the candidate adds,
// sorted. A dev dependency that was a runtime one before is not new;
// one that moved from dev to runtime is (it now reaches users).
func newDeps(s *core.Subject) (runtime, dev []string) {
	eco := s.Update.Eco
	for _, n := range slices.Sorted(maps.Keys(s.New.Deps)) {
		if _, ok := s.Old.Deps[n]; !ok && !platformDep(eco, n) {
			runtime = append(runtime, n)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(s.New.DevDeps)) {
		_, wasDev := s.Old.DevDeps[n]
		_, wasRuntime := s.Old.Deps[n]
		_, isRuntime := s.New.Deps[n]
		if !wasDev && !wasRuntime && !isRuntime && !platformDep(eco, n) {
			dev = append(dev, n)
		}
	}
	return runtime, dev
}

// manifest is the file dependencies are declared in.
func manifest(eco core.Ecosystem) string {
	if eco == core.Composer {
		return composerManifest
	}
	return npmManifest
}

// depFinding reports one new dependency with what run learnt about it:
// "adds left-pad ^1.3.0 (published 2 days ago, has an install script)".
func depFinding(s *core.Subject, name, constraint string, dev bool) core.Finding {
	what := "adds "
	if dev {
		what = "adds dev dependency "
	}
	ev := what + strings.TrimSpace(name+" "+constraint)
	info := s.New.DepInfo[name]
	var notes []string
	young := false
	if info != nil {
		if !info.Published.IsZero() && !s.Now.IsZero() {
			age := s.Now.Sub(info.Published)
			young = age < youngDependency
			notes = append(notes, "published "+ago(age))
		}
		if info.HasInstallScript {
			notes = append(notes, "has an install script")
		}
		if info.Downloads > 0 {
			notes = append(notes, fmt.Sprintf("%d downloads", info.Downloads))
		}
	}
	if len(notes) > 0 {
		ev += " (" + strings.Join(notes, ", ") + ")"
	}
	f := newFinding(SigDependencyNew, ev)
	f.File = manifest(s.Update.Eco)
	switch {
	case dev:
		f.Severity, f.Demoted = cli.SeverityInfo, "development dependency"
	case young || info != nil && info.HasInstallScript:
		f.Severity = cli.SeverityHigh
	}
	return f
}

// addedFinding is dependency-new for a package a lockfile change adds:
// "adds left-pad-plus 1.0.0 (published 3 hours ago, has an install script)"
// at its lockfile line. Young or with an install script it is high, as
// a dependency a release adds; a development entry is info.
func addedFinding(s *core.Subject) core.Finding {
	ev := "adds " + strings.TrimSpace(s.Update.Name+" "+s.Update.Version)
	var notes []string
	young := false
	if !s.New.Published.IsZero() && !s.Now.IsZero() {
		age := s.Now.Sub(s.New.Published)
		young = age < youngDependency
		notes = append(notes, "published "+ago(age))
	}
	if s.New.HasInstallScript {
		notes = append(notes, "has an install script")
	}
	if len(notes) > 0 {
		ev += " (" + strings.Join(notes, ", ") + ")"
	}
	f := newFinding(SigDependencyNew, ev)
	f.File = manifest(s.Update.Eco)
	if l := s.NewLock; l != nil && l.Lockfile != "" {
		f.File, f.Line = l.Lockfile, l.LockLine
	}
	switch {
	case s.NewLock != nil && s.NewLock.Dev:
		f.Severity, f.Demoted = cli.SeverityInfo, "development dependency"
	case young || s.New.HasInstallScript:
		f.Severity = cli.SeverityHigh
	}
	return f
}

// ago says how long ago something happened: "today", "1 day ago",
// "12 days ago". Under a day it counts hours.
func ago(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "less than an hour ago"
	case d < 24*time.Hour:
		return plural(int(d/time.Hour), "hour", "hours") + " ago"
	}
	return plural(int(d/(24*time.Hour)), "day", "days") + " ago"
}

// depMaintainers are the maintainers run found for a new name: its
// DepInfo, or the candidate's own for an added package.
func depMaintainers(s *core.Subject, name string) []core.Person {
	if info := s.New.DepInfo[name]; info != nil && len(info.Maintainers) > 0 {
		return info.Maintainers
	}
	if s.Old == nil && name == s.Update.Name {
		return s.New.Maintainers
	}
	return nil
}

// shareMaintainer reports whether a and b name a person in common, by
// login, name or e-mail.
func shareMaintainer(a, b []core.Person) bool {
	for _, x := range a {
		if personIdent(x).in(identsOf(b)) {
			return true
		}
	}
	return false
}

// identsOf makes the idents of people.
func identsOf(people []core.Person) []ident {
	out := make([]ident, 0, len(people))
	for _, p := range people {
		if id := personIdent(p); len(id.keys) > 0 {
			out = append(out, id)
		}
	}
	return out
}

// typosquatFinding checks one new name against the popular names pack.
// A popular name and one run found popular (DepInfo.Popular) are never
// typosquats.
func typosquatFinding(s *core.Subject, name string) (core.Finding, bool) {
	packs := core.GetDataPacks()
	if packs == nil || name == "" {
		return core.Finding{}, false
	}
	idx := packs.Names()
	eco := s.Update.Eco
	if idx == nil || idx.Popular(eco, name) {
		return core.Finding{}, false
	}
	if info := s.New.DepInfo[name]; info != nil && info.Popular {
		return core.Finding{}, false
	}
	near := idx.Near(eco, name)
	// A package the popular one's own maintainers publish is a sibling,
	// not a lookalike (PRD 12.1 guard).
	own := depMaintainers(s, name)
	near = slices.DeleteFunc(near, func(p string) bool {
		info := s.New.DepInfo[p]
		return info != nil && shareMaintainer(own, info.Maintainers)
	})
	if len(near) == 0 {
		return core.Finding{}, false
	}
	if len(near) > maxNear {
		near = near[:maxNear]
	}
	ev := name + " is close to the popular " + strings.Join(near, ", ")
	if info := s.New.DepInfo[name]; info != nil && info.HasInstallScript {
		ev += "; it has an install script"
	}
	f := newFinding(SigTyposquat, ev)
	f.File = manifest(eco)
	return f, true
}
