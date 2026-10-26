// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// inChangeConfigNote is the header line for a config change the change
// under review made itself and that Sightread did not apply.
const inChangeConfigNote = "%s: relaxed in this change, not counted (--trust-pr-allow counts it)"

// ConfigAtBase applies the pull request rule to the config itself, as
// LoadAllow does to the allow file (SR-61: the config is code). The
// config's own file is read at baseRef through core.GetGitShow. What the
// working tree relaxes against it is put back:
//
//   - an ignore entry the base doesn't have is dropped; one whose
//     until the change moved later keeps the base's date;
//   - a signals.severity value lower than the base's (or than the
//     catalogue default when the base has none) is raised back;
//   - a domains_ok host the base doesn't have is dropped;
//   - min_confidence confirmed counts only when the base has it;
//   - fail_on keeps the stricter of the two (the base's when the
//     change removed it).
//
// cfg is changed in place. It returns one note per change it did not
// apply, for Report.Notes. With baseRef or configPath empty, or a config
// outside the repository, it does nothing. A config the ref can't show
// or parse counts as empty there, so nothing the change relaxed counts.
func (s *Store) ConfigAtBase(cfg *core.Config, configPath, baseRef string) ([]string, error) {
	if cfg == nil || configPath == "" || baseRef == "" {
		return nil, nil
	}
	gitShow := core.GetGitShow()
	if gitShow == nil {
		return nil, fmt.Errorf("reading the config at %s: git show %w", baseRef, core.ErrNotLinked)
	}
	repo := gitRoot(projectRoot(configPath))
	if repo == "" {
		return nil, nil
	}
	rel, ok := inside(repo, configPath)
	if !ok {
		// Outside the repository the change can't touch it.
		return nil, nil
	}
	base := &core.Config{}
	if data, err := gitShow(context.Background(), repo, baseRef, rel); err == nil {
		// The base's own warnings were printed when it was the working
		// tree; repeating them here would confuse.
		quiet := &Store{Stderr: io.Discard, Now: s.Now}
		if c, err := quiet.ParseConfig(data, rel+" at "+baseRef); err == nil {
			base = c
		}
	}
	return relaxBack(cfg, base), nil
}

// relaxBack puts back in cfg what it relaxes against base and returns a
// note for each.
func relaxBack(cfg, base *core.Config) []string {
	var notes []string
	note := func(what string) { notes = append(notes, fmt.Sprintf(inChangeConfigNote, what)) }

	var kept []core.IgnoreEntry
	for _, ig := range cfg.Ignore {
		b, ok := baseIgnore(base.Ignore, ig)
		if !ok {
			note(fmt.Sprintf("ignore %s", ignoreName(ig)))
			continue
		}
		if b.Until != "" && (ig.Until == "" || ig.Until > b.Until) {
			note(fmt.Sprintf("ignore %s until %s", ignoreName(ig), untilText(ig.Until)))
			ig.Until = b.Until
		}
		kept = append(kept, ig)
	}
	cfg.Ignore = kept

	for _, id := range sortedKeys(cfg.Signals.Severity) {
		head, _ := cli.ParseFailOn(cfg.Signals.Severity[id])
		floor := defaultSeverity(id)
		if v, ok := base.Signals.Severity[id]; ok {
			floor, _ = cli.ParseFailOn(v)
		}
		if head < floor {
			note(fmt.Sprintf("signals.severity.%s %s", id, head))
			cfg.Signals.Severity[id] = floor.String()
		}
	}
	// A raise the base had and the change removed is a lowering too.
	for _, id := range sortedKeys(base.Signals.Severity) {
		if _, ok := cfg.Signals.Severity[id]; ok {
			continue
		}
		if sev, _ := cli.ParseFailOn(base.Signals.Severity[id]); sev > defaultSeverity(id) {
			note(fmt.Sprintf("signals.severity.%s removed", id))
			if cfg.Signals.Severity == nil {
				cfg.Signals.Severity = map[string]string{}
			}
			cfg.Signals.Severity[id] = sev.String()
		}
	}

	var hosts []string
	for _, d := range cfg.Signals.DomainsOK {
		if slices.Contains(base.Signals.DomainsOK, d) {
			hosts = append(hosts, d)
		} else {
			note(fmt.Sprintf("signals.domains_ok %s", show(d)))
		}
	}
	cfg.Signals.DomainsOK = hosts

	if cfg.MinConfidence == string(core.Confirmed) && base.MinConfidence != string(core.Confirmed) {
		note("min_confidence confirmed")
		cfg.MinConfidence = base.MinConfidence
	}

	if base.FailOn != "" {
		head, _ := cli.ParseFailOn(cfg.FailOn)
		was, _ := cli.ParseFailOn(base.FailOn)
		if cfg.FailOn == "" || weaker(head, was) {
			what := "fail_on removed"
			if cfg.FailOn != "" {
				what = "fail_on " + head.String()
			}
			note(what)
			cfg.FailOn = base.FailOn
		}
	}
	return notes
}

// baseIgnore finds the base entry that hides the same thing as ig: the
// same signal, package and path. The reason may be reworded freely.
func baseIgnore(list []core.IgnoreEntry, ig core.IgnoreEntry) (core.IgnoreEntry, bool) {
	for _, b := range list {
		if b.ID == ig.ID && b.Package == ig.Package && b.Path == ig.Path {
			return b, true
		}
	}
	return core.IgnoreEntry{}, false
}

// ignoreName names an ignore entry for a note: its signal and, when set,
// its package and path.
func ignoreName(ig core.IgnoreEntry) string {
	parts := []string{ig.ID}
	if ig.Package != "" {
		parts = append(parts, "package "+show(ig.Package))
	}
	if ig.Path != "" {
		parts = append(parts, "path "+show(ig.Path))
	}
	return strings.Join(parts, " ")
}

func untilText(u string) string {
	if u == "" {
		return "never"
	}
	return u
}

// weaker reports whether fail_on a fails fewer findings than fail_on b.
// none fails nothing, so it is the weakest.
func weaker(a, b cli.Severity) bool {
	if b == cli.SeverityNone {
		return false
	}
	return a == cli.SeverityNone || a > b
}

func defaultSeverity(id string) cli.Severity {
	info, _ := core.Signal(id)
	return info.Severity
}
