// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/detect/code"
)

// SigChangelogMismatch is the signal of the changelog detector.
const SigChangelogMismatch = "changelog-mismatch"

// changelogQuote caps the changelog text the evidence quotes.
const changelogQuote = 80

func init() { core.RegisterDetector(changelogDetector{}) }

// changelogDetector reports an update whose changelog says nothing (or
// only "compatibility", "tested up to", "bug fixes") while the code
// adds network, execution, file write, user or install time behaviour
// (PRD 12.1, the Essential Plugin takeover).
type changelogDetector struct{}

func (changelogDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-changelog", Signals: []string{SigChangelogMismatch}}
}

// capability is one thing the candidate adds that a changelog should
// mention.
type capability struct {
	what       string // "network sends"
	file       string
	line       int
	words      []string // text that, in the changelog, explains it
	seriousIDs map[string]bool
}

// changelogKinds are the feature kinds that need a changelog line, what
// the evidence calls them and the code signals they raise.
var changelogKinds = map[core.FeatureKind]struct {
	what string
	ids  []string
}{
	core.FSend:       {"network sends", []string{code.SigDataExfil}},
	core.FFlow:       {"fetched or decoded code that runs", []string{code.SigRemoteFetchExec, code.SigDecodeExec, code.SigEvalDynamic, code.SigInputUnserialize}},
	core.FEval:       {"eval", []string{code.SigDecodeExec, code.SigEvalDynamic}},
	core.FDynCall:    {"dynamic calls", []string{code.SigDecodeExec, code.SigEvalDynamic}},
	core.FWrite:      {"file writes outside the package", []string{code.SigWriteOutsidePackage}},
	core.FUserCreate: {"user creation", []string{code.SigAdminUserCreate}},
	core.FCap:        {"capability changes", []string{code.SigCapabilityChange}},
	core.FCron:       {"scheduled tasks", []string{code.SigCronNewHook}},
}

// capabilityWords are the words that explain any capability (PRD 12.1:
// "a changelog that names the capability does not fire").
var capabilityWords = regexp.MustCompile(`(?i)\b(telemetry|auto[- ]?updates?|licen[cs]e[- ]?(check|key|verification)s?|licensing|analytics|cron|users?|roles?)\b`)

func (changelogDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.New == nil || s.Old == nil {
		return
	}
	caps := addedCapabilities(s)
	if len(caps) == 0 {
		return
	}
	entries := s.New.Changelog
	if len(entries) > 0 && !allGeneric(entries) {
		return
	}
	var text strings.Builder
	for _, e := range entries {
		text.WriteString(e.Text)
		text.WriteByte('\n')
	}
	if explains(text.String(), s, caps) {
		return
	}
	f := newFinding(SigChangelogMismatch, mismatchEvidence(s, entries, caps))
	f.File, f.Line = caps[0].file, caps[0].line
	if serious(ctx, s, caps) {
		f.Severity = cli.SeverityHigh
	}
	out.send(f)
}

func allGeneric(entries []core.ChangelogEntry) bool {
	for _, e := range entries {
		if !e.Generic {
			return false
		}
	}
	return true
}

// addedCapabilities lists what the candidate adds, first place of each
// kind, in feature order, then install time hooks.
func addedCapabilities(s *core.Subject) []capability {
	var caps []capability
	seen := map[string]bool{}
	for _, f := range s.NewFeatures.NewIn(s.OldFeatures) {
		k, ok := changelogKinds[f.Kind]
		if !ok || !firesInCode(f) || f.Kind == core.FWrite && f.Key == "own" {
			continue
		}
		c := capability{what: k.what, file: f.Ev.Path, line: f.Ev.Line, seriousIDs: map[string]bool{}}
		for _, id := range k.ids {
			c.seriousIDs[id] = true
		}
		if h := f.Attrs["host"]; h != "" {
			c.words = append(c.words, h)
		}
		if seen[k.what] {
			// Later places of a kind only add words that may explain it.
			for i := range caps {
				if caps[i].what == k.what {
					caps[i].words = append(caps[i].words, c.words...)
					caps[i].words = append(caps[i].words, c.file)
				}
			}
			continue
		}
		seen[k.what] = true
		c.words = append(c.words, c.file)
		caps = append(caps, c)
	}
	switch s.Update.Eco {
	case core.NPM:
		if keys := changedInstallScripts(s); len(keys) > 0 || newBindingGyp(s) {
			caps = append(caps, capability{what: "an install script", file: npmManifest, words: []string{"install script", "postinstall", "preinstall", "node-gyp"}})
		}
	case core.Composer:
		events := changedComposerEvents(s)
		plugin := s.New.Type == "composer-plugin" && s.Old.Type != "composer-plugin"
		if len(events) > 0 || plugin {
			caps = append(caps, capability{what: "Composer install hooks", file: composerManifest, words: []string{"composer plugin", "post-install", "post-update", "post-autoload"}})
		}
	}
	return caps
}

// firesInCode reports whether a feature is in code, decoded or vendored
// code; comments, docs and tests need no changelog line.
func firesInCode(f core.Feature) bool {
	switch f.Context {
	case core.CtxCode, core.CtxDecoded, core.CtxVendored:
		return true
	}
	return false
}

// explains reports whether the changelog names what the update adds: a
// new domain, a file the capability is in, or a word such as telemetry,
// auto-update, license check, analytics, cron, user or role.
func explains(text string, s *core.Subject, caps []capability) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	if capabilityWords.MatchString(text) {
		return true
	}
	low := strings.ToLower(text)
	for _, f := range s.NewFeatures.NewIn(s.OldFeatures) {
		if f.Kind == core.FDomain && f.Key != "" && strings.Contains(low, strings.ToLower(f.Key)) {
			return true
		}
	}
	for _, c := range caps {
		for _, w := range c.words {
			w = strings.ToLower(w)
			if w == "" {
				continue
			}
			if strings.Contains(low, w) || strings.Contains(low, path.Base(w)) && strings.Contains(path.Base(w), ".") {
				return true
			}
		}
	}
	return false
}

// serious reports whether a capability raised a high or critical code
// finding, or is an install time hook (high on its own): the mismatch is
// then high.
func serious(ctx context.Context, s *core.Subject, caps []capability) bool {
	ids := map[string]bool{}
	for _, c := range caps {
		if c.file == npmManifest && c.what == "an install script" || c.file == composerManifest {
			return true
		}
		for id := range c.seriousIDs {
			ids[id] = true
		}
	}
	found := false
	for _, d := range code.FeatureDetectors() {
		d.Detect(ctx, s, func(f core.Finding) {
			if ids[f.ID] && f.Severity >= cli.SeverityHigh {
				found = true
			}
		})
	}
	return found
}

// mismatchEvidence is
// `changelog for 2.0.0 says only "Tested up to 6.8"; the update adds network sends (includes/stats.php:22)`
// or `no changelog entry for 2.0.0; the update adds ...`.
func mismatchEvidence(s *core.Subject, entries []core.ChangelogEntry, caps []capability) string {
	var head string
	v := s.New.Ref.Version
	if v == core.LocalVersion {
		v = "the local copy"
	}
	if len(entries) == 0 {
		head = "no changelog entry for " + v
	} else {
		q := strings.Join(strings.Fields(entries[0].Text), " ")
		if len(q) > changelogQuote {
			cut := changelogQuote
			for cut > 0 && q[cut]&0xC0 == 0x80 {
				cut--
			}
			q = q[:cut] + "…"
		}
		head = "changelog for " + v + " says only \"" + q + "\""
	}
	var parts []string
	for _, c := range caps {
		at := c.file
		if c.line > 0 {
			at += ":" + strconv.Itoa(c.line)
		}
		parts = append(parts, c.what+" ("+at+")")
	}
	return head + "; the update adds " + list(parts)
}
