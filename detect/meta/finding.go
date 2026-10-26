// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// maxListed is the most names or paths one evidence line lists before
// it ends in "and <n> more".
const maxListed = 5

// maxPerSignal caps the findings one signal gives for one update when it
// fires once per entry (archive issues, unanalysed files). A hostile
// archive with 100,000 links must not make a 100,000 line report; the
// last finding says how many were left out.
const maxPerSignal = 20

// newFinding fills a finding of signal id from the catalogue (title,
// severity, confidence) and the explain text (advice). Metadata findings
// have no line; detectors set File when one fits.
func newFinding(id, evidence string) core.Finding {
	info, _ := core.Signal(id)
	ex, _ := core.ExplainFor(id)
	return core.Finding{
		ID: id, Title: info.Title, Severity: info.Severity, Confidence: info.Confidence,
		Evidence: core.NewSnippet(evidence), Advice: ex.Advice,
	}
}

// forEco reports whether signal id applies to the update's ecosystem.
func forEco(id string, s *core.Subject) bool {
	info, ok := core.Signal(id)
	return ok && (s.Update.Eco == "" || slices.Contains(info.Ecosystems, s.Update.Eco))
}

// emitter sends findings on, skipping signals that don't apply to the
// ecosystem and a repeat of the same finding.
type emitter struct {
	s    *core.Subject
	emit func(core.Finding)
	seen map[string]bool
}

func newEmitter(s *core.Subject, emit func(core.Finding)) *emitter {
	return &emitter{s: s, emit: emit, seen: map[string]bool{}}
}

func (e *emitter) send(f core.Finding) {
	if !forEco(f.ID, e.s) {
		return
	}
	k := strings.Join([]string{f.ID, f.File, strconv.Itoa(f.Line), f.Evidence.String()}, "\x00")
	if e.seen[k] {
		return
	}
	e.seen[k] = true
	e.emit(f)
}

// list joins up to maxListed items with ", " and says how many more
// there are: "a, b, c, d, e and 3 more".
func list(items []string) string {
	if len(items) <= maxListed {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:maxListed], ", "), len(items)-maxListed)
}

// plural returns "<n> <one>" or "<n> <many>".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// packageWord is what the wording calls the package: plugin, theme or
// package.
func packageWord(eco core.Ecosystem) string {
	switch eco {
	case core.WPPlugin:
		return "plugin"
	case core.WPTheme:
		return "theme"
	}
	return "package"
}

// sourceName is who publishes the package's hashes, for the
// integrity-mismatch wording of PRD E6.
func sourceName(eco core.Ecosystem) string {
	switch eco {
	case core.WPPlugin, core.WPTheme:
		return "wordpress.org"
	case core.NPM:
		return "the npm registry"
	case core.Composer:
		return "Packagist"
	}
	return "the source"
}

// version returns m's version, or "" for a nil meta.
func version(m *core.Meta) string {
	if m == nil {
		return ""
	}
	return m.Ref.Version
}
