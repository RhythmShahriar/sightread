// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func changelogSubject(text string, generic bool, feats ...core.Feature) *core.Subject {
	s := subject(core.WPPlugin)
	if text != "" {
		s.New.Changelog = []core.ChangelogEntry{{Version: "2.0.0", Text: text, Generic: generic}}
	}
	s.OldFeatures, s.NewFeatures = core.NewFeatureSet(), coretest.Features(feats...)
	return s
}

func TestChangelogWording(t *testing.T) {
	send := coretest.Feat(core.FSend, "wp_remote_post", "includes/stats.php", 22, "host", "collect.test")
	cron := coretest.Feat(core.FCron, "acme_sync", "inc/cron.php", 5)
	s := changelogSubject("Tested up to 6.8", true, send, cron)
	f := only(t, run(t, changelogDetector{}, s), SigChangelogMismatch)
	want := `changelog for 2.0.0 says only "Tested up to 6.8"; the update adds scheduled tasks (inc/cron.php:5), network sends (includes/stats.php:22)`
	if f.Evidence.String() != want || f.File != "inc/cron.php" || f.Line != 5 {
		t.Errorf("finding = %q @%s:%d\nwant %q", f.Evidence, f.File, f.Line, want)
	}
	s = changelogSubject("", false, cron)
	f = only(t, run(t, changelogDetector{}, s), SigChangelogMismatch)
	if want := "no changelog entry for 2.0.0; the update adds scheduled tasks (inc/cron.php:5)"; f.Evidence.String() != want || f.Severity != cli.SeverityMedium {
		t.Errorf("finding = %s %q", f.Severity, f.Evidence)
	}
	// A local copy that declares no version is named as such.
	s = changelogSubject("", false, cron)
	s.New.Ref.Version = core.LocalVersion
	f = only(t, run(t, changelogDetector{}, s), SigChangelogMismatch)
	if want := "no changelog entry for the local copy; the update adds scheduled tasks (inc/cron.php:5)"; f.Evidence.String() != want {
		t.Errorf("local copy: %q", f.Evidence)
	}
	s = changelogSubject(strings.Repeat("Compatibility ", 20), true, cron)
	f = only(t, run(t, changelogDetector{}, s), SigChangelogMismatch)
	if !strings.Contains(f.Evidence.String(), `Compatibility Compat`) {
		t.Errorf("long entry not cut: %q", f.Evidence)
	}
}

func TestChangelogHighForSeriousCapability(t *testing.T) {
	flow := coretest.Feat(core.FFlow, "remote->eval", "x.php", 3)
	f := only(t, run(t, changelogDetector{}, changelogSubject("Bug fixes", true, flow)), SigChangelogMismatch)
	if f.Severity != cli.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
}

func TestChangelogGuards(t *testing.T) {
	send := coretest.Feat(core.FSend, "wp_remote_post", "includes/stats.php", 22, "host", "collect.test")
	dom := coretest.Feat(core.FDomain, "collect.test", "includes/stats.php", 20)
	for text, why := range map[string]string{
		"Sends counts to collect.test":       "names the domain",
		"Moved the code into stats.php":      "names the file",
		"Adds anonymous analytics":           "capability word",
		"New role for shop managers":         "capability word",
		"Opt-in auto-update for the add-ons": "capability word",
		"License check against our server":   "capability word",
	} {
		s := changelogSubject(text, true, send, dom)
		for _, f := range run(t, changelogDetector{}, s) {
			t.Errorf("%s (%q) fired: %q", why, text, f.Evidence)
		}
	}
	// An added package has no installed changelog to compare.
	s := changelogSubject("Bug fixes", true, send)
	s.Old = nil
	if fs := run(t, changelogDetector{}, s); len(fs) != 0 {
		t.Errorf("an added package fired: %+v", fs)
	}
}
