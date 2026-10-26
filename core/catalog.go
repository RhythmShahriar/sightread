// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "github.com/RhythmShahriar/rhythm/kit/cli"

// SignalInfo describes one signal of the catalogue: what the terminal
// and reports call it and how serious it is by default.
type SignalInfo struct {
	ID         string
	Title      string       // terminal and report title, e.g. "Fetches remote code and runs it"
	Severity   cli.Severity // default
	Confidence Confidence
	Ecosystems []Ecosystem
	Emitter    string // "detect", or "policy" for approved-version-changed
	// Unignorable signals can never be ignored, allowed or demoted below
	// critical: they say the bytes are not the ones that were published
	// or reviewed.
	Unignorable bool
}

// Emitters of a signal.
const (
	EmitDetect = "detect"
	EmitPolicy = "policy"
)

var (
	allEcos      = []Ecosystem{WPPlugin, WPTheme, Composer, NPM}
	wpEcos       = []Ecosystem{WPPlugin, WPTheme}
	pkgEcos      = []Ecosystem{NPM, Composer}
	phpEcos      = []Ecosystem{WPPlugin, WPTheme, Composer}
	wpNPMEcos    = []Ecosystem{WPPlugin, WPTheme, NPM}
	npmEcos      = []Ecosystem{NPM}
	composerEcos = []Ecosystem{Composer}
)

func sig(id, title string, sev cli.Severity, conf Confidence, ecos []Ecosystem) SignalInfo {
	return SignalInfo{ID: id, Title: title, Severity: sev, Confidence: conf, Ecosystems: ecos, Emitter: EmitDetect}
}

func unignorable(s SignalInfo) SignalInfo { s.Unignorable = true; return s }

// Catalog is every signal of PRD section 12.1, in that order. Titles
// describe behaviour, never intent: "Fetches remote code and runs it",
// not "backdoor".
var Catalog = []SignalInfo{
	unignorable(sig("integrity-mismatch", "Archive does not match the published hash", cli.SeverityCritical, Confirmed, allEcos)),
	unignorable(sig("version-republished", "Same version, different bytes than the lockfile recorded", cli.SeverityCritical, Confirmed, pkgEcos)),
	func() SignalInfo {
		s := unignorable(sig("approved-version-changed", "Allowed version now has a different hash", cli.SeverityCritical, Confirmed, allEcos))
		s.Emitter = EmitPolicy
		return s
	}(),
	unignorable(sig("known-malicious", "Listed as malicious by OSV", cli.SeverityCritical, Confirmed, pkgEcos)),
	sig("wporg-closed", "Closed on WordPress.org", cli.SeverityCritical, Confirmed, wpEcos),
	unignorable(sig("archive-path-escape", "Archive entry points outside the package", cli.SeverityCritical, Confirmed, allEcos)),
	sig("remote-fetch-exec", "Fetches remote code and runs it", cli.SeverityCritical, Confirmed, allEcos),
	sig("decode-exec", "Decodes hidden code and runs it", cli.SeverityCritical, Confirmed, allEcos),
	sig("admin-user-hidden", "Hides users from the admin user list", cli.SeverityCritical, Confirmed, wpEcos),
	sig("lockfile-source-change", "Lockfile entry moved off the registry", cli.SeverityHigh, Confirmed, pkgEcos),
	sig("archive-link", "Archive holds a link or special file", cli.SeverityHigh, Confirmed, allEcos),
	sig("archive-collision", "Archive holds two entries with the same name", cli.SeverityHigh, Confirmed, allEcos),
	sig("unanalysed", "Code that could not be analysed", cli.SeverityHigh, Confirmed, allEcos),
	sig("eval-dynamic", "Runs code built at run time", cli.SeverityHigh, Confirmed, allEcos),
	sig("obfuscation", "Adds a large encoded or scrambled blob", cli.SeverityHigh, Likely, allEcos),
	sig("input-unserialize", "Unserializes request or remote data", cli.SeverityHigh, Likely, phpEcos),
	sig("write-outside-package", "Writes files outside its own folder", cli.SeverityHigh, Likely, allEcos),
	sig("admin-user-create", "Creates an administrator account", cli.SeverityHigh, Confirmed, wpEcos),
	sig("capability-change", "Grants admin capabilities to another role", cli.SeverityHigh, Likely, wpEcos),
	sig("update-suppression", "Blocks updates of other plugins or themes", cli.SeverityHigh, Likely, wpEcos),
	sig("bot-cloaking", "Shows search engines different content", cli.SeverityHigh, Likely, wpNPMEcos),
	sig("credential-access", "Reads credentials or tokens", cli.SeverityHigh, Likely, allEcos),
	sig("data-exfil", "Sends site data to a new host", cli.SeverityHigh, Likely, allEcos),
	sig("code-in-asset", "Hides code in an image, font or text file", cli.SeverityHigh, Confirmed, allEcos),
	sig("npm-install-script-new", "Adds or changes an install script", cli.SeverityHigh, Confirmed, npmEcos),
	sig("composer-plugin-new", "Runs code when Composer installs it", cli.SeverityHigh, Confirmed, composerEcos),
	sig("owner-change", "New owner or publisher", cli.SeverityHigh, Confirmed, allEcos),
	sig("provenance-dropped", "Release lost its build provenance", cli.SeverityHigh, Confirmed, npmEcos),
	sig("typosquat", "New dependency named like a popular package", cli.SeverityHigh, Likely, pkgEcos),
	sig("known-vulnerable", "Has a known vulnerability", cli.SeverityHigh, Confirmed, pkgEcos),
	sig("dependency-confusion", "Private name also published publicly", cli.SeverityCritical, Confirmed, pkgEcos),
	sig("outbound-new-domain", "Contacts a new domain", cli.SeverityMedium, Confirmed, allEcos),
	sig("rest-open-route", "Adds a REST route anyone can call", cli.SeverityMedium, Likely, wpEcos),
	sig("changelog-mismatch", "Changelog does not mention what the code adds", cli.SeverityMedium, Likely, allEcos),
	sig("dependency-new", "Adds a runtime dependency", cli.SeverityMedium, Confirmed, pkgEcos),
	sig("composer-autoload-files", "Adds a file that runs on every request", cli.SeverityMedium, Confirmed, composerEcos),
	sig("fresh-release", "Released very recently", cli.SeverityMedium, Likely, allEcos),
	sig("dormant-release", "First release after a long silence", cli.SeverityMedium, Likely, allEcos),
	sig("git-tag-missing", "No matching tag in the repository", cli.SeverityMedium, Likely, npmEcos),
	sig("size-jump", "Code grew far more than usual", cli.SeverityMedium, Likely, allEcos),
	sig("unicode-hidden", "Hidden or bidirectional characters in code", cli.SeverityMedium, Confirmed, allEcos),
	sig("secret-added", "Adds a credential to the code", cli.SeverityMedium, Confirmed, allEcos),
	sig("cron-new-hook", "Schedules a new background task", cli.SeverityLow, Confirmed, wpEcos),
	sig("license-change", "License changed", cli.SeverityLow, Confirmed, allEcos),
	sig("abandoned", "Marked abandoned or not updated in years", cli.SeverityLow, Confirmed, phpEcos),
	sig("local-drift", "Installed copy differs from the official one", cli.SeverityInfo, Confirmed, phpEcos),
	sig("php-requirement", "PHP requirement changed", cli.SeverityInfo, Confirmed, phpEcos),
	sig("files-removed", "Removes security-relevant files", cli.SeverityInfo, Confirmed, allEcos),
}

// Signal returns the catalogue entry for id.
func Signal(id string) (SignalInfo, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return SignalInfo{}, false
}

// SignalIDs returns every catalogue ID in catalogue order.
func SignalIDs() []string {
	ids := make([]string, len(Catalog))
	for i, s := range Catalog {
		ids[i] = s.ID
	}
	return ids
}

// Unignorable reports whether id names a signal that can never be
// ignored, allowed or demoted below critical.
func Unignorable(id string) bool {
	s, ok := Signal(id)
	return ok && s.Unignorable
}
