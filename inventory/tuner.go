// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// TunerSchemas are the rhythm-tuner JSON report layouts ReadTuner reads.
// Tuner writes rhythm-tuner/v0 until its 1.0, which will write v1 with
// the same fingerprint fields.
var TunerSchemas = []string{"rhythm-tuner/v0", "rhythm-tuner/v1"}

// tunerReport is the part of a rhythm-tuner report Sightread reads
// (tuner/schema/report-v0.json). Unknown fields are allowed, as the
// schema asks: Tuner adds optional fields in any release.
type tunerReport struct {
	Schema      string `json:"schema"`
	Target      string `json:"target"`
	Complete    *bool  `json:"complete"`
	StoppedBy   string `json:"stopped_by"`
	Error       string `json:"error"` // a TargetError entry in an array
	Fingerprint struct {
		WordPress  string           `json:"wordpress_version"`
		Components []tunerComponent `json:"components"`
	} `json:"fingerprint"`
}

// tunerComponent is one plugin or theme the scan saw.
type tunerComponent struct {
	Type       string `json:"type"` // plugin or theme
	Slug       string `json:"slug"`
	Version    string `json:"version"`
	Confidence string `json:"confidence"` // high, or low for a weak hint
}

// Not checked text for a component the Tuner report has no version for.
const (
	tunerNoVersionText = "the Tuner report has no version for it"
	tunerNoVersionHint = "give the version with --from <version>, or read the site with --path or --wp"
)

// ReadTuner reads the plugins and themes of a rhythm-tuner JSON report
// (--from-tuner, sites.yaml tuner_report) as a site. Installed entries
// have no Path: there are no files to read. A component without a
// version is Not checked fetch-failed. A report of several sites, a
// file that isn't a Tuner report or a schema Sightread doesn't know is
// E12.
func ReadTuner(path string) (*core.Site, error) {
	data, err := readAll(path, maxLockBytes)
	if err != nil {
		return nil, tunerError(path, fmt.Sprintf("can't be read (%s)", errText(err)), err)
	}
	return ParseTuner(path, data)
}

// ParseTuner is ReadTuner from the report's bytes. name is the file as
// messages show it.
func ParseTuner(name string, data []byte) (*core.Site, error) {
	data = bytes.TrimSpace(trimBOM(data))
	var reports []tunerReport
	var err error
	if len(data) > 0 && data[0] == '[' {
		err = json.Unmarshal(data, &reports)
	} else {
		var one tunerReport
		err = json.Unmarshal(data, &one)
		reports = []tunerReport{one}
	}
	if err != nil {
		return nil, notTuner(name, "not JSON: "+clipText(err.Error()), err)
	}
	var sites []tunerReport
	var failed []string
	for _, r := range reports {
		switch {
		case r.Schema == "" && r.Error != "":
			failed = append(failed, fmt.Sprintf("%q: %q", clipText(r.Target), clipText(r.Error)))
		case !knownTunerSchema(r.Schema):
			return nil, notTuner(name, schemaText(r.Schema), nil)
		default:
			sites = append(sites, r)
		}
	}
	switch {
	case len(sites) == 0 && len(failed) > 0:
		return nil, tunerError(name, "has no scan results, only an error: "+failed[0], nil)
	case len(sites) == 0:
		return nil, notTuner(name, "an empty list", nil)
	case len(sites) > 1:
		return nil, tunerError(name, fmt.Sprintf("holds the scans of %d sites; give a report of one site", len(sites)), nil)
	}
	return tunerSite(sites[0]), nil
}

// tunerSite turns one Tuner report into a site.
func tunerSite(rep tunerReport) *core.Site {
	r := &wpReader{site: &core.Site{Kind: "wordpress", WordPress: rep.Fingerprint.WordPress}}
	if rep.Fingerprint.WordPress != "" && !validRef(core.WPPlugin, "wordpress", rep.Fingerprint.WordPress) {
		r.warn("the Tuner report gives a WordPress version Sightread can't use: %q", clipText(rep.Fingerprint.WordPress))
		r.site.WordPress = ""
	}
	r.site.NotChecked = append(r.site.NotChecked, notChecked("", "wordpress", r.site.WordPress, core.Core))
	if rep.Complete != nil && !*rep.Complete {
		why := "it did not finish"
		if rep.StoppedBy != "" {
			why = fmt.Sprintf("it stopped early (%q)", clipText(rep.StoppedBy))
		}
		r.warn("the Tuner report of %q may miss plugins and themes: %s", clipText(rep.Target), why)
	}
	seen := map[string]bool{}
	for _, c := range rep.Fingerprint.Components {
		var eco core.Ecosystem
		switch c.Type {
		case "plugin":
			eco = core.WPPlugin
		case "theme":
			eco = core.WPTheme
		default:
			r.warn("skipped a Tuner component of type %q: want plugin or theme", clipText(c.Type))
			continue
		}
		if !validRef(eco, c.Slug, c.Version) {
			r.warn("skipped a Tuner %s entry with a name or version Sightread can't use: %q %q", ecoNoun(eco), clipText(c.Slug), clipText(c.Version))
			continue
		}
		key := string(eco) + ":" + strings.ToLower(c.Slug)
		if seen[key] {
			continue
		}
		seen[key] = true
		if c.Version == "" {
			nc := notChecked(eco, c.Slug, "", core.FetchFailed)
			nc.Text, nc.Hint = tunerNoVersionText, tunerNoVersionHint
			r.site.NotChecked = append(r.site.NotChecked, nc)
			continue
		}
		if c.Confidence == "low" {
			r.warn("the Tuner report found %s %s %s from a weak hint only, so the version may be wrong", ecoNoun(eco), c.Slug, c.Version)
		}
		r.addPlugin(c.Slug, "", "", WPHeader{Version: c.Version}, eco)
	}
	return r.site
}

// knownTunerSchema reports whether s is one of TunerSchemas.
func knownTunerSchema(s string) bool {
	return slices.Contains(TunerSchemas, s)
}

// schemaText is the reason for a report with another schema.
func schemaText(s string) string {
	if s == "" {
		return "no schema"
	}
	return fmt.Sprintf("schema %q", clipText(s))
}

// notTuner is E12 for a file that is not a Tuner report Sightread reads.
func notTuner(name, why string, cause error) error {
	return &core.Error{
		Code: core.EBadConfig,
		Exit: 2,
		What: fmt.Sprintf("%s is not a rhythm-tuner report (%s)", name, why),
		Hint: []string{"write one with rhythm-tuner <site> --json -o report.json; Sightread reads " + strings.Join(TunerSchemas, " and ")},
		Err:  cause,
	}
}

// tunerError is E12 for a Tuner report Sightread can't use.
func tunerError(name, what string, cause error) error {
	return &core.Error{
		Code: core.EBadConfig,
		Exit: 2,
		What: name + " " + what,
		Hint: []string{"give the JSON report of one scan: rhythm-tuner <site> --json -o report.json"},
		Err:  cause,
	}
}

// clipText drops control characters and cuts s to 100 bytes, for text
// from a file that goes into a message.
func clipText(s string) string { return clipN(s, 100) }

// clipN is clipText with a cap of n bytes.
func clipN(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "") + "..."
	}
	return s
}
