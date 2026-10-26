// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzDecodeVerify: whatever rhythm-roadie prints, decoding never
// panics, only a rhythm-roadie/v1 verify document passes and every
// reason it gives is printable text.
func FuzzDecodeVerify(f *testing.F) {
	for _, s := range []string{
		`{"schema":"rhythm-roadie/v1","kind":"verify","verdict":"ok","data":{"signed":true,"sealed":true,` +
			`"copy_created":"2026-10-01T10:00:00Z","verified_at":"2026-10-01T11:00:00Z","production_url":"https://shop.example.com"}}`,
		`{"schema":"rhythm-roadie/v1","kind":"verify","verdict":"fail","data":{"problems":[{"kind":"mail","count":1,"text":"mail is live\u001b[31m"}]}}`,
		`{"schema":"rhythm-roadie/v2","kind":"verify"}`,
		`{"schema":"rhythm-roadie/v1","kind":"copy"}`,
		`not json`,
		``,
	} {
		f.Add([]byte(s), 0)
	}
	f.Fuzz(func(t *testing.T, b []byte, code int) {
		doc, err := decodeVerify(b)
		if err != nil {
			if doc != nil {
				t.Fatalf("%q: a document with error %v", b, err)
			}
			return
		}
		if doc.Schema != roadieSchema || doc.Kind != "verify" {
			t.Fatalf("%q: accepted schema %q kind %q", b, doc.Schema, doc.Kind)
		}
		for _, w := range verifyProblems(doc, code) {
			if strings.ContainsFunc(w, unicode.IsControl) {
				t.Fatalf("%q: reason %q holds a control character", b, w)
			}
		}
		if code != 0 && len(verifyProblems(doc, code)) == 0 {
			t.Fatalf("%q: exit %d cleared the copy", b, code)
		}
	})
}

// FuzzDecodeComparison: only a finished comparison passes.
func FuzzDecodeComparison(f *testing.F) {
	for _, s := range []string{
		`{"schema":"rhythm-soundcheck/v1","kind":"comparison","summary":{"broke":1,"new":0,"changed":2,"verdict":"broke"},"after":{"dir":".soundcheck/x"}}`,
		`{"kind":"comparison","interrupted":true}`,
		`{"kind":"snapshot"}`,
		`[]`,
		``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := decodeComparison(b)
		if err != nil {
			if c != nil {
				t.Fatalf("%q: a comparison with error %v", b, err)
			}
			return
		}
		if c.Kind != "comparison" || c.Interrupted {
			t.Fatalf("%q: accepted kind %q interrupted %v", b, c.Kind, c.Interrupted)
		}
		// With counts as Soundcheck writes them (none below zero) the
		// gate classes nest: new trips whenever broke does, changed
		// whenever new does.
		n := c.Summary
		nested := (!c.trips("broke") || c.trips("new")) && (!c.trips("new") || c.trips("changed"))
		if n.Broke >= 0 && n.New >= 0 && n.Changed >= 0 && !nested {
			t.Fatalf("%q: classes don't nest: %+v", b, n)
		}
	})
}

// FuzzParseProduction: the Soundcheck config's production list never
// panics the parser and keeps every entry with where it came from.
func FuzzParseProduction(f *testing.F) {
	for _, s := range []string{
		"production:\n  - shop.example.com\n  - \"*.example.org\"\n",
		"production: https://shop.example.com\n",
		"targets: [a]\n",
		"production: [\n",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		prods, err := parseProduction(b, ".soundcheck/config.yaml")
		if err != nil {
			if !strings.HasPrefix(err.Error(), ".soundcheck/config.yaml: ") {
				t.Fatalf("%q: error %q doesn't name the file", b, err)
			}
			return
		}
		for _, p := range prods {
			if p.from == "" {
				t.Fatalf("%q: entry %q without its file", b, p.entry)
			}
			_ = p.matches("shop.example.com")
		}
	})
}
