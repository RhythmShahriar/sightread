// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func TestReadTunerGolden(t *testing.T) {
	s, err := ReadTuner(filepath.Join("testdata", "tuner", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	coretest.Golden(t, "tuner/report.json", append(b, '\n'))
}

func TestReadTunerEntries(t *testing.T) {
	s, err := ReadTuner(filepath.Join("testdata", "tuner", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != "wordpress" || s.WordPress != "6.6.2" {
		t.Fatalf("site = %+v", s)
	}
	got := map[string]core.Installed{}
	for _, in := range s.Installed {
		got[in.Ref.String()] = in
		if in.Path != "" || in.Lockfile != "" {
			t.Errorf("%s has a path: %+v", in.Ref, in)
		}
	}
	for _, want := range []string{"wp-plugin:contact-form-7@5.9.8", "wp-plugin:woocommerce@9.3.3", "wp-plugin:elementor@3.24.5", "wp-theme:storefront@4.6.0", "wp-plugin:acme+pro@1.0.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, keys(got))
		}
	}
	if len(s.Installed) != 5 {
		t.Errorf("installed = %v, want 5 (duplicate woocommerce, widget and ../etc dropped)", keys(got))
	}
	if !got["wp-plugin:acme+pro@1.0.0"].Private {
		t.Error("a slug WordPress.org can't have is not Private")
	}
	nc := map[string]core.NotChecked{}
	for _, n := range s.NotChecked {
		nc[string(n.Reason)+":"+n.Name] = n
	}
	wf, ok := nc["fetch-failed:wordfence"]
	if !ok || wf.Eco != core.WPPlugin || wf.Text != "the Tuner report has no version for it" ||
		wf.Hint != "give the version with --from <version>, or read the site with --path or --wp" {
		t.Errorf("wordfence not checked = %+v (%v)", wf, ok)
	}
	if _, ok := nc["not-wporg:acme+pro"]; !ok {
		t.Error("acme+pro is not listed as not-wporg")
	}
	if c, ok := nc["core:wordpress"]; !ok || c.Version != "6.6.2" {
		t.Errorf("core = %+v", c)
	}
	warns := strings.Join(s.Warnings, "\n")
	for _, w := range []string{
		"the Tuner report found plugin elementor 3.24.5 from a weak hint only, so the version may be wrong",
		`skipped a Tuner component of type "widget": want plugin or theme`,
		`skipped a Tuner plugin entry with a name or version Sightread can't use: "../etc" "1.0"`,
	} {
		if !strings.Contains(warns, w) {
			t.Errorf("warnings lack %q:\n%s", w, warns)
		}
	}
}

func TestReadTunerArrayWithError(t *testing.T) {
	s, err := ReadTuner(filepath.Join("testdata", "tuner", "partial-array.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Installed) != 1 || s.Installed[0].Ref.String() != "wp-plugin:akismet@5.3.5" {
		t.Fatalf("installed = %+v", s.Installed)
	}
	want := `the Tuner report of "https://blog.example.test" may miss plugins and themes: it stopped early ("max-time")`
	if len(s.Warnings) != 1 || s.Warnings[0] != want {
		t.Errorf("warnings = %q", s.Warnings)
	}
}

func TestParseTunerErrors(t *testing.T) {
	cases := []struct {
		name, data, want string
	}{
		{"wrong schema", `{"schema": "rhythm-soundcheck/v1"}`,
			`r.json is not a rhythm-tuner report (schema "rhythm-soundcheck/v1")` + "\n  write one with rhythm-tuner <site> --json -o report.json; Sightread reads rhythm-tuner/v0 and rhythm-tuner/v1"},
		{"no schema", `{"fingerprint": {}}`, "r.json is not a rhythm-tuner report (no schema)"},
		{"future schema", `{"schema": "rhythm-tuner/v2"}`, `r.json is not a rhythm-tuner report (schema "rhythm-tuner/v2")`},
		{"not json", `<html>`, "r.json is not a rhythm-tuner report (not JSON: invalid character '<' looking for beginning of value)"},
		{"empty list", `[]`, "r.json is not a rhythm-tuner report (an empty list)"},
		{"two sites", `[{"schema": "rhythm-tuner/v0"}, {"schema": "rhythm-tuner/v0"}]`,
			"r.json holds the scans of 2 sites; give a report of one site\n  give the JSON report of one scan: rhythm-tuner <site> --json -o report.json"},
		{"only an error", `[{"target": "https://a.test", "error": "no such host"}]`,
			`r.json has no scan results, only an error: "https://a.test": "no such host"`},
		{"control bytes", "{\"schema\": \"x\\u001b[31m\"}", `r.json is not a rhythm-tuner report (schema "x[31m")`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseTuner("r.json", []byte(c.data))
			if err == nil {
				t.Fatal("no error")
			}
			if core.CodeOf(err) != core.EBadConfig {
				t.Errorf("code = %q", core.CodeOf(err))
			}
			var ce *core.Error
			if !errors.As(err, &ce) {
				t.Fatalf("not a core.Error: %v", err)
			}
			got := ce.What
			if strings.Contains(c.want, "\n") {
				got += "\n  " + strings.Join(ce.Hint, "\n  ")
			}
			if got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestParseTunerV1AndBOM(t *testing.T) {
	data := "\ufeff" + `{"schema": "rhythm-tuner/v1", "fingerprint": {"components": [{"type": "theme", "slug": "astra", "version": "4.8.1"}]}}`
	s, err := ParseTuner("r.json", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Installed) != 1 || s.Installed[0].Ref.String() != "wp-theme:astra@4.8.1" || s.Installed[0].Private {
		t.Fatalf("installed = %+v", s.Installed)
	}
	if s.WordPress != "" || len(s.Warnings) != 0 {
		t.Errorf("site = %+v", s)
	}
}

func TestReadTunerMissingFile(t *testing.T) {
	_, err := ReadTuner(filepath.Join(t.TempDir(), "nope.json"))
	if core.CodeOf(err) != core.EBadConfig || !strings.Contains(err.Error(), "nope.json can't be read (") {
		t.Fatalf("err = %v", err)
	}
}

func FuzzParseTuner(f *testing.F) {
	f.Add([]byte(`{"schema": "rhythm-tuner/v0", "fingerprint": {"wordpress_version": "6.6", "components": [{"type": "plugin", "slug": "a", "version": "1"}]}}`))
	f.Add([]byte(`[{"schema": "rhythm-tuner/v0"}, {"target": "x", "error": "y"}]`))
	f.Add([]byte(`{"schema": "rhythm-tuner/v0", "complete": false, "fingerprint": {"components": [{"type": "theme", "slug": "../x"}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseTuner("r.json", data)
		if err != nil {
			if core.CodeOf(err) != core.EBadConfig {
				t.Fatalf("error without E12: %v", err)
			}
			return
		}
		for _, in := range s.Installed {
			if !validRef(in.Ref.Eco, in.Ref.Name, in.Ref.Version) || in.Ref.Version == "" {
				t.Fatalf("bad entry %+v", in)
			}
		}
		for _, w := range s.Warnings {
			if strings.ContainsAny(w, "\x1b\r\n") {
				t.Fatalf("control byte in warning %q", w)
			}
		}
	})
}
