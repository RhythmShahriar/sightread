// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// reviewJSON writes r in the PRD 9.2 shape, as far as a baseline reads
// it. dropFingerprints leaves the fingerprint out, as an older or
// hand-edited report might.
func reviewJSON(t *testing.T, r *core.Report, dropFingerprints bool) []byte {
	t.Helper()
	type finding struct {
		ID          string       `json:"id"`
		File        string       `json:"file"`
		Evidence    core.Snippet `json:"evidence"`
		Fingerprint string       `json:"fingerprint,omitempty"`
	}
	type update struct {
		Ecosystem core.Ecosystem    `json:"ecosystem"`
		Name      string            `json:"name"`
		To        map[string]string `json:"to"`
		Findings  []finding         `json:"findings"`
	}
	var ups []update
	for _, u := range r.Updates {
		up := update{Ecosystem: u.Eco, Name: u.Name, To: map[string]string{"version": u.To.Version}, Findings: []finding{}}
		for _, f := range u.Findings {
			fd := finding{ID: f.ID, File: f.File, Evidence: f.Evidence, Fingerprint: f.Fingerprint}
			if dropFingerprints {
				fd.Fingerprint = ""
			}
			up.Findings = append(up.Findings, fd)
		}
		ups = append(ups, up)
	}
	b, err := json.Marshal(map[string]any{
		"schema": core.Schema, "kind": core.KindReview, "tool": "rhythm-sightread", "version": "1.0.0",
		"complete": false, "summary": map[string]int{}, "verdict": "findings",
		"data": map[string]any{"updates": ups, "future_field": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoadBaseline(t *testing.T) {
	dir := inProject(t)
	r := coretest.SampleReport()
	want := map[string]bool{}
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			want[f.Fingerprint] = true
		}
	}
	for _, drop := range []bool{false, true} {
		p := filepath.Join(dir, "base.json")
		writeFile(t, p, string(reviewJSON(t, r, drop)))
		got, err := testStore(nil).LoadBaseline(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) || len(got) < 40 {
			t.Fatalf("drop %v: %d fingerprints, want %d", drop, len(got), len(want))
		}
		for fp := range want {
			if !got[fp] {
				t.Fatalf("drop %v: fingerprint %s missing", drop, fp)
			}
		}
	}
}

func TestLoadBaselineErrors(t *testing.T) {
	dir := inProject(t)
	cases := []struct{ name, content, want string }{
		{"other schema", `{"schema":"rhythm-tuner/v1","kind":"scan"}`, "rhythm sightread: other.json is not a rhythm-sightread report"},
		{"no schema", `{"runs":[]}`, "rhythm sightread: other.json is not a rhythm-sightread report"},
		{"other kind", `{"schema":"rhythm-sightread/v1","kind":"allowed"}`, `rhythm sightread: other.json is a rhythm-sightread "allowed" document, not a review report`},
		{"corrupt", `{"schema":"rhythm-sightread/v1","kind":"review","data":{"updates":[`, "rhythm sightread: other.json is not valid JSON (the file ends early)"},
		{"not JSON", "fail_on: high\n", "rhythm sightread: other.json is not valid JSON (invalid character 'i' in literal false (expecting 'l'))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "other.json")
			writeFile(t, p, tc.content)
			_, err := testStore(nil).LoadBaseline(p)
			if err == nil {
				t.Fatal("no error")
			}
			want := tc.want + "\n  --baseline takes the JSON a review wrote, such as -o sightread.json"
			if err.Error() != want {
				t.Errorf("\n got %q\nwant %q", err, want)
			}
			if core.CodeOf(err) != core.EBadConfig {
				t.Errorf("code %q", core.CodeOf(err))
			}
		})
	}
	_, err := testStore(nil).LoadBaseline(filepath.Join(dir, "missing.json"))
	if err == nil || err.Error() != "rhythm sightread: missing.json: no such file" {
		t.Errorf("missing: %v", err)
	}
}

func TestPolicyRegistered(t *testing.T) {
	coretest.NeedPolicy(t)
	if _, ok := core.GetPolicy().(*Store); !ok {
		t.Fatalf("registered policy is %T", core.GetPolicy())
	}
}
