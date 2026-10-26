// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"encoding/hex"
	"reflect"
	"slices"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
	"github.com/RhythmShahriar/sightread/run/runtest"
	"github.com/RhythmShahriar/sightread/score"
)

// sameRequest names lib, installed at 1.0.0, the latest release.
func sameRequest(t *testing.T, w *runtest.World) (run.Request, *core.Installed) {
	t.Helper()
	w.Publish(core.NPM, "lib", "0.9.0", "1.0.0")
	inst := w.Install(core.NPM, "lib", "1.0.0")
	inst.Direct, inst.Lockfile = true, "package-lock.json"
	req := request(t, "npm")
	req.Eco, req.Names = core.NPM, []string{"lib"}
	return req, inst
}

// TestSameVersionRepublished: a lock entry with an integrity is checked
// against the source even when it is already the latest, and only the
// byte signals of that check are reported (PRD 11).
func TestSameVersionRepublished(t *testing.T) {
	w := runtest.Install(t)
	req, inst := sameRequest(t, w)
	inst.Integrity = "sha512-" + "AAAA"
	w.Detector.Set("lib", "version-republished", "eval-dynamic")
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"lib 1.0.0→1.0.0 hold"}) {
		t.Fatalf("updates %q", got)
	}
	var ids []string
	for _, f := range rep.Updates[0].Findings {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"version-republished"}) {
		t.Errorf("findings %q, want only version-republished", ids)
	}
	subs := w.Detector.Subjects()
	if len(subs) != 1 || subs[0].OldLock == nil || subs[0].OldLock.Integrity != inst.Integrity || subs[0].Old != subs[0].New {
		t.Fatalf("subject %+v", subs)
	}
	if n := w.Sources[core.NPM].Fetches(); n != 0 {
		t.Errorf("%d fetches; the lock check needs the metadata only", n)
	}
	if len(rep.Notes) != 0 {
		t.Errorf("notes %q", rep.Notes)
	}
}

// TestSameVersionMatches: when the source still serves what the lock
// recorded, the run says the version is up to date as before.
func TestSameVersionMatches(t *testing.T) {
	w := runtest.Install(t)
	req, inst := sameRequest(t, w)
	inst.Reference = "abc123"
	rep := review(t, req)
	if len(rep.Updates) != 0 {
		t.Fatalf("updates %q", names(rep))
	}
	if want := []string{"lib 1.0.0 is already the latest: nothing to compare"}; !reflect.DeepEqual(rep.Notes, want) {
		t.Errorf("notes %q, want %q", rep.Notes, want)
	}
	if len(w.Detector.Subjects()) != 1 {
		t.Errorf("the lock reference was not checked")
	}
}

// TestSameVersionNothingRecorded: without a lock hash or an allow entry
// an up-to-date package costs no request beyond picking.
func TestSameVersionNothingRecorded(t *testing.T) {
	w := runtest.Install(t)
	req, _ := sameRequest(t, w)
	rep := review(t, req)
	if len(rep.Updates) != 0 || len(w.Detector.Subjects()) != 0 || w.Sources[core.NPM].Fetches() != 0 {
		t.Fatalf("updates %q, %d subjects, %d fetches", names(rep), len(w.Detector.Subjects()), w.Sources[core.NPM].Fetches())
	}
	if want := []string{"lib 1.0.0 is already the latest: nothing to compare"}; !reflect.DeepEqual(rep.Notes, want) {
		t.Errorf("notes %q", rep.Notes)
	}
}

// TestSameVersionAllowChanged: an allow entry for the installed version
// with another hash fetches the archive and reports
// approved-version-changed (SR-9); an entry with the same hash is quiet.
func TestSameVersionAllowChanged(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "other bytes", true: "same bytes"}[same], func(t *testing.T) {
			w := runtest.Install(t)
			t.Cleanup(core.SwapScorer(score.New()))
			req, _ := sameRequest(t, w)
			sum := "0000000000000000000000000000000000000000000000000000000000000000"
			if same {
				tree, _, err := w.Sources[core.NPM].FakeSource.Fetch(t.Context(), &core.Meta{Ref: core.Ref{Eco: core.NPM, Name: "lib", Version: "1.0.0"}})
				if err != nil {
					t.Fatal(err)
				}
				sum = hexSum(tree)
			}
			w.Policy.Allow = []core.AllowEntry{{Package: "npm:lib", Version: "1.0.0", SHA256: sum, Reason: "reviewed", By: "ann", Date: "2026-10-01"}}
			rep := review(t, req)
			if n := w.Sources[core.NPM].Fetches(); n != 1 {
				t.Errorf("%d fetches, want the archive once", n)
			}
			if same {
				if len(rep.Updates) != 0 {
					t.Errorf("updates %q for unchanged bytes", names(rep))
				}
				return
			}
			if len(rep.Updates) != 1 || !slices.ContainsFunc(rep.Updates[0].Findings, func(f core.Finding) bool {
				return f.ID == "approved-version-changed"
			}) {
				t.Fatalf("updates %+v", rep.Updates)
			}
		})
	}
}

func hexSum(t *core.Tree) string { return hex.EncodeToString(t.SHA256[:]) }
