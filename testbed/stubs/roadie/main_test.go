// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

// accepted applies the acceptance rule of docs/roadie-contract.md, so
// each mode is checked against what Sightread will do with it.
func accepted(d Document, exit int, target string) bool {
	if exit != 0 || d.Schema != "rhythm-roadie/v1" || d.Kind != "verify" || d.Verdict != "ok" {
		return false
	}
	if !d.Data.Signed || !d.Data.Sealed || len(d.Data.Problems) != 0 {
		return false
	}
	created, err1 := time.Parse(time.RFC3339, d.Data.CopyCreated)
	verified, err2 := time.Parse(time.RFC3339, d.Data.VerifiedAt)
	if err1 != nil || err2 != nil || !verified.After(created) {
		return false
	}
	return d.Data.ProductionURL != target
}

func TestAnswerModes(t *testing.T) {
	const target = "http://127.0.0.1:18907"
	want := map[string]bool{ModeOK: true, ModeFailed: false, ModeStale: false, ModeUnsealed: false, ModeProduction: false}
	for _, mode := range Modes {
		d, exit, err := Answer(mode, target, now)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if got := accepted(d, exit, target); got != want[mode] {
			t.Errorf("%s: accepted = %v, want %v", mode, got, want[mode])
		}
		if d.Data.Target != target {
			t.Errorf("%s: target %q", mode, d.Data.Target)
		}
	}
	if _, exit, err := Answer("bogus", target, now); err == nil || exit != 3 {
		t.Errorf("unknown mode: exit %d err %v, want exit 3 and an error", exit, err)
	}
	d, exit, _ := Answer(ModeFailed, target, now)
	if exit != 1 || d.Verdict != "findings" || len(d.Data.Problems) != 2 {
		t.Errorf("failed: exit %d verdict %s problems %d", exit, d.Verdict, len(d.Data.Problems))
	}
}

func TestRunReadsStateAndLogs(t *testing.T) {
	state := t.TempDir()
	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(args, state, now, &out, &errb)
		return code, out.String(), errb.String()
	}

	// No state file: ok.
	code, out, _ := run1("verify", "--target", "http://127.0.0.1:18907", "--wp", "testbed/bin/wp", "--json")
	if code != 0 {
		t.Fatalf("ok: exit %d", code)
	}
	var d Document
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("ok: %v\n%s", err, out)
	}
	if d.Verdict != "ok" || !d.Data.Sealed {
		t.Errorf("ok: %+v", d)
	}

	// Switching the state file changes the next answer without a rebuild.
	if err := os.WriteFile(filepath.Join(state, "roadie"), []byte("unsealed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run1("verify", "--target=http://127.0.0.1:18907", "--json")
	if code != 0 || !strings.Contains(out, `"sealed": false`) {
		t.Errorf("unsealed: exit %d\n%s", code, out)
	}

	log, err := os.ReadFile(filepath.Join(state, "roadie.log"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(log), "\n"); lines != 2 {
		t.Errorf("roadie.log has %d lines, want 2:\n%s", lines, log)
	}
	if !strings.Contains(string(log), `"--target"`) || !strings.Contains(string(log), `"mode":"unsealed"`) {
		t.Errorf("roadie.log misses the arguments or the mode:\n%s", log)
	}
}

func TestRunRefusesBadCommandLines(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"prepare"},
		{"verify", "--json"},
		{"verify", "--target"},
		{"verify", "--target", "x", "--bogus"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, "", now, &out, &errb); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
		if errb.Len() == 0 {
			t.Errorf("%q: no message on stderr", args)
		}
	}
	var out bytes.Buffer
	if code := run([]string{"--version"}, "", now, &out, &out); code != 0 || !strings.Contains(out.String(), "rhythm-roadie") {
		t.Errorf("--version: exit %d %q", code, out.String())
	}
}
