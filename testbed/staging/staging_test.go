// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package staging

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCasesCoverEveryRefusal(t *testing.T) {
	cases := Cases()
	if !cases[0].Applies || cases[0].WantExit != 0 {
		t.Fatalf("the first case must apply the update: %+v", cases[0])
	}
	applying := 0
	names := map[string]bool{}
	for _, c := range cases {
		if names[c.Name] {
			t.Errorf("duplicate case %s", c.Name)
		}
		names[c.Name] = true
		if c.Applies {
			applying++
		}
		if !c.Applies && c.WantExit == 0 {
			t.Errorf("%s: a refusal must not exit 0", c.Name)
		}
		args := c.Args("/tb/bin/wp")
		if !slices.Contains(args, "--soundcheck") || !slices.Contains(args, URL) {
			t.Errorf("%s: args %q miss --soundcheck %s", c.Name, args, URL)
		}
	}
	if applying != 1 {
		t.Errorf("%d applying cases, want 1", applying)
	}
	// PRD 15 and decisions.md: HOLD (E17), production (E14), Roadie failed
	// or missing (E15), remote --wp (E21).
	for _, want := range []string{"hold", "production", "roadie-failed", "roadie-stale", "roadie-unsealed", "roadie-missing", "remote-wp"} {
		if !names[want] {
			t.Errorf("no %s case", want)
		}
	}
	remote := cases[len(cases)-1]
	if got := remote.Args("/tb/bin/wp"); !strings.HasPrefix(got[5], "ssh ") {
		t.Errorf("remote-wp --wp = %q, want an ssh prefix", got[5])
	}
}

func TestJudge(t *testing.T) {
	apply := Cases()[0]
	ok := Result{Exit: 0, Output: "the staging site ran the update; Sightread did not", Before: "1.0.0", After: "1.1.0"}
	if bad := Judge(apply, ok); len(bad) != 0 {
		t.Errorf("a correct apply was judged wrong: %v", bad)
	}
	notApplied := ok
	notApplied.After = "1.0.0"
	if bad := Judge(apply, notApplied); len(bad) != 1 {
		t.Errorf("an apply that left the old version: %v", bad)
	}
	hostTouched := ok
	hostTouched.HostChanged = []string{"wp-content/plugins/e15-soundcheck/feature.php"}
	if bad := Judge(apply, hostTouched); len(bad) != 1 {
		t.Errorf("an apply that wrote the host project: %v", bad)
	}

	var refusal Case
	for _, c := range Cases() {
		if c.Name == "roadie-failed" {
			refusal = c
		}
	}
	good := Result{Exit: 3, Output: "rhythm-sightread: 127.0.0.1 failed rhythm roadie verify (2 real-looking emails)", Before: "1.0.0", After: "1.0.0"}
	if bad := Judge(refusal, good); len(bad) != 0 {
		t.Errorf("a correct refusal was judged wrong: %v", bad)
	}
	changed := good
	changed.After = "1.1.0"
	if bad := Judge(refusal, changed); len(bad) != 1 || !strings.Contains(bad[0], "refusal changed") {
		t.Errorf("a refusal that installed the update: %v", bad)
	}
	wrongExit := good
	wrongExit.Exit, wrongExit.Output = 0, ""
	if bad := Judge(refusal, wrongExit); len(bad) != 2 {
		t.Errorf("exit 0 with no message: %v", bad)
	}
}

func TestWriteZipIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"plugin.php": "<?php\n", "inc/a.php": "<?php // a\n"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var a, b bytes.Buffer
	if err := WriteZip(&a, dir, "demo"); err != nil {
		t.Fatal(err)
	}
	if err := WriteZip(&b, dir, "demo"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two zips of the same tree differ")
	}
	zr, err := zip.NewReader(bytes.NewReader(a.Bytes()), int64(a.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if want := []string{"demo/inc/a.php", "demo/plugin.php"}; !slices.Equal(names, want) {
		t.Errorf("entries %v, want %v", names, want)
	}
}
