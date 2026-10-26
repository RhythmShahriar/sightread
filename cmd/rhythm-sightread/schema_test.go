// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/schematest"
	"github.com/RhythmShahriar/sightread/report"
)

// TestCommandsMatchSchema runs the commands that print a document of
// their own kind with the real JSON writer and checks each against the
// published schema, strictly, so the commands can't drift from it.
func TestCommandsMatchSchema(t *testing.T) {
	schema := schematest.Load(t, "../../docs/schema/rhythm-sightread-v1.json")
	realJSON := func(t *testing.T) { t.Cleanup(core.SwapWriter(report.JSONWriter{})) }
	check := func(t *testing.T, args ...string) {
		t.Helper()
		code, out, errOut := execute(t, args...)
		if code != cli.ExitOK {
			t.Fatalf("%s: exit %d %q", strings.Join(args, " "), code, errOut)
		}
		if !strings.Contains(out, `"schema": "`+core.Schema+`"`) {
			t.Fatalf("%s: not the JSON writer's document: %s", strings.Join(args, " "), out)
		}
		if errs := schematest.ValidateStrict(schema, []byte(out)); len(errs) > 0 {
			t.Errorf("%s:\n%s\n%s", strings.Join(args, " "), strings.Join(errs, "\n"), out)
		}
	}
	t.Run("signals", func(t *testing.T) {
		world(t)
		realJSON(t)
		check(t, "signals", "--json")
	})
	t.Run("doctor", func(t *testing.T) {
		world(t)
		doctorWorld(t)
		realJSON(t)
		check(t, "doctor", "--offline", "--json")
	})
	t.Run("allow list", func(t *testing.T) {
		w := world(t)
		installAllow(t, w)
		realJSON(t)
		w.Policy.Allow = append(w.Policy.Allow, core.AllowEntry{Package: "npm:sharp", Version: "0.33.5",
			SHA256: strings.Repeat("ab", 32), Hash: core.HashArchive, Reason: "known install script",
			By: "Ann Reviewer", Date: time.Now().Format(time.DateOnly), Signals: []string{"npm-install-script-new"}})
		check(t, "allow", "list", "--json")
	})
	t.Run("verify-report", func(t *testing.T) {
		w := world(t)
		realJSON(t)
		t.Cleanup(core.SwapSigner(keySigner{}))
		w.Policy.Config = &core.Config{TrustedKeys: []string{"trusted-key"}}
		path := filepath.Join(t.TempDir(), "r.json")
		if err := os.WriteFile(path, []byte(`{"kind":"review"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := (keySigner{}).Sign(path, ""); err != nil {
			t.Fatal(err)
		}
		check(t, "verify-report", path, "--json")
	})
}
