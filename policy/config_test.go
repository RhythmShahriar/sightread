// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// testNow is the clock of every policy test.
var testNow = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

func testStore(stderr *bytes.Buffer) *Store {
	s := &Store{Now: func() time.Time { return testNow }}
	if stderr != nil {
		s.Stderr = stderr
	}
	return s
}

// inProject makes a temp project folder, changes into it and names the
// program as the router does, so messages read as users see them.
func inProject(t *testing.T) string {
	t.Helper()
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, Dir, ConfigName)
	writeFile(t, p, content)
	return p
}

func TestConfigRules(t *testing.T) {
	const pre = "rhythm sightread: .sightread/config.yaml: "
	key := coretest.FakeKey(coretest.KeyStripe)
	cases := []struct {
		name, yaml, want string
	}{
		{"unknown key", "fial_on: high\n", "unknown key fial_on (did you mean fail_on?)"},
		{"unknown key far from any", "colour: red\n", "unknown key colour (line 1)"},
		{"unknown nested key", "sources:\n  npm:\n    regstry: https://r.example\n", "unknown key regstry in sources.npm (did you mean registry?)"},
		{"unknown key in an ignore entry", "ignore:\n  - id: license-change\n    reasn: ok\n", "unknown key reasn in ignore 1 (did you mean reason?)"},
		{"list where a value goes", "fail_on: [high]\n", "line 1: fail_on wants a single value"},
		{"value where a list goes", "ecosystems: npm\n", "line 1: ecosystems wants a list"},
		{"not a mapping", "- a\n", "line 1: the file must hold keys and values"},
		{"two documents", "fail_on: high\n---\nfail_on: low\n", "holds more than one YAML document; keep the settings in one"},
		{"fail_on", "fail_on: severe\n", `fail_on "severe": want none, info, low, medium, high or critical`},
		{"min_confidence", "min_confidence: maybe\n", `min_confidence "maybe": want confirmed or likely`},
		{"min_age", "min_age: soon\n", `min_age: invalid age "soon"; use a duration such as 3d, 1w or 36h`},
		{"ecosystem", "ecosystems: [pip]\n", `ecosystems: unknown ecosystem "pip": want wp-plugin, wp-theme, composer or npm`},
		{"plain http mirror", "sources:\n  packagist: http://mirror.example\n", `sources.packagist: "http://mirror.example": want https://, or http:// on a loopback host (127.0.0.1, ::1, localhost)`},
		{"ftp mirror", "sources:\n  osv: ftp://osv.example\n", `sources.osv: "ftp://osv.example": want https://, or http:// on a loopback host (127.0.0.1, ::1, localhost)`},
		{"not a URL", "sources:\n  npm:\n    registry: registry.example\n", `sources.npm.registry: "registry.example" is not a URL such as https://registry.example`},
		{"URL with a password", "sources:\n  composer:\n    repositories: [\"https://u:" + key + "@repo.example\"]\n", "sources.composer.repositories 1: the URL holds a user name or password; set credentials in the environment instead"},
		{"bad scope", "sources:\n  npm:\n    scopes:\n      acme: https://npm.acme.example\n", `sources.npm.scopes: "acme" is not an npm scope; write it as "@acme"`},
		{"http scope", "sources:\n  npm:\n    scopes:\n      \"@acme\": http://npm.acme.example\n", `sources.npm.scopes.@acme: "http://npm.acme.example": want https://, or http:// on a loopback host (127.0.0.1, ::1, localhost)`},
		{"ignore without id", "ignore:\n  - reason: ok\n", "ignore 1: needs an id, the signal it hides, such as outbound-new-domain"},
		{"ignore without reason", "ignore:\n  - id: outbound-new-domain\n", "ignore 1 (outbound-new-domain): needs a reason, so the next person knows why it is accepted"},
		{"ignore unknown id", "ignore:\n  - id: outbound-new-domian\n    reason: ok\n", `ignore 1 (outbound-new-domian): no signal "outbound-new-domian" (did you mean outbound-new-domain?)`},
		{"ignore unignorable", "ignore:\n  - id: integrity-mismatch\n    reason: ok\n", "ignore 1 (integrity-mismatch): integrity-mismatch can't be ignored; it says the bytes are not the ones published or reviewed"},
		{"ignore bad until", "ignore:\n  - id: license-change\n    reason: ok\n    until: next year\n", `ignore 1 (license-change): until "next year": want a date such as 2027-03-31`},
		{"ignore bad glob", "ignore:\n  - id: license-change\n    reason: ok\n    path: \"src/[\"\n", `ignore 1 (license-change): bad pattern "src/["`},
		{"severity value", "signals:\n  severity:\n    fresh-release: meh\n", `signals.severity.fresh-release "meh": want info, low, medium, high or critical`},
		{"severity none", "signals:\n  severity:\n    fresh-release: none\n", `signals.severity.fresh-release "none": want info, low, medium, high or critical`},
		{"severity unknown id", "signals:\n  severity:\n    fresh-relase: low\n", `signals.severity: no signal "fresh-relase" (did you mean fresh-release?)`},
		{"severity lowers unignorable", "signals:\n  severity:\n    known-malicious: high\n", "signals.severity.known-malicious: known-malicious can't be lowered below critical; it says the bytes are not the ones published or reviewed"},
		{"domains_ok glob", "signals:\n  domains_ok: [\"[x\"]\n", `signals.domains_ok: bad pattern "[x"`},
		{"production URL", "soundcheck:\n  production: [shop.example.com]\n", `soundcheck.production 1: "shop.example.com" is not a site URL such as https://shop.example.com`},
		{"local_files empty", "local_files:\n  gravityforms: \"\"\n", "local_files.gravityforms: needs a path such as ~/vendor-zips/gravityforms-{version}.zip"},
		{"allow_from empty", "allow_from: [\"\"]\n", "allow_from: a path is empty"},
		{"trusted key no prefix", "trusted_keys: [abc]\n", `trusted_keys 1: "abc" is not a key such as ed25519:<base64>; rhythm sightread verify-report prints a report's key`},
		{"trusted key short", "trusted_keys: [\"ed25519:AAAA\"]\n", `trusted_keys 1: "ed25519:AAAA" is not a key such as ed25519:<base64>; rhythm sightread verify-report prints a report's key`},
		{"syntax", "fail_on: \"high\n", "line 2: found unexpected end of stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := inProject(t)
			writeConfig(t, dir, tc.yaml)
			_, _, err := testStore(nil).LoadConfig(dir, "", false)
			if err == nil {
				t.Fatalf("no error, want %q", tc.want)
			}
			if got := err.Error(); got != pre+tc.want {
				t.Errorf("\n got %q\nwant %q", got, pre+tc.want)
			}
			if core.CodeOf(err) != core.EBadConfig {
				t.Errorf("code %q, want E12", core.CodeOf(err))
			}
			var ce *core.Error
			if !errors.As(err, &ce) || ce.ExitCode() != cli.ExitUsage {
				t.Errorf("exit code is not 2: %v", err)
			}
			if strings.Contains(err.Error(), key) {
				t.Errorf("message shows a secret: %q", err)
			}
		})
	}
}

func TestConfigValid(t *testing.T) {
	dir := inProject(t)
	writeConfig(t, dir, `fail_on: HIGH
min_confidence: confirmed
min_age: 3d
ecosystems: [plugin, npm]
path: .
osv: false
sources:
  wporg_api: http://127.0.0.1:31080
  npm:
    registry: https://registry.npmjs.org
    scopes:
      "@acme": https://npm.acme.example
  composer:
    repositories: [http://localhost:31081, "http://[::1]:31082"]
local_files:
  gravityforms: ~/vendor-zips/gravityforms-{version}.zip
allow_file: .sightread/allowed.yaml
allow_from: [../agency-reviews/allowed.yaml]
trusted_keys: [" ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= "]
signals:
  severity:
    fresh-release: LOW
    integrity-mismatch: critical
  domains_ok: [api.wordpress.org, "*.stripe.com"]
ignore:
  - id: outbound-new-domain
    package: wp-plugin:woocommerce
    path: src/Internal/Admin/RemoteInboxNotifications/*
    reason: " WooCommerce inbox notes, reviewed "
    until: 2027-03-31
soundcheck:
  staging: https://staging.shop.test
  production: [https://shop.example.com]
  fail_on: broke
  args: [--limit, "100"]
`)
	cfg, p, err := testStore(nil).LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, Dir, ConfigName); p != want {
		t.Errorf("path %q, want %q", p, want)
	}
	if cfg.FailOn != "high" || cfg.MinConfidence != "confirmed" || cfg.MinAge != "3d" {
		t.Errorf("values not normalised: %+v", cfg)
	}
	if len(cfg.Ecosystems) != 2 || cfg.Ecosystems[0] != core.WPPlugin {
		t.Errorf("ecosystems %v", cfg.Ecosystems)
	}
	if cfg.OSV == nil || *cfg.OSV {
		t.Errorf("osv not false: %v", cfg.OSV)
	}
	if cfg.Signals.Severity["fresh-release"] != "low" {
		t.Errorf("severity %v", cfg.Signals.Severity)
	}
	if len(cfg.Ignore) != 1 || cfg.Ignore[0].Reason != "WooCommerce inbox notes, reviewed" {
		t.Errorf("ignore %+v", cfg.Ignore)
	}
	if len(cfg.TrustedKeys) != 1 || cfg.TrustedKeys[0] != "ed25519:"+strings.Repeat("A", 43)+"=" {
		t.Errorf("trusted keys %q", cfg.TrustedKeys)
	}
	if got := cfg.Soundcheck.Args; len(got) != 2 || got[1] != "100" {
		t.Errorf("soundcheck args %v", got)
	}
}

func TestConfigEmptyFile(t *testing.T) {
	dir := inProject(t)
	writeConfig(t, dir, "# every key is optional\n")
	cfg, p, err := testStore(nil).LoadConfig(dir, "", false)
	if err != nil || p == "" || cfg == nil {
		t.Fatalf("cfg %v, path %q, err %v", cfg, p, err)
	}
}

func TestConfigExpiredIgnore(t *testing.T) {
	dir := inProject(t)
	writeConfig(t, dir, `ignore:
  - id: license-change
    reason: old
    until: 2026-10-25
  - id: license-change
    reason: today still applies
    until: 2026-10-26
`)
	var stderr bytes.Buffer
	cfg, _, err := testStore(&stderr).LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ignore) != 1 || cfg.Ignore[0].Reason != "today still applies" {
		t.Errorf("ignore %+v", cfg.Ignore)
	}
	want := "rhythm sightread: .sightread/config.yaml: ignore 1 (license-change) expired 2026-10-25 and no longer hides anything\n"
	if stderr.String() != want {
		t.Errorf("warning\n got %q\nwant %q", stderr.String(), want)
	}
}

func TestConfigSearch(t *testing.T) {
	root := inProject(t)
	deep := filepath.Join(root, "repo", "web", "app")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	s := testStore(nil)

	// Nothing anywhere: an empty config and no path.
	cfg, p, err := s.LoadConfig(deep, "", false)
	if err != nil || p != "" || cfg == nil {
		t.Fatalf("no config: cfg %v, path %q, err %v", cfg, p, err)
	}

	// The nearest parent wins over one further up.
	writeConfig(t, root, "fail_on: low\n")
	writeConfig(t, filepath.Join(root, "repo"), "fail_on: high\n")
	cfg, p, err = s.LoadConfig(deep, "", false)
	if err != nil || cfg.FailOn != "high" || p != filepath.Join(root, "repo", Dir, ConfigName) {
		t.Fatalf("nearest: fail_on %q, path %q, err %v", cfg.FailOn, p, err)
	}

	// The search stops at the top of a repository.
	if err := os.Remove(filepath.Join(root, "repo", Dir, ConfigName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo", ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	cfg, p, err = s.LoadConfig(deep, "", false)
	if err != nil || p != "" || cfg.FailOn != "" {
		t.Fatalf("stop at .git: fail_on %q, path %q, err %v", cfg.FailOn, p, err)
	}

	// The folder that holds .git is still searched.
	writeConfig(t, filepath.Join(root, "repo"), "fail_on: medium\n")
	cfg, _, err = s.LoadConfig(deep, "", false)
	if err != nil || cfg.FailOn != "medium" {
		t.Fatalf("repo top: fail_on %q, err %v", cfg.FailOn, err)
	}

	// --no-config ignores every file.
	cfg, p, err = s.LoadConfig(deep, "", true)
	if err != nil || p != "" || cfg.FailOn != "" {
		t.Fatalf("--no-config: fail_on %q, path %q, err %v", cfg.FailOn, p, err)
	}

	// --config reads exactly that file.
	other := filepath.Join(root, "ci.yaml")
	writeFile(t, other, "fail_on: critical\n")
	cfg, p, err = s.LoadConfig(deep, other, false)
	if err != nil || cfg.FailOn != "critical" || p != other {
		t.Fatalf("--config: fail_on %q, path %q, err %v", cfg.FailOn, p, err)
	}
	_, _, err = s.LoadConfig(deep, filepath.Join(root, "missing.yaml"), false)
	if err == nil || err.Error() != "rhythm sightread: missing.yaml: no such file" {
		t.Fatalf("missing --config: %v", err)
	}
}

func TestConfigFolderInsteadOfFile(t *testing.T) {
	dir := inProject(t)
	if err := os.MkdirAll(filepath.Join(dir, Dir, ConfigName), 0o750); err != nil {
		t.Fatal(err)
	}
	_, _, err := testStore(nil).LoadConfig(dir, "", false)
	if err == nil || err.Error() != "rhythm sightread: .sightread/config.yaml: is a folder, not a config file" {
		t.Fatalf("got %v", err)
	}
}

// TestConfigBillionLaughs checks the alias cap (SR-16): a config built
// to expand fails fast with an E12 naming the file instead of eating
// memory.
func TestConfigBillionLaughs(t *testing.T) {
	dir := inProject(t)
	var b strings.Builder
	b.WriteString("a: &a [x, x, x, x, x, x, x, x, x, x]\n")
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		b.WriteString(n + ": &" + n + " [")
		for i := range 10 {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString("*" + prev)
		}
		b.WriteString("]\n")
		prev = n
	}
	writeConfig(t, dir, b.String())
	start := time.Now()
	_, _, err := testStore(nil).LoadConfig(dir, "", false)
	if err == nil {
		t.Fatal("no error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	want := "rhythm sightread: .sightread/config.yaml: line 5: alias *d stands for over 10000 values; write the values out"
	if err.Error() != want {
		t.Errorf("\n got %q\nwant %q", err, want)
	}
	if core.CodeOf(err) != core.EBadConfig {
		t.Errorf("code %q", core.CodeOf(err))
	}
}

func TestConfigManyAliases(t *testing.T) {
	dir := inProject(t)
	var b strings.Builder
	b.WriteString("x: &a [" + strings.TrimSuffix(strings.Repeat("v, ", 5000), ", ") + "]\ny: [")
	for i := range 30 {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("*a")
	}
	b.WriteString("]\n")
	writeConfig(t, dir, b.String())
	_, _, err := testStore(nil).LoadConfig(dir, "", false)
	if err == nil || !strings.Contains(err.Error(), "aliases expand to over 100000 values") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigDepth(t *testing.T) {
	dir := inProject(t)
	writeConfig(t, dir, "ecosystems: "+strings.Repeat("[", 80)+strings.Repeat("]", 80)+"\n")
	_, _, err := testStore(nil).LoadConfig(dir, "", false)
	if err == nil || !strings.Contains(err.Error(), "nests deeper than 64 levels") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigTooBig(t *testing.T) {
	dir := inProject(t)
	writeConfig(t, dir, "# "+strings.Repeat("x", maxConfigBytes)+"\n")
	_, _, err := testStore(nil).LoadConfig(dir, "", false)
	want := "rhythm sightread: .sightread/config.yaml: is over 1 MiB, more than a file of this kind ever needs"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("got %v", err)
	}
}

// FuzzConfig checks that no input makes the loader panic and that every
// error names the file and a key or a line.
func FuzzConfig(f *testing.F) {
	for _, s := range []string{
		"fail_on: high\n",
		"fial_on: high\n",
		"ignore:\n  - id: license-change\n    reason: x\n    until: 2030-01-01\n",
		"sources:\n  npm:\n    scopes:\n      \"@a\": https://a.example\n",
		"a: &a [1]\nb: *a\n",
		"signals:\n  severity:\n    unanalysed: low\n",
		"<<: {fail_on: low}\n",
		"[",
	} {
		f.Add([]byte(s))
	}
	s := testStore(nil)
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := s.ParseConfig(data, "c.yaml")
		if err != nil {
			msg := err.Error()
			if !strings.Contains(msg, "c.yaml: ") {
				t.Fatalf("error does not name the file: %q", msg)
			}
			if core.CodeOf(err) != core.EBadConfig {
				t.Fatalf("not E12: %q", msg)
			}
			return
		}
		if cfg == nil {
			t.Fatal("nil config without an error")
		}
		for _, ig := range cfg.Ignore {
			if core.Unignorable(ig.ID) || ig.Reason == "" {
				t.Fatalf("ignore entry passed validation: %+v", ig)
			}
		}
	})
}
