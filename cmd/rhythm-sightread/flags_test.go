// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func reviewCommandNamed(t *testing.T, name string) *reviewCommand {
	t.Helper()
	for _, c := range reviewCommands {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no review command %s", name)
	return nil
}

// parsePlan parses a review command line into its plan, as Run would.
func parsePlan(t *testing.T, args ...string) (*plan, error) {
	t.Helper()
	t.Setenv(cli.InvokedAsEnv, "rhythm-sightread")
	p, _, err := reviewCommandNamed(t, args[0]).parse(args[1:], io.Discard, io.Discard)
	return p, err
}

// TestHelpGolden: every command's --help page matches its golden file
// (go test ./cmd/rhythm-sightread -update rewrites them), under both
// program names.
func TestHelpGolden(t *testing.T) {
	for _, prog := range []string{"rhythm-sightread", "rhythm sightread"} {
		for _, c := range commands() {
			t.Run(prog+"/"+c.Name, func(t *testing.T) {
				t.Setenv(cli.InvokedAsEnv, prog)
				var out strings.Builder
				if err := c.Run(t.Context(), []string{"--help"}, &out, io.Discard); !errors.Is(err, cli.ErrHelp) {
					t.Fatalf("--help returned %v", err)
				}
				if !strings.HasPrefix(out.String(), "Usage: "+prog+" ") && c.Name != "pick" {
					t.Errorf("usage line %q", strings.SplitN(out.String(), "\n", 2)[0])
				}
				dir := map[string]string{"rhythm-sightread": "direct", "rhythm sightread": "router"}[prog]
				coretest.Golden(t, "help/"+dir+"/"+c.Name+".txt", []byte(out.String()))
			})
		}
	}
}

// TestHelpPages: the review pages carry their groups, examples and, on
// plugin, all and changes only, the contacted hosts.
func TestHelpPages(t *testing.T) {
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	for _, c := range reviewCommands {
		var out strings.Builder
		fs, f := c.flags(io.Discard)
		c.usage(&out, fs, f)
		page := out.String()
		for _, g := range []string{"Versions:", "Sources and integrity:", "Signals:", "Gate:", "Output:", "Examples:"} {
			if !strings.Contains(page, "\n"+g+"\n") {
				t.Errorf("%s: no %s block", c.name, g)
			}
		}
		if got := strings.Contains(page, "Contacts: api.wordpress.org"); got != (c.name == "plugin" || c.name == "all" || c.name == "changes") {
			t.Errorf("%s: contacts line %v", c.name, got)
		}
		if got := strings.Contains(page, "\nSoundcheck:\n"); got != c.soundcheck {
			t.Errorf("%s: soundcheck block %v", c.name, got)
		}
		if got := strings.Contains(page, "--trust-pr-allow"); got != (c.name == "changes") {
			t.Errorf("%s: --trust-pr-allow %v", c.name, got)
		}
		if !strings.Contains(page, "  rhythm sightread "+c.name+" ") {
			t.Errorf("%s: examples don't use the router name", c.name)
		}
		for _, line := range strings.Split(page, "\n") {
			if len([]rune(line)) > helpWidth && !strings.Contains(line, "Usage:") {
				t.Errorf("%s: line over %d columns: %q", c.name, helpWidth, line)
			}
		}
	}
}

// TestBadFlagValues are the E13 texts, exact.
func TestBadFlagValues(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"plugin", "a", "--fail-on", "severe"}, `rhythm-sightread: --fail-on "severe": want none, info, low, medium, high or critical`},
		{[]string{"plugin", "a", "--min-confidence", "sure"}, `rhythm-sightread: --min-confidence "sure": want confirmed or likely`},
		{[]string{"plugin", "a", "--severity", "none"}, `rhythm-sightread: --severity "none": want info, low, medium, high or critical`},
		{[]string{"plugin", "a", "--timeout", "soon"}, `rhythm-sightread: --timeout "soon": want a duration such as 30s, 10m, 72h or 3d`},
		{[]string{"plugin", "a", "--deadline", "-5m"}, `rhythm-sightread: --deadline "-5m": want a duration such as 30s, 10m, 72h or 3d`},
		{[]string{"plugin", "a", "--min-age", "x"}, `rhythm-sightread: --min-age "x": want a duration such as 30s, 10m, 72h or 3d`},
		{[]string{"plugin", "a", "--max-size", "lots"}, `rhythm-sightread: --max-size "lots": want a size such as 256MB, 1GB or 512KiB`},
		{[]string{"plugin", "a", "--jobs", "0"}, `rhythm-sightread: --jobs 0: want 1 to 64`},
		{[]string{"plugin", "a", "--retries", "11"}, `rhythm-sightread: --retries 11: want 0 to 10`},
		{[]string{"plugin", "a", "--max-findings", "-1"}, `rhythm-sightread: --max-findings -1: want 0 or more`},
		{[]string{"plugin", "a", "-o", "review.txt"}, `rhythm-sightread: -o "review.txt": want a file ending in .json, .jsonl, .md, .html or .sarif`},
		{[]string{"plugin", "a", "--json", "--md"}, `rhythm-sightread: --json and --md both print to stdout: pick one, or write the other with -o <file>`},
		{[]string{"plugin", "a", "--open"}, `rhythm-sightread: --open opens the HTML report, so write one with -o <file>.html`},
		{[]string{"plugin", "a", "--sign", "-o", "r.md"}, `rhythm-sightread: --sign signs the JSON report, so write one with -o <file>.json`},
		{[]string{"plugin", "a", "--config", "c.yaml", "--no-config"}, `rhythm-sightread: --config and --no-config can't be used together`},
		{[]string{"plugin", "a", "--soundcheck-fail-on", "all"}, `rhythm-sightread: --soundcheck-fail-on "all": want broke, new or changed`},
		{[]string{"plugin", "a", "--proxy", "proxy.example"}, `rhythm-sightread: --proxy "proxy.example": want a URL such as http://proxy.example:3128`},
		{[]string{"plugin", "a", "--wp", "wp 'x"}, `rhythm-sightread: --wp "wp 'x": a quote is not closed`},
		{[]string{"all", "--only", "wordpress"}, `rhythm-sightread: --only or --skip "wordpress": want an ecosystem (wp-plugin, wp-theme, composer, npm) or <eco>:<name>, globs allowed`},
		{[]string{"plugin", "a", "--exclude-id", "eval-dynamik"}, "rhythm-sightread: no signal \"eval-dynamik\" (did you mean eval-dynamic?)\n  list them: rhythm-sightread signals"},
		{[]string{"changes", "--before", "a.json"}, `rhythm-sightread: --before and --after go together: the old and the new lockfile`},
		{[]string{"all", "--to-file", "x.zip"}, `rhythm-sightread: --to-file and --from-file review one package: use rhythm-sightread plugin, theme, composer or npm with a name`},
		{[]string{"plugin", "a", "--", "--limit", "100"}, `rhythm-sightread: the arguments after -- go to rhythm-soundcheck, so they need --soundcheck <staging-url>`},
		{[]string{"all", "--rereview", "--to", "latest"}, `rhythm-sightread: --rereview reviews the installed versions against the release before them, so it takes no --to or --from`},
	}
	for _, c := range cases {
		code, _, errOut := execute(t, c.args...)
		if code != cli.ExitUsage || errOut != c.want+"\n" {
			t.Errorf("%q: exit %d\n got: %q\nwant: %q", c.args, code, errOut, c.want+"\n")
		}
	}
}

// TestFlagMapping is the table of PRD 7: each flag lands in the field of
// run.Request, the Getter, the gate, the writers or the stage that uses
// it.
func TestFlagMapping(t *testing.T) {
	for _, k := range []string{"GITHUB_TOKEN", "RHYTHM_GITHUB_TOKEN", "HTTPS_PROXY", "https_proxy", "CI", "NO_COLOR", cli.OfflineEnv, "COMPOSER_AUTH"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	cases := []struct {
		name  string
		args  []string
		env   map[string]string
		check func(p *plan) any
		want  any
	}{
		{"to", []string{"plugin", "a", "--to", "1.2.3"}, nil, func(p *plan) any { return p.req.To }, "1.2.3"},
		{"from", []string{"plugin", "a", "--from", "1.0"}, nil, func(p *plan) any { return p.req.From }, "1.0"},
		{"to-file", []string{"plugin", "a", "--to-file", "n.zip"}, nil, func(p *plan) any { return p.req.ToFile }, "n.zip"},
		{"from-file", []string{"plugin", "a", "--from-file", "o.zip"}, nil, func(p *plan) any { return p.req.FromFile }, "o.zip"},
		{"allow-downgrade", []string{"plugin", "a", "--allow-downgrade"}, nil, func(p *plan) any { return p.req.AllowDowngrade }, true},
		{"pre", []string{"plugin", "a", "--pre"}, nil, func(p *plan) any { return p.req.Pre }, true},
		{"transitive", []string{"npm", "--transitive"}, nil, func(p *plan) any { return p.req.Transitive && p.req.Inventory.Transitive }, true},
		{"only", []string{"all", "--only", "wp-plugin:*,npm:@acme/*", "--only", "composer"}, nil, func(p *plan) any { return p.req.Only }, []string{"wp-plugin:*", "npm:@acme/*", "composer"}},
		{"skip", []string{"all", "--skip", "wp-theme"}, nil, func(p *plan) any { return p.req.Skip }, []string{"wp-theme"}},
		{"path", []string{"npm", "--path", "web"}, nil, func(p *plan) any { return p.req.Inventory.Root }, "web"},
		{"path default", []string{"npm"}, nil, func(p *plan) any { return p.req.Inventory.Root }, "."},
		{"all <path>", []string{"all", "/var/www/shop"}, nil, func(p *plan) any { return p.req.Inventory.Root + " " + boolText(p.req.Set["path"]) }, "/var/www/shop true"},
		{"wp", []string{"plugin", "a", "--wp", "ssh deploy@h -- wp --path='/srv/my www'"}, nil, func(p *plan) any { return p.req.Inventory.WP }, []string{"ssh", "deploy@h", "--", "wp", "--path=/srv/my www"}},
		{"from-tuner", []string{"plugin", "a", "--from-tuner", "t.json"}, nil, func(p *plan) any { return p.req.Inventory.TunerReport }, "t.json"},
		{"offline", []string{"plugin", "a", "--offline"}, nil, func(p *plan) any { return p.req.Getter.Offline }, true},
		{"RHYTHM_OFFLINE", []string{"plugin", "a"}, map[string]string{cli.OfflineEnv: "1"}, func(p *plan) any { return p.req.Getter.Offline }, true},
		{"timeout", []string{"plugin", "a", "--timeout", "5s"}, nil, func(p *plan) any { return p.req.Getter.Timeout }, 5 * time.Second},
		{"timeout default", []string{"plugin", "a"}, nil, func(p *plan) any { return p.req.Getter.Timeout }, 30 * time.Second},
		{"retries", []string{"plugin", "a", "--retries", "0"}, nil, func(p *plan) any { return p.req.Getter.Retries }, 0},
		{"retries default", []string{"plugin", "a"}, nil, func(p *plan) any { return p.req.Getter.Retries }, 2},
		{"jobs", []string{"all", "--jobs", "8"}, nil, func(p *plan) any { return []int{p.req.Jobs, p.req.Getter.PerHost} }, []int{8, 4}},
		{"jobs low", []string{"all", "--jobs", "2"}, nil, func(p *plan) any { return []int{p.req.Jobs, p.req.Getter.PerHost} }, []int{2, 2}},
		{"proxy", []string{"plugin", "a", "--proxy", "http://p:3128"}, map[string]string{"HTTPS_PROXY": "http://env:1"}, func(p *plan) any { return p.req.Getter.Proxy }, "http://p:3128"},
		{"HTTPS_PROXY", []string{"plugin", "a"}, map[string]string{"HTTPS_PROXY": "http://env:1"}, func(p *plan) any { return p.req.Getter.Proxy }, "http://env:1"},
		{"user-agent", []string{"plugin", "a", "-A", "probe/1"}, nil, func(p *plan) any { return p.req.Getter.UserAgent }, "probe/1"},
		{"user-agent default", []string{"plugin", "a"}, nil, func(p *plan) any { return p.req.Getter.UserAgent }, "rhythm-sightread/dev (+https://github.com/RhythmShahriar/sightread)"},
		{"GITHUB_TOKEN", []string{"plugin", "a"}, map[string]string{"GITHUB_TOKEN": "a", "RHYTHM_GITHUB_TOKEN": "b"}, func(p *plan) any { return p.req.Getter.GitHubToken }, "a"},
		{"RHYTHM_GITHUB_TOKEN", []string{"plugin", "a"}, map[string]string{"RHYTHM_GITHUB_TOKEN": "b"}, func(p *plan) any { return p.req.Getter.GitHubToken }, "b"},
		{"SIGHTREAD_* mirrors", []string{"plugin", "a"}, map[string]string{"SIGHTREAD_WPORG_API": "http://127.0.0.1:31100", "SIGHTREAD_NPM_REGISTRY": "http://127.0.0.1:31101", "SIGHTREAD_OSV_API": "http://127.0.0.1:31102"},
			func(p *plan) any { return p.req.Getter.Bases },
			map[string]string{core.BaseWPOrgAPI: "http://127.0.0.1:31100", core.BaseNPM: "http://127.0.0.1:31101", core.BaseOSV: "http://127.0.0.1:31102"}},
		{"SIGHTREAD_NPM_TOKEN_<SCOPE>", []string{"npm"}, map[string]string{"SIGHTREAD_NPM_TOKEN_MY_ORG": "t1"}, func(p *plan) any { return p.req.Getter.ScopeTokens["@my-org"] }, "t1"},
		{"COMPOSER_AUTH", []string{"composer"}, map[string]string{"COMPOSER_AUTH": `{"bearer":{}}`}, func(p *plan) any { return p.req.Getter.ComposerAuth }, `{"bearer":{}}`},
		{"allow-unverified", []string{"plugin", "a", "--allow-unverified"}, nil, func(p *plan) any { return p.gate.AllowUnverified && p.req.AllowUnverified }, true},
		{"allow-partial", []string{"plugin", "a", "--allow-partial"}, nil, func(p *plan) any { return p.gate.AllowPartial }, true},
		{"fail-on", []string{"plugin", "a", "--fail-on", "HIGH"}, nil, func(p *plan) any { return p.req.FailOn }, "high"},
		{"svn-check", []string{"theme", "a", "--svn-check"}, nil, func(p *plan) any { return p.req.Options.SVNCheck }, true},
		{"check-confusion", []string{"npm", "--check-confusion"}, nil, func(p *plan) any { return p.req.Options.CheckConfusion }, true},
		{"no-osv", []string{"npm", "--no-osv"}, nil, func(p *plan) any { return p.req.NoOSV }, true},
		{"max-size", []string{"npm", "--max-size", "64MiB"}, nil, func(p *plan) any { return p.req.MaxSize }, int64(64 << 20)},
		{"max-size default", []string{"npm"}, nil, func(p *plan) any { return p.req.MaxSize }, int64(256 << 20)},
		{"max-size GB", []string{"npm", "--max-size", "2GB"}, nil, func(p *plan) any { return p.req.MaxSize }, int64(2 << 30)},
		{"deadline", []string{"npm", "--deadline", "1h"}, nil, func(p *plan) any { return p.req.Deadline }, time.Hour},
		{"signals", []string{"npm", "--signals", "a", "--signals", "b,c"}, nil, func(p *plan) any { return p.req.SignalDirs }, []string{"a", "b,c"}},
		{"no-signal-updates", []string{"npm", "--no-signal-updates"}, nil, func(p *plan) any { return p.req.NoSignalUpdates }, true},
		{"id", []string{"npm", "--id", "eval-*,typosquat"}, nil, func(p *plan) any { return p.req.IDs }, []string{"eval-*", "typosquat"}},
		{"exclude-id", []string{"npm", "--exclude-id", "fresh-release"}, nil, func(p *plan) any { return p.req.ExcludeIDs }, []string{"fresh-release"}},
		{"severity", []string{"npm", "--severity", "medium"}, nil, func(p *plan) any { return p.req.Severity }, cli.SeverityMedium},
		{"min-confidence", []string{"npm", "--min-confidence", "confirmed"}, nil, func(p *plan) any { return p.req.MinConfidence }, "confirmed"},
		{"min-confidence default leaves config", []string{"npm"}, nil, func(p *plan) any { return p.req.MinConfidence }, ""},
		{"min-age", []string{"npm", "--min-age", "3d"}, nil, func(p *plan) any { return p.req.MinAge }, "3d"},
		{"baseline", []string{"npm", "--baseline", "old.json"}, nil, func(p *plan) any { return p.req.Baseline }, "old.json"},
		{"no-allow", []string{"npm", "--no-allow"}, nil, func(p *plan) any { return p.req.NoAllow }, true},
		{"trust-pr-allow", []string{"changes", "--trust-pr-allow"}, nil, func(p *plan) any { return p.req.TrustPRAllow }, true},
		{"config", []string{"npm", "--config", "c.yaml"}, nil, func(p *plan) any { return p.req.ConfigFile }, "c.yaml"},
		{"no-config", []string{"npm", "--no-config"}, nil, func(p *plan) any { return p.req.NoConfig }, true},
		{"json", []string{"npm", "--json"}, nil, func(p *plan) any { return p.stdout }, core.FormatJSON},
		{"jsonl", []string{"npm", "--jsonl"}, nil, func(p *plan) any { return p.stdout }, core.FormatJSONL},
		{"md", []string{"npm", "--md"}, nil, func(p *plan) any { return p.stdout }, core.FormatMarkdown},
		{"html", []string{"npm", "--html"}, nil, func(p *plan) any { return []any{p.stdout, p.req.AllHunks} }, []any{core.FormatHTML, true}},
		{"sarif", []string{"npm", "--sarif"}, nil, func(p *plan) any { return p.stdout }, core.FormatSARIF},
		{"terminal default", []string{"npm"}, nil, func(p *plan) any { return p.stdout }, core.FormatTerminal},
		{"-o by extension, repeatable", []string{"npm", "-o", "r.json", "--output", "r.HTML", "-o", "r.md", "-o", "r.sarif", "-o", "r.jsonl"}, nil,
			func(p *plan) any { return p.files },
			[]output{{"r.json", core.FormatJSON}, {"r.HTML", core.FormatHTML}, {"r.md", core.FormatMarkdown}, {"r.sarif", core.FormatSARIF}, {"r.jsonl", core.FormatJSONL}}},
		{"html file keeps every hunk", []string{"npm", "-o", "r.html"}, nil, func(p *plan) any { return p.req.AllHunks }, true},
		{"diff", []string{"npm", "--diff"}, nil, func(p *plan) any { return p.write.ShowDiff && p.req.AllHunks }, true},
		{"max-findings", []string{"npm", "--max-findings", "3"}, nil, func(p *plan) any { return p.write.MaxFindings }, 3},
		{"max-findings default", []string{"npm"}, nil, func(p *plan) any { return p.write.MaxFindings }, 10},
		{"plain off a terminal", []string{"npm"}, nil, func(p *plan) any { return []bool{p.write.Plain, p.write.Color} }, []bool{true, false}},
		{"quiet", []string{"npm", "-q"}, nil, func(p *plan) any { return p.write.Quiet }, true},
		{"redact-paths in CI", []string{"npm"}, map[string]string{"CI": "true"}, func(p *plan) any { return p.write.RedactPaths }, true},
		{"redact-paths off in CI", []string{"npm", "--redact-paths=false"}, map[string]string{"CI": "true"}, func(p *plan) any { return p.write.RedactPaths }, false},
		{"redact-paths", []string{"npm", "--redact-paths"}, nil, func(p *plan) any { return p.write.RedactPaths }, true},
		{"program", []string{"npm"}, nil, func(p *plan) any { return p.write.Program }, "rhythm-sightread"},
		{"verbose", []string{"npm", "-v"}, nil, func(p *plan) any { return p.req.Log != nil && p.req.Getter.Debug != nil && p.verbose }, true},
		{"open and sign", []string{"npm", "--open", "--sign", "-o", "r.html", "-o", "r.json"}, nil, func(p *plan) any { return []bool{p.open, p.sign} }, []bool{true, true}},
		{"soundcheck", []string{"plugin", "a", "--soundcheck", "https://staging.shop.test", "--apply", "wp plugin install x", "--rollback",
			"--soundcheck-fail-on", "new", "--soundcheck-anyway", "--skip-roadie-verify", "--", "--limit", "100"}, nil,
			func(p *plan) any { return []any{p.soundcheck, p.write.Soundcheck} },
			[]any{soundcheckPlan{Staging: "https://staging.shop.test", Apply: "wp plugin install x", FailOn: "new", Rollback: true, Anyway: true,
				Skip: true, Args: []string{"--limit", "100"}}, true}},
		{"rereview", []string{"all", "--rereview"}, nil, func(p *plan) any { return p.req.Rereview }, true},
		{"no rereview", []string{"all"}, nil, func(p *plan) any { return p.req.Rereview }, false},
		{"soundcheck-fail-on default", []string{"plugin", "a"}, nil, func(p *plan) any { return p.soundcheck.FailOn }, "broke"},
		{"changes", []string{"changes", "--base", "origin/main", "--lockfile", "web/package-lock.json", "--path", "repo"}, nil,
			func(p *plan) any { return *p.req.Changes },
			core.ChangesRequest{Repo: "repo", Base: "origin/main", Lockfiles: []string{"web/package-lock.json"}}},
		{"changes GITHUB_BASE_REF", []string{"changes"}, map[string]string{"GITHUB_BASE_REF": "main"}, func(p *plan) any { return p.req.Changes.Base }, "origin/main"},
		{"changes before/after", []string{"changes", "--before", "a.json", "--after", "b.json"}, map[string]string{"GITHUB_BASE_REF": "main"},
			func(p *plan) any { return []string{p.req.Changes.Base, p.req.Changes.Before, p.req.Changes.After} }, []string{"", "a.json", "b.json"}},
		{"names", []string{"plugin", "akismet", "--to", "5.3.5", "woocommerce"}, nil, func(p *plan) any { return p.req.Names }, []string{"akismet", "woocommerce"}},
		{"command and ecosystem", []string{"theme", "astra"}, nil, func(p *plan) any { return []string{p.req.Command, string(p.req.Eco)} }, []string{"theme", "wp-theme"}},
		{"set flags", []string{"npm", "--transitive", "--pre=false"}, nil, func(p *plan) any { return []bool{p.req.Set["transitive"], p.req.Set["pre"], p.req.Set["path"]} }, []bool{true, true, false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			p, err := parsePlan(t, c.args...)
			if err != nil {
				t.Fatalf("%q: %v", c.args, err)
			}
			if got := c.check(p); !reflect.DeepEqual(got, c.want) {
				t.Errorf("%q: got %#v, want %#v", c.args, got, c.want)
			}
		})
	}
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestFlagsAfterArguments: flags may come before or after the names.
func TestFlagsAfterArguments(t *testing.T) {
	a, err := parsePlan(t, "plugin", "akismet", "--to", "5.3.5", "--json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := parsePlan(t, "plugin", "--json", "--to", "5.3.5", "akismet")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.req.Names, b.req.Names) || a.req.To != b.req.To || a.stdout != b.stdout || a.stdout != core.FormatJSON {
		t.Errorf("%+v vs %+v", a.req, b.req)
	}
}

// TestPluginNeedsASlug: plugin and theme need a name; composer and npm
// don't.
func TestPluginNeedsASlug(t *testing.T) {
	code, _, errOut := execute(t, "plugin")
	if code != cli.ExitUsage || !strings.Contains(errOut, "plugin needs a slug: rhythm-sightread plugin <slug>") {
		t.Errorf("exit %d %q", code, errOut)
	}
	if _, err := parsePlan(t, "npm"); err != nil {
		t.Errorf("npm without names: %v", err)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"256MB": 256 << 20, "256mib": 256 << 20, "1GiB": 1 << 30, "512KB": 512 << 10,
		"100": 100, "10 MB": 10 << 20, "3G": 3 << 30, "7B": 7} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "-1MB", "MB", "1.5GB", "1TB", "9999999999999999GB"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) passed", in)
		}
	}
}

func FuzzParseSize(f *testing.F) {
	for _, s := range []string{"256MB", "1GiB", "100", " 7 kb ", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := parseSize(s)
		if err == nil && n <= 0 {
			t.Fatalf("%q: %d without an error", s, n)
		}
	})
}
