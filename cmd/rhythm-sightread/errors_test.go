// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

// mainRun runs cli.Main in this process as the binary does, with prog
// as the program name. It returns the exit code, stdout and stderr.
// The fakes the test installed are what the commands find.
func mainRun(t *testing.T, prog string, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv(cli.InvokedAsEnv, prog)
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "1")
	config.FirstRun(firstRunKey) // the note isn't part of these messages
	dir := t.TempDir()
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	oldArgs, oldOut, oldErr := os.Args, os.Stdout, os.Stderr
	os.Args, os.Stdout, os.Stderr = append([]string{"rhythm-sightread"}, args...), outF, errF
	code := cli.Main(tool(args))
	os.Args, os.Stdout, os.Stderr = oldArgs, oldOut, oldErr
	_ = outF.Close()
	_ = errF.Close()
	out, _ := os.ReadFile(outF.Name())
	errOut, _ := os.ReadFile(errF.Name())
	return code, string(out), string(errOut)
}

// failingSource is a fake source whose Versions or Fetch fail for some
// packages.
type failingSource struct {
	*runtest.Source
	versions, fetch map[string]error
}

func (f failingSource) Versions(ctx context.Context, name string) ([]string, error) {
	if err := f.versions[name]; err != nil {
		return nil, err
	}
	return f.Source.Versions(ctx, name)
}

func (f failingSource) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	if err := f.fetch[m.Ref.Name]; err != nil {
		return nil, core.Integrity{}, err
	}
	return f.Source.Fetch(ctx, m)
}

func failVersions(t *testing.T, w *runtest.World, eco core.Ecosystem, name string, err error) {
	t.Helper()
	t.Cleanup(core.SwapSource(eco, func(*core.Env) core.Source {
		return failingSource{Source: w.Sources[eco], versions: map[string]error{name: err}}
	}))
}

func failFetch(t *testing.T, w *runtest.World, eco core.Ecosystem, name string, err error) {
	t.Helper()
	t.Cleanup(core.SwapSource(eco, func(*core.Env) core.Source {
		return failingSource{Source: w.Sources[eco], fetch: map[string]error{name: err}}
	}))
}

// badAllow is the fake policy with an allow file that doesn't load.
type badAllow struct {
	core.Policy
	err error
}

func (b badAllow) LoadAllow(*core.Config, string, string) (core.AllowSet, error) { return nil, b.err }

// errorCase is one row of PRD section 10.
type errorCase struct {
	code  core.ErrorCode
	setup func(t *testing.T, w *runtest.World) []string // returns the arguments
	exit  int
	// stderr is the exact output, with {prog} for the program name and
	// {dir} for the folder the setup made.
	stderr string
	skip   string
}

func stageErr(code core.ErrorCode, exit int, command, what string, hint ...string) *core.Error {
	return &core.Error{Code: code, Exit: exit, Command: command, What: what, Hint: hint}
}

var errorCases = []errorCase{
	{code: core.ENothingInstalled, exit: cli.ExitUsage, setup: func(t *testing.T, _ *runtest.World) []string {
		return []string{"plugin", "countdown-timer-ultimate", "--path", siteDir(t)}
	}, stderr: "{prog} plugin: no installed countdown-timer-ultimate under {dir}\n" +
		"  name the site with --path /var/www/site, read it with --wp \"wp --path=...\" or give the version: --from <version>\n"},
	{code: core.EUnknownPackage, exit: cli.ExitUsage, setup: func(t *testing.T, w *runtest.World) []string {
		failVersions(t, w, core.WPPlugin, "contact-form7", stageErr(core.EUnknownPackage, cli.ExitUsage, "",
			`wordpress.org has no plugin "contact-form7"`,
			"did you mean contact-form-7? A premium plugin has no official source: use --to-file <zip>"))
		return []string{"plugin", "contact-form7", "--from", "5.9"}
	}, stderr: "{prog} plugin: wordpress.org has no plugin \"contact-form7\"\n" +
		"  did you mean contact-form-7? A premium plugin has no official source: use --to-file <zip>\n"},
	{code: core.EVersionMissing, exit: cli.ExitUsage, setup: func(_ *testing.T, w *runtest.World) []string {
		w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
		return []string{"plugin", "akismet", "--from", "5.3.3", "--to", "9.9.9"}
	}, stderr: "{prog} plugin: akismet has no version 9.9.9 on wordpress.org\n" +
		"  newest: 5.3.5 · see them all: {prog} plugin akismet --to list\n"},
	{code: core.ENoLockfile, exit: cli.ExitUsage, setup: func(_ *testing.T, w *runtest.World) []string {
		w.Inventory.Err = stageErr(core.ENoLockfile, cli.ExitUsage, "",
			"no lockfile in ./web (looked for npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock)",
			"run your package manager once to write one; Sightread compares versions a lockfile pins")
		return []string{"npm", "--path", "web"}
	}, stderr: "{prog} npm: no lockfile in ./web (looked for npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock)\n" +
		"  run your package manager once to write one; Sightread compares versions a lockfile pins\n"},
	{code: core.EUnverifiable, exit: cli.ExitUnavailable, setup: func(_ *testing.T, w *runtest.World) []string {
		w.Publish(core.WPPlugin, "countdown-timer-ultimate", "2.6.7", "2.6.8")
		w.Install(core.WPPlugin, "countdown-timer-ultimate", "2.6.7")
		w.Sources[core.WPPlugin].Integrity[core.Ref{Eco: core.WPPlugin, Name: "countdown-timer-ultimate", Version: "2.6.8"}] =
			core.Integrity{By: core.ByNone, Detail: "wordpress.org checksums answered 503"}
		return []string{"plugin", "countdown-timer-ultimate", "--fail-on", "high"}
	}, stderr: "{prog} plugin: couldn't verify countdown-timer-ultimate 2.6.8: wordpress.org checksums answered 503\n" +
		"  not diffed; run again later, or --allow-unverified to review it anyway (the report marks it unverified)\n" +
		"{prog}: the run is partial, so --fail-on high can't pass it\n"},
	{code: core.EIntegrityMismatch, exit: cli.ExitFindings, setup: func(_ *testing.T, w *runtest.World) []string {
		w.Publish(core.WPPlugin, "countdown-timer-ultimate", "2.6.7", "2.6.8")
		w.Install(core.WPPlugin, "countdown-timer-ultimate", "2.6.7")
		w.Detector.Set("countdown-timer-ultimate", "integrity-mismatch")
		return []string{"plugin", "countdown-timer-ultimate", "--fail-on", "high"}
	}, stderr: ""},
	{code: core.ENetwork, exit: cli.ExitUnavailable, setup: func(t *testing.T, w *runtest.World) []string {
		w.Publish(core.NPM, "left-pad", "1.3.0", "1.4.0")
		failFetch(t, w, core.NPM, "left-pad", stageErr(core.ENetwork, cli.ExitUnavailable, "",
			"can't reach registry.npmjs.org (no such host)", "check the connection or HTTPS_PROXY"))
		return []string{"npm", "left-pad", "--from", "1.3.0"}
	}, stderr: "{prog}: can't reach registry.npmjs.org (no such host)\n  check the connection or HTTPS_PROXY\n"},
	{code: core.EUnsupportedLock, exit: cli.ExitUsage, setup: func(_ *testing.T, w *runtest.World) []string {
		w.Inventory.Err = stageErr(core.EUnsupportedLock, cli.ExitUsage, "npm",
			"bun.lockb is Bun's binary lockfile, which Sightread can't read", "run bun install --save-text-lockfile once to write bun.lock")
		return []string{"npm"}
	}, stderr: "{prog} npm: bun.lockb is Bun's binary lockfile, which Sightread can't read\n" +
		"  run bun install --save-text-lockfile once to write bun.lock\n"},
	{code: core.ERateLimited, exit: cli.ExitUnavailable, setup: func(t *testing.T, w *runtest.World) []string {
		w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
		w.Publish(core.WPPlugin, "jetpack", "13.0", "13.1")
		w.Install(core.WPPlugin, "akismet", "5.3.3")
		w.Install(core.WPPlugin, "jetpack", "13.0")
		failFetch(t, w, core.WPPlugin, "jetpack", stageErr(core.ERateLimited, cli.ExitUnavailable, "",
			"api.wordpress.org asked us to slow down (429) and still did after 2 retries", "run again in a few minutes or lower --jobs"))
		return []string{"all", "--fail-on", "high"}
	}, stderr: "{prog}: api.wordpress.org asked us to slow down (429) and still did after 2 retries\n" +
		"  reviewed 1 of 2 updates; run again in a few minutes or lower --jobs\n" +
		"{prog}: the run is partial, so --fail-on high can't pass it\n"},
	{code: core.EAuth, exit: cli.ExitUnavailable, setup: func(t *testing.T, w *runtest.World) []string {
		w.Publish(core.Composer, "acme/billing", "2.0.0", "2.1.0")
		failFetch(t, w, core.Composer, "acme/billing", stageErr(core.EAuth, cli.ExitUnavailable, "composer",
			"repo.acme.example answered 401 for acme/billing",
			"set COMPOSER_AUTH (as Composer reads it); credentials go only to repo.acme.example"))
		return []string{"composer", "acme/billing", "--from", "2.0.0"}
	}, stderr: "{prog} composer: repo.acme.example answered 401 for acme/billing\n" +
		"  set COMPOSER_AUTH (as Composer reads it); credentials go only to repo.acme.example\n"},
	{code: core.ETooLarge, exit: cli.ExitUnavailable, setup: func(t *testing.T, w *runtest.World) []string {
		w.Publish(core.NPM, "huge-pkg", "1.3.0", "1.4.0")
		failFetch(t, w, core.NPM, "huge-pkg", stageErr(core.ETooLarge, cli.ExitUnavailable, "npm",
			"the 1.4.0 tarball of huge-pkg unpacks to over 1 GiB",
			"raise --max-size if you expect that; a size jump this big is worth a look on its own"))
		return []string{"npm", "huge-pkg", "--from", "1.3.0"}
	}, stderr: "{prog} npm: the 1.4.0 tarball of huge-pkg unpacks to over 1 GiB\n" +
		"  raise --max-size if you expect that; a size jump this big is worth a look on its own\n"},
	{code: core.EBadConfig, exit: cli.ExitUsage, setup: func(t *testing.T, w *runtest.World) []string {
		w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
		t.Cleanup(core.SwapPolicy(badAllow{w.Policy, stageErr(core.EBadConfig, cli.ExitUsage, "",
			".sightread/allowed.yaml: entry 3 (npm:left-pad@1.4.0) needs a reason, so the next person knows why it is allowed")}))
		return []string{"plugin", "akismet", "--from", "5.3.3"}
	}, stderr: "{prog}: .sightread/allowed.yaml: entry 3 (npm:left-pad@1.4.0) needs a reason, so the next person knows why it is allowed\n"},
	{code: core.EBadFlag, exit: cli.ExitUsage, setup: func(*testing.T, *runtest.World) []string {
		return []string{"all", "--fail-on", "severe"}
	}, stderr: "{prog}: --fail-on \"severe\": want none, info, low, medium, high or critical\n"},
	{code: core.EProduction, exit: cli.ExitUsage, setup: func(t *testing.T, w *runtest.World) []string {
		dir := t.TempDir()
		chdir(t, dir)
		if err := os.MkdirAll(filepath.Join(dir, ".soundcheck"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".soundcheck", "config.yaml"), []byte("production:\n  - shop.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return soundcheckUpdate(w, "https://shop.example.com", "wp --path=/srv/staging")
	}, stderr: "{prog} plugin: shop.example.com is listed as production in .soundcheck/config.yaml\n" +
		"  --soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)\n"},
	{code: core.ESoundcheckMissing, exit: cli.ExitUnavailable, setup: func(t *testing.T, w *runtest.World) []string {
		t.Setenv("PATH", t.TempDir())
		chdir(t, t.TempDir())
		return soundcheckUpdate(w, "https://staging.shop.test", "wp --path=/srv/staging")
	}, stderr: "{prog}: --soundcheck needs rhythm-soundcheck and rhythm-roadie\n  install them with: rhythm install soundcheck roadie\n"},
	{code: core.EGitHubLimit, exit: cli.ExitUnavailable, setup: func(t *testing.T, w *runtest.World) []string {
		w.Publish(core.Composer, "monolog/monolog", "3.0.0", "3.1.0")
		failFetch(t, w, core.Composer, "monolog/monolog", stageErr(core.EGitHubLimit, cli.ExitUnavailable, "composer",
			"api.github.com allows 60 requests an hour without a token and this run needs about 111",
			"set GITHUB_TOKEN (sent only to api.github.com); 23 of 111 packages were reviewed"))
		return []string{"composer", "monolog/monolog", "--from", "3.0.0"}
	}, stderr: "{prog} composer: api.github.com allows 60 requests an hour without a token and this run needs about 111\n" +
		"  set GITHUB_TOKEN (sent only to api.github.com); 23 of 111 packages were reviewed\n"},
	{code: core.ESoundcheckOnHold, exit: cli.ExitFindings, setup: func(t *testing.T, w *runtest.World) []string {
		chdir(t, t.TempDir())
		args := soundcheckUpdate(w, "https://staging.shop.test", "wp --path=/srv/staging")
		w.Detector.Set("countdown-timer-ultimate", "remote-fetch-exec")
		return args
	}, stderr: "{prog} plugin: countdown-timer-ultimate 2.6.8 is on HOLD, so --soundcheck won't install it\n" +
		"  review the findings first; --soundcheck-anyway installs it on the staging copy regardless\n"},
	{code: core.EAllowUnverified, exit: cli.ExitUsage, setup: func(t *testing.T, w *runtest.World) []string {
		t.Setenv("PATH", t.TempDir())
		w.Publish(core.NPM, "left-pad", "1.4.0")
		w.Sources[core.NPM].Integrity[core.Ref{Eco: core.NPM, Name: "left-pad", Version: "1.4.0"}] = core.Integrity{By: core.ByNone}
		return []string{"allow", "npm:left-pad@1.4.0", "--reason", "checked"}
	}, stderr: "{prog} allow: npm:left-pad@1.4.0 couldn't be verified, so it can't be allowed\n" +
		"  allow records a reviewed archive by its hash; review it first with {prog} npm left-pad --to 1.4.0\n"},
	{code: core.EDowngrade, exit: cli.ExitUsage, setup: func(_ *testing.T, w *runtest.World) []string {
		w.Publish(core.WPPlugin, "akismet", "5.3.1", "5.3.5")
		w.Install(core.WPPlugin, "akismet", "5.3.5")
		return []string{"plugin", "akismet", "--to", "5.3.1"}
	}, stderr: "{prog} plugin: --to 5.3.1 is older than the installed 5.3.5\n  add --allow-downgrade to review a downgrade\n"},
	{code: core.ERemoteWPSoundcheck, exit: cli.ExitUsage, setup: func(t *testing.T, w *runtest.World) []string {
		chdir(t, t.TempDir())
		return soundcheckUpdate(w, "https://staging.shop.test", "ssh deploy@staging -- wp --path=/srv/www")
	}, stderr: "{prog} plugin: --soundcheck can install the verified zip only through a local wp command\n" +
		"  for a remote staging site give --apply \"<command that installs countdown-timer-ultimate>\"; " +
		"the report then says the applied bytes were not checked\n"},
	{code: core.EUnknownCommand, exit: cli.ExitUsage, setup: func(*testing.T, *runtest.World) []string {
		return []string{"plugn"}
	}, stderr: "{prog}: unknown command \"plugn\"\n  did you mean: {prog} plugin\n  run '{prog} help' to see the commands\n"},
}

// soundcheckUpdate publishes countdown-timer-ultimate 2.6.7 and 2.6.8
// with 2.6.7 installed and returns the --soundcheck command line for it.
func soundcheckUpdate(w *runtest.World, staging, wp string) []string {
	w.Publish(core.WPPlugin, "countdown-timer-ultimate", "2.6.7", "2.6.8")
	w.Install(core.WPPlugin, "countdown-timer-ultimate", "2.6.7")
	return []string{"plugin", "countdown-timer-ultimate", "--soundcheck", staging, "--wp", wp}
}

// siteDir is a site folder whose absolute path the E1 text names.
func siteDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestErrorMessages is PRD section 10 end to end: each case through
// cli.Main, stderr and the exit code byte for byte, under both program
// names.
func TestErrorMessages(t *testing.T) {
	seen := map[core.ErrorCode]bool{}
	for _, c := range errorCases {
		seen[c.code] = true
		for _, prog := range []string{"rhythm-sightread", "rhythm sightread"} {
			t.Run(string(c.code)+"/"+prog, func(t *testing.T) {
				if c.skip != "" {
					t.Skip(c.skip)
				}
				w := world(t)
				args := c.setup(t, w)
				dir := ""
				for i, a := range args {
					if a == "--path" && i+1 < len(args) {
						dir = args[i+1]
					}
				}
				code, _, errOut := mainRun(t, prog, args...)
				want := strings.ReplaceAll(strings.ReplaceAll(c.stderr, "{prog}", prog), "{dir}", dir)
				if code != c.exit || errOut != want {
					t.Errorf("%s: exit %d, stderr\n%q\nwant exit %d, stderr\n%q", c.code, code, errOut, c.exit, want)
				}
			})
		}
	}
	for i := 1; i <= 20; i++ {
		if code := core.ErrorCode("E" + strconv.Itoa(i)); !seen[code] {
			t.Errorf("no case for %s", code)
		}
	}
}

// TestRunCounts: E16 and an offline E7 from fetch get the run's counts
// (PRD section 10); without fetch's cause they print as they came.
func TestRunCounts(t *testing.T) {
	const partial = "rhythm-sightread: the run is partial, so --fail-on high can't pass it\n"
	for _, c := range []struct {
		name string
		err  *core.Error
		want string
	}{
		{"github budget", &core.Error{Code: core.EGitHubLimit, Exit: cli.ExitUnavailable, What: "x", Err: &fetch.ErrGitHubBudget{Limit: 60, Needed: 111}},
			"rhythm-sightread composer: api.github.com allows 60 requests an hour without a token and this run needs about 111\n" +
				"  set GITHUB_TOKEN (sent only to api.github.com); 1 of 2 packages were reviewed\n" + partial},
		{"offline", stageErr(core.ENetwork, cli.ExitUnavailable, "", "can't reach repo.packagist.org (offline and not cached)",
			"with --offline only cached data and archives are used; run once without it to fill the cache"),
			"rhythm-sightread: can't reach repo.packagist.org (offline and not cached)\n" +
				"  with --offline only cached data and archives are used and 1 of 2 aren't cached; run once without it to fill the cache\n" + partial},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := world(t)
			w.Publish(core.Composer, "monolog/monolog", "3.0.0", "3.1.0")
			w.Publish(core.Composer, "psr/log", "3.0.0", "3.0.1")
			w.Install(core.Composer, "monolog/monolog", "3.0.0")
			w.Install(core.Composer, "psr/log", "3.0.0")
			e := *c.err
			if e.Code == core.EGitHubLimit {
				e.Command = "composer"
			}
			failFetch(t, w, core.Composer, "monolog/monolog", &e)
			code, _, errOut := mainRun(t, "rhythm-sightread", "all", "--fail-on", "high")
			if code != cli.ExitUnavailable || errOut != c.want {
				t.Errorf("exit %d stderr\n%q\nwant\n%q", code, errOut, c.want)
			}
		})
	}
}

// TestVerboseCause: -v adds the cause on its own line, masked.
func TestVerboseCause(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	cause := errors.New("open .sightread/allowed.yaml: permission denied")
	t.Cleanup(core.SwapPolicy(badAllow{w.Policy, &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage,
		What: ".sightread/allowed.yaml: can't be read", Err: cause}}))
	code, _, errOut := mainRun(t, "rhythm-sightread", "plugin", "akismet", "--from", "5.3.3", "-v")
	want := "rhythm-sightread: .sightread/allowed.yaml: can't be read\n  cause: open .sightread/allowed.yaml: permission denied\n"
	if code != cli.ExitUsage || errOut != want {
		t.Errorf("exit %d %q, want %q", code, errOut, want)
	}
}
