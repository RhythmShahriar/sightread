// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// actionSHA is the release commit, set at release time with -ldflags
// "-X main.actionSHA=<sha>" so init ci pins the Action to the exact
// commit of the binary that wrote the workflow.
var actionSHA = ""

// checkoutPin is actions/checkout pinned as Echo's ci.yml pins it.
const checkoutPin = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"

// detectTimeout bounds init's look at what the folder holds.
const detectTimeout = 10 * time.Second

// lockfilePaths are the lockfiles the workflow's pull_request trigger
// watches.
var lockfilePaths = []string{"**/composer.lock", "**/package-lock.json", "**/npm-shrinkwrap.json", "**/pnpm-lock.yaml",
	"**/yarn.lock", "**/bun.lock"}

// initCommand is `init` and `init ci` (PRD 6.9 and 16).
var initCommand = &simpleCommand{
	name: "init", args: "[ci] [--force]", summary: "write .sightread/config.yaml or a CI workflow",
	long: "Without ci, writes .sightread/config.yaml in this folder with every setting explained, the ecosystems found " +
		"here and fail_on high. With ci, writes .github/workflows/sightread.yml in the repository root: the Sightread " +
		"Action reviews lockfile changes on pull requests and everything once a week. Neither replaces an existing file " +
		"without --force.",
	examples: []string{"init", "init ci", "init ci --fail-on critical --sarif"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		force := fs.Bool("force", false, "replace an existing file")
		failOn := fs.String("fail-on", "high", "ci: fail the job on findings at or above this `level`, or none")
		sarif := fs.Bool("sarif", false, "ci: also upload findings to GitHub code scanning")
		comment := fs.Bool("comment", true, "ci: keep one pull request comment with the result; --comment=false turns it off")
		return func(ctx context.Context, pos []string, stdout, _ io.Writer) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			switch {
			case len(pos) == 0:
				return initConfig(ctx, wd, *force, stdout)
			case len(pos) == 1 && pos[0] == "ci":
				if _, err := cli.ParseFailOn(*failOn); err != nil {
					return badFlag("%s", err.Error())
				}
				return initCI(wd, ciOptions{failOn: strings.ToLower(*failOn), sarif: *sarif, comment: *comment, force: *force}, stdout)
			}
			return cli.Usagef("init takes nothing or ci: %s init [ci] [--force]", cli.Name())
		}
	},
}

// writeNew writes body to path (shown as display), creating its folder, unless the file is
// there and force is off. Both files are committed and read by everyone,
// so they are 0644 like any source file.
func writeNew(path, display, body string, force bool) error {
	if _, err := os.Lstat(path); err == nil && !force {
		return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, Command: "init",
			What: display + " exists (use --force to replace it)"}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // a folder in the user's project
		return err
	}
	return os.WriteFile(path, []byte(body), 0o644) //nolint:gosec // committed and read by everyone
}

// initConfig writes .sightread/config.yaml in dir.
func initConfig(ctx context.Context, dir string, force bool, stdout io.Writer) error {
	ecos := detectEcosystems(ctx, dir)
	path := filepath.Join(dir, ".sightread", "config.yaml")
	if err := writeNew(path, shown(path), configYAML(ecos), force); err != nil {
		return err
	}
	names := make([]string, len(ecos))
	for i, e := range ecos {
		names[i] = string(e)
	}
	fmt.Fprintf(stdout, "Wrote %s: reviews %s, fails on high or worse.\n\nNext steps:\n", shown(path), joinAnd(names))
	fmt.Fprintln(stdout, "  1. Review the file, then commit it.")
	fmt.Fprintf(stdout, "  2. Review what is installed here: %s all\n", cli.Name())
	fmt.Fprintf(stdout, "  3. Review every pull request that moves a lockfile: %s init ci\n", cli.Name())
	return nil
}

// detectEcosystems lists the ecosystems the folder holds, in report
// order, or all of them when nothing is found (or no inventory is
// linked), so a fresh project reviews whatever it adds later.
func detectEcosystems(ctx context.Context, dir string) []core.Ecosystem {
	inv := core.GetInventory()
	if inv == nil {
		return core.Ecosystems()
	}
	ctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()
	site, err := inv.Read(ctx, core.InventoryRequest{Root: dir, MaxDepth: 6})
	if err != nil || site == nil {
		return core.Ecosystems()
	}
	var out []core.Ecosystem
	for _, eco := range core.Ecosystems() {
		if slices.ContainsFunc(site.Installed, func(i core.Installed) bool { return i.Ref.Eco == eco }) {
			out = append(out, eco)
		}
	}
	if len(out) == 0 {
		return core.Ecosystems()
	}
	return out
}

// configYAML is the commented config init writes.
func configYAML(ecos []core.Ecosystem) string {
	names := make([]string, len(ecos))
	for i, e := range ecos {
		names[i] = string(e)
	}
	return `# Sightread settings for this project. Commit this file.
# Every key is optional and flags on the command line win.
# All keys: https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Config

# Fail the run (exit 1) on findings at or above this severity:
# none, info, low, medium, high or critical.
fail_on: high

# Count only findings at this confidence or surer: confirmed or likely.
min_confidence: likely

# A release younger than this gets the fresh-release signal.
min_age: 72h

# What "all" reviews here. These were found when this file was written.
ecosystems: [` + strings.Join(names, ", ") + `]

# Also review packages you don't require directly.
transitive: false

# Look versions up on OSV for known-malicious and known-vulnerable.
osv: true

# Versions someone reviewed. Protect this file with CODEOWNERS.
allow_file: .sightread/allowed.yaml

# Mirrors and private registries, https only. Tokens come from the
# environment (SIGHTREAD_NPM_TOKEN_<SCOPE>, COMPOSER_AUTH), never from here.
# sources:
#   npm:
#     scopes:
#       "@acme": https://npm.acme.example
#   composer:
#     repositories: [https://repo.acme.example]

# Premium plugins have no official source: say where their zips are.
# local_files:
#   gravityforms: ~/vendor-zips/gravityforms-{version}.zip

# Hide a finding someone reviewed. id and reason are required.
# ignore:
#   - id: outbound-new-domain
#     package: wp-plugin:woocommerce
#     path: src/Internal/Admin/RemoteInboxNotifications/*
#     reason: WooCommerce inbox notes, reviewed
#     until: 2027-03-31
`
}

// ciOptions are the flags of init ci.
type ciOptions struct {
	failOn         string
	sarif, comment bool
	force          bool
}

// initCI writes the workflow of PRD 16 in the repository holding dir.
func initCI(dir string, o ciOptions, stdout io.Writer) error {
	root, inRepo := repoRoot(dir)
	path := filepath.Join(root, ".github", "workflows", "sightread.yml")
	// Shown from the working folder, so the git add line works as typed.
	rel := filepath.ToSlash(path)
	if r, err := filepath.Rel(dir, path); err == nil {
		rel = filepath.ToSlash(r)
	}
	if err := writeNew(path, rel, ciWorkflow(o, actionSHA, version), o.force); err != nil {
		return err
	}
	gate := "never fails on findings"
	if o.failOn != "none" {
		gate = "fails on " + o.failOn + " or worse"
	}
	if !inRepo {
		fmt.Fprintf(stdout, "No git repository found above %s, so the workflow went there.\n", shown(dir))
	}
	fmt.Fprintf(stdout, "Wrote %s: reviews lockfile changes on pull requests and everything each Monday, %s.\n\nNext steps:\n", rel, gate)
	fmt.Fprintf(stdout, "  1. Review the file, then commit and push it:\n       git add %s\n       git commit -m \"ci: review updates with sightread\"\n", rel)
	fmt.Fprintln(stdout, "  2. Protect .sightread/allowed.yaml with CODEOWNERS, so a pull request can't approve its own update:")
	fmt.Fprintln(stdout, "       /.sightread/allowed.yaml @your-org/reviewers")
	fmt.Fprintln(stdout, "  3. Dependabot and Renovate pull requests get a read-only token: the gate and the job summary still")
	fmt.Fprintln(stdout, "     work while the comment and the SARIF upload are skipped with a notice.")
	if o.sarif {
		fmt.Fprintln(stdout, "  4. Findings also appear under Security > Code scanning.")
	}
	fmt.Fprintln(stdout, "More: https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CI")
	return nil
}

// ciWorkflow is the workflow file. A release build pins the Action to
// its own commit; a dev build has no commit to pin, so it writes @v1
// and says to pin it.
func ciWorkflow(o ciOptions, sha, ver string) string {
	quoted := make([]string, len(lockfilePaths))
	for i, p := range lockfilePaths {
		quoted[i] = `"` + p + `"`
	}
	action := "RhythmShahriar/sightread@v1 # pin this to a commit SHA"
	if sha != "" {
		action = "RhythmShahriar/sightread@" + sha + " # v" + strings.TrimPrefix(ver, "v")
	}
	var b strings.Builder
	b.WriteString("name: Sightread\non:\n  pull_request:\n    paths: [" + strings.Join(quoted, ", ") + "]\n")
	b.WriteString("  schedule:\n    - cron: \"17 3 * * 1\"\npermissions:\n  contents: read\n")
	if o.comment {
		b.WriteString("  pull-requests: write\n")
	}
	if o.sarif {
		b.WriteString("  security-events: write\n")
	}
	b.WriteString("jobs:\n  sightread:\n    runs-on: ubuntu-latest\n    steps:\n")
	b.WriteString("      - uses: " + checkoutPin + "\n        with: {fetch-depth: 0}\n")
	b.WriteString("      - uses: " + action + "\n        with:\n")
	b.WriteString("          fail-on: " + o.failOn + "\n")
	if o.sarif {
		b.WriteString("          sarif: true\n")
	}
	if o.comment {
		b.WriteString("          comment: true\n")
	}
	return b.String()
}

// repoRoot returns the nearest folder at or above dir that holds .git (a
// folder, or a file in worktrees and submodules). Without one it returns
// dir itself and false.
func repoRoot(dir string) (string, bool) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d, true
		}
		if filepath.Dir(d) == d {
			return dir, false
		}
	}
}
