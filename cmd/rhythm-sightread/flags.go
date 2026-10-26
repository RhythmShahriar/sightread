// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"cmp"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/update"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
)

// The flag groups of PRD section 7, in help order.
const (
	groupVersions   = "Versions"
	groupSources    = "Sources and integrity"
	groupSignals    = "Signals"
	groupGate       = "Gate"
	groupOutput     = "Output"
	groupSoundcheck = "Soundcheck"
	groupChanges    = "Lockfile change"
	groupFleet      = "Fleet"
)

// Defaults of PRD section 7 shown in help.
const (
	defaultMaxSize     = "256MB"
	defaultTimeout     = "30s"
	defaultDeadline    = "30m"
	defaultRetries     = 2
	defaultJobs        = 4
	defaultMaxFindings = 10
	defaultSeverity    = "info"
	defaultConfidence  = "likely"
	defaultMinAge      = "72h"
	defaultSCFailOn    = "broke"
)

// mirrorEnv maps the SIGHTREAD_* mirror variables to Getter base keys.
// They beat config sources; no flag sets them.
var mirrorEnv = []struct{ env, base string }{
	{"SIGHTREAD_WPORG_API", core.BaseWPOrgAPI},
	{"SIGHTREAD_WPDL_API", core.BaseWPOrgDownloads},
	{"SIGHTREAD_WPSVN", core.BaseWPOrgSVN},
	{"SIGHTREAD_WPTHEMESVN", core.BaseWPOrgThemeSVN},
	{"SIGHTREAD_PACKAGIST", core.BasePackagist},
	{"SIGHTREAD_PACKAGIST_META", core.BasePackagistMeta},
	{"SIGHTREAD_GITHUB_API", core.BaseGitHubAPI},
	{"SIGHTREAD_GITHUB_CODELOAD", core.BaseGitHubCodeload},
	{"SIGHTREAD_NPM_REGISTRY", core.BaseNPM},
	{"SIGHTREAD_OSV_API", core.BaseOSV},
}

// npmTokenPrefix starts a private npm scope's token variable:
// SIGHTREAD_NPM_TOKEN_ACME is the token of @acme.
const npmTokenPrefix = "SIGHTREAD_NPM_TOKEN_" //nolint:gosec // a variable name prefix, not a credential

// reviewFlags holds every flag of the review commands.
type reviewFlags struct {
	// Versions
	to, from, toFile, fromFile, path, wp, fromTuner string
	allowDowngrade, pre, transitive                 bool
	only, skip                                      cli.ListFlag

	// Sources and integrity
	offline, allowUnverified, allowPartial, svnCheck, noOSV, checkConfusion bool
	maxSize, timeout, deadline                                              string
	retries, jobs                                                           int
	proxy, userAgent                                                        string

	// Signals
	signals                         cli.RepeatFlag
	noSignalUpdates                 bool
	ids, excludeIDs                 cli.ListFlag
	severity, minConfidence, minAge string

	// Gate
	failOn, baseline, configFile    string
	noAllow, trustPRAllow, noConfig bool

	// Output
	asJSON, jsonl, md, html, sarif                                bool
	outputs                                                       cli.RepeatFlag
	open, diff, sign, redactPaths, quiet, plain, noColor, verbose bool
	maxFindings                                                   int

	// Soundcheck
	soundcheck, apply, scFailOn               string
	rollback, scAnyway, skipRoadieVerify      bool
	passthrough                               []string // after --
	base, before, after                       string   // changes
	lockfiles                                 cli.RepeatFlag
	sites                                     string // all --sites
	rereview                                  bool   // all --rereview
	set                                       map[string]bool
	groups                                    []flagGroup
	shortOf                                   map[string]string // long name to its one-letter alias
	soundcheckOn, changesOn, sitesOn, namedOn bool
}

// flagGroup is one block of a help page.
type flagGroup struct {
	title string
	names []string
}

// group runs fn, which registers one group's flags; it records their
// names in registration order for the help page.
func (f *reviewFlags) group(fs *flag.FlagSet, title string, fn func(fs *flag.FlagSet)) {
	f.groups = append(f.groups, flagGroup{title: title})
	fn(fs)
}

// add records a flag registered on fs under the current group.
func (f *reviewFlags) add(name string) string {
	g := &f.groups[len(f.groups)-1]
	g.names = append(g.names, name)
	return name
}

// short registers a one-letter alias of a long flag.
func (f *reviewFlags) short(fs *flag.FlagSet, letter, long string) {
	fs.Var(fs.Lookup(long).Value, letter, fs.Lookup(long).Usage)
	if f.shortOf == nil {
		f.shortOf = map[string]string{}
	}
	f.shortOf[long] = letter
}

// versionFlags registers the Versions group.
func (f *reviewFlags) versionFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.to, f.add("to"), "", "the candidate `version`: latest (plugins, themes), wanted (composer, npm), installed, x.y.z, an npm dist-tag, or list to print the published versions")
	fs.StringVar(&f.from, f.add("from"), "", "the installed `version` (default: read from --path, --wp, --from-tuner or the lockfile)")
	fs.StringVar(&f.toFile, f.add("to-file"), "", "the candidate from a local zip, tgz or folder at this `path` (premium plugins, vendor downloads); marked unverified")
	fs.StringVar(&f.fromFile, f.add("from-file"), "", "the installed version from a local zip, tgz or folder at this `path`")
	fs.StringVar(&f.path, f.add("path"), ".", "the site or project `folder`: a WordPress root or a folder with lockfiles")
	fs.StringVar(&f.wp, f.add("wp"), "", "read installed WordPress versions with this WP-CLI `command`, e.g. \"ssh deploy@host -- wp --path=/srv/www\"")
	fs.StringVar(&f.fromTuner, f.add("from-tuner"), "", "read installed plugin and theme versions from a rhythm-tuner JSON `report`")
	fs.BoolVar(&f.allowDowngrade, f.add("allow-downgrade"), false, "review a --to older than the installed version")
	fs.BoolVar(&f.pre, f.add("pre"), false, "let latest and wanted pick pre-releases")
	fs.BoolVar(&f.transitive, f.add("transitive"), false, "composer and npm: review transitive dependencies too")
	fs.Var(&f.only, f.add("only"), "only these `packages`: ecosystem IDs or <eco>:<name> globs, e.g. wp-plugin:*,npm:@acme/*")
	fs.Var(&f.skip, f.add("skip"), "leave these `packages` out (same form as --only)")
}

// sourceFlags registers the Sources and integrity group.
func (f *reviewFlags) sourceFlags(fs *flag.FlagSet) {
	fs.BoolVar(&f.offline, f.add("offline"), false, "use cached archives only (RHYTHM_OFFLINE=1 does the same)")
	fs.BoolVar(&f.allowUnverified, f.add("allow-unverified"), false, "review packages whose integrity couldn't be checked and let --fail-on pass them")
	fs.BoolVar(&f.allowPartial, f.add("allow-partial"), false, "let --fail-on pass a run with packages not checked, fetch failures or timeouts")
	fs.BoolVar(&f.svnCheck, f.add("svn-check"), false, "verify themes file by file against themes.svn.wordpress.org")
	fs.BoolVar(&f.noOSV, f.add("no-osv"), false, "don't ask api.osv.dev for known malicious and vulnerable versions")
	fs.BoolVar(&f.checkConfusion, f.add("check-confusion"), false, "ask the public registry about private names (this sends them there)")
	fs.StringVar(&f.maxSize, f.add("max-size"), defaultMaxSize, "largest archive to download, a `size` in KB, MB or GB (KiB, MiB, GiB); unpacked it may be 4 times that, at most 1GiB")
	fs.StringVar(&f.timeout, f.add("timeout"), defaultTimeout, "how long one request may take (a `duration` such as 30s)")
	fs.StringVar(&f.deadline, f.add("deadline"), defaultDeadline, "how long the whole run may take (a `duration` such as 30m)")
	fs.IntVar(&f.retries, f.add("retries"), defaultRetries, "`n` retries after network errors, 429 and 503")
	fs.IntVar(&f.jobs, f.add("jobs"), defaultJobs, "`n` packages reviewed in parallel (at most 4 requests per host)")
	fs.StringVar(&f.proxy, f.add("proxy"), "", "HTTP proxy `url` (default HTTPS_PROXY)")
	fs.StringVar(&f.userAgent, f.add("user-agent"), "", "the User-Agent `header` (default rhythm-sightread/<version> (+https://github.com/RhythmShahriar/sightread))")
	f.short(fs, "A", "user-agent")
}

// signalFlags registers the Signals group.
func (f *reviewFlags) signalFlags(fs *flag.FlagSet) {
	fs.Var(&f.signals, f.add("signals"), "load extra signal YAML from this `folder` (repeatable)")
	fs.BoolVar(&f.noSignalUpdates, f.add("no-signal-updates"), false, "use the built-in signals and names, not a newer downloaded pack")
	fs.Var(&f.ids, f.add("id"), "only findings with these signal `ids` (globs)")
	fs.Var(&f.excludeIDs, f.add("exclude-id"), "drop findings with these signal `ids` (globs); integrity and allow signals always stay")
	fs.StringVar(&f.severity, f.add("severity"), defaultSeverity, "hide findings below this `level`: info, low, medium, high or critical")
	fs.StringVar(&f.minConfidence, f.add("min-confidence"), defaultConfidence, "`confidence` a finding needs to count: confirmed or likely (config min_confidence)")
	fs.StringVar(&f.minAge, f.add("min-age"), defaultMinAge, "fresh-release fires for a candidate younger than this `duration` (config min_age)")
}

// gateFlags registers the Gate group.
func (f *reviewFlags) gateFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.failOn, f.add("fail-on"), "", "exit 1 on a finding at or above this `level`: none, info, low, medium, high or critical (config fail_on; default none)")
	fs.StringVar(&f.baseline, f.add("baseline"), "", "hide findings already in this saved JSON `report`")
	fs.BoolVar(&f.noAllow, f.add("no-allow"), false, "ignore .sightread/allowed.yaml for this run")
	if f.changesOn {
		fs.BoolVar(&f.trustPRAllow, f.add("trust-pr-allow"), false, "count allow entries, config and baseline the change itself edits (default: only the base ref's count)")
	}
	fs.StringVar(&f.configFile, f.add("config"), "", "config `file` (default: the nearest .sightread/config.yaml here or above)")
	fs.BoolVar(&f.noConfig, f.add("no-config"), false, "read no config, for folders you don't trust")
}

// outputFlags registers the Output group.
func (f *reviewFlags) outputFlags(fs *flag.FlagSet) {
	fs.BoolVar(&f.asJSON, f.add("json"), false, "print the rhythm-sightread/v1 JSON report")
	fs.BoolVar(&f.jsonl, f.add("jsonl"), false, "print one JSON line per update as it finishes, then the summary")
	fs.BoolVar(&f.md, f.add("md"), false, "print Markdown for pull requests and job summaries")
	fs.BoolVar(&f.html, f.add("html"), false, "print a standalone HTML report with the full diff")
	fs.BoolVar(&f.sarif, f.add("sarif"), false, "print SARIF 2.1.0 for GitHub code scanning")
	fs.Var(&f.outputs, f.add("output"), "also write the report to this `file`, format from .json .jsonl .md .html or .sarif (repeatable; written once complete)")
	f.short(fs, "o", "output")
	fs.BoolVar(&f.open, f.add("open"), false, "open the HTML report when done")
	fs.BoolVar(&f.diff, f.add("diff"), false, "print every changed hunk, not just the ones findings point at")
	fs.IntVar(&f.maxFindings, f.add("max-findings"), defaultMaxFindings, "`n` findings shown per update on the terminal")
	fs.BoolVar(&f.sign, f.add("sign"), false, "sign the JSON report (<file>.json.sig, Ed25519)")
	fs.BoolVar(&f.redactPaths, f.add("redact-paths"), false, "write paths relative to the target or ~ (default on when CI is set)")
	fs.BoolVar(&f.quiet, f.add("quiet"), false, "verdicts and findings only")
	f.short(fs, "q", "quiet")
	fs.BoolVar(&f.plain, f.add("plain"), false, "no color, boxes or glyphs (also when stdout is not a terminal)")
	fs.BoolVar(&f.noColor, f.add("no-color"), false, "no color (NO_COLOR does the same)")
	fs.BoolVar(&f.verbose, f.add("verbose"), false, "every request, hash and program started to stderr, header values masked")
	f.short(fs, "v", "verbose")
}

// soundcheckFlags registers the Soundcheck group.
func (f *reviewFlags) soundcheckFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.soundcheck, f.add("soundcheck"), "", "install the update on this staging `url` and compare it before and after with rhythm-soundcheck")
	fs.StringVar(&f.apply, f.add("apply"), "", "composer and npm, or a remote --wp: the `command` that installs the update on staging")
	fs.BoolVar(&f.rollback, f.add("rollback"), false, "reinstall the reviewed old version when Soundcheck finds changes at --soundcheck-fail-on")
	fs.StringVar(&f.scFailOn, f.add("soundcheck-fail-on"), defaultSCFailOn, "Soundcheck change `class` that fails: broke, new or changed")
	fs.BoolVar(&f.scAnyway, f.add("soundcheck-anyway"), false, "install on staging even when the update is on HOLD")
	fs.BoolVar(&f.skipRoadieVerify, f.add("skip-roadie-verify"), false, "don't check the staging copy with rhythm-roadie verify (the report says so)")
}

// changesFlags registers the flags only changes takes.
func (f *reviewFlags) changesFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.base, f.add("base"), "", "compare the lockfiles at this git `ref` (default: GITHUB_BASE_REF in Actions, else the merge base with origin/HEAD)")
	fs.StringVar(&f.before, f.add("before"), "", "the old `lockfile` (with --after; no git needed)")
	fs.StringVar(&f.after, f.add("after"), "", "the new `lockfile`")
	fs.Var(&f.lockfiles, f.add("lockfile"), "a `lockfile` to compare (repeatable; default: every one found)")
}

// fleetFlags registers the flags only all takes.
func (f *reviewFlags) fleetFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.sites, f.add("sites"), "", "review every site of this sites.yaml `file` once per update")
	fs.BoolVar(&f.rereview, f.add("rereview"), false, "review each installed version against the release before it, so new signals reach what you already run (watch does this after a signal data update)")
}

// register adds every flag of c to fs, by group.
func (f *reviewFlags) register(fs *flag.FlagSet, c *reviewCommand) {
	f.changesOn, f.sitesOn, f.soundcheckOn, f.namedOn = c.name == "changes", c.name == "all", c.soundcheck, c.named
	f.group(fs, groupVersions, f.versionFlags)
	if f.changesOn {
		f.group(fs, groupChanges, f.changesFlags)
	}
	if f.sitesOn {
		f.group(fs, groupFleet, f.fleetFlags)
	}
	f.group(fs, groupSources, f.sourceFlags)
	f.group(fs, groupSignals, f.signalFlags)
	f.group(fs, groupGate, f.gateFlags)
	f.group(fs, groupOutput, f.outputFlags)
	if f.soundcheckOn {
		f.group(fs, groupSoundcheck, f.soundcheckFlags)
	}
}

// badFlag is E13: a flag value that can't be used.
func badFlag(format string, a ...any) error {
	return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, What: fmt.Sprintf(format, a...)}
}

// plan is a parsed review command line: the request for run, where the
// report goes and how the gate reads it.
type plan struct {
	req        run.Request
	stdout     string   // the format printed to stdout
	files      []output // -o files
	write      core.WriteOptions
	gate       core.GateOptions
	open, sign bool
	verbose    bool
	soundcheck soundcheckPlan
}

// output is one -o file.
type output struct{ path, format string }

// soundcheckPlan is what the --soundcheck flags ask for. The stage
// package carries it out.
type soundcheckPlan struct {
	Staging, Apply, FailOn string
	Rollback, Anyway, Skip bool
	Args                   []string
	ApplyArgv              []string // Apply split into argv
	FailOnSet              bool     // --soundcheck-fail-on was given, so it beats the config
}

// formatOf maps an -o extension to its writer format.
func formatOf(path string) (string, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return core.FormatJSON, true
	case ".jsonl":
		return core.FormatJSONL, true
	case ".md":
		return core.FormatMarkdown, true
	case ".html", ".htm":
		return core.FormatHTML, true
	case ".sarif":
		return core.FormatSARIF, true
	}
	return "", false
}

// plan validates the flag values (E13) and builds the run request. env
// reads the environment; tests pass their own. -v logs go to stderr.
func (f *reviewFlags) plan(c *reviewCommand, env func(string) string, version string, stderr io.Writer) (*plan, error) {
	p := &plan{verbose: f.verbose}
	q := &p.req
	q.Command, q.Version, q.Set = c.name, version, f.set
	q.Eco = c.eco

	// Versions
	q.To, q.From, q.ToFile, q.FromFile = f.to, f.from, f.toFile, f.fromFile
	if q.Rereview = f.rereview; f.rereview && (f.to != "" || f.from != "") {
		return nil, badFlag("--rereview reviews the installed versions against the release before them, so it takes no --to or --from")
	}
	q.AllowDowngrade, q.Pre, q.Transitive = f.allowDowngrade, f.pre, f.transitive
	q.Only, q.Skip = slices.Clone(f.only), slices.Clone(f.skip)
	q.Inventory = core.InventoryRequest{Root: f.path, TunerReport: f.fromTuner, Transitive: f.transitive}
	if f.wp != "" {
		argv, err := run.SplitCommand(f.wp)
		if err != nil {
			return nil, badFlag("--wp %q: %v", f.wp, err)
		}
		q.Inventory.WP = argv
	}
	for _, list := range [][]string{q.Only, q.Skip} {
		for _, pat := range list {
			if err := checkPackagePattern(pat); err != nil {
				return nil, err
			}
		}
	}

	// Sources and integrity
	timeout, err := parseDuration("timeout", f.timeout)
	if err != nil {
		return nil, err
	}
	deadline, err := parseDuration("deadline", f.deadline)
	if err != nil {
		return nil, err
	}
	size, err := parseSize(f.maxSize)
	if err != nil {
		return nil, err
	}
	if f.retries < 0 || f.retries > 10 {
		return nil, badFlag("--retries %d: want 0 to 10", f.retries)
	}
	if f.jobs < 1 || f.jobs > 64 {
		return nil, badFlag("--jobs %d: want 1 to 64", f.jobs)
	}
	proxy := cmp.Or(f.proxy, env("HTTPS_PROXY"), env("https_proxy"))
	if proxy != "" {
		if u, err := url.Parse(proxy); err != nil || u.Host == "" || !slices.Contains([]string{"http", "https", "socks5"}, u.Scheme) {
			return nil, badFlag("--proxy %q: want a URL such as http://proxy.example:3128", shownProxy(proxy))
		}
	}
	q.MaxSize, q.Deadline, q.Jobs = size, deadline, f.jobs
	q.NoOSV, q.AllowUnverified = f.noOSV, f.allowUnverified
	q.Options = core.SourceOptions{SVNCheck: f.svnCheck, CheckConfusion: f.checkConfusion}
	// GetterConfig reads Retries 0 as the default and a negative value
	// as none, so --retries 0 must reach it as -1.
	retries := f.retries
	if retries == 0 {
		retries = -1
	}
	q.Getter = core.GetterConfig{
		Bases:        mirrors(env),
		UserAgent:    cmp.Or(f.userAgent, "rhythm-sightread/"+version+" (+https://github.com/RhythmShahriar/sightread)"),
		Proxy:        proxy,
		Timeout:      timeout,
		Retries:      retries,
		PerHost:      min(f.jobs, 4),
		GitHubToken:  cmp.Or(env("GITHUB_TOKEN"), env("RHYTHM_GITHUB_TOKEN")),
		ScopeTokens:  scopeTokens(),
		ComposerAuth: env("COMPOSER_AUTH"),
		Offline:      f.offline || env(cli.OfflineEnv) != "",
	}

	// Signals
	sev, err := parseSeverity(f.severity)
	if err != nil {
		return nil, err
	}
	if _, ok := core.ParseConfidence(f.minConfidence); !ok {
		return nil, badFlag("--min-confidence %q: want confirmed or likely", f.minConfidence)
	}
	if _, err := parseDuration("min-age", f.minAge); err != nil {
		return nil, err
	}
	for _, id := range append(slices.Clone(f.ids), f.excludeIDs...) {
		if !strings.ContainsAny(id, "*?") {
			if _, ok := core.Signal(id); !ok {
				return nil, unknownSignal(id)
			}
		}
	}
	q.SignalDirs, q.NoSignalUpdates = slices.Clone(f.signals), f.noSignalUpdates
	q.IDs, q.ExcludeIDs, q.Severity = slices.Clone(f.ids), slices.Clone(f.excludeIDs), sev
	// The defaults shown in help are the config's defaults too, so only
	// a flag the user typed overrides config.
	if f.set["min-confidence"] {
		q.MinConfidence = f.minConfidence
	}
	if f.set["min-age"] {
		q.MinAge = f.minAge
	}

	// Gate
	if f.failOn != "" {
		if _, err := cli.ParseFailOn(f.failOn); err != nil {
			return nil, badFlag("%s", err.Error())
		}
		q.FailOn = strings.ToLower(f.failOn)
	}
	if f.configFile != "" && f.noConfig {
		return nil, badFlag("--config and --no-config can't be used together")
	}
	q.Baseline, q.NoAllow, q.TrustPRAllow = f.baseline, f.noAllow, f.trustPRAllow
	q.ConfigFile, q.NoConfig = f.configFile, f.noConfig
	p.gate = core.GateOptions{AllowPartial: f.allowPartial, AllowUnverified: f.allowUnverified}

	// Output
	if err := f.outputPlan(p, env, version); err != nil {
		return nil, err
	}
	if f.verbose {
		q.Log = stderr
		q.Getter.Debug = stderr
	}

	// Soundcheck
	if f.scFailOn != "" && !slices.Contains([]string{"broke", "new", "changed"}, f.scFailOn) {
		return nil, badFlag("--soundcheck-fail-on %q: want broke, new or changed", f.scFailOn)
	}
	p.soundcheck = soundcheckPlan{Staging: f.soundcheck, Apply: f.apply, FailOn: f.scFailOn, Rollback: f.rollback,
		Anyway: f.scAnyway, Skip: f.skipRoadieVerify, Args: slices.Clone(f.passthrough), FailOnSet: f.set["soundcheck-fail-on"]}
	if f.soundcheck == "" && len(f.passthrough) > 0 {
		return nil, badFlag("the arguments after -- go to rhythm-soundcheck, so they need --soundcheck <staging-url>")
	}
	if f.soundcheck == "" {
		for _, name := range []string{"apply", "rollback", "soundcheck-anyway", "skip-roadie-verify", "soundcheck-fail-on"} {
			if f.set[name] {
				return nil, badFlag("--%s goes with --soundcheck <staging-url>", name)
			}
		}
	}
	if f.apply != "" {
		argv, err := run.SplitCommand(f.apply)
		if err != nil {
			return nil, badFlag("--apply %q: %v", f.apply, err)
		}
		p.soundcheck.ApplyArgv = argv
	}
	p.write.Soundcheck = f.soundcheck != ""
	return p, nil
}

// outputPlan decides what goes to stdout and to each -o file.
func (f *reviewFlags) outputPlan(p *plan, env func(string) string, version string) error {
	var picked []string
	for _, o := range []struct {
		on     bool
		flag   string
		format string
	}{{f.asJSON, "--json", core.FormatJSON}, {f.jsonl, "--jsonl", core.FormatJSONL}, {f.md, "--md", core.FormatMarkdown},
		{f.html, "--html", core.FormatHTML}, {f.sarif, "--sarif", core.FormatSARIF}} {
		if o.on {
			picked = append(picked, o.flag)
			p.stdout = o.format
		}
	}
	if len(picked) > 1 {
		return badFlag("%s and %s both print to stdout: pick one, or write the other with -o <file>", picked[0], picked[1])
	}
	p.stdout = cmp.Or(p.stdout, core.FormatTerminal)
	html := p.stdout == core.FormatHTML
	for _, path := range f.outputs {
		format, ok := formatOf(path)
		if !ok {
			return badFlag("-o %q: want a file ending in .json, .jsonl, .md, .html or .sarif", path)
		}
		p.files = append(p.files, output{path: path, format: format})
		html = html || format == core.FormatHTML
	}
	if f.maxFindings < 0 {
		return badFlag("--max-findings %d: want 0 or more", f.maxFindings)
	}
	if f.open && !slices.ContainsFunc(p.files, func(o output) bool { return o.format == core.FormatHTML }) {
		return badFlag("--open opens the HTML report, so write one with -o <file>.html")
	}
	if f.sign && !slices.ContainsFunc(p.files, func(o output) bool { return o.format == core.FormatJSON }) {
		return badFlag("--sign signs the JSON report, so write one with -o <file>.json")
	}
	p.open, p.sign = f.open, f.sign
	p.req.AllHunks = f.diff || html
	terminal := cli.IsTerminal(os.Stdout)
	plain := f.plain || !terminal
	redact := env("CI") != ""
	if f.set["redact-paths"] {
		redact = f.redactPaths
	}
	p.write = core.WriteOptions{
		Plain:       plain,
		Color:       !plain && !f.noColor && env("NO_COLOR") == "",
		Quiet:       f.quiet,
		MaxFindings: f.maxFindings,
		ShowDiff:    f.diff,
		Program:     cli.Name(),
		Version:     version,
		RedactPaths: redact,
		// The terminal writer's read-only line says the staging copy runs
		// the update when --soundcheck installs it there.
		Soundcheck: f.soundcheck != "",
	}
	return nil
}

// checkPackagePattern checks one --only or --skip value: an ecosystem
// ID, or <eco>:<glob>.
func checkPackagePattern(p string) error {
	if _, err := core.ParseEcosystem(p); err == nil {
		return nil
	}
	eco, rest, ok := strings.Cut(p, ":")
	if _, err := core.ParseEcosystem(eco); !ok || err != nil || rest == "" {
		return badFlag("--only or --skip %q: want an ecosystem (wp-plugin, wp-theme, composer, npm) or <eco>:<name>, globs allowed", p)
	}
	return nil
}

// parseDuration reads a --timeout, --deadline or --min-age value: a Go
// duration that may use d for days and w for weeks.
func parseDuration(flagName, s string) (time.Duration, error) {
	d, err := update.ParseAge(s)
	if err != nil {
		return 0, badFlag("--%s %q: want a duration such as 30s, 10m, 72h or 3d", flagName, s)
	}
	return d, nil
}

// parseSeverity reads --severity.
func parseSeverity(s string) (cli.Severity, error) {
	sev, err := cli.ParseFailOn(s)
	if err != nil || sev == cli.SeverityNone {
		return 0, badFlag("--severity %q: want info, low, medium, high or critical", s)
	}
	return sev, nil
}

// sizeUnits are the --max-size suffixes. MB and MiB both mean 2^20
// bytes, as most tools read them, so the default 256MB is 256 MiB.
var sizeUnits = []struct {
	suffix string
	mult   int64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
	{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1},
}

// parseSize reads --max-size.
func parseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range sizeUnits {
		if rest, ok := strings.CutSuffix(t, u.suffix); ok {
			t, mult = strings.TrimSpace(rest), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, badFlag("--max-size %q: want a size such as 256MB, 1GB or 512KiB", s)
	}
	return n * mult, nil
}

// mirrors reads the SIGHTREAD_* mirror variables.
func mirrors(env func(string) string) map[string]string {
	b := map[string]string{}
	for _, m := range mirrorEnv {
		if v := env(m.env); v != "" {
			b[m.base] = v
		}
	}
	return b
}

// scopeTokens reads SIGHTREAD_NPM_TOKEN_<SCOPE> variables: ACME is the
// token of @acme, MY_ORG of @my-org.
func scopeTokens() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		scope, ok := strings.CutPrefix(k, npmTokenPrefix)
		if !ok || scope == "" || v == "" {
			continue
		}
		out["@"+strings.ReplaceAll(strings.ToLower(scope), "_", "-")] = v
	}
	return out
}

// unknownSignal is the E13-style error for an ID that isn't in the
// catalogue, with the nearest one.
func unknownSignal(id string) error {
	what := fmt.Sprintf("no signal %q", id)
	if s := cli.Suggest(id, core.SignalIDs()); s != "" {
		what += " (did you mean " + s + "?)"
	}
	return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, What: what, Hint: []string{"list them: " + cli.Name() + " signals"}}
}

// visited lists the flags given on the command line, by long name.
func visited(fs *flag.FlagSet, shortOf map[string]string) map[string]bool {
	set := map[string]bool{}
	long := map[string]string{}
	for l, s := range shortOf {
		long[s] = l
	}
	fs.Visit(func(fl *flag.Flag) {
		set[cmp.Or(long[fl.Name], fl.Name)] = true
	})
	return set
}

// splitPassthrough cuts args at the first "--": what follows goes to
// rhythm-soundcheck untouched.
func splitPassthrough(args []string) (own, pass []string) {
	if i := slices.Index(args, "--"); i >= 0 {
		return args[:i], args[i+1:]
	}
	return args, nil
}

// shownProxy is a proxy URL safe to print: a proxy URL can carry a
// password and the error lands in CI logs, so the user info is dropped
// (or, when the value doesn't parse, everything before the last @) and
// the rest is masked like any other output.
func shownProxy(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return secrets.Redact(u.Scheme + "://" + u.Host)
	}
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		raw = "***" + raw[i:]
	}
	return secrets.Redact(raw)
}
