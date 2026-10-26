// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/ui"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/internal/proc"
	"github.com/RhythmShahriar/sightread/run"
)

// doctorTimeout bounds each network check.
const doctorTimeout = 10 * time.Second

// probeLimit is how much of an answer a reachability check reads.
const probeLimit = 64 << 10

// officialBases are the source URLs a run uses when neither config nor a
// SIGHTREAD_* variable names a mirror, in the order doctor checks them.
var officialBases = []struct{ key, url string }{
	{core.BaseWPOrgAPI, "https://api.wordpress.org"},
	{core.BaseWPOrgDownloads, "https://downloads.wordpress.org"},
	{core.BaseWPOrgSVN, "https://plugins.svn.wordpress.org"},
	{core.BaseWPOrgThemeSVN, "https://themes.svn.wordpress.org"},
	{core.BasePackagist, "https://repo.packagist.org"},
	{core.BasePackagistMeta, "https://packagist.org"},
	{core.BaseGitHubAPI, "https://api.github.com"},
	{core.BaseGitHubCodeload, "https://codeload.github.com"},
	{core.BaseNPM, "https://registry.npmjs.org"},
	{core.BaseOSV, "https://api.osv.dev"},
}

// keyChecker is implemented by the npm source: it loads the registry's
// signing keys and reports how many match the set pinned in the binary.
type keyChecker interface {
	CheckKeys(ctx context.Context) (detail string, err error)
}

// doctorCommand is `doctor` (PRD 6.9), laid out like rhythm-echo
// doctor.
var doctorCommand = &simpleCommand{
	name: "doctor", args: "[--offline] [--json]", brief: "[--json]", summary: "check sources, cache, tokens and helpers",
	long: "Checks what a review needs: each source answers, the npm registry's signing keys load and match the set " +
		"pinned in this build, the cache folder is writable, GITHUB_TOKEN is set (and how many GitHub requests are " +
		"left), git is on PATH and, when the config has a soundcheck section, rhythm-soundcheck and rhythm-roadie are " +
		"installed. --offline skips the network checks. Exit 1 when a check fails.",
	examples: []string{"doctor", "doctor --offline --json"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		offline := fs.Bool("offline", false, "skip the network checks (also RHYTHM_OFFLINE)")
		asJSON := fs.Bool("json", false, "print the kind doctor JSON document")
		plain := fs.Bool("plain", false, "no symbols or color (also when stdout is not a terminal)")
		return func(ctx context.Context, pos []string, stdout, _ io.Writer) error {
			if len(pos) > 0 {
				return cli.Usagef("doctor takes no arguments, got %q", pos[0])
			}
			d := &doctor{out: stdout, asJSON: *asJSON, plain: *plain || !cli.IsTerminal(stdout)}
			d.run(ctx, os.Getenv, *offline || os.Getenv(cli.OfflineEnv) != "")
			return d.end()
		}
	},
}

// doctor runs, prints and keeps doctor's checks.
type doctor struct {
	out           io.Writer
	asJSON, plain bool
	checks        []core.DoctorCheck
	ok, fails     int
}

func (d *doctor) add(status, name, detail string) {
	switch status {
	case core.DoctorOK:
		d.ok++
	case core.DoctorFail:
		d.fails++
	}
	d.checks = append(d.checks, core.DoctorCheck{Name: name, Status: status, Detail: detail})
	if d.asJSON {
		return
	}
	m := doctorMarks[status]
	if d.plain {
		fmt.Fprintf(d.out, "%-4s  %s: %s\n", m.word, name, detail)
		return
	}
	mark := lipgloss.NewStyle().Foreground(lipgloss.Color(m.color)).Bold(true).Render(m.glyph)
	fmt.Fprintf(d.out, "  %s %s %s\n", mark, lipgloss.NewStyle().Bold(true).Width(16).Render(name), detail)
}

// doctorMark is how one status prints: a glyph on a terminal, a word
// in plain output.
type doctorMark struct{ glyph, word, color string }

var doctorMarks = map[string]doctorMark{
	core.DoctorOK:      {"✓", "ok", ui.Ok},
	core.DoctorFail:    {"✗", "FAIL", ui.Danger},
	core.DoctorWarn:    {"!", "warn", ui.Warn},
	core.DoctorSkipped: {"·", "skip", ui.Muted},
}

// lookPath finds a program on PATH; tests replace it.
var lookPath = proc.LookPath

// end prints the tally (or writes the document with --json) and gives
// exit 1 when a check failed.
func (d *doctor) end() error {
	if d.asJSON {
		verdict := core.VerdictOK
		if d.fails > 0 {
			verdict = core.VerdictFindings
		}
		if err := writeDocument(d.out, core.KindDoctor, verdict, core.DoctorData{Checks: d.checks}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(d.out, "\n  %s passed, %d failed.\n", plural(d.ok, "check"), d.fails)
	}
	if d.fails > 0 {
		return cli.ErrFindings
	}
	return nil
}

// run makes every check in order.
func (d *doctor) run(ctx context.Context, env func(string) string, offline bool) {
	cfg := &core.Config{}
	cfgPath := ""
	if policy := core.GetPolicy(); policy != nil {
		c, p, err := policy.LoadConfig(".", "", false)
		if err != nil {
			d.add(core.DoctorFail, "Config", err.Error())
		} else {
			cfg, cfgPath = c, p
			detail := "none here, so every default applies"
			if cfgPath != "" {
				detail = shown(cfgPath)
			}
			d.add(core.DoctorOK, "Config", detail)
		}
	}
	d.cache()
	gc := envGetter(env, offline)
	gc.Bases = doctorBases(cfg, gc.Bases)
	if offline {
		d.add(core.DoctorSkipped, "Sources", "offline")
	} else {
		d.sources(ctx, gc)
	}
	d.github(ctx, gc, offline)
	d.git()
	if cfg.Soundcheck.Staging != "" {
		d.helpers()
	}
	if dp := core.GetDataPacks(); dp != nil {
		var packs []string
		for _, p := range dp.Packs() {
			packs = append(packs, p.Name+" "+p.Version)
		}
		d.add(core.DoctorOK, "Signal data", cmp.Or(strings.Join(packs, ", "), "embedded"))
	}
}

// doctorBases is every source base a review would use: the official
// URL, then config sources, then the SIGHTREAD_* variables.
func doctorBases(cfg *core.Config, env map[string]string) map[string]string {
	b := map[string]string{}
	for _, o := range officialBases {
		b[o.key] = o.url
	}
	s := cfg.Sources
	for k, v := range map[string]string{
		core.BaseWPOrgAPI: s.WPOrgAPI, core.BaseWPOrgDownloads: s.WPOrgDownloads, core.BaseWPOrgSVN: s.WPOrgSVN,
		core.BaseWPOrgThemeSVN: s.WPOrgThemeSVN, core.BasePackagist: s.Packagist, core.BasePackagistMeta: s.PackagistMeta,
		core.BaseGitHubAPI: s.GitHubAPI, core.BaseGitHubCodeload: s.GitHubCodeload, core.BaseNPM: s.NPM.Registry, core.BaseOSV: s.OSV,
	} {
		if v != "" {
			b[k] = v
		}
	}
	for k, v := range env {
		b[k] = v
	}
	return b
}

// cache checks that the cache folder takes a file.
func (d *doctor) cache() {
	dir, err := run.CacheDir("")
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	var f *os.File
	if err == nil {
		f, err = os.CreateTemp(dir, ".doctor-*")
	}
	if err != nil {
		d.add(core.DoctorFail, "Cache", fmt.Sprintf("can't write the cache folder (%v); set RHYTHM_CACHE_DIR to a writable folder", err))
		return
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	d.add(core.DoctorOK, "Cache", dir+" is writable")
}

// sources checks that each source base answers and that the npm keys
// match the pinned set.
func (d *doctor) sources(ctx context.Context, gc core.GetterConfig) {
	get, err := core.NewGetter(gc)
	if err != nil {
		d.add(core.DoctorFail, "Sources", err.Error())
		return
	}
	seen := map[string]bool{}
	for _, o := range officialBases {
		base := gc.Bases[o.key]
		if seen[base] {
			continue
		}
		seen[base] = true
		name := strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(base, "/"), "https://"), "http://")
		pctx, cancel := context.WithTimeout(ctx, doctorTimeout)
		_, _, err := get.Text(pctx, "HEAD", strings.TrimRight(base, "/")+"/", nil, probeLimit)
		cancel()
		switch code := core.CodeOf(err); {
		case err == nil, errors.Is(err, core.ErrTooLarge):
			d.add(core.DoctorOK, name, "answers")
		case code == core.ENetwork || code == core.EBadConfig || errors.Is(err, context.DeadlineExceeded):
			d.add(core.DoctorFail, name, firstLineOf(err))
		case code == core.ERateLimited || code == core.EGitHubLimit:
			d.add(core.DoctorWarn, name, firstLineOf(err))
		default:
			// Any HTTP answer, even an error status for the bare base
			// URL, shows the host is reachable through the Getter.
			d.add(core.DoctorOK, name, "answers ("+firstLineOf(err)+")")
		}
	}
	src := core.SourceFor(core.NPM, &core.Env{Get: get, Limits: core.DefaultLimits(), Bases: gc.Bases})
	kc, ok := src.(keyChecker)
	if !ok {
		d.add(core.DoctorWarn, "npm keys", "this build can't check the registry's signing keys")
		return
	}
	kctx, cancel := context.WithTimeout(ctx, doctorTimeout)
	defer cancel()
	if detail, err := kc.CheckKeys(kctx); err != nil {
		d.add(core.DoctorFail, "npm keys", firstLineOf(err))
	} else {
		d.add(core.DoctorOK, "npm keys", detail)
	}
}

// rateLimit is the part of GitHub's /rate_limit answer doctor reads.
type rateLimit struct {
	Resources struct {
		Core struct {
			Limit     int `json:"limit"`
			Remaining int `json:"remaining"`
		} `json:"core"`
	} `json:"resources"`
}

// github checks the token and the requests left this hour.
func (d *doctor) github(ctx context.Context, gc core.GetterConfig, offline bool) {
	token := gc.GitHubToken != ""
	if offline {
		if token {
			d.add(core.DoctorOK, "GitHub token", "set (sent only to api.github.com)")
		} else {
			d.add(core.DoctorWarn, "GitHub token", "not set: api.github.com allows 60 requests an hour without one")
		}
		return
	}
	get, err := core.NewGetter(gc)
	if err != nil {
		return // sources already said why
	}
	var rl rateLimit
	rctx, cancel := context.WithTimeout(ctx, doctorTimeout)
	defer cancel()
	err = get.JSON(rctx, strings.TrimRight(gc.Bases[core.BaseGitHubAPI], "/")+"/rate_limit", &rl, fetch.KindRate)
	left := ""
	if err == nil {
		left = fmt.Sprintf("%d of %d requests left this hour", rl.Resources.Core.Remaining, rl.Resources.Core.Limit)
	}
	switch {
	case token && err == nil:
		d.add(core.DoctorOK, "GitHub token", "set (sent only to api.github.com); "+left)
	case token:
		d.add(core.DoctorWarn, "GitHub token", "set; the rate left couldn't be read ("+firstLineOf(err)+")")
	case err == nil:
		d.add(core.DoctorWarn, "GitHub token", "not set, so "+left+"; set GITHUB_TOKEN for Composer packages and tag checks")
	default:
		d.add(core.DoctorWarn, "GitHub token", "not set: api.github.com allows 60 requests an hour without one")
	}
}

// git checks that git is on PATH.
func (d *doctor) git() {
	if p, err := lookPath("git"); err == nil {
		d.add(core.DoctorOK, "git", p)
		return
	}
	d.add(core.DoctorWarn, "git", "not on PATH: changes --base and allow --by need it")
}

// helpers checks the programs --soundcheck runs.
func (d *doctor) helpers() {
	var missing []string
	for _, name := range []string{"rhythm-soundcheck", "rhythm-roadie"} {
		if p, err := lookPath(name); err == nil {
			d.add(core.DoctorOK, name, p)
		} else {
			missing = append(missing, strings.TrimPrefix(name, "rhythm-"))
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		verb := "isn't"
		if len(missing) > 1 {
			verb = "aren't"
		}
		d.add(core.DoctorFail, "Soundcheck", "the config has a soundcheck section but rhythm-"+strings.Join(missing, " and rhythm-")+
			" "+verb+" installed: rhythm install "+strings.Join(missing, " "))
	}
}

// firstLineOf is an error's first line, the summary doctor shows.
func firstLineOf(err error) string {
	var e *core.Error
	if errors.As(err, &e) {
		return e.What
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
