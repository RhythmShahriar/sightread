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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/report"
	"github.com/RhythmShahriar/sightread/run"
)

// reportCommand is `report` (PRD 6.8): it renders saved JSON reports,
// merged into one, to Markdown, HTML, SARIF or JSON without network.
var reportCommand = &simpleCommand{
	name: "report", args: "<report.json>... -o <file>", brief: "<report.json>...", summary: "render saved JSON as Markdown, HTML or SARIF",
	long: "Renders one or more JSON reports a review saved into another format, by the extension of each -o file: " +
		".md, .html, .sarif or .json. Several reports merge into one, for example the reports of several CI jobs. " +
		"It needs no network.",
	examples: []string{"report review.json -o review.html", "report web.json api.json -o all.md -o all.sarif"},
	flags: func(fs *flag.FlagSet, sf *simpleFlags) runFunc {
		var outputs cli.RepeatFlag
		fs.Var(&outputs, "output", "write the merged report to this `file` (repeatable; .md, .html, .sarif or .json)")
		sf.short(fs, "o", "output")
		redact := fs.Bool("redact-paths", os.Getenv("CI") != "", "show paths relative to the project only (default on when CI is set)")
		diff := fs.Bool("diff", false, "keep every changed hunk the reports hold")
		return func(_ context.Context, pos []string, stdout, _ io.Writer) error {
			if len(pos) == 0 {
				return cli.Usagef("report needs a JSON report: %s report <report.json>... -o <file>", cli.Name())
			}
			if len(outputs) == 0 {
				return badFlag("report writes files: give -o <file> ending in .md, .html, .sarif or .json")
			}
			var files []output
			for _, path := range outputs {
				format, ok := formatOf(path)
				if !ok || format == core.FormatJSONL {
					return badFlag("-o %q: want a file ending in .md, .html, .sarif or .json", path)
				}
				files = append(files, output{path: path, format: format})
			}
			var reps []*core.Report
			for _, path := range pos {
				rep, err := readReport("report", path)
				if err != nil {
					return err
				}
				reps = append(reps, rep)
			}
			merged := mergeReports(reps)
			o := core.WriteOptions{Program: cli.Name(), Version: version, Plain: true, RedactPaths: *redact, ShowDiff: *diff}
			for _, f := range files {
				b, err := render(f.format, merged, o)
				if err != nil {
					return err
				}
				if err := run.WriteFile(f.path, b); err != nil {
					return fmt.Errorf("-o %s: %w", f.path, err)
				}
				fmt.Fprintf(stdout, "wrote %s\n", shown(f.path))
			}
			return nil
		}
	},
}

// mergeReports joins reports into one: every update, Not checked entry,
// warning, error and note, in the order given. One report comes back as
// it is. The summary is counted again by the scorer. Reports of one
// target keep it, so SARIF still finds its files. Reports of several
// targets in one repository have their installed paths and lockfiles
// rewritten relative to the repository root, which becomes the merged
// target's repository path.
func mergeReports(reps []*core.Report) *core.Report {
	if len(reps) == 1 {
		return reps[0]
	}
	m := &core.Report{Kind: core.KindReview, Complete: true, Target: core.Target{Kind: "merged"}}
	same, inRepo := true, true
	for _, r := range reps {
		t, first := r.Target, reps[0].Target
		same = same && t.Path == first.Path && report.TargetRepoPath(t) == report.TargetRepoPath(first)
		inRepo = inRepo && report.TargetRepoPath(t) != ""
	}
	switch {
	case same:
		m.Target = reps[0].Target
		m.Target.RepoPath = report.TargetRepoPath(m.Target)
		m.Target.Sites = slices.Clone(m.Target.Sites)
	case inRepo:
		m.Target.RepoPath = "."
	}
	for _, r := range reps {
		if m.Started.IsZero() || !r.Started.IsZero() && r.Started.Before(m.Started) {
			m.Started = r.Started
		}
		m.Duration += r.Duration
		m.StoppedBy = cmp.Or(m.StoppedBy, r.StoppedBy)
		m.SignalPack, m.NamesPack = cmp.Or(m.SignalPack, r.SignalPack), cmp.Or(m.NamesPack, r.NamesPack)
		m.FailOn, m.MinConfidence = cmp.Or(m.FailOn, r.FailOn), cmp.Or(m.MinConfidence, r.MinConfidence)
		m.Complete = m.Complete && r.Complete
		if !same {
			if r.Target.Path != "" && !slices.Contains(m.Target.Sites, r.Target.Path) {
				m.Target.Sites = append(m.Target.Sites, r.Target.Path)
			}
			for _, s := range r.Target.Sites {
				if !slices.Contains(m.Target.Sites, s) {
					m.Target.Sites = append(m.Target.Sites, s)
				}
			}
		}
		ups := r.Updates
		if !same && inRepo {
			ups = inRepoRoot(ups, report.TargetRepoPath(r.Target))
		}
		m.Updates = append(m.Updates, ups...)
		m.NotChecked = append(m.NotChecked, r.NotChecked...)
		m.Warnings = append(m.Warnings, r.Warnings...)
		m.Errors = append(m.Errors, r.Errors...)
		m.Notes = append(m.Notes, r.Notes...)
	}
	if s := core.GetScorer(); s != nil {
		s.Summarise(m)
	}
	return m
}

// verifyCommand is `verify-report` (PRD 6.8): exit 0 for a good
// signature from a trusted key, 1 for a bad or untrusted one, 2 when a
// file is missing.
var verifyCommand = &simpleCommand{
	name: "verify-report", args: "<report.json> [--key <pub>]", brief: "<report.json>", summary: "check a signed report",
	long: "Checks the signature <report.json>.sig that --sign wrote against this machine's report key, the keys " +
		"listed in config trusted_keys and --key. Exit 0 means the report is unchanged and signed by one of them, 1 a bad " +
		"or untrusted signature and 2 a missing file.",
	examples: []string{"verify-report review.json", "verify-report review.json --key ci-report-key.pub"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		var keys cli.RepeatFlag
		fs.Var(&keys, "key", "also trust this public key `file` (repeatable)")
		asJSON := fs.Bool("json", false, "print the kind verify JSON document")
		configFile := fs.String("config", "", "read trusted_keys from this config `file`")
		return func(_ context.Context, pos []string, stdout, _ io.Writer) error {
			if len(pos) != 1 {
				return cli.Usagef("verify-report takes one report: %s verify-report <report.json>", cli.Name())
			}
			return verifyReport(pos[0], keys, *configFile, *asJSON, stdout)
		}
	},
}

func verifyReport(path string, keys []string, configFile string, asJSON bool, stdout io.Writer) error {
	signer := core.GetSigner()
	if signer == nil {
		return fmt.Errorf("signer %w", core.ErrNotLinked)
	}
	body, err := readNamed(path, "")
	if err != nil {
		return err
	}
	sig, err := readNamed(path+".sig", "it was not signed: sign a review with --sign -o <file>.json")
	if err != nil {
		return err
	}
	trusted, err := trustedKeys(keys, configFile)
	if err != nil {
		return err
	}
	keyID, verr := signer.Verify(body, sig, trusted)
	if asJSON {
		verdict := core.VerdictOK
		if verr != nil {
			verdict = core.VerdictFindings
		}
		if err := writeDocument(stdout, core.KindVerify, verdict,
			core.VerifyData{File: shown(path), Key: keyID, Trusted: verr == nil, Valid: verr == nil}); err != nil {
			return err
		}
	}
	if verr != nil {
		e := &core.Error{Exit: cli.ExitFindings, Command: "verify-report",
			What: fmt.Sprintf("%s: the signature doesn't check out (%v)", shown(path), verr),
			Hint: []string{"the report changed after it was signed, or its key isn't trusted here (add it with --key or trusted_keys)"}}
		if asJSON {
			// The document already says so; stderr gets the line too.
			e.Hint = nil
		}
		return e
	}
	if !asJSON {
		fmt.Fprintf(stdout, "%s: signature good, signed by %s\n", shown(path), keyID)
	}
	return nil
}

// readNamed reads a file the user named. A missing one is exit 2.
func readNamed(path, hint string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // a file the user named
	if err == nil {
		return b, nil
	}
	e := &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, Command: "verify-report", Err: err,
		What: fmt.Sprintf("can't read %s (%v)", shown(path), errors.Unwrap(err))}
	if errors.Is(err, fs.ErrNotExist) {
		e.What = shown(path) + ": no such file"
	}
	if hint != "" {
		e.Hint = []string{hint}
	}
	return nil, e
}

// trustedKeys gathers the public keys a signature may come from: this
// machine's report key, every --key file and each config trusted_keys
// value (a key file's path, or the key itself).
func trustedKeys(files []string, configFile string) ([][]byte, error) {
	var keys [][]byte
	if dir, err := config.Dir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "sightread", "report-key.pub")); err == nil { //nolint:gosec // our own key
			keys = append(keys, b)
		}
	}
	for _, f := range files {
		b, err := readNamed(f, "")
		if err != nil {
			return nil, err
		}
		keys = append(keys, b)
	}
	if policy := core.GetPolicy(); policy != nil {
		cfg, cfgPath, err := policy.LoadConfig(".", configFile, false)
		if err != nil {
			return nil, err
		}
		for _, k := range cfg.TrustedKeys {
			p := k
			if !filepath.IsAbs(p) {
				p = filepath.Join(projectDir(cfgPath), p)
			}
			if b, err := os.ReadFile(p); err == nil { //nolint:gosec // a key file the config names
				keys = append(keys, b)
				continue
			}
			keys = append(keys, []byte(k))
		}
	}
	return keys, nil
}

// inRepoRoot returns copies of ups whose installed path and lockfile,
// relative to a target at repoPath, are relative to the repository root
// instead.
func inRepoRoot(ups []core.Update, repoPath string) []core.Update {
	out := slices.Clone(ups)
	for i := range out {
		in := &out[i].Installed
		if in.Path != "" && !path.IsAbs(filepath.ToSlash(in.Path)) {
			in.Path = path.Join(repoPath, filepath.ToSlash(in.Path))
		}
		if in.Lockfile != "" && !path.IsAbs(filepath.ToSlash(in.Lockfile)) {
			in.Lockfile = path.Join(repoPath, filepath.ToSlash(in.Lockfile))
		}
	}
	return out
}
