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
	"text/tabwriter"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
	"github.com/RhythmShahriar/sightread/run"
)

// gitTimeout bounds `git config user.name`.
const gitTimeout = 5 * time.Second

// allowFlags are the flags of allow and its list, remove and import.
type allowFlags struct {
	reason, by, until, file, from string
	signals                       cli.ListFlag
	asJSON, offline               bool
	configFile                    string
	noConfig                      bool
}

// allowCommand is `allow` (PRD 6.6): it records reviewed versions in
// .sightread/allowed.yaml, bound to the sha256 of the bytes that were
// verified. It also lists, removes and imports entries.
var allowCommand = &simpleCommand{
	name: "allow", args: "<eco:name@version>... --reason <text> | --from <report.json> | list | remove <ref> | import <file>",
	brief:   "<eco:name@version>...",
	summary: "record a reviewed version",
	long: "Records that someone reviewed a version, so later reviews show its findings as allowed. An entry is bound to " +
		"the sha256 of the archive that was verified: allow fetches and verifies the version itself, or takes the hash " +
		"from a saved report with --from. It refuses a version that couldn't be verified or doesn't match its " +
		"published hash. list prints the entries, remove drops one and import merges another allowed.yaml. Commit " +
		"the file and protect it with CODEOWNERS.",
	examples: []string{
		"allow npm:sharp@0.33.5 --reason \"known install script\" --signals npm-install-script-new",
		"allow --from review.json --reason \"reviewed in PR 412\"", "allow list --json", "allow remove npm:sharp@0.33.5",
		"allow import ~/agency/allowed.yaml"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		f := &allowFlags{}
		fs.StringVar(&f.reason, "reason", "", "why it is accepted, in `text` the next person understands (required when adding)")
		fs.StringVar(&f.by, "by", "", "the `name` of who reviewed it (default git config user.name, else $USER)")
		fs.StringVar(&f.until, "until", "", "`date` (YYYY-MM-DD) after which the entry no longer counts")
		fs.Var(&f.signals, "signals", "only these signal `IDs` (default every finding of that version)")
		fs.StringVar(&f.file, "file", "", "the allow `file` (default .sightread/allowed.yaml next to the config)")
		fs.StringVar(&f.from, "from", "", "take every update of this saved JSON `report`")
		fs.BoolVar(&f.asJSON, "json", false, "allow list: print the kind allowed JSON document")
		fs.BoolVar(&f.offline, "offline", false, "use only cached archives (also RHYTHM_OFFLINE)")
		fs.StringVar(&f.configFile, "config", "", "read this config `file` instead of the nearest .sightread/config.yaml")
		fs.BoolVar(&f.noConfig, "no-config", false, "read no config")
		return func(ctx context.Context, pos []string, stdout, stderr io.Writer) error {
			return f.run(ctx, pos, stdout, stderr)
		}
	},
}

func (f *allowFlags) run(ctx context.Context, pos []string, stdout, stderr io.Writer) error {
	if f.configFile != "" && f.noConfig {
		return badFlag("--config and --no-config can't be used together")
	}
	policy, err := policyNow()
	if err != nil {
		return err
	}
	cfg, cfgPath, err := policy.LoadConfig(".", f.configFile, f.noConfig)
	if err != nil {
		return err
	}
	path := allowPath(f.file, cfg, cfgPath)
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}
	switch sub {
	case "list":
		if len(pos) > 1 {
			return cli.Usagef("allow list takes no arguments, got %q", pos[1])
		}
		return f.list(policy, cfg, cfgPath, path, stdout)
	case "remove":
		if len(pos) < 2 {
			return cli.Usagef("allow remove needs a package: %s allow remove <eco:name[@version]>", cli.Name())
		}
		for _, raw := range pos[1:] {
			ref, err := parseAllowRef(raw, false)
			if err != nil {
				return err
			}
			if err := policy.RemoveAllow(path, ref); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "removed %s from %s\n", ref, shown(path))
		}
		return nil
	case "import":
		if len(pos) != 2 {
			return cli.Usagef("allow import takes one file: %s allow import <allowed.yaml>", cli.Name())
		}
		n, err := policy.ImportAllow(path, pos[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "imported %s from %s into %s\n", plural(n, "entry", "entries"), shown(pos[1]), shown(path))
		return nil
	}
	if strings.TrimSpace(f.reason) == "" {
		return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, Command: "allow",
			What: "--reason is required, so the next person knows why it is allowed",
			Hint: []string{"add --reason \"<what you checked>\""}}
	}
	if f.until != "" {
		if _, err := time.Parse(time.DateOnly, f.until); err != nil {
			return badFlag("--until %q: want a date such as 2027-01-31", f.until)
		}
	}
	for _, id := range f.signals {
		if _, ok := core.Signal(id); !ok {
			return unknownSignal(id)
		}
	}
	if f.by == "" {
		f.by = reviewer(ctx)
	}
	switch {
	case f.from != "" && len(pos) > 0:
		return cli.Usagef("give packages or --from <report.json>, not both")
	case f.from != "":
		return f.fromReport(policy, path, stdout, stderr)
	case len(pos) == 0:
		return cli.Usagef("allow needs a package such as npm:left-pad@1.4.0, or --from <report.json>")
	}
	refs := make([]core.Ref, 0, len(pos))
	for _, raw := range pos {
		ref, err := parseAllowRef(raw, true)
		if err != nil {
			return err
		}
		refs = append(refs, ref)
	}
	for _, ref := range refs {
		side, err := run.Verify(ctx, run.Request{Command: "allow", Version: version, ConfigFile: f.configFile, NoConfig: f.noConfig,
			NoAllow: true, Getter: envGetter(os.Getenv, f.offline)}, ref)
		if err != nil {
			return err
		}
		if err := refuse(ref, side.Verified, false); err != nil {
			return err
		}
		if err := f.add(policy, path, ref, side, stdout); err != nil {
			return err
		}
	}
	return nil
}

// fromReport allows every update a saved report reviewed. A refused
// update is reported and the others are still recorded; the exit is 2
// when any was refused.
func (f *allowFlags) fromReport(policy core.Policy, path string, stdout, stderr io.Writer) error {
	rep, err := readReport("allow", f.from)
	if err != nil {
		return err
	}
	if len(rep.Updates) == 0 {
		return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, Command: "allow",
			What: shown(f.from) + " reviewed no update, so there is nothing to allow"}
	}
	refused := 0
	for _, u := range rep.Updates {
		ref := core.Ref{Eco: u.Eco, Name: u.Name, Version: u.To.Version}
		mismatch := slices.ContainsFunc(u.Findings, func(f core.Finding) bool { return f.ID == "integrity-mismatch" })
		if err := refuse(ref, u.To.Verified, mismatch); err != nil {
			fmt.Fprintln(stderr, err.Error())
			refused++
			continue
		}
		if err := f.add(policy, path, ref, u.To, stdout); err != nil {
			return err
		}
	}
	if refused > 0 {
		return &cli.ExitError{Code: cli.ExitUsage}
	}
	return nil
}

// add writes one entry.
func (f *allowFlags) add(policy core.Policy, path string, ref core.Ref, side core.Side, stdout io.Writer) error {
	e := core.AllowEntry{Package: ref.Unversioned().String(), Version: ref.Version, SHA256: side.SHA256,
		Signals: slices.Clone(f.signals), Reason: strings.TrimSpace(f.reason), By: f.by,
		Date: time.Now().Format(time.DateOnly), Until: f.until}
	if side.HashKind == core.HashManifest {
		e.Hash = core.HashManifest
	}
	if err := policy.AddAllow(path, e); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "allowed %s (sha256 %s) in %s\n", ref, short(side.SHA256), shown(path))
	return nil
}

// refuse is E18 (PRD 10): a version that couldn't be verified, or whose
// bytes don't match the published hash, has no hash worth binding an
// entry to.
func refuse(ref core.Ref, by core.VerifiedBy, mismatch bool) error {
	review := fmt.Sprintf("review it first with %s %s %s --to %s", cli.Name(), ecoCommandName(ref.Eco), ref.Name, ref.Version)
	switch {
	case mismatch || by == core.ByFailed:
		return &core.Error{Code: core.EAllowUnverified, Exit: cli.ExitUsage, Command: "allow",
			What: ref.String() + " doesn't match its published hash, so it can't be allowed",
			Hint: []string{"someone between you and the registry changed it, or the release was edited; don't install this copy"}}
	case by == core.ByNone || by == "":
		return &core.Error{Code: core.EAllowUnverified, Exit: cli.ExitUsage, Command: "allow",
			What: ref.String() + " couldn't be verified, so it can't be allowed",
			Hint: []string{"allow records a reviewed archive by its hash; " + review}}
	}
	return nil
}

// list prints the allow entries, or the kind allowed document.
func (f *allowFlags) list(policy core.Policy, cfg *core.Config, cfgPath, path string, stdout io.Writer) error {
	c := *cfg
	c.AllowFile, c.AllowFrom = path, nil
	set, err := policy.LoadAllow(&c, cfgPath, "")
	if err != nil {
		return err
	}
	lister, ok := set.(interface{ Entries() []core.AllowEntry })
	if !ok {
		return errors.New("the linked policy can't list allow entries")
	}
	entries := lister.Entries()
	if entries == nil {
		entries = []core.AllowEntry{}
	}
	if f.asJSON {
		return writeDocument(stdout, core.KindAllowed, "", core.AllowedData{File: shown(path), Entries: entries})
	}
	if len(entries) == 0 {
		fmt.Fprintf(stdout, "%s allows nothing yet\n", shown(path))
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tSHA256\tSIGNALS\tBY\tDATE\tUNTIL\tREASON")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s@%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Package, e.Version, short(e.SHA256),
			cmp.Or(strings.Join(e.Signals, ","), "all"), e.By, e.Date, cmp.Or(e.Until, "-"), e.Reason)
	}
	return tw.Flush()
}

// parseAllowRef reads a package reference; adding needs its version.
func parseAllowRef(raw string, needVersion bool) (core.Ref, error) {
	ref, err := core.ParseRef(raw)
	if err != nil {
		return core.Ref{}, cli.Usagef("%v", err)
	}
	if needVersion && ref.Version == "" {
		return core.Ref{}, cli.Usagef("%s needs a version: %s@<version>", raw, ref)
	}
	return ref, nil
}

// reviewer is the default --by: git config user.name, else the login
// name the environment gives.
func reviewer(ctx context.Context) string {
	if _, err := proc.LookPath("git"); err == nil {
		res, err := proc.Run(ctx, proc.Spec{Argv: []string{"git", "config", "user.name"}, Purpose: proc.PurposeGit, Timeout: gitTimeout})
		if name := strings.TrimSpace(string(res.Stdout)); err == nil && res.Code == 0 && name != "" {
			return name
		}
	}
	return cmp.Or(os.Getenv("USER"), os.Getenv("USERNAME"), "unknown")
}

// short is the first 12 hex of a sha256, as reports show it.
func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// ecoCommandName is the review command of an ecosystem.
func ecoCommandName(eco core.Ecosystem) string {
	switch eco {
	case core.WPPlugin:
		return "plugin"
	case core.WPTheme:
		return "theme"
	}
	return string(eco)
}
