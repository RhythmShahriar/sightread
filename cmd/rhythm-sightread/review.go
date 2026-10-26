// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/run"
)

// reviewCommand is one of the review commands of PRD 6.1 to 6.4.
type reviewCommand struct {
	name, args, summary string
	long                string   // the paragraph under the usage line
	examples            []string // command lines after the program name
	eco                 core.Ecosystem
	named               bool // takes package names (plugin, theme, composer, npm)
	needsName           bool // at least one name (plugin, theme)
	soundcheck          bool // takes the Soundcheck flags
	contacts            bool // its help page lists the contacted hosts
}

var reviewCommands = []*reviewCommand{
	{name: "plugin", args: "<slug>... [flags]", summary: "review a WordPress.org plugin update",
		long: "Reviews a WordPress.org plugin update before you install it. Sightread fetches the installed version and the one " +
			"WordPress.org offers, checks both against WordPress.org's checksums, diffs them and ranks what is new. " +
			"Without --from it reads the installed version under --path. It never runs the code.",
		examples: []string{"plugin akismet --from 5.3.3", "plugin woocommerce --path /var/www/shop -o review.html --open",
			"plugin akismet --to list", "plugin gravityforms --to-file ~/zips/gravityforms-2.9.1.zip"},
		eco: core.WPPlugin, named: true, needsName: true, soundcheck: true, contacts: true},
	{name: "theme", args: "<slug>... [flags]", summary: "review a WordPress.org theme update",
		long: "Reviews a WordPress.org theme update before you install it: the installed version under --path against the one " +
			"WordPress.org offers. WordPress.org publishes no theme checksums, so a theme is verified by TLS, or file by " +
			"file against themes.svn.wordpress.org with --svn-check. It never runs the code.",
		examples: []string{"theme astra --path /var/www/shop", "theme astra --from 4.8.0 --svn-check"},
		eco:      core.WPTheme, named: true, needsName: true, soundcheck: true},
	{name: "composer", args: "[<vendor/pkg>...] [flags]", summary: "review Composer updates in composer.lock",
		long: "Reviews the Composer updates of composer.lock under --path: by default the newest version each composer.json " +
			"constraint allows. Names limit it to those packages; --transitive adds packages you don't require directly. " +
			"It never runs the code or any Composer script.",
		examples: []string{"composer --path api", "composer monolog/monolog --to 3.12.1", "composer --transitive --md -o composer.md"},
		eco:      core.Composer, named: true, soundcheck: true},
	{name: "npm", args: "[<pkg>...] [flags]", summary: "review npm updates in the lockfile",
		long: "Reviews the npm updates of the first lockfile under --path (npm-shrinkwrap.json, package-lock.json, " +
			"pnpm-lock.yaml, yarn.lock, bun.lock): by default the newest version each package.json range allows. Names " +
			"limit it to those packages. It never runs the code or any install script.",
		examples: []string{"npm --path web --sarif -o sightread.sarif", "npm axios --to latest", "npm left-pad --to list"},
		eco:      core.NPM, named: true, soundcheck: true},
	{name: "all", args: "[<path>] [flags]", summary: "review every available update in a site or project",
		long: "Reviews every available update a folder holds in one report: WordPress plugins and themes (the WordPress root " +
			"is found up to 6 folders down), composer.lock and npm lockfiles. With --sites it reviews every site of a fleet " +
			"file once per update.",
		examples: []string{"all /var/www/shop -o review.html --open", "all --sites sites.yaml --md -o fleet.md",
			"all --only wp-plugin:* --fail-on high"},
		contacts: true},
	{name: "changes", args: "[--base <ref>] [flags]", summary: "review every version a lockfile change moves",
		long: "Reviews every package a lockfile change adds or moves, transitive ones included: each lockfile at --base " +
			"against the working tree, or --before against --after with no git. Allow entries count from the base ref " +
			"only, so a pull request can't approve its own update. This is what the GitHub Action runs on pull requests.",
		examples: []string{"changes --base origin/main --fail-on high --md",
			"changes --before old.json --after package-lock.json"},
		contacts: true},
}

// flags returns c's flag set, with every flag of its groups registered.
func (c *reviewCommand) flags(stderr io.Writer) (*flag.FlagSet, *reviewFlags) {
	f := &reviewFlags{}
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	f.register(fs, c)
	fs.Usage = func() { c.usage(fs.Output(), fs, f) }
	return fs, f
}

// command is c as a kit command.
func (c *reviewCommand) command() cli.Command {
	return cli.Command{
		Name: c.name, Args: c.args, Summary: c.summary,
		Flags: func() *flag.FlagSet { fs, _ := c.flags(io.Discard); return fs },
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			p, pos, err := c.parse(args, stdout, stderr)
			if err != nil {
				return finish(stderr, err, false)
			}
			return finish(stderr, c.run(ctx, p, pos, stdout, stderr), p.verbose)
		},
	}
}

// parse reads args into a plan.
func (c *reviewCommand) parse(args []string, stdout, stderr io.Writer) (*plan, []string, error) {
	own, pass := splitPassthrough(args)
	fs, f := c.flags(stderr)
	if cli.HasFlag(own, "h") || cli.HasFlag(own, "help") {
		fs.SetOutput(stdout) // help asked for is not an error, so it goes to stdout
	}
	pos, err := cli.ParseArgs(fs, own)
	if err != nil {
		return nil, nil, err
	}
	f.set, f.passthrough = visited(fs, f.shortOf), pass
	p, err := f.plan(c, os.Getenv, version, stderr)
	if err != nil {
		return nil, nil, err
	}
	if err := c.positional(p, f, pos); err != nil {
		return nil, nil, err
	}
	if err := c.checkSoundcheck(p); err != nil {
		return nil, nil, err
	}
	return p, pos, nil
}

// positional applies the arguments after the command.
func (c *reviewCommand) positional(p *plan, f *reviewFlags, pos []string) error {
	q := &p.req
	switch {
	case c.needsName && len(pos) == 0:
		return cli.Usagef("%s needs a slug: %s %s <slug>", c.name, cli.Name(), c.name)
	case c.named:
		q.Names = pos
	case c.name == "all":
		if len(pos) > 1 {
			return cli.Usagef("all takes one folder, got %d", len(pos))
		}
		if len(pos) == 1 {
			q.Inventory.Root = pos[0]
			q.Set["path"] = true
		}
		if f.sites != "" {
			sites, err := run.LoadSites(f.sites)
			if err != nil {
				return err
			}
			q.Sites = sites
		}
	case c.name == "changes":
		if len(pos) > 0 {
			return cli.Usagef("changes takes no arguments; name lockfiles with --lockfile")
		}
		if (f.before == "") != (f.after == "") {
			return badFlag("--before and --after go together: the old and the new lockfile")
		}
		if f.before != "" && f.base != "" {
			return badFlag("--base reads the lockfiles from git and --before and --after from files: pick one")
		}
		base := f.base
		if base == "" && f.before == "" {
			if ref := os.Getenv("GITHUB_BASE_REF"); ref != "" {
				base = "origin/" + ref
			}
		}
		q.Changes = &core.ChangesRequest{Repo: q.Inventory.Root, Base: base, Before: f.before, After: f.after,
			Lockfiles: slices.Clone(f.lockfiles)}
	}
	if !c.named && (q.ToFile != "" || q.FromFile != "") {
		return badFlag("--to-file and --from-file review one package: use %s plugin, theme, composer or npm with a name", cli.Name())
	}
	return nil
}

// run reviews and writes the report.
func (c *reviewCommand) run(ctx context.Context, p *plan, _ []string, stdout, stderr io.Writer) error {
	if p.req.To == run.ToList {
		return c.list(ctx, p, stdout)
	}
	if cli.IsTerminal(stderr) && !p.write.Quiet && p.stdout == core.FormatTerminal {
		p.req.Progress = stderr
	}
	hard, stopHard := hardStop()
	defer stopHard()
	p.req.HardStop = hard

	stream, err := newStreams(p, stdout)
	if err != nil {
		return err
	}
	defer stream.abort()
	p.req.OnUpdate = stream.update
	probs := &problems{}
	p.req.OnProblem = probs.add

	rep, err := run.Review(ctx, p.req)
	if err != nil {
		return err
	}
	// --soundcheck runs before the report is written, so the report holds
	// what the staging site did; a refusal is returned once it is written.
	tripped, scErr := false, error(nil)
	if p.soundcheck.Staging != "" {
		tripped, scErr = c.runSoundcheck(ctx, p, rep)
	}
	// With nothing to compare the terminal says only that while every -o
	// file is still written: a CI job reads it and a missing report
	// would look like a failed run.
	quiet := p.stdout == core.FormatTerminal && nothingElse(rep)
	if err := writeOutputs(p, rep, stdout, stream, !quiet); err != nil {
		return err
	}
	if quiet {
		for _, n := range rep.Notes {
			if strings.HasSuffix(n, run.NothingToCompare) {
				fmt.Fprintln(stdout, n)
			}
		}
		return nil
	}
	if p.open {
		openReport(ctx, p, stderr)
	}
	if scErr != nil {
		return scErr
	}
	if len(rep.Updates) == 0 && probs.any() {
		// Nothing could be checked at all: that is a failed run, not a
		// run with gaps, whatever --fail-on says (PRD 10, E7 to E16).
		probs.print(stderr, rep)
		return &cli.ExitError{Code: cli.ExitUnavailable}
	}
	err = gate(rep, p.gate)
	if ee := (*cli.ExitError)(nil); errors.As(err, &ee) && ee.Code == cli.ExitUnavailable {
		probs.print(stderr, rep)
		if tripped {
			// Findings beat gaps (PRD 10): the Soundcheck gate is 1.
			return cli.ErrFindings
		}
	}
	if err == nil && tripped {
		return cli.ErrFindings
	}
	return err
}

// problems collects the coded errors that kept packages from being
// reviewed, from every worker, to print when the run fails.
type problems struct {
	mu   sync.Mutex
	errs []*core.Error
}

func (p *problems) add(e *core.Error) {
	p.mu.Lock()
	p.errs = append(p.errs, e)
	p.mu.Unlock()
}

func (p *problems) any() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.errs) > 0
}

// print writes each problem once, in a stable order, the way PRD
// section 10 shows it. The rate limit hint gets the run's count of
// reviewed updates, which only the run knows.
func (p *problems) print(w io.Writer, rep *core.Report) {
	p.mu.Lock()
	defer p.mu.Unlock()
	failed := 0
	for _, n := range rep.NotChecked {
		if n.Reason == core.FetchFailed || n.Reason == core.TooLarge {
			failed++
		}
	}
	seen := map[string]bool{}
	var lines []string
	for _, e := range p.errs {
		c := *e
		reviewed, total := len(rep.Updates), len(rep.Updates)+failed
		var budget *fetch.ErrGitHubBudget
		switch {
		case c.Code == core.ERateLimited && len(c.Hint) > 0:
			c.Hint = slices.Clone(c.Hint)
			c.Hint[0] = fmt.Sprintf("reviewed %d of %d updates; %s", reviewed, total, c.Hint[0])
		case c.Code == core.EGitHubLimit && errors.As(c.Err, &budget):
			c = *fetch.GitHubLimitError(c.Command, budget.Limit, budget.Needed, reviewed, total)
		case fetch.IsOffline(&c) && failed > 0:
			c.Hint = slices.Clone(c.Hint)
			c.Hint[0] = fetch.OfflineHint(failed, total)
		}
		if text := c.Error(); !seen[text] {
			seen[text] = true
			lines = append(lines, text)
		}
	}
	slices.Sort(lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// nothingElse reports whether a run reviewed nothing and left nothing
// out, so only its "nothing to compare" notes have something to say.
func nothingElse(rep *core.Report) bool {
	return len(rep.Updates) == 0 && len(rep.NotChecked) == 0 && len(rep.Errors) == 0 && rep.StoppedBy == "" &&
		slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.HasSuffix(n, run.NothingToCompare) })
}

// list answers --to list.
func (c *reviewCommand) list(ctx context.Context, p *plan, stdout io.Writer) error {
	if len(p.req.Names) == 0 {
		return cli.Usagef("--to list needs a package name: %s %s <name> --to list", cli.Name(), c.name)
	}
	lists, err := run.ListVersions(ctx, p.req)
	if err != nil {
		return err
	}
	for _, l := range lists {
		if len(lists) > 1 {
			fmt.Fprintf(stdout, "%s:\n", l.Name)
		}
		for _, v := range l.Versions {
			fmt.Fprintln(stdout, v)
		}
	}
	return nil
}

// gate turns the scorer's gate into the exit code of PRD section 10.
func gate(rep *core.Report, o core.GateOptions) error {
	s := core.GetScorer()
	if s == nil {
		return fmt.Errorf("scorer %w", core.ErrNotLinked)
	}
	o.FailOn, _ = cli.ParseFailOn(rep.FailOn) // checked by the flag or the config loader
	switch code, reason := s.Gate(rep, o); code {
	case cli.ExitOK:
		return nil
	case cli.ExitFindings:
		return cli.ErrFindings
	default:
		return &cli.ExitError{Code: code, Err: errors.New(reason)}
	}
}

// writeOutputs writes the report to every -o file and, when toStdout is
// set, to stdout: JSON first, so --sign can sign it and the other
// formats can name its hash.
func writeOutputs(p *plan, rep *core.Report, stdout io.Writer, stream *streams, toStdout bool) error {
	files := slices.Clone(p.files)
	slices.SortStableFunc(files, func(a, b output) int {
		return cmp.Compare(boolRank(a.format != core.FormatJSON), boolRank(b.format != core.FormatJSON))
	})
	o := p.write
	for _, f := range files {
		if f.format == core.FormatJSONL {
			if err := stream.closeFile(f.path, rep, o); err != nil {
				return err
			}
			continue
		}
		b, err := render(f.format, rep, o)
		if err != nil {
			return err
		}
		if err := run.WriteFile(f.path, b); err != nil {
			return fmt.Errorf("-o %s: %w", f.path, err)
		}
		if f.format == core.FormatJSON && p.sign && o.Signed == "" {
			if err := signReport(f.path); err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			o.Signed = hex.EncodeToString(sum[:])
		}
	}
	if !toStdout {
		return nil
	}
	if p.stdout == core.FormatJSONL {
		return stream.closeStdout(rep, o)
	}
	w := core.WriterFor(p.stdout)
	if w == nil {
		return fmt.Errorf("%s writer %w", p.stdout, core.ErrNotLinked)
	}
	return w.Write(stdout, rep, o)
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// render writes rep in format to memory, for a file written whole.
func render(format string, rep *core.Report, o core.WriteOptions) ([]byte, error) {
	w := core.WriterFor(format)
	if w == nil {
		return nil, fmt.Errorf("%s writer %w", format, core.ErrNotLinked)
	}
	var b bytes.Buffer
	if err := w.Write(&b, rep, o); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// signReport signs a JSON report with the machine's report key.
func signReport(path string) error {
	s := core.GetSigner()
	if s == nil {
		return fmt.Errorf("signer %w", core.ErrNotLinked)
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	if _, err := s.Sign(path, filepath.Join(dir, "sightread", "report-key")); err != nil {
		return fmt.Errorf("--sign: %w", err)
	}
	return nil
}

// streams writes --jsonl lines as updates finish: to stdout and to each
// .jsonl -o file through a temp file renamed once the run is complete.
type streams struct {
	mu     sync.Mutex
	stdout io.Writer // nil unless --jsonl prints to stdout
	files  map[string]*os.File
	opts   core.WriteOptions
	err    error
}

func newStreams(p *plan, stdout io.Writer) (*streams, error) {
	s := &streams{files: map[string]*os.File{}, opts: p.write}
	if p.stdout == core.FormatJSONL {
		s.stdout = stdout
	}
	for _, f := range p.files {
		if f.format != core.FormatJSONL {
			continue
		}
		dir := filepath.Dir(f.path)
		tmp, err := os.CreateTemp(dir, ".tmp-*.jsonl")
		if err != nil {
			s.abort()
			return nil, fmt.Errorf("-o %s: %w", f.path, err)
		}
		s.files[f.path] = tmp
	}
	return s, nil
}

func (s *streams) writer() core.StreamWriter {
	sw, _ := core.WriterFor(core.FormatJSONL).(core.StreamWriter)
	return sw
}

// targetWriter is the jsonl writer's WriteUpdate that also knows the
// report's target (report.JSONLWriter.WriteUpdateIn).
type targetWriter interface {
	WriteUpdateIn(w io.Writer, u *core.Update, target string, o core.WriteOptions) error
}

// writeUpdate writes u with sw, relative to target when sw can.
func writeUpdate(sw core.StreamWriter, w io.Writer, u *core.Update, target string, o core.WriteOptions) error {
	if tw, ok := sw.(targetWriter); ok {
		return tw.WriteUpdateIn(w, u, target, o)
	}
	return sw.WriteUpdate(w, u, o)
}

// update writes one finished update of the report on target to every
// stream. With RedactPaths a path inside target is written relative to
// it, as the closing json envelope writes it.
func (s *streams) update(u core.Update, target string) {
	if s.stdout == nil && len(s.files) == 0 {
		return
	}
	sw := s.writer()
	if sw == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stdout != nil {
		if err := writeUpdate(sw, s.stdout, &u, target, s.opts); err != nil && s.err == nil {
			s.err = err
		}
	}
	for _, f := range s.files {
		if err := writeUpdate(sw, f, &u, target, s.opts); err != nil && s.err == nil {
			s.err = err
		}
	}
}

// closeStdout writes the closing envelope to stdout.
func (s *streams) closeStdout(rep *core.Report, o core.WriteOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	w := core.WriterFor(core.FormatJSONL)
	if w == nil {
		return fmt.Errorf("jsonl writer %w", core.ErrNotLinked)
	}
	return w.Write(s.stdout, rep, o)
}

// closeFile writes the closing envelope to one .jsonl file and puts it
// in place, mode 0600.
func (s *streams) closeFile(path string, rep *core.Report, o core.WriteOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.files[path]
	delete(s.files, path)
	w := core.WriterFor(core.FormatJSONL)
	err := s.err
	if err == nil && w == nil {
		err = fmt.Errorf("jsonl writer %w", core.ErrNotLinked)
	}
	if err == nil {
		err = w.Write(f, rep, o)
	}
	if cerr := f.Chmod(0o600); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("-o %s: %w", path, err)
	}
	return nil
}

// abort removes the temp files of streams never closed.
func (s *streams) abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for path, f := range s.files {
		_ = f.Close()
		_ = os.Remove(f.Name())
		delete(s.files, path)
	}
}

// hardStop returns a channel closed on the second Ctrl-C. The first one
// cancels the command's context (cli.Main does that), which lets the
// packages under way finish; the second ends the run at once.
func hardStop() (<-chan struct{}, func()) {
	hard := make(chan struct{})
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		n := 0
		for {
			select {
			case <-sig:
				// cli.Main's own handler sees the first signal too; the
				// count here only decides when the second has come.
				if n++; n >= 2 {
					close(hard)
					return
				}
			case <-done:
				return
			}
		}
	}()
	return hard, func() { signal.Stop(sig); close(done) }
}
