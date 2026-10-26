// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// simpleCommand is a command outside the review group: its own flags, a
// help page with one Flags block and examples.
type simpleCommand struct {
	name, args, summary string
	// brief is args in the top-level command list, which kit pads to
	// its longest entry; empty means args. The help page shows args.
	brief    string
	long     string   // the paragraph under the usage line
	examples []string // command lines after the program name
	// flags registers the command's flags on fs and returns what runs
	// it with the positional arguments.
	flags func(fs *flag.FlagSet, s *simpleFlags) runFunc
}

// runFunc runs a simple command once its flags are parsed.
type runFunc func(ctx context.Context, pos []string, stdout, stderr io.Writer) error

// simpleFlags records the one-letter aliases a simple command declares.
type simpleFlags struct {
	shortOf map[string]string // long name to its one-letter alias
	verbose bool
}

// short registers a one-letter alias of a long flag.
func (s *simpleFlags) short(fs *flag.FlagSet, letter, long string) {
	fs.Var(fs.Lookup(long).Value, letter, fs.Lookup(long).Usage)
	if s.shortOf == nil {
		s.shortOf = map[string]string{}
	}
	s.shortOf[long] = letter
}

func (c *simpleCommand) flagSet(stderr io.Writer) (*flag.FlagSet, *simpleFlags, runFunc) {
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	sf := &simpleFlags{}
	run := c.flags(fs, sf)
	fs.Usage = func() { c.usage(fs.Output(), fs, sf) }
	return fs, sf, run
}

// command is c as a kit command.
func (c *simpleCommand) command() cli.Command {
	return cli.Command{
		Name: c.name, Args: cmp.Or(c.brief, c.args), Summary: c.summary,
		Flags: func() *flag.FlagSet { fs, _, _ := c.flagSet(io.Discard); return fs },
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			fs, sf, run := c.flagSet(stderr)
			if cli.HasFlag(args, "h") || cli.HasFlag(args, "help") {
				fs.SetOutput(stdout) // help asked for is not an error, so it goes to stdout
			}
			pos, err := cli.ParseArgs(fs, args)
			if err != nil {
				return err
			}
			return finish(stderr, run(ctx, pos, stdout, stderr), sf.verbose)
		},
	}
}

// usage writes c's help page: the usage line, what it does, its flags
// and examples. Every program name is cli.Name().
func (c *simpleCommand) usage(w io.Writer, fs *flag.FlagSet, sf *simpleFlags) {
	prog := cli.Name()
	fmt.Fprintf(w, "Usage: %s %s %s\n\n", prog, c.name, c.args)
	fmt.Fprintln(w, wrap(strings.ReplaceAll(c.long, "{prog}", prog), helpWidth, ""))
	letters := map[string]bool{}
	for _, l := range sf.shortOf {
		letters[l] = true
	}
	var rows [][2]string
	width := 0
	fs.VisitAll(func(fl *flag.Flag) {
		if letters[fl.Name] {
			return
		}
		left, text := flagRow(fl, sf.shortOf[fl.Name])
		rows = append(rows, [2]string{left, text})
		width = max(width, len(left))
	})
	if len(rows) > 0 {
		width = min(width, 28)
		fmt.Fprintln(w, "\nFlags:")
		for _, r := range rows {
			indent := strings.Repeat(" ", 2+width+3)
			if len(r[0]) > width {
				fmt.Fprintf(w, "  %s\n%s\n", r[0], wrap(r[1], helpWidth, indent))
				continue
			}
			fmt.Fprintf(w, "  %-*s   %s\n", width, r[0], strings.TrimPrefix(wrap(r[1], helpWidth, indent), indent))
		}
	}
	if len(c.examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		for _, e := range c.examples {
			fmt.Fprintf(w, "  %s %s\n", prog, e)
		}
	}
}

// documentWriter is the JSON writer's way to write a kind other than
// review in the rhythm-sightread/v1 envelope (package report).
type documentWriter interface {
	WriteDocument(w io.Writer, env core.Envelope, o core.WriteOptions) error
}

// writeDocument writes data as a JSON document of kind (signals,
// allowed, explain, doctor, verify) through the linked JSON writer, so
// every Sightread document has one envelope.
func writeDocument(w io.Writer, kind, verdict string, data any) error {
	jw, ok := core.WriterFor(core.FormatJSON).(documentWriter)
	if !ok {
		return fmt.Errorf("json document writer %w", core.ErrNotLinked)
	}
	return jw.WriteDocument(w, core.Envelope{Kind: kind, Complete: true, Verdict: cmp.Or(verdict, core.VerdictOK), Data: data},
		core.WriteOptions{Program: cli.Name(), Version: version})
}

// policyNow returns the linked policy or the error cli.Main shows.
func policyNow() (core.Policy, error) {
	if p := core.GetPolicy(); p != nil {
		return p, nil
	}
	return nil, fmt.Errorf("policy %w", core.ErrNotLinked)
}

// projectDir is the folder whose .sightread/ holds the config and the
// allow file: the config's project, else the nearest folder at or above
// the working folder that has .sightread/, else the working folder.
func projectDir(cfgPath string) string {
	if cfgPath != "" {
		if filepath.Base(filepath.Dir(cfgPath)) == ".sightread" {
			return filepath.Dir(filepath.Dir(cfgPath))
		}
		return filepath.Dir(cfgPath)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for d := wd; ; d = filepath.Dir(d) {
		if fi, err := os.Stat(filepath.Join(d, ".sightread")); err == nil && fi.IsDir() {
			return d
		}
		if filepath.Dir(d) == d {
			return wd
		}
	}
}

// allowPath is the allow file allow writes: --file when given, else the
// config's allow_file relative to the project, else
// .sightread/allowed.yaml in the project.
func allowPath(file string, cfg *core.Config, cfgPath string) string {
	if file != "" {
		return file
	}
	p := cmp.Or(cfg.AllowFile, filepath.Join(".sightread", "allowed.yaml"))
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(projectDir(cfgPath), p)
}

// shown is path as messages print it: relative to the working folder
// when it is inside it, with forward slashes.
func shown(path string) string {
	wd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	if rel, err := filepath.Rel(wd, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(abs)
}

// envGetter is the Getter config a command outside the review group
// uses: the mirrors, tokens and offline switch of the environment.
func envGetter(env func(string) string, offline bool) core.GetterConfig {
	return core.GetterConfig{
		Bases:        mirrors(env),
		UserAgent:    "rhythm-sightread/" + version + " (+https://github.com/RhythmShahriar/sightread)",
		Proxy:        cmp.Or(env("HTTPS_PROXY"), env("https_proxy")),
		GitHubToken:  cmp.Or(env("GITHUB_TOKEN"), env("RHYTHM_GITHUB_TOKEN")),
		ScopeTokens:  scopeTokens(),
		ComposerAuth: env("COMPOSER_AUTH"),
		Offline:      offline || env(cli.OfflineEnv) != "",
	}
}

// plural is "1 file" or "3 files". many is the plural form when adding
// an s won't do ("indexes").
func plural(n int, word string, many ...string) string {
	if n == 1 {
		return "1 " + word
	}
	if len(many) > 0 {
		return fmt.Sprintf("%d %s", n, many[0])
	}
	return fmt.Sprintf("%d %ss", n, word)
}
