// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/term"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// The picker's choices (PRD 6.10), in the order it shows them.
const (
	pickAll     = "all"
	pickOne     = "one"
	pickChanges = "changes"
	pickDemo    = "demo"
	pickCI      = "ci"
)

// lookTimeout bounds the picker's look at the current folder.
const lookTimeout = 5 * time.Second

// pickCommand is the hidden command a bare terminal run becomes.
func pickCommand() cli.Command {
	return cli.Command{
		Name: "pick", Summary: "pick what to review (the bare terminal run)", Hidden: true,
		Flags: func() *flag.FlagSet { return pickFlags(io.Discard) },
		Run:   runPick,
	}
}

func pickFlags(stderr io.Writer) *flag.FlagSet {
	return cli.NewFlagSet("pick", "Usage: "+cli.Name()+"\n\nOn a terminal, asks what to review and prints the command it runs.", stderr)
}

func runPick(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := pickFlags(stderr)
	if cli.HasFlag(args, "h") || cli.HasFlag(args, "help") {
		fs.SetOutput(stdout)
	}
	if _, err := cli.ParseArgs(fs, args); err != nil {
		return err
	}
	if err := needTTY(isTerminalIn, openTTY); err != nil {
		return finish(stderr, err, false)
	}
	found := lookAround(ctx, ".")
	fmt.Fprintf(stdout, "\n  ♪ %s %s\n  What will this update really change?\n\n  %s\n\n", cli.Name(), version, found.describe())

	choice, kind, slug := pickDemo, "plugin", ""
	if found.any() {
		choice = pickAll
	}
	prog := cli.Name()
	opt := func(label, value, cmd string) huh.Option[string] {
		return huh.NewOption(fmt.Sprintf("%-40s %s %s", label, prog, cmd), value)
	}
	form := huh.NewForm(
		huh.NewGroup(huh.NewSelect[string]().Title("What should Sightread do?").Options(
			opt("Review every available update here", pickAll, "all"),
			opt("Review one plugin or theme", pickOne, "plugin <slug>"),
			opt("Review a lockfile change against main", pickChanges, "changes"),
			opt("Try it on built-in examples", pickDemo, "demo"),
			opt("Set up CI", pickCI, "init ci"),
		).Value(&choice)),
		huh.NewGroup(
			huh.NewSelect[string]().Title("A plugin or a theme?").Options(
				huh.NewOption("Plugin", "plugin"), huh.NewOption("Theme", "theme")).Value(&kind),
			huh.NewInput().Title("Its WordPress.org slug").Placeholder("akismet").Value(&slug).
				Validate(func(s string) error {
					if _, err := core.ParseRef("wp-plugin:" + strings.TrimSpace(s)); err != nil {
						return errors.New("enter a slug such as akismet")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return choice != pickOne }),
	).WithTheme(huh.ThemeCharm()).WithWidth(pickWidth(stdout))
	if err := form.RunWithContext(ctx); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return &cli.ExitError{Code: cli.ExitInterrupted}
		}
		return err
	}
	argv := pickArgs(choice, kind, slug)
	fmt.Fprintf(stdout, "→ %s %s\n\n", prog, strings.Join(argv, " "))
	for _, c := range commands() {
		if c.Name == argv[0] {
			return c.Run(ctx, argv[1:], stdout, stderr)
		}
	}
	return fmt.Errorf("pick: no command %s", argv[0])
}

// openTTY opens the terminal the picker falls back to when stdin is not
// one, as huh does.
func openTTY() (io.Closer, error) { return os.Open("/dev/tty") }

// needTTY refuses the picker (exit 2) when it has no terminal to read
// keys from: stdin is not one and the controlling terminal can't be
// opened. huh's own error would name /dev/tty and its library.
func needTTY(stdinTerminal func() bool, open func() (io.Closer, error)) error {
	if stdinTerminal() {
		return nil
	}
	if f, err := open(); err == nil {
		_ = f.Close()
		return nil
	}
	return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: "pick",
		What: "the picker needs a terminal to read keys from",
		Hint: []string{"run it in a terminal, or name a command: " + cli.Name() + " help lists them"}}
}

// defaultPickWidth is the picker's width when the terminal reports none.
const defaultPickWidth = 80

// pickWidth is the terminal's width, or defaultPickWidth when out is not
// a terminal or reports a width of 0. A pty with no window size would
// leave huh's input a negative width; it panics drawing it.
func pickWidth(out io.Writer) int {
	if f, ok := out.(*os.File); ok {
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 0 {
			return w
		}
	}
	return defaultPickWidth
}

// pickArgs is the command line a picker choice stands for.
func pickArgs(choice, kind, slug string) []string {
	switch choice {
	case pickOne:
		return []string{kind, strings.TrimSpace(slug)}
	case pickChanges:
		return []string{"changes"}
	case pickDemo:
		return []string{"demo"}
	case pickCI:
		return []string{"init", "ci"}
	}
	return []string{"all"}
}

// found is what the picker saw in the current folder.
type found struct {
	wordpress       bool
	plugins, themes int
	lockfiles       []string
}

func (f found) any() bool { return f.wordpress || len(f.lockfiles) > 0 }

// describe is the "Found here:" line.
func (f found) describe() string {
	var parts []string
	if f.wordpress {
		parts = append(parts, fmt.Sprintf("a WordPress site (%s, %s)", count(f.plugins, "plugin"), count(f.themes, "theme")))
	}
	parts = append(parts, f.lockfiles...)
	if len(parts) == 0 {
		return "Found here: no WordPress site or lockfile"
	}
	return "Found here: " + joinAnd(parts)
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// joinAnd joins "a", "b" and "c" as "a, b and c".
func joinAnd(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// lookAround reads the inventory of dir for the picker. Any problem just
// means nothing was found: the picker still offers every choice.
func lookAround(ctx context.Context, dir string) found {
	var f found
	inv := core.GetInventory()
	if inv == nil {
		return f
	}
	ctx, cancel := context.WithTimeout(ctx, lookTimeout)
	defer cancel()
	site, err := inv.Read(ctx, core.InventoryRequest{Root: dir, MaxDepth: 6})
	if err != nil || site == nil {
		return f
	}
	f.wordpress = site.Kind == "wordpress" || site.Kind == "mixed" && site.WordPress != ""
	for _, in := range site.Installed {
		switch in.Ref.Eco {
		case core.WPPlugin:
			f.plugins++
			f.wordpress = true
		case core.WPTheme:
			f.themes++
			f.wordpress = true
		}
		// A WordPress entry's Lockfile is its main file (kept for SARIF),
		// not a lockfile.
		if (in.Ref.Eco == core.Composer || in.Ref.Eco == core.NPM) && in.Lockfile != "" {
			if name := filepath.Base(in.Lockfile); !slices.Contains(f.lockfiles, name) {
				f.lockfiles = append(f.lockfiles, name)
			}
		}
	}
	return f
}
