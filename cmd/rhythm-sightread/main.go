// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command rhythm-sightread reads a package update before you install it:
// it diffs the installed version against the one the official source
// would give you and ranks what is new. It never runs the code.
//
// It is built on kit cli.Main, which answers help, version and the exit
// codes. A bare run on an interactive terminal outside CI opens the
// picker (the hidden pick command); off a terminal it prints the usage.
// The commands are those of PRD section 6, in that order.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// version is set at release time with -ldflags "-X main.version=1.0.0".
var version = "dev"

// summary is the line under the banner in help.
const summary = "What will this update really change? Diff it against the official source and rank what is new. Never runs the code."

// firstRunKey names the once-per-machine marker of the first-run note.
const firstRunKey = "sightread-first-run"

// firstRunNote is PRD 6.10's note, printed once per machine.
const firstRunNote = `Note: Sightread downloads packages from WordPress.org, Packagist and npm and reads
them as text. It never runs their code. A clean result is a static diff, not proof
an update is safe. This notice is shown once.
`

// stub is a command a later part of the build fills in. It answers
// --help and otherwise says it isn't built yet (exit 3).
type stub struct {
	name, args, summary string
}

// The commands still to come.
var (
	watchStub  = stub{"watch", "-l <sites.yaml> --every <d> [flags]", "check sites on a schedule"}
	demoStub   = stub{"demo", "[--keep]", "try it on built-in packages, no network"}
)

func (s stub) flags(stderr io.Writer) *flag.FlagSet {
	return cli.NewFlagSet(s.name, "Usage: "+cli.Name()+" "+s.name+" "+s.args+"\n\n"+s.summary, stderr)
}

func (s stub) command() cli.Command {
	return cli.Command{
		Name: s.name, Args: s.args, Summary: s.summary,
		Flags: func() *flag.FlagSet { return s.flags(io.Discard) },
		Run: func(_ context.Context, args []string, stdout, stderr io.Writer) error {
			fs := s.flags(stderr)
			if cli.HasFlag(args, "h") || cli.HasFlag(args, "help") {
				fs.SetOutput(stdout)
			}
			if _, err := cli.ParseArgs(fs, args); err != nil {
				return err
			}
			return &cli.ExitError{Code: cli.ExitUnavailable, Err: errors.New(s.name + ": not built yet")}
		},
	}
}

// commands lists every command in PRD 6 order: the review commands, the
// rest, update and the hidden picker.
func commands() []cli.Command {
	var out []cli.Command
	for _, c := range reviewCommands {
		out = append(out, c.command())
	}
	out = append(out, explainCommand.command(), allowCommand.command(), watchStub.command())
	out = append(out, reportCommand.command(), verifyCommand.command(), initCommand.command(), doctorCommand.command(), demoStub.command(),
		signalsCommand.command(), cacheCommand.command())
	return append(out, updateCommand(), pickCommand())
}

// tool describes rhythm-sightread for cli.Main. args are the arguments
// after the program name.
func tool(args []string) cli.Tool {
	t := cli.Tool{
		Name: "rhythm-sightread", Version: version, Summary: summary, Commands: commands(),
		Offline: func() bool { return cli.HasFlag(args, "offline") },
	}
	// cli.Main records the first-run marker before the command runs, so a
	// -q or --json run, which must print nothing extra, leaves the note
	// for a later run instead of using it up.
	if !cli.QuietRun(args) {
		t.FirstRun = func(stderr io.Writer) { fmt.Fprint(stderr, firstRunNote) }
		t.FirstRunKey = firstRunKey
	}
	return t
}

// bareTerminal reports whether a run with no arguments should open the
// picker: an interactive terminal on both ends, outside CI.
func bareTerminal(args []string, getenv func(string) string) bool {
	return len(args) == 0 && cli.IsTerminal(os.Stdout) && isTerminalIn() && getenv("CI") == ""
}

// isTerminalIn reports whether stdin is a terminal, which the picker
// needs to read keys.
func isTerminalIn() bool { return cli.IsTerminal(os.Stdin) }

func main() {
	if bareTerminal(os.Args[1:], os.Getenv) {
		os.Args = append(os.Args, "pick")
	}
	os.Exit(cli.Main(tool(os.Args[1:])))
}

// dataPacks returns the linked data packs or the error cli.Main shows.
func dataPacks() (core.DataPacks, error) {
	if dp := core.GetDataPacks(); dp != nil {
		return dp, nil
	}
	return nil, fmt.Errorf("data packs %w", core.ErrNotLinked)
}
