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
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// version is set at release time with -ldflags "-X main.version=1.0.0".
var version = "dev"

// summary is the text under the banner in help.
// kit prints it as given, so it is broken to fit 80 columns.
const summary = "What will this update really change? Diff it against the official source\nand rank what is new. Never runs the code."

// firstRunKey names the once-per-machine marker of the first-run note.
const firstRunKey = "sightread-first-run"

// firstRunNote is PRD 6.10's note, printed once per machine.
const firstRunNote = `Note: Sightread downloads packages from WordPress.org, Packagist and npm and reads
them as text. It never runs their code. A clean result is a static diff, not proof
an update is safe. This notice is shown once.
`

// commands lists every command in PRD 6 order: the review commands, the
// rest, update and the hidden picker.
func commands() []cli.Command {
	var out []cli.Command
	for _, c := range reviewCommands {
		out = append(out, c.command())
	}
	out = append(out, explainCommand.command(), allowCommand.command(), watchCmd())
	for _, c := range []*simpleCommand{reportCommand, verifyCommand, initCommand, doctorCommand, demoCommand, signalsCommand, cacheCommand} {
		out = append(out, c.command())
	}
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
