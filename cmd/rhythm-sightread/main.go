// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command rhythm-sightread reads a package update before you install it:
// it diffs the installed version against the one the official source
// would give you and ranks what is new. It never runs the code.
//
// The skeleton registers every command of PRD section 6; each answers
// --help and otherwise says it is not built yet. The cli lane builds
// them.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// version is set at release time with -ldflags "-X main.version=1.0.0".
var version = "dev"

// summary is the line under the banner in help.
const summary = "What will this update really change? Diff it against the official source and rank what is new. Never runs the code."

// command is one subcommand of PRD section 6.
type command struct {
	name, args, summary string
	hidden              bool
}

var commands = []command{
	{"plugin", "<slug>... [flags]", "review a WordPress.org plugin update", false},
	{"theme", "<slug>... [flags]", "review a WordPress.org theme update", false},
	{"composer", "[<vendor/pkg>...] [flags]", "review Composer updates in composer.lock", false},
	{"npm", "[<pkg>...] [flags]", "review npm updates in the lockfile", false},
	{"all", "[<path>] [flags]", "review every available update in a site or project", false},
	{"changes", "[--base <ref>] [flags]", "review every version a lockfile change moves", false},
	{"explain", "<signal-id> | <report.json> <n|fp>", "what a signal means and how to review it", false},
	{"allow", "<ref>... | --from <json> | list | remove | import", "record a reviewed version", false},
	{"watch", "-l <sites.yaml> --every <d> [flags]", "check sites on a schedule", false},
	{"report", "<report.json>... -o <file>", "render saved JSON as Markdown, HTML or SARIF", false},
	{"verify-report", "<report.json> [--key <pub>]", "check a signed report", false},
	{"init", "[ci] [--force]", "write .sightread/config.yaml or a CI workflow", false},
	{"doctor", "[--offline] [--json]", "check sources, cache, tokens and helpers", false},
	{"demo", "[--keep]", "try it on built-in packages, no network", false},
	{"signals", "[--json]", "list every signal with its default severity", false},
	{"cache", "prune [--older <d>]", "remove cached archives nothing uses", false},
	{"pick", "", "pick what to review (the bare terminal run)", true},
}

// flags returns the flag set of c. Its usage is the synopsis and the
// summary; the cli lane adds the flags of PRD section 7.
func (c command) flags(stderr io.Writer) *flag.FlagSet {
	return cli.NewFlagSet(c.name, "Usage: "+cli.Name()+" "+c.name+" "+c.args+"\n\n"+c.summary, stderr)
}

// stub answers --help and reports the command isn't built yet (exit 3).
func (c command) stub() cli.Command {
	return cli.Command{
		Name: c.name, Args: c.args, Summary: c.summary, Hidden: c.hidden,
		Flags: func() *flag.FlagSet { return c.flags(io.Discard) },
		Run: func(_ context.Context, args []string, _, stderr io.Writer) error {
			if _, err := cli.ParseArgs(c.flags(stderr), args); err != nil {
				return err
			}
			return &cli.ExitError{Code: cli.ExitUnavailable, Err: errors.New(c.name + ": not built yet")}
		},
	}
}

func tool() cli.Tool {
	t := cli.Tool{Name: "rhythm-sightread", Version: version, Summary: summary}
	for _, c := range commands {
		t.Commands = append(t.Commands, c.stub())
	}
	return t
}

func main() { os.Exit(cli.Main(tool())) }
