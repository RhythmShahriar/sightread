// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// flagHints are the one-line hints for flags users bring from another
// command, by command and the flag's name as typed without dashes.
var flagHints = map[string]map[string]string{
	"report": {
		"jsonl": "report writes .md, .html, .sarif and .json; the JSONL stream comes only from a review (--jsonl)",
	},
	"demo": {
		"md":      "the demo writes other formats as files: -o demo.md",
		"html":    "the demo writes other formats as files: -o demo.html --open",
		"sarif":   "the demo writes other formats as files: -o demo.sarif",
		"path":    "the demo reviews its own example site; on yours run all /path/to/site",
		"offline": "the demo never leaves 127.0.0.1, so it needs no --offline",
	},
}

// flagErr matches the flag package's error texts, which name the flag
// with one dash whatever the user typed.
var flagErr = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`^flag provided but not defined: -(.+)$`), "unknown"},
	{regexp.MustCompile(`^flag needs an argument: -(.+)$`), "needs"},
	{regexp.MustCompile(`^invalid (?:boolean )?value "(?:.*)" for (?:flag )?-([^:]+): (.*)$`), "invalid"},
}

// parseFlags parses args with fs the way cli.ParseArgs does, flags
// before or after the arguments, but reports a bad flag the PRD 10 way
// instead of the flag package's: the flag as the user typed it, one
// hint and where every flag is listed, without dumping the help page.
// -h and --help still print the help page and return cli.ErrHelp.
func parseFlags(fs *flag.FlagSet, args []string, command string) ([]string, error) {
	if cli.HasFlag(args, "h") || cli.HasFlag(args, "help") {
		return cli.ParseArgs(fs, args)
	}
	out, usage := fs.Output(), fs.Usage
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	defer func() { fs.SetOutput(out); fs.Usage = usage }()
	pos, err := cli.ParseInterspersed(fs, args)
	switch {
	case err == nil:
		return pos, nil
	case errors.Is(err, flag.ErrHelp):
		return nil, cli.ErrHelp
	}
	return nil, flagError(fs, err, args, command)
}

// flagError rewrites a flag package error as a *core.Error (E13, exit
// 2) for command.
func flagError(fs *flag.FlagSet, err error, args []string, command string) error {
	e := &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: command, What: err.Error()}
	help := fmt.Sprintf("%s help %s lists every flag", cli.Name(), command)
	for _, m := range flagErr {
		sub := m.re.FindStringSubmatch(err.Error())
		if sub == nil {
			continue
		}
		name := sub[1]
		typed := typedAs(args, name)
		switch m.kind {
		case "unknown":
			e.What = "unknown flag " + typed
			switch {
			case flagHints[command][name] != "":
				e.Hint = append(e.Hint, flagHints[command][name])
			case suggestFlag(fs, name) != "":
				e.Hint = append(e.Hint, "did you mean "+suggestFlag(fs, name)+"?")
			}
		case "needs":
			e.What = typed + " needs a value"
		case "invalid":
			e.What = fmt.Sprintf("%s: %s", typed, sub[2])
		}
		break
	}
	e.Hint = append(e.Hint, help)
	return e
}

// typedAs is how args spelled the flag name: "--md", "-q" or "--to=x"
// without its value. It falls back to "--name".
func typedAs(args []string, name string) string {
	for _, a := range args {
		if a == "--" {
			break
		}
		flagPart, _, _ := strings.Cut(a, "=")
		if strings.TrimLeft(flagPart, "-") == name && strings.HasPrefix(flagPart, "-") {
			return flagPart
		}
	}
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// suggestFlag is the defined flag closest to name, as the user would
// type it, or "".
func suggestFlag(fs *flag.FlagSet, name string) string {
	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		if len(f.Name) > 1 {
			names = append(names, f.Name)
		}
	})
	if s := cli.Suggest(name, names); s != "" {
		return "--" + s
	}
	return ""
}
