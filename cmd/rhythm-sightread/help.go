// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// contacts is the privacy line of PRD 6 on the plugin, all and changes
// help pages.
const contacts = "Contacts: api.wordpress.org, downloads.wordpress.org, plugins.svn.wordpress.org, " +
	"themes.svn.wordpress.org, repo.packagist.org, packagist.org, api.github.com, codeload.github.com, " +
	"registry.npmjs.org and api.osv.dev. It sends package names and versions only and never uploads site files."

// helpWidth is the width help text wraps at.
const helpWidth = 80

// usage writes c's help page: the usage line, what it does, its flags by
// group, examples and, on plugin, all and changes, the hosts it
// contacts. Every program name is cli.Name(), so the page shows "rhythm
// sightread" when the router runs it.
func (c *reviewCommand) usage(w io.Writer, fs *flag.FlagSet, f *reviewFlags) {
	prog := cli.Name()
	fmt.Fprintf(w, "Usage: %s %s %s\n\n", prog, c.name, c.args)
	fmt.Fprintln(w, wrap(c.long, helpWidth, ""))
	rows := map[string][2]string{}
	width := 0
	for _, g := range f.groups {
		for _, name := range g.names {
			left, text := flagRow(fs.Lookup(name), f.shortOf[name])
			rows[name] = [2]string{left, text}
			width = max(width, len(left))
		}
	}
	width = min(width, 28)
	for _, g := range f.groups {
		fmt.Fprintf(w, "\n%s:\n", g.title)
		for _, name := range g.names {
			left, text := rows[name][0], rows[name][1]
			indent := strings.Repeat(" ", 2+width+3)
			if len(left) > width {
				fmt.Fprintf(w, "  %s\n%s\n", left, wrap(text, helpWidth, indent))
				continue
			}
			fmt.Fprintf(w, "  %-*s   %s\n", width, left, strings.TrimPrefix(wrap(text, helpWidth, indent), indent))
		}
	}
	if len(c.examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		for _, e := range c.examples {
			fmt.Fprintf(w, "  %s %s\n", prog, e)
		}
	}
	if c.contacts {
		fmt.Fprintf(w, "\n%s\n", wrap(contacts, helpWidth, ""))
	}
	if c.soundcheck {
		fmt.Fprintf(w, "\n%s\n", wrap("Arguments after -- go to rhythm-soundcheck snapshot.", helpWidth, ""))
	}
}

// flagRow is a flag's left column ("-o, --output <file>") and its text
// with the default.
func flagRow(fl *flag.Flag, short string) (left, text string) {
	arg, usage := flag.UnquoteUsage(fl)
	left = "--" + fl.Name
	if short != "" {
		left = "-" + short + ", " + left
	}
	if _, isBool := fl.Value.(interface{ IsBoolFlag() bool }); !isBool && arg != "" {
		left += " <" + arg + ">"
	}
	switch fl.DefValue {
	case "", "false", "0", "[]":
	default:
		usage += " (default " + fl.DefValue + ")"
	}
	return left, usage
}

// wrap breaks s into lines of at most width columns, each after the
// first starting with indent. The first line gets the indent too, so a
// caller that prints it after a left column trims it.
func wrap(s string, width int, indent string) string {
	var b strings.Builder
	line := indent
	for _, word := range strings.Fields(s) {
		if len(line) > len(indent) && len(line)+1+len(word) > width {
			b.WriteString(line + "\n")
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += word
	}
	b.WriteString(line)
	return b.String()
}
