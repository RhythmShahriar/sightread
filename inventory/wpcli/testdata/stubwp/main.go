// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command stubwp stands in for WP-CLI in the wpcli tests. It appends its
// argv to $STUBWP_LOG and prints the fixture for the subcommand from
// $STUBWP_DIR: plugin.json, theme.json, core.txt or option.json. A
// <sub>.exit file makes it exit with that code after printing
// <sub>.stderr; $STUBWP_SLEEP=<sub> makes it hang on that subcommand.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	args := os.Args[1:]
	if log := os.Getenv("STUBWP_LOG"); log != "" {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintln(f, strings.Join(args, "\x1f"))
			f.Close()
		}
	}
	sub := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			sub = a
			break
		}
	}
	if os.Getenv("STUBWP_SLEEP") == sub {
		time.Sleep(time.Minute)
	}
	dir := os.Getenv("STUBWP_DIR")
	name := map[string]string{"plugin": "plugin.json", "theme": "theme.json", "core": "core.txt", "option": "option.json"}[sub]
	if b, err := os.ReadFile(filepath.Join(dir, sub+".exit")); err == nil {
		errText, _ := os.ReadFile(filepath.Join(dir, sub+".stderr"))
		os.Stderr.Write(errText)
		code, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		os.Exit(code)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a registered wp command.\n", sub)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}
