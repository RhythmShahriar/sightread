// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command roadie is the testbed's stand-in for rhythm-roadie. It answers
// `rhythm-roadie verify --target <url> [--wp <cmd>] --json` with the
// document of docs/roadie-contract.md, in the outcome the e15 case asks
// for, so every --soundcheck refusal can be tested before Roadie 1.0
// ships. The benchmark builds it as rhythm-roadie into a folder it puts
// first on PATH.
//
// The outcome is read from the file "roadie" in $TESTBED_STATE (the
// testbed's state folder) on every call, so a case switches it without a
// rebuild. Each call is logged as one JSON line to roadie.log next to it.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The outcomes the stub can give, one per e15 case.
const (
	// ModeOK is a staging copy that passes: signed, sealed, no problems
	// and verified after the copy was made.
	ModeOK = "ok"
	// ModeFailed is a verify with findings (exit 1): real-looking emails
	// and a live payment key on the copy.
	ModeFailed = "failed"
	// ModeStale is a verify that answers ok but is older than the copy,
	// so it says nothing about the copy as it is now.
	ModeStale = "stale"
	// ModeUnsealed is a verify that answers ok while Echo's seal is off.
	ModeUnsealed = "unsealed"
	// ModeProduction names the target itself as the production site the
	// copy was made from, which --soundcheck must refuse (E14).
	ModeProduction = "production"
)

// Modes lists every outcome, for the help text and the tests.
var Modes = []string{ModeOK, ModeFailed, ModeStale, ModeUnsealed, ModeProduction}

// Problem is one entry of data.problems.
type Problem struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
	Text  string `json:"text"`
}

// Data is the verify document's data block.
type Data struct {
	Target        string    `json:"target"`
	ProductionURL string    `json:"production_url"`
	Signed        bool      `json:"signed"`
	Sealed        bool      `json:"sealed"`
	CopyCreated   string    `json:"copy_created"`
	VerifiedAt    string    `json:"verified_at"`
	Problems      []Problem `json:"problems"`
}

// Document is the rhythm-roadie/v1 verify document.
type Document struct {
	Schema  string `json:"schema"`
	Kind    string `json:"kind"`
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Verdict string `json:"verdict"`
	Data    Data   `json:"data"`
}

// stubVersion is what --version prints and the document carries.
const stubVersion = "1.0.0-testbed"

// Answer builds the document and exit code for a mode. now is the time
// of the call; target is the --target value.
func Answer(mode, target string, now time.Time) (Document, int, error) {
	d := Document{
		Schema:  "rhythm-roadie/v1",
		Kind:    "verify",
		Tool:    "rhythm-roadie",
		Version: stubVersion,
		Verdict: "ok",
		Data: Data{
			Target:        target,
			ProductionURL: "https://shop.example.com",
			Signed:        true,
			Sealed:        true,
			CopyCreated:   now.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
			VerifiedAt:    now.UTC().Format(time.RFC3339),
			Problems:      []Problem{},
		},
	}
	switch mode {
	case ModeOK:
		return d, 0, nil
	case ModeFailed:
		d.Verdict = "findings"
		d.Data.Problems = []Problem{
			{Kind: "real-email", Count: 2, Text: "2 real-looking emails"},
			{Kind: "live-key", Count: 1, Text: "1 live payment key"},
		}
		return d, 1, nil
	case ModeStale:
		// The copy was remade after this check ran.
		d.Data.CopyCreated = now.Add(-10 * time.Minute).UTC().Format(time.RFC3339)
		d.Data.VerifiedAt = now.Add(-3 * time.Hour).UTC().Format(time.RFC3339)
		return d, 0, nil
	case ModeUnsealed:
		d.Data.Sealed = false
		return d, 0, nil
	case ModeProduction:
		d.Data.ProductionURL = target
		return d, 0, nil
	}
	return Document{}, 3, fmt.Errorf("unknown mode %q in the state file: want one of %s", mode, strings.Join(Modes, ", "))
}

// readMode returns the outcome named in stateDir/roadie, ModeOK when the
// file is missing.
func readMode(stateDir string) string {
	if stateDir == "" {
		return ModeOK
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "roadie")) //nolint:gosec // the testbed's own state folder
	if err != nil {
		return ModeOK
	}
	if m := strings.TrimSpace(string(b)); m != "" {
		return m
	}
	return ModeOK
}

// logCall appends the call's arguments to stateDir/roadie.log so a test
// can prove Sightread asked with --target and --json.
func logCall(stateDir string, args []string, mode string) {
	if stateDir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "roadie.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // testbed log
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	b, _ := json.Marshal(map[string]any{"args": args, "mode": mode})
	_, _ = f.Write(append(b, '\n'))
}

// verifyArgs is the parsed verify command line.
type verifyArgs struct {
	target, wp string
	json       bool
}

// parseVerify reads `verify --target <url> [--wp <cmd>] --json`, in any
// order and in both --flag value and --flag=value forms.
func parseVerify(args []string) (verifyArgs, error) {
	var v verifyArgs
	rest := args
	for len(rest) > 0 {
		a := rest[0]
		rest = rest[1:]
		name, val, hasVal := strings.Cut(a, "=")
		switch name {
		case "--json":
			v.json = true
		case "--target", "--wp":
			if !hasVal {
				if len(rest) == 0 {
					return v, fmt.Errorf("%s needs a value", name)
				}
				val, rest = rest[0], rest[1:]
			}
			if name == "--target" {
				v.target = val
			} else {
				v.wp = val
			}
		default:
			return v, fmt.Errorf("unknown flag %s", a)
		}
	}
	if v.target == "" {
		return v, fmt.Errorf("verify needs --target <url>")
	}
	return v, nil
}

// run is main without the process exit, for the tests.
func run(args []string, stateDir string, now time.Time, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, "rhythm-roadie "+stubVersion)
		return 0
	}
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(stderr, "rhythm-roadie (testbed stub): only `verify --target <url> [--wp <cmd>] --json` is supported")
		return 2
	}
	logCall(stateDir, args[1:], readMode(stateDir))
	v, err := parseVerify(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, "rhythm-roadie verify:", err)
		return 2
	}
	doc, code, err := Answer(readMode(stateDir), v.target, now)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm-roadie verify:", err)
		return code
	}
	if !v.json {
		fmt.Fprintf(stdout, "%s: %s\n", doc.Data.Target, doc.Verdict)
		return code
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return 3
	}
	return code
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv("TESTBED_STATE"), time.Now(), os.Stdout, os.Stderr))
}
