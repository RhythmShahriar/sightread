// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"slices"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// updateSummary is the help line PRD 0 asks for, so nobody reads
// `update` as updating their packages.
const updateSummary = "refresh signal and name data, never packages"

// updateCommand is `update`, which refreshes the data packs. kit's
// Tool.Update provides the same command but its help line can't be
// changed, so Sightread registers its own with the same contract: --json
// prints rhythm-data/v1, --pin brings packs to named versions (exit 3
// when one can't be had) and a failure exits 3.
func updateCommand() cli.Command {
	return cli.Command{
		Name: "update", Args: "[--json]", Summary: updateSummary,
		Flags: func() *flag.FlagSet { fs, _, _ := updateFlags(io.Discard); return fs },
		Run:   runUpdate,
	}
}

func updateFlags(stderr io.Writer) (*flag.FlagSet, *bool, *string) {
	fs := cli.NewFlagSet("update", "Usage: "+cli.Name()+" update [--json] [--pin <name=version,...>]\n\n"+
		"Downloads the latest signal and popular-name data Sightread works from, verified against the signed "+
		"release checksums, or with --pin the versions named. It never updates a package.", stderr)
	asJSON := fs.Bool("json", false, "print the "+cli.DataSchema+" JSON document")
	pin := fs.String("pin", "", "download these data `versions`, as name=version,...")
	return fs, asJSON, pin
}

func runUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs, asJSON, pinSpec := updateFlags(stderr)
	if cli.HasFlag(args, "h") || cli.HasFlag(args, "help") {
		fs.SetOutput(stdout)
	}
	pos, err := cli.ParseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return cli.Usagef("update takes no arguments, got %q", pos[0])
	}
	pins, err := cli.ParsePins(*pinSpec)
	if err != nil {
		return cli.Usagef("--pin: %v", err)
	}
	dp, err := dataPacks()
	if err != nil {
		return err
	}
	progress := stdout
	if *asJSON {
		progress = stderr // stdout carries only the JSON
	}
	var packs []cli.DataPack
	if len(pins) > 0 {
		packs, err = dp.UpdatePinned(ctx, progress, pins)
	} else {
		packs, err = dp.Update(ctx, progress)
	}
	if ctx.Err() != nil {
		return ctx.Err() // cli.Main exits 130
	}
	if err == nil {
		err = checkPins(packs, pins)
	}
	if err != nil {
		return &cli.ExitError{Code: cli.ExitUnavailable, Err: fmt.Errorf("update failed: %w", err)}
	}
	if packs == nil {
		packs = []cli.DataPack{} // "data": [] rather than null
	}
	if *asJSON {
		return json.NewEncoder(stdout).Encode(struct {
			Schema string         `json:"schema"`
			Data   []cli.DataPack `json:"data"`
		}{cli.DataSchema, packs})
	}
	for _, p := range packs {
		fmt.Fprintf(stdout, "%s %s\n", p.Name, p.Version)
	}
	return nil
}

// checkPins marks the packs pins named and reports the first pin, by
// name, the packs don't meet, as cli.Main's own update does.
func checkPins(packs []cli.DataPack, pins map[string]string) error {
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		got := ""
		for i := range packs {
			if packs[i].Name == name {
				got = packs[i].Version
				packs[i].Pinned = true
			}
		}
		switch {
		case got == "":
			return fmt.Errorf("no %s data to pin at %s", name, pins[name])
		case got != pins[name]:
			return fmt.Errorf("%s %s isn't available (got %s)", name, pins[name], got)
		}
	}
	return nil
}
