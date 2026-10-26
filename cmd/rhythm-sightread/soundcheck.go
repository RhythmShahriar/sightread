// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"cmp"
	"context"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
	"github.com/RhythmShahriar/sightread/stage"
)

// checkSoundcheck refuses a --soundcheck run that can't install one
// update, before the review starts: it installs exactly one package.
func (c *reviewCommand) checkSoundcheck(p *plan) error {
	if p.soundcheck.Staging == "" {
		return nil
	}
	if len(p.req.Names) != 1 {
		return badFlag("--soundcheck installs one update: name one package, e.g. %s %s <name> --soundcheck <staging-url>", cli.Name(), c.name)
	}
	return stage.Precheck(c.name, c.eco, p.soundcheck.Staging, len(p.soundcheck.ApplyArgv) > 0)
}

// runSoundcheck runs the --soundcheck flow on the reviewed update (PRD
// 15), with the config's soundcheck section filling what the flags left
// out. tripped reports changes at --soundcheck-fail-on.
func (c *reviewCommand) runSoundcheck(ctx context.Context, p *plan, rep *core.Report) (tripped bool, err error) {
	policy, err := policyNow()
	if err != nil {
		return false, err
	}
	cfg, _, err := policy.LoadConfig(cmp.Or(p.req.ConfigStart, "."), p.req.ConfigFile, p.req.NoConfig)
	if err != nil {
		return false, err
	}
	sc := p.soundcheck
	wp := p.req.Inventory.WP
	if len(wp) == 0 && cfg.Soundcheck.WP != "" {
		if wp, err = run.SplitCommand(cfg.Soundcheck.WP); err != nil {
			return false, badFlag("soundcheck.wp %q in the config: %v", cfg.Soundcheck.WP, err)
		}
	}
	failOn := sc.FailOn
	if !sc.FailOnSet && cfg.Soundcheck.FailOn != "" {
		failOn = cfg.Soundcheck.FailOn
	}
	args := sc.Args
	if len(args) == 0 {
		args = cfg.Soundcheck.Args
	}
	cache, err := run.CacheDir(p.req.CacheDir)
	if err != nil {
		return false, err
	}
	blobs, err := core.OpenBlobs(cache)
	if err != nil {
		return false, err
	}
	plan := stage.Plan{Command: c.name, Staging: sc.Staging, WP: wp, Apply: sc.ApplyArgv, FailOn: failOn, Rollback: sc.Rollback,
		Anyway: sc.Anyway, SkipRoadie: sc.Skip, Args: args, Production: cfg.Soundcheck.Production, Dir: ".",
		Tree:  func(ref core.Ref) (*core.Tree, bool) { return run.CachedTree(cache, ref, blobs) },
		Blobs: blobs, Log: p.req.Log}
	tripped, err = stage.Run(ctx, plan, rep)
	if err != nil {
		return false, err
	}
	return tripped, nil
}
