// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/notify"
	"github.com/RhythmShahriar/sightread/run"
	"github.com/RhythmShahriar/sightread/watch"
)

// watchKeep is how many runs a watch keeps by default: a month of daily
// runs.
const watchKeep = 30

// smtpPasswordEnv holds the password for --notify smtp:// URLs.
const smtpPasswordEnv = "SIGHTREAD_SMTP_PASSWORD" //nolint:gosec // a variable name, not a credential

// watchOwned are the review flags the watch sets itself: passing them
// after -- would break the run's report or its rereview.
var watchOwned = []string{"o", "output", "json", "jsonl", "md", "html", "sarif", "sites", "rereview", "q", "quiet", "plain", "open"}

// watchOnly are the watch's own flags, which mean nothing to a review.
var watchOnly = []string{"l", "list", "every", "at", "now", "once", "name", "dir", "keep", "notify", "notify-min",
	"notify-strict", "fail-on-new"}

// watchCommand is `watch` (PRD 6.7). Its Run splits off the review
// flags after -- before parsing, which simpleCommand's parser would mix
// with positional arguments.
var watchCommand = &simpleCommand{
	name: "watch", args: "-l <sites.yaml> --every <d> | --at <HH:MM> [flags] [-- <review flags>]",
	brief:   "-l <sites.yaml>",
	summary: "check sites on a schedule",
	long: "Reviews every site of a sites file on a schedule and tells you what is new: an update with findings at or above " +
		"--notify-min, a new signal on a version a site already runs (after a signal data update), an owner change or a " +
		"WordPress.org closure of an installed plugin. Each version is notified once. Each run is its own {prog} all " +
		"--sites process, so the watch stays small however long it runs; it writes <dir>/<UTC time>.json and prints one " +
		"line. Ctrl-C lets a review in progress finish, then stops; a second Ctrl-C stops the review too. Arguments " +
		"after -- go to every review, e.g. -- --jobs 2.",
	examples: []string{"watch -l sites.yaml --at 02:00 --notify slack://hooks.slack.com/services/T0/B0/XXXX",
		"watch -l sites.yaml --every 24h --notify-min medium --html", "watch -l sites.yaml --once --fail-on-new high"},
	flags: watchFlags,
}

// watchCmd is watchCommand as a kit command.
func watchCmd() cli.Command {
	c := watchCommand
	return cli.Command{
		Name: c.name, Args: cmp.Or(c.brief, c.args), Summary: c.summary,
		Flags: func() *flag.FlagSet { fs, _, _ := c.flagSet(io.Discard); return fs },
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			own, pass := splitPassthrough(args)
			fs, sf, runWatch := c.flagSet(stderr)
			if cli.HasFlag(own, "h") || cli.HasFlag(own, "help") {
				fs.SetOutput(stdout)
			}
			pos, err := cli.ParseArgs(fs, own)
			if err != nil {
				return err
			}
			if len(pos) > 0 {
				return cli.Usagef("watch takes no arguments, got %q; review flags go after --", pos[0])
			}
			return finish(stderr, runWatch(ctx, pass, stdout, stderr), sf.verbose)
		},
	}
}

// watchFlags registers watch's flags; the returned function gets the
// review flags after -- as its positional arguments.
func watchFlags(fs *flag.FlagSet, sf *simpleFlags) runFunc {
	var o watchOptions
	fs.StringVar(&o.list, "list", "", "the sites.yaml `file` to review (read again on every run)")
	sf.short(fs, "l", "list")
	fs.StringVar(&o.every, "every", "", "run now, then every `duration`, e.g. 24h or 6h (at least 1m)")
	fs.StringVar(&o.at, "at", "", "run every day at this local `time`; several separated by commas, e.g. 02:00,14:00")
	fs.BoolVar(&o.now, "now", false, "with --at, also run once right away")
	fs.BoolVar(&o.once, "once", false, "run once now and exit (for cron and CI)")
	fs.StringVar(&o.name, "name", "", "the watch's `name`, in notifications and its folder (default: the sites file's name)")
	fs.StringVar(&o.dir, "dir", "", "`folder` for reports, logs and state (default: the user cache, rhythm/sightread/watch/<name>)")
	fs.IntVar(&o.keep, "keep", watchKeep, "`n` runs to keep, oldest deleted first (0 keeps all)")
	fs.Var(&o.notify, "notify", "tell this `url` what is new: slack://, discord://, webhook+https:// or smtp:// (repeatable; the SMTP password comes from "+smtpPasswordEnv+")")
	fs.StringVar(&o.notifyMin, "notify-min", "high", "lowest finding `level` notified: info, low, medium, high or critical")
	fs.BoolVar(&o.strict, "notify-strict", false, "exit 3 when a notification can't be sent")
	fs.StringVar(&o.failOnNew, "fail-on-new", "", "exit 1 when a run finds a new finding at or above this `level`")
	fs.BoolVar(&o.html, "html", false, "also write each run's report as HTML next to its JSON")
	fs.BoolVar(&sf.verbose, "verbose", false, "every program started and notification sent to stderr, secrets masked")
	sf.short(fs, "v", "verbose")
	return func(ctx context.Context, extra []string, stdout, stderr io.Writer) error {
		o.extra, o.verbose = extra, sf.verbose
		w, err := o.watcher(os.Getenv, stderr)
		if err != nil {
			return err
		}
		if o.once {
			return watchOnce(ctx, w, o.strict, stdout)
		}
		return watchLoop(ctx, w, o, stdout, stderr)
	}
}

// watchOptions are watch's flag values.
type watchOptions struct {
	list, every, at, name, dir, notifyMin, failOnNew string
	now, once, strict, html, verbose                 bool
	keep                                             int
	notify                                           cli.RepeatFlag
	extra                                            []string
}

// watcher checks the flags and builds the Watcher.
func (o *watchOptions) watcher(env func(string) string, stderr io.Writer) (*watch.Watcher, error) {
	if o.list == "" {
		return nil, cli.Usagef("watch needs a sites file: %s watch -l <sites.yaml> --every 24h", cli.Name())
	}
	var sched watch.Schedule
	if o.every != "" {
		d, err := parseDuration("every", o.every)
		if err != nil {
			return nil, err
		}
		sched.Every = d
	}
	if o.at != "" {
		at, err := watch.ParseAt(o.at)
		if err != nil {
			return nil, badFlag("%v", err)
		}
		sched.At = at
	}
	switch {
	case o.once && (o.every != "" || o.at != "" || o.now):
		return nil, badFlag("--once runs a single review; drop --every, --at and --now, or drop --once")
	case o.now && o.at == "":
		return nil, badFlag("--now goes with --at; --every already starts with a run")
	case !o.once:
		if err := sched.Validate(); err != nil {
			return nil, badFlag("%v", err)
		}
	}
	if o.keep < 0 {
		return nil, badFlag("--keep %d: want 0 or more", o.keep)
	}
	notifyMin, err := cli.ParseFailOn(o.notifyMin)
	if err != nil || notifyMin == cli.SeverityNone {
		return nil, badFlag("--notify-min %q: want info, low, medium, high or critical", o.notifyMin)
	}
	failOnNew, err := cli.ParseFailOn(o.failOnNew)
	if err != nil {
		return nil, badFlag("--fail-on-new %q: want none, info, low, medium, high or critical", o.failOnNew)
	}
	for _, a := range o.extra {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		n, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case slices.Contains(watchOwned, n):
			return nil, badFlag("the watch sets %s itself; drop it after --", a)
		case slices.Contains(watchOnly, n):
			return nil, badFlag("%s is a watch flag; put it before --", a)
		}
	}
	list, err := filepath.Abs(o.list)
	if err != nil {
		return nil, err
	}
	sites, err := run.LoadSites(list)
	if err != nil {
		return nil, err
	}
	var notifiers []notify.Notifier
	for _, raw := range o.notify {
		n, err := notify.Parse(raw, notify.Options{SMTPPassword: env(smtpPasswordEnv)})
		if err != nil {
			return nil, badFlag("--notify: %v", err)
		}
		notifiers = append(notifiers, n)
	}
	name := o.name
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(list), filepath.Ext(list))
	}
	name = safeWatchName(name)
	dir := o.dir
	if dir == "" {
		cache, err := config.CacheDir("sightread")
		if err != nil {
			return nil, fmt.Errorf("no user cache folder (%w); pass --dir", err)
		}
		dir = filepath.Join(cache, "watch", name)
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("can't find this program to run each review (%w)", err)
	}
	w := &watch.Watcher{Exe: exe, Sites: list, Name: name, Extra: o.extra, Dir: dir, Schedule: sched, RunNow: o.now,
		Keep: o.keep, HTML: o.html, NotifyMin: notifyMin, Notifiers: notifiers, FailOnNew: failOnNew, Version: version}
	if o.verbose {
		w.Verbose = stderr
	}
	w.Installed = func(ctx context.Context) ([]run.InstalledStatus, error) {
		req := run.Request{Command: "watch", Version: version, Sites: sites, Getter: envGetter(env, false)}
		req.Getter.UserAgent = "rhythm-sightread/" + version + " (+https://github.com/RhythmShahriar/sightread)"
		req.Getter.Timeout, req.Getter.Retries = 30*time.Second, defaultRetries
		req.Log = w.Verbose
		return run.Installed(ctx, req)
	}
	return w, nil
}

// watchOnce is --once: one run, its line and its exit code.
func watchOnce(ctx context.Context, w *watch.Watcher, strict bool, stdout io.Writer) error {
	hard, stopHard := hardStop()
	defer stopHard()
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	go func() {
		select {
		case <-hard:
			cancel()
		case <-runCtx.Done():
		}
	}()
	r, err := w.RunOnce(runCtx)
	switch {
	case errors.Is(err, watch.ErrReviewUsage):
		return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: "watch", What: err.Error()}
	case err != nil:
		return &core.Error{Exit: cli.ExitUnavailable, Command: "watch", What: err.Error()}
	}
	fmt.Fprintln(stdout, r.Lines())
	if r.Exit < 0 && ctx.Err() != nil {
		return &cli.ExitError{Code: cli.ExitInterrupted}
	}
	if code := r.Outcome().Code(strict); code != cli.ExitOK {
		return &cli.ExitError{Code: code}
	}
	return nil
}

// watchLoop runs on the schedule until Ctrl-C, then exits with the
// worst outcome of its runs.
func watchLoop(ctx context.Context, w *watch.Watcher, o watchOptions, stdout, stderr io.Writer) error {
	w.Log = stdout
	hard, stopHard := hardStop()
	defer stopHard()
	go func() {
		select {
		case <-ctx.Done():
		case <-hard:
			return
		}
		fmt.Fprintf(stderr, "%s: stopping once the current review finishes; press Ctrl-C again to stop it now\n", cli.Name())
		<-hard
		w.Abort()
	}()
	fmt.Fprintf(stdout, "Watching the sites in %s, %s; reports go to %s\n", shown(w.Sites), describeSchedule(w.Schedule), w.Dir)
	out, err := w.Run(ctx)
	if errors.Is(err, watch.ErrReviewUsage) {
		return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: "watch", What: err.Error()}
	}
	if err != nil {
		return &core.Error{Exit: cli.ExitUnavailable, Command: "watch", What: err.Error()}
	}
	fmt.Fprintln(stdout, "Stopped.")
	if code := out.Code(o.strict); code != cli.ExitOK {
		return &cli.ExitError{Code: code}
	}
	return nil
}

// describeSchedule reads "every 24h" or "daily at 02:00, 14:00".
func describeSchedule(s watch.Schedule) string {
	if s.Every > 0 {
		return "every " + watch.DurationText(s.Every)
	}
	times := make([]string, len(s.At))
	for i, t := range s.At {
		times[i] = t.String()
	}
	return "daily at " + strings.Join(times, ", ")
}

// unsafeName matches runs of characters a folder name must not hold, so
// --name can't name a folder outside the watch's own.
var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// windowsDevice matches the names Windows keeps for devices, such as
// CON or com1.txt, which can't name a folder there.
var windowsDevice = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)

// safeWatchName turns a watch name into one folder name.
func safeWatchName(name string) string {
	name = strings.TrimRight(strings.TrimLeft(unsafeName.ReplaceAllString(name, "-"), ".-"), ". ")
	if name == "" {
		return "watch"
	}
	if windowsDevice.MatchString(name) {
		name += "-watch"
	}
	return name
}
