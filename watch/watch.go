// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
	"github.com/RhythmShahriar/sightread/notify"
	"github.com/RhythmShahriar/sightread/run"
)

// Review exit codes the watch acts on (the review commands' own).
const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

// InstalledEvery is how often owners and closures of installed packages
// are asked again: a source's answer is good for 12 hours.
const InstalledEvery = 12 * time.Hour

// maxChildOutput bounds what a review child may print. It runs with -q,
// so this is a safety cap, not a size a real fleet reaches.
const maxChildOutput = 64 << 20

// sendTimeout bounds one notification.
const sendTimeout = time.Minute

// ErrReviewUsage means the review rejected its arguments. Every later
// run would fail the same way, so Run stops.
var ErrReviewUsage = errors.New("the review rejected its flags")

// Watcher runs reviews of one sites file into one watch folder.
type Watcher struct {
	Exe   string   // the Sightread binary to run, normally os.Executable()
	Sites string   // the sites.yaml handed to all --sites (read on every run)
	Name  string   // the watch's name, in notifications
	Extra []string // review flags after --, passed as written
	Dir   string   // the watch folder: reports, logs, lock and state.json
	// Schedule says when runs start. RunNow starts a daily (At) schedule
	// with a run right away; an interval schedule always starts with one.
	Schedule Schedule
	RunNow   bool
	// Keep is how many runs' files to keep; older ones are deleted. 0
	// keeps them all.
	Keep int
	// HTML also writes each run's report as <stamp>.html.
	HTML bool
	// NotifyMin is the lowest severity a finding needs to be notified.
	NotifyMin cli.Severity
	// Notifiers receive what is new; none means the watch only records.
	Notifiers []notify.Notifier
	// FailOnNew marks a run that found a new finding at or above it
	// (Run.FailNew); SeverityNone never does.
	FailOnNew cli.Severity
	Version   string
	// Read parses a report the child wrote; nil uses core.ReadReport.
	Read func(path string) (*core.Report, error)
	// Installed asks the sources about the versions the sites run, for
	// owner changes and closures; nil leaves that check out.
	Installed func(ctx context.Context) ([]run.InstalledStatus, error)
	Env       []string  // the child's environment; nil inherits this one
	Clock     Clock     // default RealClock
	Log       io.Writer // one summary line per run; default none
	// Verbose (-v) gets every program started and every notification
	// sent, secrets masked.
	Verbose io.Writer

	mu    sync.Mutex
	abort context.CancelFunc
}

// Run is one finished watch run.
type Run struct {
	Started, Finished time.Time
	Report            string // the JSON report, "" when the review wrote none
	HTML              string
	LogFile           string // the review's own output
	Exit              int    // the review's exit code, -1 when it didn't start or was killed

	Sites, Updates, Review, Hold int

	// Complete is the report's complete flag. NotChecked, Errors,
	// Unverified and StoppedBy say what an incomplete review left out,
	// counted as the report's own incomplete line counts them.
	Complete                       bool
	NotChecked, Errors, Unverified int
	StoppedBy                      string

	// New is what this run notified (or would have, without notifiers).
	New []notify.Item
	// FailNew is set when a new finding reached Watcher.FailOnNew.
	FailNew bool
	// SendErrors are the notifications that failed, as "<receiver>:
	// <error>" with secrets masked.
	SendErrors []string
	// Warnings are problems worth a line that didn't stop the run.
	Warnings []string
}

func (w *Watcher) clock() Clock {
	if w.Clock == nil {
		return RealClock{}
	}
	return w.Clock
}

func (w *Watcher) logf(format string, a ...any) {
	if w.Log != nil {
		fmt.Fprintf(w.Log, format+"\n", a...)
	}
}

// Run runs reviews on the schedule until ctx is done. A run in progress
// when ctx ends is finished, not killed: canceling ctx is the polite
// stop, Abort the impatient one. It returns the worst outcome of the
// runs (see Outcome) after a polite stop, or the error that made the
// watch give up.
func (w *Watcher) Run(ctx context.Context) (Outcome, error) {
	var out Outcome
	if err := w.Schedule.Validate(); err != nil {
		return out, err
	}
	c := w.clock()
	var next time.Time
	if w.Schedule.Every > 0 || w.RunNow {
		next = c.Now()
	} else {
		next = w.Schedule.Next(time.Time{}, c.Now())
		w.logf("Next run %s", stamp(next))
	}
	for {
		if err := sleepUntil(ctx, c, next); err != nil {
			return out, nil //nolint:nilerr // ctx ended between runs: a clean stop
		}
		start := c.Now()
		runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		w.mu.Lock()
		w.abort = cancel
		w.mu.Unlock()
		r, err := w.RunOnce(runCtx)
		cancel()
		switch {
		case errors.Is(err, ErrLocked):
			w.logf("%s: skipped: %v", stamp(start), err)
		case err != nil:
			w.logf("%s: %v", stamp(start), err)
			if errors.Is(err, ErrReviewUsage) {
				return out, err
			}
		default:
			w.logf("%s", r.Lines())
			out.add(r)
		}
		if ctx.Err() != nil {
			return out, nil
		}
		next = w.Schedule.Next(start, c.Now())
		w.logf("Next run %s", stamp(next))
	}
}

// Abort stops the review in progress, if any: an interrupt first, so
// it writes what it has, then a kill.
func (w *Watcher) Abort() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.abort != nil {
		w.abort()
	}
}

// Outcome sums up the runs of a watch for its exit code.
type Outcome struct {
	FailNew    bool // a run found a new finding at --fail-on-new
	SendFailed bool // a notification failed
	Findings   bool // a review exited 1 (its own --fail-on)
	Failed     bool // a review exited 3 or wrote no report
}

func (o *Outcome) add(r Run) {
	o.FailNew = o.FailNew || r.FailNew
	o.SendFailed = o.SendFailed || len(r.SendErrors) > 0
	o.Findings = o.Findings || r.Exit == exitFindings
	o.Failed = o.Failed || r.Report == "" || (r.Exit != exitOK && r.Exit != exitFindings)
}

// Outcome is the outcome of this one run.
func (r Run) Outcome() Outcome {
	var o Outcome
	o.add(r)
	return o
}

// Code is the exit code of PRD section 10 for an outcome: 1 for new
// findings at --fail-on-new or the review's own gate (it wins over the
// rest, as in a review), 3 for a failed review or, when strict, a failed
// notification, else 0.
func (o Outcome) Code(strict bool) int {
	switch {
	case o.FailNew || o.Findings:
		return cli.ExitFindings
	case o.Failed || (strict && o.SendFailed):
		return cli.ExitUnavailable
	}
	return cli.ExitOK
}

// Line is PRD 6.7's summary line: "2026-10-27 02:00 AEST: 6 sites, 14
// updates available, 2 to review (1 hold); report <dir>/<stamp>.json".
func (r Run) Line() string {
	if r.Report == "" {
		return fmt.Sprintf("%s: the review exited %d without a report; see %s", stamp(r.Started), r.Exit, r.LogFile)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s, %s available, %d to review", stamp(r.Started), plural(r.Sites, "site"), plural(r.Updates, "update"), r.Review+r.Hold)
	if r.Hold > 0 {
		fmt.Fprintf(&b, " (%d hold)", r.Hold)
	}
	fmt.Fprintf(&b, "; report %s", r.Report)
	if gap := r.gap(); gap != "" {
		fmt.Fprintf(&b, "; incomplete: %s (see %s)", gap, r.LogFile)
	}
	return b.String()
}

// gap says what a run with a report left out, "" for a complete review
// that exited 0 or 1: "2 not checked, 1 error".
func (r Run) gap() string {
	var parts []string
	if r.NotChecked > 0 {
		parts = append(parts, fmt.Sprintf("%d not checked", r.NotChecked))
	}
	if r.Unverified > 0 {
		parts = append(parts, fmt.Sprintf("%d unverified", r.Unverified))
	}
	if r.Errors > 0 {
		parts = append(parts, plural(r.Errors, "error"))
	}
	switch r.StoppedBy {
	case "":
	case "deadline":
		parts = append(parts, "the run hit its --deadline")
	default:
		parts = append(parts, "the run was "+r.StoppedBy)
	}
	failed := r.Exit != exitOK && r.Exit != exitFindings
	switch {
	case len(parts) > 0:
		return strings.Join(parts, ", ")
	case failed && r.Exit < 0:
		return "the review was stopped"
	case failed:
		return fmt.Sprintf("the review exited %d", r.Exit)
	case !r.Complete:
		return "the review is not complete"
	}
	return ""
}

// failed reports whether the run went wrong rather than only leaving
// packages out: no report, an error, a stop or a review that exited
// neither 0 nor 1. Such a run is notified every time; a run that only
// left packages out is notified when what it left out changes.
func (r Run) failed() bool {
	return r.Report == "" || r.Errors > 0 || r.StoppedBy != "" || r.Exit != exitOK && r.Exit != exitFindings
}

// Lines is Line plus one indented line per failed notification and
// warning.
func (r Run) Lines() string {
	lines := []string{r.Line()}
	for _, e := range r.SendErrors {
		lines = append(lines, "  couldn't notify "+e)
	}
	for _, wn := range r.Warnings {
		lines = append(lines, "  "+wn)
	}
	return strings.Join(lines, "\n")
}

func stamp(t time.Time) string { return t.Format("2006-01-02 15:04 MST") }

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Args returns the review arguments for a run writing to report (and
// html when set). A rereview reviews the installed versions against the
// release before them.
func (w *Watcher) Args(report, html string, rereview bool) []string {
	args := []string{"all", "--sites", w.Sites}
	if rereview {
		args = append(args, "--rereview")
	}
	args = append(args, "-q", "--plain", "-o", report)
	if html != "" {
		args = append(args, "-o", html)
	}
	return append(args, w.Extra...)
}

// RunOnce runs one review now, unless another run of this watch holds
// the lock (ErrLocked). ctx canceling stops the review.
func (w *Watcher) RunOnce(ctx context.Context) (Run, error) {
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		return Run{}, err
	}
	unlock, err := Lock(w.Dir)
	if err != nil {
		return Run{}, err
	}
	defer unlock()

	c := w.clock()
	r := Run{Started: c.Now(), Exit: -1}
	st, err := loadState(w.Dir)
	switch {
	case errors.Is(err, errCorrupt):
		setAside(w.Dir)
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s couldn't be read, so it was set aside as %s.bad; "+
			"this run may repeat earlier notifications", StateName, StateName))
	case err != nil:
		return r, err
	}
	base := w.freeName(r.Started)
	report := filepath.Join(w.Dir, base+".json")
	r.LogFile = filepath.Join(w.Dir, base+".log")
	html := ""
	if w.HTML {
		html = filepath.Join(w.Dir, base+".html")
	}

	r.Exit, err = w.exec(ctx, w.Args(report, html, false), r.LogFile)
	r.Finished = c.Now()
	if err != nil {
		return r, err
	}
	if r.Exit == exitUsage {
		return r, fmt.Errorf("%w (exit 2); see %s", ErrReviewUsage, r.LogFile)
	}
	if !fileExists(report) {
		w.tellFailure(ctx, st, fmt.Sprintf("the review exited %d without a report", r.Exit), &r)
		if err := st.save(w.Dir, c.Now()); err != nil {
			return r, err
		}
		w.prune(st.Report)
		return r, nil
	}
	rep, err := w.read(report)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("couldn't read the report: %v", err))
		w.tellFailure(ctx, st, "the review's report couldn't be read", &r)
		if err := st.save(w.Dir, c.Now()); err != nil {
			return r, err
		}
		return r, nil
	}
	r.Report = report
	if fileExists(html) {
		r.HTML = html
	}
	r.Sites, r.Updates = len(rep.Target.Sites), rep.Summary.Updates
	r.Review, r.Hold = rep.Summary.Review, rep.Summary.Hold
	r.Complete, r.StoppedBy = rep.Complete, rep.StoppedBy
	r.NotChecked, r.Errors, r.Unverified = core.CountNotChecked(rep.NotChecked), rep.ErrorCount(), rep.Summary.Unverified

	now := c.Now()
	var n news
	n.updates(rep, notify.KindUpdate, st, w.NotifyMin, w.FailOnNew, now)
	if newerPack(rep.SignalPack, st.SignalPack) {
		w.rereview(ctx, base, rep.SignalPack, st, &n, &r, now)
	}
	if w.Installed != nil && now.Sub(st.InstalledChecked) >= InstalledEvery {
		statuses, err := w.Installed(ctx)
		if err != nil {
			r.Warnings = append(r.Warnings, "couldn't check owners and closures: "+secrets.Redact(err.Error()))
		} else {
			n.installed(statuses, st)
			st.InstalledChecked = now
		}
	}
	r.New = n.items
	r.FailNew = n.failNew
	// What the run left out is told with what is new. It is told on its
	// own when the run failed or left out something else than last time.
	gap, partial := r.gap(), ""
	if gap != "" {
		partial = partialLine(gap, r.LogFile)
	}
	tell := len(n.items) > 0 || gap != "" && (r.failed() || gap != st.Partial)
	sent := !tell || w.send(ctx, report, partial, n.items, &r)
	if sent {
		for _, k := range n.keys {
			st.Seen[k] = now
		}
		st.Partial = gap
	}
	for _, k := range n.always {
		st.Seen[k] = now
	}
	st.Report, st.Finished = base+".json", r.Finished
	if rep.SignalPack != "" {
		st.SignalPack = rep.SignalPack
	}
	if err := st.save(w.Dir, now); err != nil {
		return r, err
	}
	w.prune(report)
	return r, nil
}

// rereview runs the installed versions against the release before them
// after a signal data update and adds what the new signals found.
func (w *Watcher) rereview(ctx context.Context, base, pack string, st *state, n *news, r *Run, now time.Time) {
	report := filepath.Join(w.Dir, base+".signals.json")
	code, err := w.exec(ctx, w.Args(report, "", true), r.LogFile)
	if err != nil || !fileExists(report) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("signal data %s is new; the rereview of the installed versions "+
			"exited %d without a report; see %s", pack, code, r.LogFile))
		return
	}
	rep, err := w.read(report)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("couldn't read the rereview report: %v", err))
		return
	}
	n.updates(rep, notify.KindNewSignal, st, w.NotifyMin, w.FailOnNew, now)
}

// newerPack reports whether a run's signal pack is newer than the last
// run's. Pack versions are dates (2026.10.24), so they compare as text;
// the first run has nothing to compare with.
func newerPack(now, before string) bool {
	return now != "" && before != "" && now > before
}

// tellFailure notifies a run that left no report to read. It is sent
// on every such run, so a nightly watch that keeps failing keeps
// saying so.
func (w *Watcher) tellFailure(ctx context.Context, st *state, why string, r *Run) {
	if w.send(ctx, "", "Failed: "+why+"; see "+r.LogFile, nil, r) {
		st.Partial = why
	}
}

// send hands what is new (and what the run left out) to every notifier.
// It reports whether the news may be recorded as told: there was no
// notifier or every send went through. A failed send leaves it for the
// next run.
func (w *Watcher) send(ctx context.Context, report, partial string, items []notify.Item, r *Run) bool {
	if len(w.Notifiers) == 0 {
		return true
	}
	m := notify.New(w.Name, w.Version, w.NotifyMin.String(), report, partial, items)
	ok := true
	for _, nt := range w.Notifiers {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendTimeout)
		err := nt.Send(sctx, m)
		cancel()
		if err != nil {
			ok = false
			r.SendErrors = append(r.SendErrors, secrets.Redact(nt.String()+": "+err.Error()))
			continue
		}
		if w.Verbose != nil {
			fmt.Fprintf(w.Verbose, "notified %s: %s\n", nt.String(), m.Summary)
		}
	}
	return ok
}

// read parses a report the child wrote.
func (w *Watcher) read(path string) (*core.Report, error) {
	if w.Read != nil {
		return w.Read(path)
	}
	f, err := os.Open(path) //nolint:gosec // a report this watch's child wrote
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return core.ReadReport(f)
}

// exec runs the review child with args, appending its output to the log
// file; it returns the exit code. ctx canceling stops it (and anything
// it started).
func (w *Watcher) exec(ctx context.Context, args []string, logFile string) (int, error) {
	logf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // the watch's own folder
	if err != nil {
		return -1, err
	}
	defer func() { _ = logf.Close() }()
	argv := append([]string{w.Exe}, args...)
	fmt.Fprintf(logf, "$ %s\n", secrets.Redact(filepath.Base(w.Exe)+" "+strings.Join(args, " ")))
	res, err := proc.Run(ctx, proc.Spec{Argv: argv, Env: w.Env, MaxOutput: maxChildOutput, Purpose: proc.PurposeWatchChild, Log: w.Verbose})
	_, _ = logf.Write(res.Stdout)
	_, _ = logf.Write(res.Stderr)
	if err != nil {
		if ctx.Err() != nil {
			return -1, nil // stopped on purpose; the run reports what is there
		}
		return -1, fmt.Errorf("can't run the review: %w", err)
	}
	return res.Code, nil
}

// freeName returns the base name for a run starting at t: its UTC time,
// with a suffix if a run in the same second already used it.
func (w *Watcher) freeName(t time.Time) string {
	base := t.UTC().Format("20060102T150405Z")
	name := base
	for i := 2; fileExists(filepath.Join(w.Dir, name+".json")) || fileExists(filepath.Join(w.Dir, name+".log")); i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// runName matches the files of one run: its stamp, a -N suffix for a
// second run in the same second and .signals for the rereview. prune
// only ever counts and deletes such files, so anything else in Dir is
// left alone.
var runName = regexp.MustCompile(`^(\d{8}T\d{6}Z(?:-\d+)?)(?:\.signals)?\.(?:json|log|html)$`)

// prune deletes all but the newest Keep runs' files, never the run
// named in keep.
func (w *Watcher) prune(keep string) {
	if w.Keep <= 0 {
		return
	}
	entries, err := os.ReadDir(w.Dir)
	if err != nil {
		return
	}
	runs := map[string][]string{}
	for _, e := range entries {
		m := runName.FindStringSubmatch(e.Name())
		if e.IsDir() || m == nil {
			continue
		}
		runs[m[1]] = append(runs[m[1]], filepath.Join(w.Dir, e.Name()))
	}
	bases := make([]string, 0, len(runs))
	for b := range runs {
		bases = append(bases, b)
	}
	// Names start with the UTC time, so they sort oldest first; runs in
	// one second sort by their numeric suffix (-2 before -10).
	slices.SortFunc(bases, compareRuns)
	kept := strings.TrimSuffix(filepath.Base(keep), ".json")
	for _, b := range bases[:max(0, len(bases)-w.Keep)] {
		if b == kept {
			continue
		}
		for _, f := range runs[b] {
			_ = os.Remove(f)
		}
	}
}

// compareRuns orders two run names by start time, then by suffix.
func compareRuns(a, b string) int {
	at, an := splitRun(a)
	bt, bn := splitRun(b)
	if c := strings.Compare(at, bt); c != 0 {
		return c
	}
	return an - bn
}

// splitRun splits a run name into its time stamp and suffix number; a
// name without a suffix is run 1 of its second.
func splitRun(name string) (stamp string, n int) {
	stamp, suffix, ok := strings.Cut(name, "-")
	if !ok {
		return stamp, 1
	}
	n, _ = strconv.Atoi(suffix)
	return stamp, n
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}
