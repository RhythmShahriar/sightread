// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/notify"
	"github.com/RhythmShahriar/sightread/run"
)

// TestMain doubles as a fake rhythm-sightread: with FAKE_SR_ARGV set,
// the test binary records its arguments there and acts like a review.
func TestMain(m *testing.M) {
	if argv := os.Getenv("FAKE_SR_ARGV"); argv != "" {
		os.Exit(fakeSightread(argv, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeSightread appends args as one JSON line to argvFile and copies the
// report in FAKE_SR_MAIN (FAKE_SR_SIGNALS for --rereview) to the .json
// -o file plus a stub page to an .html one. FAKE_SR_SLEEP holds it
// before exiting with FAKE_SR_EXIT; FAKE_SR_NO_REPORT writes nothing.
func fakeSightread(argvFile string, args []string) int {
	f, err := os.OpenFile(argvFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 99
	}
	b, _ := json.Marshal(args)
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
	if d, err := time.ParseDuration(os.Getenv("FAKE_SR_SLEEP")); err == nil {
		time.Sleep(d)
	}
	src := os.Getenv("FAKE_SR_MAIN")
	if slices.Contains(args, "--rereview") {
		src = os.Getenv("FAKE_SR_SIGNALS")
	}
	for i, a := range args {
		if a != "-o" || i+1 == len(args) || os.Getenv("FAKE_SR_NO_REPORT") != "" {
			continue
		}
		out := args[i+1]
		if strings.HasSuffix(out, ".html") {
			_ = os.WriteFile(out, []byte("<!doctype html><title>report</title>\n"), 0o600)
			continue
		}
		if data, err := os.ReadFile(src); err == nil {
			_ = os.WriteFile(out, data, 0o600)
		}
	}
	os.Stdout.WriteString("review output\n")
	code, _ := strconv.Atoi(os.Getenv("FAKE_SR_EXIT"))
	return code
}

// world is one fake watch: the Watcher, its argv log and the report
// files the fake child copies.
type world struct {
	w                     *Watcher
	argv, main, rereviews string
}

func fake(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	wd := &world{argv: filepath.Join(dir, "argv.jsonl"), main: filepath.Join(dir, "main.json"), rereviews: filepath.Join(dir, "signals.json")}
	t.Setenv("FAKE_SR_ARGV", wd.argv)
	t.Setenv("FAKE_SR_MAIN", wd.main)
	t.Setenv("FAKE_SR_SIGNALS", wd.rereviews)
	t.Setenv("FAKE_SR_EXIT", "0")
	t.Setenv("FAKE_SR_SLEEP", "")
	t.Setenv("FAKE_SR_NO_REPORT", "")
	// A -race build of the fake would otherwise pause a second at exit.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wd.w = &Watcher{Exe: exe, Sites: filepath.Join(dir, "sites.yaml"), Name: "agency", Dir: filepath.Join(dir, "watch"),
		NotifyMin: cli.SeverityHigh, Version: "1.0.0", Read: readJSON,
		Clock: &fakeClock{now: time.Date(2026, 10, 26, 16, 0, 0, 0, time.UTC)}}
	wd.report(t, "2026.10.01")
	return wd
}

// readJSON reads the reports the fake child writes: core.Report in
// encoding/json's default form.
func readJSON(path string) (*core.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r core.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func finding(id string, sev cli.Severity) core.Finding {
	return core.Finding{ID: id, Title: "Title of " + id, Severity: sev, Confidence: core.Likely}
}

func update(name, from, to string, verdict core.Verdict, sites []string, fs ...core.Finding) core.Update {
	return core.Update{Eco: core.WPPlugin, Name: name, From: core.Side{Version: from}, To: core.Side{Version: to, SHA256: "ab" + to},
		Verdict: verdict, Sites: sites, Findings: fs}
}

// report writes the report the next review returns: six sites,
// wpforms-lite on HOLD on two of them and a routine akismet update.
func (wd *world) report(t *testing.T, pack string, extra ...core.Update) {
	t.Helper()
	ups := append([]core.Update{
		update("wpforms-lite", "1.9.1", "1.9.2", core.Hold, []string{"shop", "blog"}, finding("remote-fetch-exec", cli.SeverityCritical)),
		update("akismet", "5.3.3", "5.3.5", core.Routine, []string{"shop"}),
	}, extra...)
	wd.write(t, wd.main, pack, ups)
}

func (wd *world) write(t *testing.T, path, pack string, ups []core.Update) {
	t.Helper()
	rep := core.Report{Kind: core.KindReview, SignalPack: pack, Complete: true, Updates: ups,
		Target: core.Target{Kind: "fleet", Sites: []string{"shop", "blog", "api", "brochure", "news", "old"}}}
	for _, u := range ups {
		rep.Summary.Updates++
		switch u.Verdict {
		case core.Hold:
			rep.Summary.Hold++
		case core.Review:
			rep.Summary.Review++
		}
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (wd *world) calls(t *testing.T) [][]string {
	t.Helper()
	f, err := os.Open(wd.argv)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var a []string
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// fakeClock jumps straight to the end of every sleep and cancels after
// a number of sleeps.
type fakeClock struct {
	mu        sync.Mutex
	now       time.Time
	stopAfter int
	sleeps    int
	cancel    context.CancelFunc
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.sleeps++
	stop := c.stopAfter > 0 && c.sleeps >= c.stopAfter
	c.mu.Unlock()
	if stop {
		c.cancel()
		return ctx.Err()
	}
	return nil
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// hook is a webhook receiver on 127.0.0.1 that keeps every message.
type hook struct {
	mu     sync.Mutex
	got    []notify.Message
	status atomic.Int32
	url    string
}

func newHook(t *testing.T) *hook {
	t.Helper()
	h := &hook{}
	h.status.Store(http.StatusOK)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m notify.Message
		_ = json.NewDecoder(r.Body).Decode(&m)
		h.mu.Lock()
		h.got = append(h.got, m)
		h.mu.Unlock()
		w.WriteHeader(int(h.status.Load()))
	}))
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	h.url = "webhook+http://" + srv.Listener.Addr().String() + "/hook/SECRETPATH"
	return h
}

func (h *hook) messages() []notify.Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.got)
}

func (h *hook) notifier(t *testing.T) notify.Notifier {
	t.Helper()
	n, err := notify.Parse(h.url, notify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// listen opens a loopback listener on the cli lane's test ports.
func listen(t *testing.T) net.Listener {
	t.Helper()
	for port := 31116; port < 31120; port++ {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return l
		}
	}
	t.Fatal("no free port in 31116-31119")
	return nil
}

// TestRunOnceLineAndArgs: one run starts all --sites with -o into the
// watch folder and prints PRD 6.7's line.
func TestRunOnceLineAndArgs(t *testing.T) {
	wd := fake(t)
	wd.w.HTML = true
	wd.w.Extra = []string{"--jobs", "2"}
	r, err := wd.w.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(wd.w.Dir, "20261026T160000Z.json")
	html := filepath.Join(wd.w.Dir, "20261026T160000Z.html")
	want := []string{"all", "--sites", wd.w.Sites, "-q", "--plain", "-o", report, "-o", html, "--jobs", "2"}
	if got := wd.calls(t); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("argv %q, want %q", got, want)
	}
	if line := r.Line(); line != "2026-10-26 16:00 UTC: 6 sites, 2 updates available, 1 to review (1 hold); report "+report {
		t.Errorf("line %q", line)
	}
	if r.HTML != html || r.Exit != 0 || r.Outcome().Code(false) != 0 {
		t.Errorf("run %+v", r)
	}
	if b, _ := os.ReadFile(r.LogFile); !strings.Contains(string(b), "review output") || !strings.Contains(string(b), "$ ") {
		t.Errorf("log %q", b)
	}
	if fi, err := os.Stat(filepath.Join(wd.w.Dir, StateName)); err != nil || fi.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Errorf("state: %v %v", fi, err)
	}
}

func isWindows() bool { return filepath.Separator == '\\' }

// TestLineWithoutHold and without a report.
func TestLineVariants(t *testing.T) {
	at := time.Date(2026, 10, 27, 2, 0, 0, 0, time.FixedZone("AEST", 10*3600))
	r := Run{Started: at, Report: "/w/x.json", Sites: 1, Updates: 1, Review: 1, Complete: true}
	if got := r.Line(); got != "2026-10-27 02:00 AEST: 1 site, 1 update available, 1 to review; report /w/x.json" {
		t.Errorf("%q", got)
	}
	r = Run{Started: at, Exit: 3, LogFile: "/w/x.log"}
	if got := r.Line(); got != "2026-10-27 02:00 AEST: the review exited 3 without a report; see /w/x.log" {
		t.Errorf("%q", got)
	}
	r = Run{Started: at, Report: "/w/x.json", Complete: true, SendErrors: []string{"slack://hooks.slack.com: receiver answered 500"}, Warnings: []string{"w"}}
	if got := r.Lines(); !strings.HasSuffix(got, "\n  couldn't notify slack://hooks.slack.com: receiver answered 500\n  w") {
		t.Errorf("%q", got)
	}
}

// TestDedupe: the same finding is sent once across three runs; a new
// site with the same update is sent again, for that site only.
func TestDedupe(t *testing.T) {
	wd := fake(t)
	h := newHook(t)
	wd.w.Notifiers = []notify.Notifier{h.notifier(t)}
	for range 3 {
		if _, err := wd.w.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		wd.w.Clock.(*fakeClock).advance(time.Hour)
	}
	msgs := h.messages()
	if len(msgs) != 1 || len(msgs[0].Items) != 1 {
		t.Fatalf("messages %+v", msgs)
	}
	it := msgs[0].Items[0]
	if it.Line() != "wpforms-lite 1.9.1 → 1.9.2 HOLD on 2 sites" || it.Top != "Title of remote-fetch-exec" || it.Severity != "critical" {
		t.Errorf("item %+v", it)
	}
	if !strings.HasSuffix(msgs[0].Report, "20261026T160000Z.json") || msgs[0].Watch != "agency" {
		t.Errorf("message %+v", msgs[0])
	}
	// The update reaches a third site: only that site is new.
	wd.report(t, "2026.10.01", update("wpforms-lite", "1.9.0", "1.9.2", core.Hold, []string{"api"}, finding("remote-fetch-exec", cli.SeverityCritical)))
	if _, err := wd.w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if msgs = h.messages(); len(msgs) != 2 || !slices.Equal(msgs[1].Items[0].Sites, []string{"api"}) {
		t.Errorf("fourth run: %+v", msgs)
	}
}

// TestNotifyMin: the default (high) leaves a medium finding out;
// --notify-min medium sends it.
func TestNotifyMin(t *testing.T) {
	medium := update("share-kit", "3.2.0", "3.2.1", core.Review, []string{"shop"}, finding("outbound-new-domain", cli.SeverityMedium))
	for _, c := range []struct {
		min  cli.Severity
		want int
	}{{cli.SeverityHigh, 0}, {cli.SeverityMedium, 1}} {
		wd := fake(t)
		wd.write(t, wd.main, "2026.10.01", []core.Update{medium})
		h := newHook(t)
		wd.w.Notifiers, wd.w.NotifyMin = []notify.Notifier{h.notifier(t)}, c.min
		r, err := wd.w.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(h.messages()) != c.want || len(r.New) != c.want {
			t.Errorf("--notify-min %s: %d messages, %d new", c.min, len(h.messages()), len(r.New))
		}
	}
}

// TestFailOnNew: a new finding at the level fails the run once; the
// next run with nothing new passes; a level above it never fails.
func TestFailOnNew(t *testing.T) {
	wd := fake(t)
	wd.w.FailOnNew = cli.SeverityHigh
	r, err := wd.w.RunOnce(context.Background())
	if err != nil || !r.FailNew || r.Outcome().Code(false) != cli.ExitFindings {
		t.Fatalf("first run: %+v %v", r, err)
	}
	wd.w.Clock.(*fakeClock).advance(time.Hour)
	if r, err = wd.w.RunOnce(context.Background()); err != nil || r.FailNew || r.Outcome().Code(false) != 0 {
		t.Errorf("second run: %+v %v", r, err)
	}

	wd = fake(t)
	wd.write(t, wd.main, "2026.10.01", []core.Update{update("x", "1", "2", core.Review, nil, finding("y", cli.SeverityMedium))})
	wd.w.FailOnNew = cli.SeverityHigh
	if r, err = wd.w.RunOnce(context.Background()); err != nil || r.FailNew {
		t.Errorf("medium under --fail-on-new high: %+v %v", r, err)
	}
}

// TestSendFailure: a failed send is reported masked, counts under
// --notify-strict and is tried again on the next run.
func TestSendFailure(t *testing.T) {
	wd := fake(t)
	h := newHook(t)
	h.status.Store(http.StatusInternalServerError)
	wd.w.Notifiers = []notify.Notifier{h.notifier(t)}
	r, err := wd.w.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.SendErrors) != 1 || strings.Contains(r.SendErrors[0], "SECRETPATH") ||
		!strings.HasSuffix(r.SendErrors[0], ": receiver answered 500 Internal Server Error") {
		t.Fatalf("send errors %q", r.SendErrors)
	}
	if r.Outcome().Code(false) != 0 || r.Outcome().Code(true) != cli.ExitUnavailable {
		t.Errorf("codes %d %d", r.Outcome().Code(false), r.Outcome().Code(true))
	}
	h.status.Store(http.StatusOK)
	wd.w.Clock.(*fakeClock).advance(time.Hour)
	if _, err := wd.w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if msgs := h.messages(); len(msgs) != 2 || len(msgs[1].Items) != 1 {
		t.Errorf("retry: %+v", msgs)
	}
}

// TestCorruptState: a damaged state.json is set aside with a warning and
// the run goes on.
func TestCorruptState(t *testing.T) {
	wd := fake(t)
	if err := os.MkdirAll(wd.w.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wd.w.Dir, StateName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := wd.w.RunOnce(context.Background())
	if err != nil || r.Report == "" {
		t.Fatalf("%+v %v", r, err)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "state.json couldn't be read, so it was set aside as state.json.bad") {
		t.Errorf("warnings %q", r.Warnings)
	}
	if _, err := os.Stat(filepath.Join(wd.w.Dir, StateName+".bad")); err != nil {
		t.Error(err)
	}
	if st, err := loadState(wd.w.Dir); err != nil || st.Report != "20261026T160000Z.json" {
		t.Errorf("new state %+v %v", st, err)
	}
	// A state of another format is not trusted either.
	if err := os.WriteFile(filepath.Join(wd.w.Dir, StateName), []byte(`{"schema":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(wd.w.Dir); !errors.Is(err, errCorrupt) {
		t.Errorf("other schema: %v", err)
	}
}

// TestLockPreventsOverlap: a held lock turns a run away before any
// review starts.
func TestLockPreventsOverlap(t *testing.T) {
	wd := fake(t)
	if err := os.MkdirAll(wd.w.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := Lock(wd.w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wd.w.RunOnce(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if len(wd.calls(t)) != 0 {
		t.Error("a review ran while the lock was held")
	}
	// A second lock in the same process is refused too: flock belongs to
	// the open file and Windows opens it without sharing.
	if _, err := Lock(wd.w.Dir); !errors.Is(err, ErrLocked) {
		t.Errorf("second lock: %v", err)
	}
	unlock()
	if r, err := wd.w.RunOnce(context.Background()); err != nil || r.Report == "" {
		t.Fatalf("after unlock: %+v %v", r, err)
	}
}

// TestRereviewAfterPackUpdate: a newer signal pack re-reviews the
// installed versions once and notifies a finding no earlier run counted.
func TestRereviewAfterPackUpdate(t *testing.T) {
	wd := fake(t)
	h := newHook(t)
	wd.w.Notifiers = []notify.Notifier{h.notifier(t)}
	clock := wd.w.Clock.(*fakeClock)
	if _, err := wd.w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The installed wpforms-lite 1.9.1 against 1.9.0: the old finding
	// was never counted for 1.9.1, the new signal is new; akismet's
	// finding is below --notify-min.
	wd.write(t, wd.rereviews, "2026.10.20", []core.Update{
		update("wpforms-lite", "1.9.0", "1.9.1", core.Hold, []string{"shop", "blog"}, finding("new-c2-domain", cli.SeverityCritical)),
		update("akismet", "5.3.2", "5.3.3", core.Review, []string{"shop"}, finding("minified-new", cli.SeverityLow)),
	})
	wd.report(t, "2026.10.20")
	clock.advance(time.Hour)
	if _, err := wd.w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := wd.calls(t)
	if len(calls) != 3 || !slices.Contains(calls[2], "--rereview") ||
		!slices.Contains(calls[2], filepath.Join(wd.w.Dir, "20261026T170000Z.signals.json")) {
		t.Fatalf("calls %q", calls)
	}
	msgs := h.messages()
	if len(msgs) != 2 || len(msgs[1].Items) != 1 ||
		msgs[1].Items[0].Line() != "new signal on a version you already run: wpforms-lite 1.9.1 HOLD on 2 sites" {
		t.Fatalf("messages %+v", msgs)
	}
	// The same pack again: no rereview, nothing sent.
	clock.advance(time.Hour)
	if _, err := wd.w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(wd.calls(t)); n != 4 || len(h.messages()) != 2 {
		t.Errorf("%d calls, %d messages", n, len(h.messages()))
	}
}

// TestFirstRunNoRereview: the first run has no earlier pack to compare
// with, so it never re-reviews.
func TestFirstRunNoRereview(t *testing.T) {
	wd := fake(t)
	if _, err := wd.w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls := wd.calls(t); len(calls) != 1 || slices.Contains(calls[0], "--rereview") {
		t.Errorf("calls %q", calls)
	}
}

// TestOwnersAndClosures: the first sighting records owners, a change
// after 12 hours is notified once, a closure once; the sources are
// not asked again within 12 hours.
func TestOwnersAndClosures(t *testing.T) {
	wd := fake(t)
	wd.write(t, wd.main, "2026.10.01", nil)
	h := newHook(t)
	wd.w.Notifiers = []notify.Notifier{h.notifier(t)}
	clock := wd.w.Clock.(*fakeClock)
	asked := 0
	statuses := []run.InstalledStatus{
		{Site: "shop", Ref: core.Ref{Eco: core.WPPlugin, Name: "share-kit", Version: "3.2.0"}, Owners: []string{"alice"}},
		{Site: "blog", Ref: core.Ref{Eco: core.WPPlugin, Name: "share-kit", Version: "3.2.0"}, Owners: []string{"alice"}},
	}
	wd.w.Installed = func(context.Context) ([]run.InstalledStatus, error) {
		asked++
		return slices.Clone(statuses), nil
	}
	if r, err := wd.w.RunOnce(context.Background()); err != nil || len(r.New) != 0 {
		t.Fatalf("first run: %+v %v", r, err)
	}
	statuses[0].Owners = []string{"growth-partners"}
	statuses[1].Owners = []string{"growth-partners"}
	statuses = append(statuses, run.InstalledStatus{Site: "shop", Ref: core.Ref{Eco: core.WPPlugin, Name: "gone", Version: "2.0.0"},
		Closed: true, ClosedReason: "security issue"})
	clock.advance(time.Hour)
	if r, err := wd.w.RunOnce(context.Background()); err != nil || len(r.New) != 0 || asked != 1 {
		t.Fatalf("within 12h: %+v %v asked %d", r, err, asked)
	}
	clock.advance(12 * time.Hour)
	r, err := wd.w.RunOnce(context.Background())
	if err != nil || asked != 2 {
		t.Fatal(err, asked)
	}
	var lines []string
	for _, it := range r.New {
		lines = append(lines, it.Line())
	}
	want := []string{"owner change: share-kit 3.2.0 on 2 sites: added growth-partners; removed alice",
		"closed on wordpress.org: gone 2.0.0 on shop: security issue"}
	if !slices.Equal(lines, want) || len(h.messages()) != 1 {
		t.Errorf("new %q, want %q", lines, want)
	}
	clock.advance(13 * time.Hour)
	if r, err := wd.w.RunOnce(context.Background()); err != nil || len(r.New) != 0 || asked != 3 {
		t.Errorf("again: %+v %v", r.New, err)
	}
}

// TestFailedReview: a review that exits 3 without a report counts as a
// failed run; exit 2 stops the watch.
func TestFailedReview(t *testing.T) {
	wd := fake(t)
	t.Setenv("FAKE_SR_NO_REPORT", "1")
	t.Setenv("FAKE_SR_EXIT", "3")
	r, err := wd.w.RunOnce(context.Background())
	if err != nil || r.Report != "" || !strings.Contains(r.Line(), "the review exited 3 without a report; see ") ||
		r.Outcome().Code(false) != cli.ExitUnavailable {
		t.Fatalf("%+v %v %q", r, err, r.Line())
	}
	t.Setenv("FAKE_SR_EXIT", "2")
	wd.w.Schedule = Schedule{Every: time.Hour}
	wd.w.Clock = &fakeClock{now: time.Now(), cancel: func() {}}
	if _, err := wd.w.Run(context.Background()); !errors.Is(err, ErrReviewUsage) {
		t.Fatalf("err %v", err)
	}
}

// TestScheduleRuns: an interval runs at once and then every interval;
// --at waits for the time unless RunNow, which runs first.
func TestScheduleRuns(t *testing.T) {
	for _, c := range []struct {
		name  string
		s     Schedule
		now   bool
		sleep int // sleeps of at most a minute before the clock stops the watch
		want  []string
	}{
		{"every", Schedule{Every: time.Hour}, false, 61, []string{"20261026T160000Z", "20261026T170000Z"}},
		{"at", Schedule{At: []TimeOfDay{{18, 30}}}, false, 151, []string{"20261026T183000Z"}},
		{"at with now", Schedule{At: []TimeOfDay{{18, 30}}}, true, 151, []string{"20261026T160000Z", "20261026T183000Z"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			wd := fake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Date(2026, 10, 26, 16, 0, 0, 0, time.UTC)
			wd.w.Clock = &fakeClock{now: start, cancel: cancel, stopAfter: c.sleep}
			wd.w.Schedule, wd.w.RunNow = c.s, c.now
			var log strings.Builder
			wd.w.Log = &log
			if _, err := wd.w.Run(ctx); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, a := range wd.calls(t) {
				got = append(got, strings.TrimSuffix(filepath.Base(a[slices.Index(a, "-o")+1]), ".json"))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("runs %q, want %q\n%s", got, c.want, log.String())
			}
		})
	}
}

// TestStopFinishesCurrentRun: a polite stop during a review lets it
// finish and records it.
func TestStopFinishesCurrentRun(t *testing.T) {
	wd := fake(t)
	t.Setenv("FAKE_SR_SLEEP", "400ms")
	wd.w.Schedule = Schedule{Every: time.Hour}
	wd.w.Clock = RealClock{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitStarted(t, wd)
		cancel()
	}()
	if _, err := wd.w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(wd.calls(t)); n != 1 {
		t.Errorf("%d reviews", n)
	}
	if _, err := os.Stat(filepath.Join(wd.w.Dir, StateName)); err != nil {
		t.Errorf("finished run not recorded: %v", err)
	}
}

// TestAbortStopsReview: Abort ends the review in progress.
func TestAbortStopsReview(t *testing.T) {
	wd := fake(t)
	t.Setenv("FAKE_SR_SLEEP", "20s")
	wd.w.Schedule = Schedule{Every: time.Hour}
	wd.w.Clock = RealClock{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitStarted(t, wd)
		cancel()
		wd.w.Abort()
	}()
	done := make(chan struct{})
	go func() {
		_, _ = wd.w.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Abort didn't stop the review")
	}
}

// waitStarted returns once the fake child recorded its arguments.
func waitStarted(t *testing.T, wd *world) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(wd.argv); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPrune keeps the newest runs, their rereview and HTML files with
// them; it never touches files that aren't runs.
func TestPrune(t *testing.T) {
	dir := t.TempDir()
	mine := []string{"0-notes.log", "2025-annual-audit.json", "report.html", "sites.yaml", "20261024T010000Zx.json", StateName}
	runs := []string{
		"20261024T010000Z.json", "20261024T010000Z.signals.json", "20261024T010000Z-2.json", "20261024T010000Z-10.json",
		"20261024T020000Z.json", "20261024T020000Z.log", "20261024T020000Z.signals.json",
	}
	for _, n := range append(slices.Clone(mine), runs...) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := &Watcher{Dir: dir, Keep: 2}
	w.prune(filepath.Join(dir, "20261024T010000Z.json"))
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := append(slices.Clone(mine), "20261024T010000Z.json", "20261024T010000Z.signals.json", "20261024T010000Z-10.json",
		"20261024T020000Z.json", "20261024T020000Z.log", "20261024T020000Z.signals.json")
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("after prune %v, want %v", names, want)
	}
}

// TestSchedule is the schedule arithmetic and parsing.
func TestSchedule(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	at, err := ParseAt("14:30, 02:00,02:00")
	if err != nil || len(at) != 2 || at[0].String() != "02:00" {
		t.Fatalf("%v %v", at, err)
	}
	s := Schedule{At: at}
	for _, c := range []struct{ now, want time.Time }{
		{time.Date(2026, 10, 24, 1, 0, 0, 0, loc), time.Date(2026, 10, 24, 2, 0, 0, 0, loc)},
		{time.Date(2026, 10, 24, 2, 0, 0, 0, loc), time.Date(2026, 10, 24, 14, 30, 0, 0, loc)},
		{time.Date(2026, 10, 24, 23, 0, 0, 0, loc), time.Date(2026, 10, 25, 2, 0, 0, 0, loc)},
	} {
		if got := s.Next(time.Time{}, c.now); !got.Equal(c.want) {
			t.Errorf("Next(%s) = %s, want %s", c.now, got, c.want)
		}
	}
	every := Schedule{Every: time.Hour}
	start := time.Date(2026, 10, 24, 1, 0, 0, 0, loc)
	if got := every.Next(start, start.Add(150*time.Minute)); !got.Equal(start.Add(3 * time.Hour)) {
		t.Errorf("overrun next %s", got)
	}
	for _, bad := range []string{"2am", "24:00", "02:60", "2:5", ""} {
		if _, err := ParseAt(bad); err == nil {
			t.Errorf("ParseAt(%q) accepted", bad)
		}
	}
	for _, c := range []struct {
		s    Schedule
		want string
	}{
		{Schedule{}, "pick a schedule"},
		{Schedule{Every: time.Hour, At: at}, "pick one of --every and --at"},
		{Schedule{Every: time.Second}, "too often"},
	} {
		if err := c.s.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.s, err)
		}
	}
}

// TestOutcomeCodes: 1 beats 3, strict makes a failed send 3.
func TestOutcomeCodes(t *testing.T) {
	for _, c := range []struct {
		o      Outcome
		strict bool
		want   int
	}{
		{Outcome{}, false, 0},
		{Outcome{FailNew: true, Failed: true}, false, 1},
		{Outcome{Findings: true}, false, 1},
		{Outcome{Failed: true}, false, 3},
		{Outcome{SendFailed: true}, false, 0},
		{Outcome{SendFailed: true}, true, 3},
	} {
		if got := c.o.Code(c.strict); got != c.want {
			t.Errorf("%+v strict %v: %d, want %d", c.o, c.strict, got, c.want)
		}
	}
}

// writeReport writes rep as the next review's report.
func (wd *world) writeReport(t *testing.T, rep core.Report) {
	t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wd.main, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestIncompleteRun: a review that exits 3 with every package Not
// checked and an E7 says so on its line and in a notification, every
// run; a run that only leaves the same package out is notified once.
func TestIncompleteRun(t *testing.T) {
	wd := fake(t)
	h := newHook(t)
	wd.w.Notifiers = []notify.Notifier{h.notifier(t)}
	t.Setenv("FAKE_SR_EXIT", "3")
	down := core.Report{Kind: core.KindReview, Target: core.Target{Kind: "fleet", Sites: []string{"shop", "blog"}},
		NotChecked: []core.NotChecked{{Eco: core.NPM, Name: "date-utils-lite", Version: "1.4.0", Reason: core.FetchFailed}},
		Errors:     []core.ErrorEntry{{Eco: core.NPM, Name: "date-utils-lite", Code: "E7", Message: "can't reach registry.npmjs.org"}}}
	down.Summary.NotChecked = 1
	wd.writeReport(t, down)
	for i := range 2 {
		r, err := wd.w.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		// The E7 is the Not checked entry's own error: counted once.
		want := "2 sites, 0 updates available, 0 to review; report " + r.Report + "; incomplete: 1 not checked (see " + r.LogFile + ")"
		if !strings.HasSuffix(r.Line(), want) {
			t.Errorf("run %d: line %q, want suffix %q", i+1, r.Line(), want)
		}
		if r.Outcome().Code(false) != cli.ExitUnavailable {
			t.Errorf("run %d: code %d", i+1, r.Outcome().Code(false))
		}
		msgs := h.messages()
		if len(msgs) != i+1 {
			t.Fatalf("run %d: %d messages, want %d", i+1, len(msgs), i+1)
		}
		m := msgs[i]
		if m.Summary != "Sightread agency: the review is incomplete" || m.Incomplete != "Partial: 1 not checked; see "+r.LogFile {
			t.Errorf("run %d: message %+v", i+1, m)
		}
		wd.w.Clock.(*fakeClock).advance(time.Hour)
	}

	// Only a package left out, the review otherwise fine: told once.
	t.Setenv("FAKE_SR_EXIT", "0")
	partial := down
	partial.Errors = nil
	partial.NotChecked = []core.NotChecked{{Eco: core.WPPlugin, Name: "premium-forms", Reason: core.NotWPOrg},
		{Eco: core.WPPlugin, Name: "premium-seo", Reason: core.NotWPOrg}}
	wd.writeReport(t, partial)
	for range 2 {
		r, err := wd.w.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(r.Line(), "; incomplete: 2 not checked (see "+r.LogFile+")") {
			t.Errorf("line %q", r.Line())
		}
		wd.w.Clock.(*fakeClock).advance(time.Hour)
	}
	if msgs := h.messages(); len(msgs) != 3 || msgs[2].Incomplete == "" {
		t.Errorf("partial runs: %d messages, want 3: %+v", len(msgs), msgs)
	}

	// A complete run clears it; the line has no incomplete part.
	wd.report(t, "2026.10.01")
	r, err := wd.w.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Line(), "incomplete") {
		t.Errorf("complete run: %q", r.Line())
	}
}

// TestFailedReviewNotifies: a review that exits 3 without a report is
// notified on every run.
func TestFailedReviewNotifies(t *testing.T) {
	wd := fake(t)
	h := newHook(t)
	wd.w.Notifiers = []notify.Notifier{h.notifier(t)}
	t.Setenv("FAKE_SR_NO_REPORT", "1")
	t.Setenv("FAKE_SR_EXIT", "3")
	for range 2 {
		if _, err := wd.w.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		wd.w.Clock.(*fakeClock).advance(time.Hour)
	}
	msgs := h.messages()
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2", len(msgs))
	}
	for _, m := range msgs {
		if m.Summary != "Sightread agency: the review is incomplete" ||
			!strings.HasPrefix(m.Incomplete, "Failed: the review exited 3 without a report; see ") || len(m.Items) != 0 {
			t.Errorf("message %+v", m)
		}
	}
}

// TestRunGap covers the incomplete part of the line.
func TestRunGap(t *testing.T) {
	for _, c := range []struct {
		r    Run
		want string
	}{
		{Run{Complete: true}, ""},
		{Run{Complete: true, Exit: 1}, ""},
		{Run{Complete: false}, "the review is not complete"},
		{Run{Complete: true, Exit: 3}, "the review exited 3"},
		{Run{Complete: true, Exit: -1}, "the review was stopped"},
		{Run{NotChecked: 2, Errors: 2, Unverified: 1, Exit: 3}, "2 not checked, 1 unverified, 2 errors"},
		{Run{StoppedBy: "deadline", Exit: 3}, "the run hit its --deadline"},
		{Run{StoppedBy: "interrupted", Exit: 3}, "the run was interrupted"},
	} {
		if got := c.r.gap(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
	}
}

// TestDurationText: no Go-style zero units in what users read.
func TestDurationText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Minute: "1m", 90 * time.Second: "1m30s", 10 * time.Second: "10s", 2 * time.Hour: "2h",
		2*time.Hour + 30*time.Minute: "2h30m", time.Hour + time.Second: "1h0m1s",
	} {
		if got := DurationText(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
	err := Schedule{Every: 10 * time.Second}.Validate()
	if err == nil || err.Error() != "--every 10s is too often; the shortest interval is 1m" {
		t.Errorf("validate: %v", err)
	}
}

// TestSendFailureSummarised: a receiver that can't be reached is one
// short cause on the run's line (PRD 10); the raw Go error goes to -v.
func TestSendFailureSummarised(t *testing.T) {
	l := listen(t)
	addr := l.Addr().String()
	_ = l.Close()
	n, err := notify.Parse("webhook+http://"+addr+"/hook", notify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	wd := fake(t)
	var verbose strings.Builder
	wd.w.Verbose = &verbose
	wd.w.Notifiers = []notify.Notifier{n}
	r, err := wd.w.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "webhook+http://" + addr + ": connection refused"
	if len(r.SendErrors) != 1 || r.SendErrors[0] != want {
		t.Fatalf("send errors %q, want %q", r.SendErrors, want)
	}
	if !strings.Contains(r.Lines(), "\n  couldn't notify "+want) || strings.Contains(r.Lines(), "dial tcp") {
		t.Errorf("lines %q", r.Lines())
	}
	// The raw error's wording is the system's own (Windows says the
	// target "actively refused it"); its "dial tcp" is the same anywhere.
	if !strings.Contains(verbose.String(), "couldn't notify webhook+http://"+addr+": dial tcp "+addr+": ") {
		t.Errorf("-v holds no raw error: %q", verbose.String())
	}
}
