// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/watch"
)

// sitesFile writes a one-site sites.yaml and returns its path.
func sitesFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agency.yaml")
	if err := os.WriteFile(p, []byte("sites:\n  - name: shop\n    path: "+filepath.ToSlash(dir)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestWatchUsage: every flag mistake is a usage error with its text,
// before anything runs.
func TestWatchUsage(t *testing.T) {
	sites := sitesFile(t)
	slack := strings.Replace(coretest.FakeKey(coretest.KeySlack), "https://", "slack://", 1)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--every", "24h"}, "rhythm-sightread: watch needs a sites file: rhythm-sightread watch -l <sites.yaml> --every 24h"},
		{[]string{"-l", sites}, "rhythm-sightread: pick a schedule: --every <interval> or --at <HH:MM>"},
		{[]string{"-l", sites, "--every", "10s"}, "rhythm-sightread: --every 10s is too often; the shortest interval is 1m0s"},
		{[]string{"-l", sites, "--every", "soon"}, `rhythm-sightread: --every "soon": want a duration such as 30s, 10m, 72h or 3d`},
		{[]string{"-l", sites, "--at", "2am"}, `rhythm-sightread: --at "2am": want a 24-hour time like 02:00 (several separated by commas)`},
		{[]string{"-l", sites, "--once", "--every", "1h"}, "rhythm-sightread: --once runs a single review; drop --every, --at and --now, or drop --once"},
		{[]string{"-l", sites, "--every", "1h", "--now"}, "rhythm-sightread: --now goes with --at; --every already starts with a run"},
		{[]string{"-l", sites, "--once", "--keep", "-1"}, "rhythm-sightread: --keep -1: want 0 or more"},
		{[]string{"-l", sites, "--once", "--notify-min", "none"}, `rhythm-sightread: --notify-min "none": want info, low, medium, high or critical`},
		{[]string{"-l", sites, "--once", "--fail-on-new", "severe"}, `rhythm-sightread: --fail-on-new "severe": want none, info, low, medium, high or critical`},
		{[]string{"-l", sites, "--once", "--", "-o", "x.json"}, "rhythm-sightread: the watch sets -o itself; drop it after --"},
		{[]string{"-l", sites, "--once", "--", "--notify-min=low"}, "rhythm-sightread: --notify-min=low is a watch flag; put it before --"},
		{[]string{"-l", sites, "--once", "--notify", strings.Replace(slack, "slack://", "gopher://", 1)},
			`rhythm-sightread: --notify: unsupported notification scheme "gopher"; want slack, discord, webhook+https or smtp`},
		{[]string{"-l", sites, "--once", "--notify", "smtp://me@mail.example.com?to=a@b.c&from=t@b.c"},
			"rhythm-sightread: --notify: smtp://mail.example.com: set SIGHTREAD_SMTP_PASSWORD to the password for the SMTP user"},
		{[]string{"-l", filepath.Join(t.TempDir(), "none.yaml"), "--once"}, "none.yaml: can't be read"},
	}
	for _, c := range cases {
		code, _, errOut := execute(t, append([]string{"watch"}, c.args...)...)
		if code != cli.ExitUsage || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: exit %d\n%s\nwant %q", c.args, code, errOut, c.want)
		}
		if strings.Contains(errOut, "/services/") {
			t.Errorf("%q: the webhook path leaked: %s", c.args, errOut)
		}
	}
	if code, _, errOut := execute(t, "watch", "-l", sites, "x"); code != cli.ExitUsage ||
		!strings.Contains(errOut, `watch takes no arguments, got "x"; review flags go after --`) {
		t.Errorf("positional: %d %s", code, errOut)
	}
}

// TestWatchOnceVerbose runs the real binary once with -v and a fake
// Slack URL: every program it starts is listed, the run line is printed
// and the URL's secret path appears nowhere (T-37).
func TestWatchOnceVerbose(t *testing.T) {
	sites := sitesFile(t)
	dir := t.TempDir()
	slack := strings.Replace(coretest.FakeKey(coretest.KeySlack), "https://", "slack://", 1)
	code, out, errOut := child(t, t.TempDir(), "watch", "-l", sites, "--once", "-v", "--dir", dir, "--notify", slack, "--", "--jobs", "1")
	all := out + errOut
	if !strings.Contains(errOut, "run watch-child: ") || !strings.Contains(errOut, "all --sites "+sites+" -q --plain -o ") ||
		!strings.Contains(errOut, "--jobs 1") {
		t.Errorf("no program line: exit %d\n%s", code, all)
	}
	secret := strings.TrimPrefix(slack, "slack://hooks.slack.com")
	if strings.Contains(all, secret) || strings.Contains(all, "/services/") {
		t.Errorf("the Slack URL leaked:\n%s", all)
	}
	logs, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	for _, l := range logs {
		if b, _ := os.ReadFile(l); strings.Contains(string(b), "/services/") {
			t.Errorf("%s holds the Slack URL", l)
		}
	}
	if len(logs) != 1 {
		t.Errorf("logs %q", logs)
	}
}

func TestDescribeSchedule(t *testing.T) {
	for want, s := range map[string]watch.Schedule{
		"every 24h":             {Every: 24 * time.Hour},
		"every 1h30m":           {Every: 90 * time.Minute},
		"every 1m30s":           {Every: 90 * time.Second},
		"daily at 02:00, 14:30": {At: []watch.TimeOfDay{{Hour: 2}, {Hour: 14, Minute: 30}}},
	} {
		if got := describeSchedule(s); got != want {
			t.Errorf("%+v: %q, want %q", s, got, want)
		}
	}
	for in, want := range map[string]string{"clients": "clients", "../../etc": "etc", "a b/c": "a-b-c", "CON": "CON-watch", "...": "watch"} {
		if got := safeWatchName(in); got != want {
			t.Errorf("safeWatchName(%q) = %q, want %q", in, got, want)
		}
	}
}
