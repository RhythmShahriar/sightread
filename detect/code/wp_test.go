// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"slices"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func TestWriteTarget(t *testing.T) {
	for in, want := range map[string]string{
		".npmrc": "npmrc", "npmrc": "npmrc", ".SSH": "ssh", "ci-files": "ci", "github-workflows": "ci",
		"wp-config.php": "wp-config", "wp-config": "wp-config", "uploads": "uploads", ".git": "git",
	} {
		if got := writeTarget(in); got != want {
			t.Errorf("writeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCapGrant(t *testing.T) {
	cases := map[string]bool{
		"add_cap:subscriber:manage_options":   true,
		"add_cap:Editor:UNFILTERED_HTML":      true,
		"add_role:helper:install_plugins":     true,
		"add_cap:administrator:manage_forms":  false,
		"add_cap:super_admin:manage_network":  false,
		"add_cap:editor:edit_acme_forms":      false,
		"remove_cap:editor:manage_options":    false,
		"add_cap:editor":                      false,
		"cap:filter:user_has_cap":             false, // grants not set
		"cap:other:user_has_cap":              false,
		"something:subscriber:manage_options": false,
	}
	for key, want := range cases {
		if got := capGrant(coretest.Feat(core.FCap, key, "a.php", 1)); got != want {
			t.Errorf("capGrant(%s) = %v, want %v", key, got, want)
		}
	}
	if !capGrant(coretest.Feat(core.FCap, "cap:filter:map_meta_cap", "a.php", 1, AttrGrants, "true")) {
		t.Error("a granting map_meta_cap filter does not count")
	}
}

func TestAdminUser(t *testing.T) {
	for _, tc := range []struct {
		key, role string
		want      bool
	}{
		{"wp_insert_user", "administrator", true},
		{"wp_create_user", "Administrator", true},
		{"wp_insert_user", "editor", false},
		{"wp_insert_user", "", false},
		{"wp_capabilities", "", true},
		{"wp_capabilities", "subscriber", false},
		{"grant_super_admin", "", true},
	} {
		f := coretest.Feat(core.FUserCreate, tc.key, "a.php", 1, AttrRole, tc.role)
		if got := adminUser(f); got != tc.want {
			t.Errorf("adminUser(%s, %q) = %v", tc.key, tc.role, got)
		}
	}
}

// An open route is raised by the signals of its own file only, each
// named once and sorted.
func TestOpenRouteRaisedBy(t *testing.T) {
	route := coretest.Feat(core.FRoute, "a/v1/x", "inc/a.php", 3, AttrPermission, "open")
	feats := []core.Feature{
		route,
		coretest.Feat(core.FFlow, "remote->unserialize", "inc/a.php", 10),
		coretest.Feat(core.FEval, "eval", "inc/a.php", 20, AttrSource, SrcRequest),
		coretest.Feat(core.FEval, "assert", "inc/a.php", 21, AttrSource, SrcRequest),
		coretest.Feat(core.FWrite, "uploads", "inc/a.php", 30),
		coretest.Feat(core.FWrite, "wp-config", "inc/b.php", 30),
	}
	fd := openRoute(route, feats)
	if fd.Severity != cli.SeverityHigh || !slices.Equal(fd.RaisedBy, []string{"eval-dynamic", "input-unserialize"}) {
		t.Errorf("severity %s raised by %v", fd.Severity, fd.RaisedBy)
	}
	if fd = openRoute(route, []core.Feature{route}); fd.Severity != cli.SeverityMedium || fd.RaisedBy != nil {
		t.Errorf("alone: %s %v", fd.Severity, fd.RaisedBy)
	}
}

// The cron hook is medium when the file that registers the hook's
// callback gains network or exec code, even if it is not the file that
// schedules it.
func TestCronCallbackFile(t *testing.T) {
	cron := coretest.Feat(core.FCron, "acme_sync", "inc/schedule.php", 5)
	hook := coretest.Feat(core.FHook, "acme_sync", "inc/sync.php", 3)
	send := coretest.Feat(core.FSend, "wp_remote_post", "inc/sync.php", 20)
	other := coretest.Feat(core.FSend, "wp_remote_post", "inc/other.php", 20)
	s := &core.Subject{NewFeatures: coretest.Features(cron, hook, send, other)}
	if fd := cronHook(s, cron, []core.Feature{cron, hook, send}); fd.Severity != cli.SeverityMedium {
		t.Errorf("callback file with a send: %s", fd.Severity)
	}
	s.NewFeatures = coretest.Features(cron, other)
	if fd := cronHook(s, cron, []core.Feature{cron, other}); fd.Severity != cli.SeverityLow {
		t.Errorf("unrelated file: %s", fd.Severity)
	}
}

// Signals for other ecosystems stay quiet: input-unserialize is PHP
// only, admin users WordPress only.
func TestWPEcosystems(t *testing.T) {
	fs := coretest.Features(
		coretest.Feat(core.FUnserialize, "unserialize", "a.php", 1, AttrSource, SrcRequest),
		coretest.Feat(core.FUserCreate, "wp_insert_user", "a.php", 2, AttrRole, "administrator"),
		coretest.Feat(core.FWrite, "ssh", "a.js", 3),
	)
	got := ids(detectAll(t, wpDetector{}, subject(core.NPM, nil, fs)))
	if got != "write-outside-package" {
		t.Errorf("npm: %s", got)
	}
	got = ids(detectAll(t, wpDetector{}, subject(core.Composer, nil, fs)))
	if got != "write-outside-package,input-unserialize" { // sorted by path: a.js, a.php
		t.Errorf("composer: %s", got)
	}
}

// The own option excuses unserialize only when it is the whole argument,
// and never a request or remote flow.
func TestOutsideUnserializeOption(t *testing.T) {
	for _, c := range []struct {
		f    core.Feature
		want bool
	}{
		{coretest.Feat(core.FUnserialize, "unserialize", "a.php", 1, AttrSource, SrcRequest, AttrArg, "get_option( 'x' )"), false},
		{coretest.Feat(core.FUnserialize, "unserialize", "a.php", 1, AttrSource, SrcRequest, AttrArg, "$_REQUEST['d'] ?: get_option('x')"), true},
		{coretest.Feat(core.FUnserialize, "unserialize", "a.php", 1, AttrSource, SrcRequest, AttrArg, "get_option('x') . $_GET['y']"), true},
		{coretest.Feat(core.FUnserialize, "unserialize", "a.php", 1, AttrSource, SrcRequest, AttrArg, "get_option($_GET['k'])"), false},
		{coretest.Feat(core.FFlow, "request->unserialize", "a.php", 1, AttrArg, "get_option('x')"), true},
		{coretest.Feat(core.FFlow, "remote->unserialize", "a.php", 1, AttrAllowedClasses, "false"), false},
	} {
		if got := outsideUnserialize(c.f); got != c.want {
			t.Errorf("outsideUnserialize(%s %v) = %v, want %v", c.f.Key, c.f.Attrs, got, c.want)
		}
	}
}
