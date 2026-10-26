// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/inventory/wpcli"
)

func testListing() *wpcli.Listing {
	return &wpcli.Listing{
		Core: "6.6.2",
		Plugins: []wpcli.Item{
			{Name: "akismet", Status: "active", Version: "5.3.5", AutoUpdate: "on"},
			{Name: "wpforms-lite", Status: "active", Version: "1.9.1", AutoUpdate: "off"},
			{Name: "hello", Status: "inactive", Version: "1.7.2", AutoUpdate: "off"},
			{Name: "acme-cache", Status: wpcli.StatusMustUse, Version: "2.0"},
			{Name: "object-cache.php", Status: wpcli.StatusDropIn},
			{Name: "acme+pro", Status: "active", Version: "1.0"},
			{Name: "bad name", Status: "active", Version: "1.0"},
		},
		Themes: []wpcli.Item{
			{Name: "twentytwentyfour", Status: "active", Version: "1.2", AutoUpdate: "on"},
		},
		AutoUpdatePlugins: []string{"akismet/akismet.php", "hello.php"},
		Warnings:          []string{"the wp command printed text before its JSON: x"},
	}
}

func TestSiteFromListing(t *testing.T) {
	s := siteFromListing(testListing(), "/srv/shop")
	if s.Kind != "wordpress" || s.WordPress != "6.6.2" {
		t.Fatalf("site = %+v", s)
	}
	var names []string
	for _, in := range s.Installed {
		names = append(names, string(in.Ref.Eco)+":"+in.Ref.Name+"@"+in.Ref.Version)
		if in.Path != "" {
			t.Errorf("%s has Path %q; a --wp listing has no folder", in.Ref.Name, in.Path)
		}
	}
	want := []string{"wp-plugin:akismet@5.3.5", "wp-plugin:wpforms-lite@1.9.1", "wp-plugin:hello@1.7.2", "wp-plugin:acme+pro@1.0", "wp-theme:twentytwentyfour@1.2"}
	if !slices.Equal(names, want) {
		t.Errorf("installed = %q, want %q", names, want)
	}
	auto := map[string]bool{}
	for _, in := range s.Installed {
		auto[in.Ref.Name] = in.AutoUpdate
		if in.Ref.Name == "acme+pro" && !in.Private {
			t.Error("a name that can't be a WordPress.org slug must be Private")
		}
	}
	if !auto["akismet"] || !auto["hello"] || auto["wpforms-lite"] || !auto["twentytwentyfour"] {
		t.Errorf("auto-update = %v", auto)
	}
	reasons := map[string]core.NotCheckedReason{}
	for _, nc := range s.NotChecked {
		reasons[nc.Name] = nc.Reason
	}
	for name, r := range map[string]core.NotCheckedReason{
		"wordpress": core.Core, "acme-cache": core.MUPlugin, "object-cache.php": core.MUPlugin, "acme+pro": core.NotWPOrg,
	} {
		if reasons[name] != r {
			t.Errorf("%s: reason %q, want %q", name, reasons[name], r)
		}
	}
	wantWarn := "auto-updates are on for 2 plugins on /srv/shop: WordPress may install them before you review (wp plugin auto-updates disable --all)"
	if !slices.Contains(s.Warnings, wantWarn) {
		t.Errorf("warnings = %q, want %q", s.Warnings, wantWarn)
	}
	if !slices.Contains(s.Warnings, `skipped a --wp plugin entry with a name or version Sightread can't use: "bad name" "1.0"`) {
		t.Errorf("warnings = %q, want the skipped entry", s.Warnings)
	}
	if !slices.Contains(s.Warnings, "the wp command printed text before its JSON: x") {
		t.Errorf("listing warnings were dropped: %q", s.Warnings)
	}
}

func TestNoAutoUpdateNoWarning(t *testing.T) {
	l := &wpcli.Listing{Core: "6.6.2", Plugins: []wpcli.Item{{Name: "akismet", Status: "active", Version: "5.3.5", AutoUpdate: "off"}}}
	s := siteFromListing(l, "shop")
	if len(s.Warnings) != 0 {
		t.Errorf("warnings = %q, want none", s.Warnings)
	}
}

func TestAutoUpdateWarningOne(t *testing.T) {
	got := AutoUpdateWarning(1, "shop")
	if got != "auto-updates are on for 1 plugin on shop: WordPress may install them before you review (wp plugin auto-updates disable --all)" {
		t.Errorf("got %q", got)
	}
}

func TestWPLabel(t *testing.T) {
	if got := wpLabel([]string{"ssh", "h", "wp", "--path=/srv/shop"}); got != "/srv/shop" {
		t.Errorf("label = %q", got)
	}
	if got := wpLabel([]string{"ddev", "wp"}); got != "ddev wp" {
		t.Errorf("label = %q", got)
	}
}

func TestReadWPMissingCommandIsE1(t *testing.T) {
	_, err := ReadWP(context.Background(), []string{filepath.Join(t.TempDir(), "wp")}, WPOptions{Command: "plugin"})
	if core.CodeOf(err) != core.ENothingInstalled {
		t.Errorf("err = %v, want E1", err)
	}
}

// TestReaderPassesCommand: a --wp read through the registered Reader
// names the run's command in its error, as ReadWP does when called
// directly. (The -v log reaches wpcli the same way; wpcli's tests check
// what it writes.)
func TestReaderPassesCommand(t *testing.T) {
	_, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: t.TempDir(),
		WP: []string{filepath.Join(t.TempDir(), "wp")}, Command: "plugin", Log: &strings.Builder{}})
	if core.CodeOf(err) != core.ENothingInstalled {
		t.Fatalf("err = %v, want E1", err)
	}
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Command != "plugin" {
		t.Errorf("error command: %+v", err)
	}
}
