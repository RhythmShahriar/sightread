// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/inventory/wpcli"
)

// WPOptions tune ReadWP.
type WPOptions struct {
	// Label names the site in the auto-update warning; empty means the
	// --path= of the prefix, else the prefix itself.
	Label string
	// Command is the Sightread command errors name.
	Command string
	// Log receives one line per WP-CLI call (-v).
	Log io.Writer
	// WPCLI tunes the calls (timeout); Command and Log above win.
	WPCLI wpcli.Options
}

// ReadWP reads the plugins and themes of a site through the user's wp
// command prefix (argv, already split). Must-use plugins and drop-ins
// are Not checked mu-plugin, core is Not checked core; plugins with
// auto-updates on give one warning, since WordPress may install those
// updates before anyone reviews them.
func ReadWP(ctx context.Context, prefix []string, opt WPOptions) (*core.Site, error) {
	wo := opt.WPCLI
	wo.Command, wo.Log = opt.Command, opt.Log
	l, err := wpcli.List(ctx, prefix, wo)
	if err != nil {
		return nil, err
	}
	label := opt.Label
	if label == "" {
		label = wpLabel(prefix)
	}
	return siteFromListing(l, label), nil
}

// wpLabel is the --path= value in prefix, or the masked prefix.
func wpLabel(prefix []string) string {
	for _, a := range prefix {
		if p, ok := strings.CutPrefix(a, "--path="); ok && p != "" {
			return wpcli.Display([]string{p})
		}
	}
	return wpcli.Display(prefix)
}

// siteFromListing turns a WP-CLI listing into a site. Names that can't
// be a package reference are skipped with a warning; names that can't
// be a WordPress.org slug are Private and not-wporg, as on disk.
func siteFromListing(l *wpcli.Listing, label string) *core.Site {
	r := &wpReader{site: &core.Site{Kind: "wordpress", WordPress: l.Core}}
	r.site.Warnings = append(r.site.Warnings, l.Warnings...)
	r.site.NotChecked = append(r.site.NotChecked, notChecked("", "wordpress", l.Core, core.Core))
	auto := map[string]bool{}
	for _, f := range l.AutoUpdatePlugins {
		slug, _, _ := strings.Cut(f, "/")
		auto[strings.TrimSuffix(slug, ".php")] = true
	}
	autoCount := 0
	add := func(it wpcli.Item, eco core.Ecosystem) {
		if it.Status == wpcli.StatusMustUse || it.Status == wpcli.StatusDropIn {
			r.site.NotChecked = append(r.site.NotChecked, notChecked(core.WPPlugin, wpcli.Display([]string{it.Name}), it.Version, core.MUPlugin))
			return
		}
		if !validRef(eco, it.Name, it.Version) {
			r.warn("skipped a --wp %s entry with a name or version Sightread can't use: %q %q", ecoNoun(eco), it.Name, it.Version)
			return
		}
		r.addPlugin(it.Name, "", "", WPHeader{Version: it.Version}, eco)
		in := &r.site.Installed[len(r.site.Installed)-1]
		in.AutoUpdate = it.AutoUpdate == "on" || eco == core.WPPlugin && auto[it.Name]
		if in.AutoUpdate && eco == core.WPPlugin {
			autoCount++
		}
	}
	for _, it := range l.Plugins {
		add(it, core.WPPlugin)
	}
	for _, it := range l.Themes {
		add(it, core.WPTheme)
	}
	if autoCount > 0 {
		r.site.Warnings = append(r.site.Warnings, AutoUpdateWarning(autoCount, label))
	}
	return r.site
}

// AutoUpdateWarning is the warning for a site that installs plugin
// updates on its own (PRD 6.3).
func AutoUpdateWarning(n int, site string) string {
	noun := "plugins"
	if n == 1 {
		noun = "plugin"
	}
	return fmt.Sprintf("auto-updates are on for %d %s on %s: WordPress may install them before you review (wp plugin auto-updates disable --all)", n, noun, site)
}

// ecoNoun is "plugin" or "theme".
func ecoNoun(eco core.Ecosystem) string {
	if eco == core.WPTheme {
		return "theme"
	}
	return "plugin"
}
