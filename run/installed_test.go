// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

// TestRereview: --rereview reviews each installed version against the
// release before it, never a newer one; a package with no earlier
// release is left out.
func TestRereview(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "wpforms-lite", "1.9.0", "1.9.1", "1.9.2")
	w.Publish(core.WPPlugin, "first", "1.0.0", "1.1.0")
	w.Publish(core.WPPlugin, "beta", "2.0.0", "2.1.0-beta.1", "2.1.0")
	w.Install(core.WPPlugin, "wpforms-lite", "1.9.1")
	w.Install(core.WPPlugin, "first", "1.0.0")
	w.Install(core.WPPlugin, "beta", "2.1.0")
	w.Detector.Set("wpforms-lite", "remote-fetch-exec")
	req := request(t, "all")
	req.Rereview = true
	rep := review(t, req)
	want := []string{"beta 2.0.0→2.1.0 routine", "wpforms-lite 1.9.0→1.9.1 hold"}
	if got := names(rep); !reflect.DeepEqual(got, want) {
		t.Fatalf("updates %q, want %q", got, want)
	}
	if u := rep.Updates[1]; u.Installed.Drift {
		t.Errorf("a rereview compared the installed copy with the older release: %+v", u.Installed)
	}
}

// TestRereviewNegative: without --rereview the same site reviews the
// updates on offer, not the installed versions.
func TestRereviewNegative(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "wpforms-lite", "1.9.0", "1.9.1", "1.9.2")
	w.Install(core.WPPlugin, "wpforms-lite", "1.9.1")
	rep := review(t, request(t, "all"))
	if got := names(rep); !reflect.DeepEqual(got, []string{"wpforms-lite 1.9.1→1.9.2 routine"}) {
		t.Fatalf("updates %q", got)
	}
}

// TestInstalledStatus: owners and closures of what each site runs, one
// Meta per distinct version; private and transitive packages are left
// out.
func TestInstalledStatus(t *testing.T) {
	w := runtest.Install(t)
	w.Publish(core.WPPlugin, "wpforms-lite", "1.9.1")
	w.Publish(core.WPPlugin, "gone", "2.0.0")
	w.Publish(core.NPM, "left-pad", "1.3.0")
	w.Publish(core.NPM, "deep", "1.0.0")
	src := w.Sources[core.WPPlugin]
	src.Metas[core.Ref{Eco: core.WPPlugin, Name: "wpforms-lite", Version: "1.9.1"}] = &core.Meta{Contributors: []string{"WPForms", "smub"}}
	src.Metas[core.Ref{Eco: core.WPPlugin, Name: "gone", Version: "2.0.0"}] = &core.Meta{Closed: true, ClosedReason: "security issue"}
	w.Sources[core.NPM].Metas[core.Ref{Eco: core.NPM, Name: "left-pad", Version: "1.3.0"}] = &core.Meta{
		Maintainers: []core.Person{{Name: "Cameron", Login: "camwest"}, {Name: "Stevemao"}}}
	w.Install(core.WPPlugin, "wpforms-lite", "1.9.1")
	w.Install(core.WPPlugin, "gone", "2.0.0")
	w.Install(core.NPM, "left-pad", "1.3.0").Direct = true
	w.Install(core.NPM, "deep", "1.0.0")
	w.Install(core.WPPlugin, "private", "1.0.0").Private = true
	req := request(t, "watch")
	for _, s := range []string{"shop", "blog"} {
		req.Sites = append(req.Sites, run.Site{Name: s, Inventory: core.InventoryRequest{Root: t.TempDir()}})
	}
	got, err := run.Installed(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, s := range got {
		lines = append(lines, s.Site+" "+s.Ref.String()+" "+strings.Join(s.Owners, ",")+" "+boolText(s.Closed, s.ClosedReason))
	}
	want := []string{
		"blog npm:left-pad@1.3.0 camwest,stevemao open",
		"blog wp-plugin:gone@2.0.0  closed: security issue",
		"blog wp-plugin:wpforms-lite@1.9.1 smub,wpforms open",
		"shop npm:left-pad@1.3.0 camwest,stevemao open",
		"shop wp-plugin:gone@2.0.0  closed: security issue",
		"shop wp-plugin:wpforms-lite@1.9.1 smub,wpforms open",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("got\n%q\nwant\n%q", lines, want)
	}
	for _, n := range w.Sources[core.WPPlugin].Names() {
		if n == "private" {
			t.Errorf("asked the source about a private plugin")
		}
	}
}

// missingRootInventory fails for a site folder that doesn't exist, as
// the real inventory does.
type missingRootInventory struct{ core.Inventory }

func (m missingRootInventory) Read(ctx context.Context, req core.InventoryRequest) (*core.Site, error) {
	if _, err := os.Stat(req.Root); err != nil {
		return nil, errors.New("no such folder")
	}
	return m.Inventory.Read(ctx, req)
}

// TestFleetSiteGone: a site whose folder disappeared between watch runs
// becomes a Not checked entry and the other sites are still reviewed.
func TestFleetSiteGone(t *testing.T) {
	w := runtest.Install(t)
	t.Cleanup(core.SwapInventory(missingRootInventory{w.Inventory}))
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	req := request(t, "all")
	req.Sites = []run.Site{{Name: "shop", Inventory: core.InventoryRequest{Root: t.TempDir()}},
		{Name: "old", Inventory: core.InventoryRequest{Root: filepath.Join(t.TempDir(), "gone")}}}
	rep := review(t, req)
	if len(rep.Updates) != 1 || !reflect.DeepEqual(rep.Updates[0].Sites, []string{"shop"}) {
		t.Fatalf("updates %+v", names(rep))
	}
	if len(rep.NotChecked) != 1 || rep.NotChecked[0].Name != "old" || rep.NotChecked[0].Reason != core.FetchFailed ||
		rep.NotChecked[0].Text != "couldn't read site old: no such folder" {
		t.Errorf("not checked %+v", rep.NotChecked)
	}
	if got, err := run.Installed(context.Background(), req); err != nil || len(got) != 1 || got[0].Site != "shop" {
		t.Errorf("Installed: %+v %v", got, err)
	}
}

func boolText(closed bool, reason string) string {
	if closed {
		return "closed: " + reason
	}
	return "open"
}
