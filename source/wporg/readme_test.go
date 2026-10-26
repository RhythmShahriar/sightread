// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"slices"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// Positive: each release names its own contributors in its readme, so
// a release keeps the list it shipped with instead of the info API's
// current one; the changelog is read too.
func TestMetaFromTreeContributors(t *testing.T) {
	readme := "=== Share Kit ===\nContributors: ShareKit, ann , sharekit\nTags: share\n\n== Changelog ==\n= 3.2.0 =\n* New: Mastodon button.\n"
	m := &core.Meta{Contributors: []string{"growth-partners", "sharekit"}}
	NewPlugin(&core.Env{}).MetaFromTree(m, coretest.Tree(map[string]string{"readme.txt": readme}))
	if !slices.Equal(m.Contributors, []string{"ann", "sharekit"}) {
		t.Errorf("contributors %q", m.Contributors)
	}
	if len(m.Changelog) != 1 || m.Changelog[0].Version != "3.2.0" {
		t.Errorf("changelog %+v", m.Changelog)
	}
}

// Negative: a readme without the line, a Contributors line below the
// header and no readme at all keep the info API's list.
func TestMetaFromTreeContributorsKept(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no line":      {"readme.txt": "=== X ===\nTags: a\n\n== Description ==\nHi.\n"},
		"below header": {"readme.txt": "=== X ===\n\n== Description ==\nContributors: mallory\n"},
		"no readme":    {"x.php": "<?php\n"},
	} {
		m := &core.Meta{Contributors: []string{"sharekit"}}
		NewTheme(&core.Env{}).MetaFromTree(m, coretest.Tree(files))
		if !slices.Equal(m.Contributors, []string{"sharekit"}) {
			t.Errorf("%s: contributors %q", name, m.Contributors)
		}
	}
}
