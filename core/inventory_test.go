// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core_test

import (
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// TestCountNotChecked: core and mu-plugin are listed but never counted,
// every other reason is.
func TestCountNotChecked(t *testing.T) {
	for _, r := range []core.NotCheckedReason{core.Core, core.MUPlugin} {
		if !r.Informational() {
			t.Errorf("%s is not informational", r)
		}
	}
	for _, r := range []core.NotCheckedReason{core.NoHeader, core.NotWPOrg, core.Private, core.VCS, core.UnsupportedLock, core.FetchFailed, core.TooLarge} {
		if r.Informational() {
			t.Errorf("%s is informational", r)
		}
	}
	ncs := []core.NotChecked{{Reason: core.Core}, {Reason: core.MUPlugin}, {Reason: core.NotWPOrg}, {Reason: core.FetchFailed}}
	if got := core.CountNotChecked(ncs); got != 2 {
		t.Errorf("count %d, want 2", got)
	}
	if got := core.CountNotChecked(ncs[:2]); got != 0 {
		t.Errorf("count of core and mu-plugin %d, want 0", got)
	}
}
