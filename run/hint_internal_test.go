// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"errors"
	"slices"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// TestInstalledSideUnknown: the E2 hint names the installed side and
// keeps a "did you mean" suggestion; other errors pass through.
func TestInstalledSideUnknown(t *testing.T) {
	cases := []struct {
		hint []string
		want []string
	}{
		{[]string{"A premium plugin has no official source: use --to-file <zip>"}, []string{InstalledSideHint}},
		{[]string{"did you mean contact-form-7? A premium plugin has no official source: use --to-file <zip>"},
			[]string{"did you mean contact-form-7? " + InstalledSideHint}},
		{nil, []string{InstalledSideHint}},
	}
	for _, c := range cases {
		in := &core.Error{Code: core.EUnknownPackage, What: "wordpress.org has no plugin \"x\"", Hint: c.hint}
		var got *core.Error
		if !errors.As(installedSideUnknown(in), &got) || !slices.Equal(got.Hint, c.want) || got.What != in.What {
			t.Errorf("%q: got %+v, want hint %q", c.hint, got, c.want)
		}
		if !slices.Equal(in.Hint, c.hint) {
			t.Errorf("the source's error was changed: %q", in.Hint)
		}
	}
	plain := errors.New("boom")
	if got := installedSideUnknown(plain); !errors.Is(got, plain) || got.Error() != "boom" {
		t.Error("a plain error was rewritten")
	}
}
