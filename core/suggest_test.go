// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "testing"

func TestSuggestSignal(t *testing.T) {
	for in, want := range map[string]string{
		"eval-dynamic": "eval-dynamic", "evil": "eval-dynamic", "typosquad": "typosquat", "cron": "cron-new-hook",
		"zzzzzzzzzz": "", "": "", "a": "", "exfil": "data-exfil", "eval-dynamik": "eval-dynamic",
	} {
		if got := SuggestSignal(in); got != want {
			t.Errorf("SuggestSignal(%q) = %q, want %q", in, got, want)
		}
	}
}
