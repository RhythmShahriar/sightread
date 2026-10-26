// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package watch

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzParseAt: --at either fails or gives sorted, distinct, valid
// times that read back the same.
func FuzzParseAt(f *testing.F) {
	for _, s := range []string{"02:00", "14:30,02:00", " 02:00 , 02:00", "24:00", "2:5", "", "02:00,", "-1:00", "+2:00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		times, err := ParseAt(s)
		if err != nil {
			return
		}
		if len(times) == 0 {
			t.Fatalf("%q: no times without an error", s)
		}
		for i, tm := range times {
			if tm.Hour < 0 || tm.Hour > 23 || tm.Minute < 0 || tm.Minute > 59 {
				t.Fatalf("%q: %v out of range", s, tm)
			}
			if i > 0 && tm.Hour*60+tm.Minute <= times[i-1].Hour*60+times[i-1].Minute {
				t.Fatalf("%q: %v not sorted or repeated", s, times)
			}
		}
		parts := make([]string, len(times))
		for i, tm := range times {
			parts[i] = tm.String()
		}
		again, err := ParseAt(strings.Join(parts, ","))
		if err != nil || !slices.Equal(again, times) {
			t.Fatalf("%q: %v reads back as %v, %v", s, times, again, err)
		}
	})
}

// FuzzLoadState: a damaged state.json costs a fresh state, never a
// panic or a nil map.
func FuzzLoadState(f *testing.F) {
	for _, s := range []string{
		`{"schema":"` + stateSchema + `","seen":{"a":"2026-10-01T00:00:00Z"},"owners":{"a":["x"]},"closed":{"a":true}}`,
		`{"schema":"` + stateSchema + `"}`,
		`{"schema":"other"}`,
		`{"schema":"` + stateSchema + `","seen":[]}`,
		`null`,
		``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, StateName), b, 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := loadState(dir)
		if err != nil && !errors.Is(err, errCorrupt) {
			t.Fatalf("%q: %v", b, err)
		}
		if st == nil || st.Seen == nil || st.Owners == nil || st.Closed == nil {
			t.Fatalf("%q: state %+v", b, st)
		}
		if st.Schema != stateSchema {
			t.Fatalf("%q: schema %q", b, st.Schema)
		}
	})
}
