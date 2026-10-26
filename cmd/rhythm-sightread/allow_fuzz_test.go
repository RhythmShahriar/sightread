// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import "testing"

// FuzzParseAllowRef: an allow reference either fails or names a package,
// with a version whenever one is required.
func FuzzParseAllowRef(f *testing.F) {
	for _, s := range []string{"npm:left-pad@1.4.0", "npm:@acme/ui@2.0.0", "wp-plugin:akismet", "composer:monolog/monolog@3.8.0", "pypi:x@1", "npm:", "@", ""} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, raw string, needVersion bool) {
		ref, err := parseAllowRef(raw, needVersion)
		if err != nil {
			return
		}
		if ref.Name == "" {
			t.Fatalf("%q: no name in %+v", raw, ref)
		}
		if needVersion && ref.Version == "" {
			t.Fatalf("%q: no version in %+v", raw, ref)
		}
	})
}
