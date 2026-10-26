// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

// VersionScheme orders and matches one ecosystem's versions: WordPress
// versions, Composer constraints or npm semver ranges.
type VersionScheme interface {
	Valid(v string) bool
	// Compare returns -1, 0 or 1 as a is older than, equal to or newer
	// than b.
	Compare(a, b string) int
	Prerelease(v string) bool
	Satisfies(v, constraint string) (bool, error)
}

// Newest returns the highest valid version that satisfies constraint
// ("" means any), skipping prereleases unless pre. It returns "" when
// none qualifies, including when the constraint can't be parsed. run uses
// it for latest and wanted.
func Newest(s VersionScheme, versions []string, constraint string, pre bool) string {
	best := ""
	for _, v := range versions {
		if !s.Valid(v) || !pre && s.Prerelease(v) {
			continue
		}
		if constraint != "" {
			ok, err := s.Satisfies(v, constraint)
			if err != nil || !ok {
				continue
			}
		}
		if best == "" || s.Compare(v, best) > 0 {
			best = v
		}
	}
	return best
}
