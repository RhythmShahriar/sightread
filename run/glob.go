// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// Match reports whether s matches the glob pattern: * stands for any run
// of characters (slashes included, so "composer:*" covers
// "composer:monolog/monolog") and ? for exactly one. Everything else is
// literal. --only, --skip, --id and --exclude-id use it.
func Match(pattern, s string) bool {
	// Iterative match with one backtrack point for the last *, which is
	// linear enough for the short names it sees and never recurses.
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// MatchAny reports whether any pattern matches s.
func MatchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if Match(p, s) {
			return true
		}
	}
	return false
}

// Selected applies --only and --skip to a package. A pattern is an
// ecosystem ID ("npm", or the "plugin" and "theme" shorthands) or a glob
// on "<eco>:<name>", where the eco part also takes the shorthands.
func Selected(eco core.Ecosystem, name string, only, skip []string) bool {
	if len(only) > 0 && !matchesPackage(only, eco, name) {
		return false
	}
	return !matchesPackage(skip, eco, name)
}

func matchesPackage(patterns []string, eco core.Ecosystem, name string) bool {
	full := string(eco) + ":" + name
	for _, p := range patterns {
		if e, err := core.ParseEcosystem(p); err == nil {
			if e == eco {
				return true
			}
			continue
		}
		if ecoText, rest, ok := strings.Cut(p, ":"); ok {
			if e, err := core.ParseEcosystem(ecoText); err == nil {
				p = string(e) + ":" + rest
			}
		}
		if Match(p, full) {
			return true
		}
	}
	return false
}
