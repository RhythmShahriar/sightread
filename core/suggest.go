// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// SuggestSignal returns the catalogue ID closest to id: kit's suggestion
// (two edits at most), else an ID with a part close to id, so "evil"
// suggests eval-dynamic and "exfil" data-exfil, else an ID starting with
// id. "" when nothing is reasonably close. Every "no signal" message
// uses it: explain, --id and --exclude-id, allow --signals and config.
func SuggestSignal(id string) string {
	ids := SignalIDs()
	if s := cli.Suggest(id, ids); s != "" {
		return s
	}
	in := strings.ToLower(id)
	best, bestDist := "", 3
	for _, full := range ids {
		for _, part := range strings.Split(full, "-") {
			if d := editDistance(in, part); d < bestDist && d < len([]rune(in)) {
				best, bestDist = full, d
			}
		}
	}
	if best != "" {
		return best
	}
	if len(in) >= 3 {
		for _, full := range ids {
			if strings.HasPrefix(full, in) {
				return full
			}
		}
	}
	return ""
}

// editDistance is the Levenshtein distance between a and b in runes.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}
