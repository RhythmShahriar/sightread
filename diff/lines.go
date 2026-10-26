// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import "slices"

// maxChain is the most times a unit may occur in the old side of a region
// and still anchor a split. Units that common ("}", blank lines) say
// little about how the two sides line up; git's histogram diff uses the
// same bound.
const maxChain = 64

// maxMyersD bounds the fallback Myers search. A region with no anchor
// and more edits than this becomes one delete and one insert: still a
// correct script, only less minimal.
const maxMyersD = 256

// opKind is one kind of run in an edit script.
type opKind uint8

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

// edit is a run of n units: equal at a (old) and b (new), deleted from
// a or inserted at b.
type edit struct {
	kind opKind
	a, b int
	n    int
}

// block is a run of n equal units at a in old and b in new.
type block struct{ a, b, n int }

// region is a part of both sides still to be matched.
type region struct{ a0, a1, b0, b1 int }

// script finds an edit script that turns a into b. It is a histogram
// diff: a region is split at its rarest common unit, extended to the
// longest equal run around it; the two sides of the run are matched
// the same way. Regions with no unit rare enough fall back to Myers.
// work bounds the total effort; once spent, the regions left become
// plain replacements so a hostile input can't make the diff slow.
func script(a, b []int, work int) []edit {
	s := &matcher{a: a, b: b, work: work}
	// An explicit stack: a long file split at its end each time would
	// recurse once per line.
	stack := []region{{0, len(a), 0, len(b)}}
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		stack = s.split(r, stack)
	}
	slices.SortFunc(s.blocks, func(x, y block) int { return x.a - y.a })
	return toEdits(s.blocks, len(a), len(b))
}

// matcher holds the state of one script call.
type matcher struct {
	a, b   []int
	blocks []block
	work   int
}

// split trims the common ends of r, then splits what is left at an
// anchor and pushes both sides onto stack.
func (s *matcher) split(r region, stack []region) []region {
	a, b := s.a, s.b
	n := 0
	for r.a0+n < r.a1 && r.b0+n < r.b1 && a[r.a0+n] == b[r.b0+n] {
		n++
	}
	if n > 0 {
		s.blocks = append(s.blocks, block{r.a0, r.b0, n})
		r.a0 += n
		r.b0 += n
	}
	n = 0
	for r.a1-n > r.a0 && r.b1-n > r.b0 && a[r.a1-n-1] == b[r.b1-n-1] {
		n++
	}
	if n > 0 {
		s.blocks = append(s.blocks, block{r.a1 - n, r.b1 - n, n})
		r.a1 -= n
		r.b1 -= n
	}
	if r.a0 == r.a1 || r.b0 == r.b1 {
		return stack
	}
	s.work -= (r.a1 - r.a0) + (r.b1 - r.b0)
	if s.work < 0 {
		return stack
	}
	if bl, ok := s.anchor(r); ok {
		s.blocks = append(s.blocks, bl)
		return append(stack,
			region{r.a0, bl.a, r.b0, bl.b},
			region{bl.a + bl.n, r.a1, bl.b + bl.n, r.b1})
	}
	s.myers(r)
	return stack
}

// anchor finds the run around the unit of r that occurs least often in
// the old side (at most maxChain times), the longest such run on a tie.
func (s *matcher) anchor(r region) (block, bool) {
	a, b := s.a, s.b
	pos := map[int][]int{}
	for i := r.a0; i < r.a1; i++ {
		if p := pos[a[i]]; len(p) <= maxChain {
			pos[a[i]] = append(p, i)
		}
	}
	best, bestCount := block{}, maxChain+1
	for j := r.b0; j < r.b1; {
		occ := pos[b[j]]
		next := j + 1
		if len(occ) == 0 || len(occ) > maxChain || len(occ) > bestCount {
			j = next
			continue
		}
		for _, i := range occ {
			as, bs := i, j
			for as > r.a0 && bs > r.b0 && a[as-1] == b[bs-1] {
				as--
				bs--
			}
			ae, be := i+1, j+1
			for ae < r.a1 && be < r.b1 && a[ae] == b[be] {
				ae++
				be++
			}
			s.work -= ae - as
			if n := ae - as; len(occ) < bestCount || n > best.n {
				best, bestCount = block{as, bs, n}, len(occ)
			}
			next = max(next, be)
		}
		if s.work < 0 {
			break
		}
		j = next
	}
	return best, best.n > 0
}

// myers matches r with the greedy O(ND) algorithm of Myers (1986),
// keeping each round's furthest points to walk the path back. Over
// maxMyersD edits it gives up and leaves r as a replacement.
func (s *matcher) myers(r region) {
	a, b := s.a[r.a0:r.a1], s.b[r.b0:r.b1]
	n, m := len(a), len(b)
	limit := min(n+m, maxMyersD)
	off := limit + 1
	v := make([]int, 2*off+1)
	var trace [][]int
	found := false
	for d := 0; d <= limit && !found; d++ {
		trace = append(trace, slices.Clone(v))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || k != d && v[off+k-1] < v[off+k+1] {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				found = true
				break
			}
		}
		s.work -= 2*d + 1
	}
	if !found {
		return
	}
	// Walk back from (n, m): each round d moved from a point of round
	// d-1 by one edit, then along a diagonal of equal units.
	x, y := n, m
	for d := len(trace) - 1; d >= 0; d-- {
		vd := trace[d]
		k := x - y
		var prevK int
		if k == -d || k != d && vd[off+k-1] < vd[off+k+1] {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		px := 0
		if d > 0 {
			px = vd[off+prevK]
		}
		py := px - prevK
		if d == 0 {
			px, py = 0, 0
		}
		// The snake runs from the point after the edit to (x, y).
		sx, sy := px, py
		if d > 0 {
			if prevK == k+1 {
				sy++
			} else {
				sx++
			}
		}
		if l := x - sx; l > 0 {
			s.blocks = append(s.blocks, block{r.a0 + sx, r.b0 + sy, l})
		}
		x, y = px, py
	}
}

// toEdits turns sorted equal blocks into a full edit script, deletions
// before insertions in each replaced stretch.
func toEdits(blocks []block, na, nb int) []edit {
	var out []edit
	add := func(e edit) {
		if e.n == 0 {
			return
		}
		if l := len(out) - 1; l >= 0 && out[l].kind == e.kind && e.kind == opEqual &&
			out[l].a+out[l].n == e.a && out[l].b+out[l].n == e.b {
			out[l].n += e.n
			return
		}
		out = append(out, e)
	}
	ai, bi := 0, 0
	for _, bl := range blocks {
		add(edit{opDelete, ai, bi, bl.a - ai})
		add(edit{opInsert, bl.a, bi, bl.b - bi})
		add(edit{opEqual, bl.a, bl.b, bl.n})
		ai, bi = bl.a+bl.n, bl.b+bl.n
	}
	add(edit{opDelete, ai, bi, na - ai})
	add(edit{opInsert, na, bi, nb - bi})
	return out
}
