// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package watch

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/notify"
	"github.com/RhythmShahriar/sightread/run"
)

// news is what one run found that state didn't know yet.
type news struct {
	items   []notify.Item // at or above NotifyMin, plus owner changes and closures
	failNew bool          // a new finding at or above FailOnNew
	// keys are the findings to record once the notifications went out;
	// always are recorded whatever happened to the sends (they were
	// below NotifyMin, so nothing was going to tell anyone).
	keys, always []string
}

// findingKey names one counted finding of one site's version across
// runs. The sha256 binds it to the bytes reviewed, so a version
// republished with other bytes is new again.
func findingKey(site string, u *core.Update, id string) string {
	return strings.Join([]string{site, string(u.Eco), u.Name, u.To.Version, u.To.SHA256, id}, "\x00")
}

// updates adds what is new in rep's updates. kind is notify.KindUpdate
// for a review of the updates on offer and notify.KindNewSignal for a
// rereview of the installed versions.
func (n *news) updates(rep *core.Report, kind string, st *state, notifyMin, failOn cli.Severity, now time.Time) {
	lowest := notifyMin
	if failOn != cli.SeverityNone && failOn < lowest {
		lowest = failOn
	}
	for i := range rep.Updates {
		u := &rep.Updates[i]
		sites := u.Sites
		if len(sites) == 0 {
			sites = []string{""}
		}
		var top *core.Finding
		newSites, notified := []string{}, false
		for _, site := range sites {
			notifies := false
			for j := range u.Findings {
				f := &u.Findings[j]
				if !f.Counted() || f.Severity < lowest {
					continue
				}
				if top == nil || f.Severity > top.Severity {
					top = f
				}
				key := findingKey(site, u, f.ID)
				if _, seen := st.Seen[key]; seen {
					st.Seen[key] = now
					continue
				}
				if failOn.Fails(f.Severity) {
					n.failNew = true
				}
				if f.Severity >= notifyMin {
					notifies = true
					n.keys = append(n.keys, key)
				} else {
					n.always = append(n.always, key)
				}
			}
			notified = notified || notifies
			if notifies && site != "" {
				newSites = append(newSites, site)
			}
		}
		if !notified {
			continue
		}
		it := notify.Item{Kind: kind, Ecosystem: string(u.Eco), Name: u.Name, From: u.From.Version, To: u.To.Version,
			Verdict: string(u.Verdict), Sites: newSites, Findings: counted(u)}
		if top != nil {
			it.Severity, it.Top = top.Severity.String(), top.Title
		}
		n.items = append(n.items, it)
	}
}

// counted is how many of u's findings count for its verdict.
func counted(u *core.Update) int {
	c := 0
	for i := range u.Findings {
		if u.Findings[i].Counted() {
			c++
		}
	}
	return c
}

// installed adds owner changes and closures from today's statuses and
// records them in st. The first sighting of a package only records its
// owners: there is nothing to compare with yet.
func (n *news) installed(statuses []run.InstalledStatus, st *state) {
	owners := map[string][]string{}
	groups := map[string]*notify.Item{}
	var order []string
	add := func(kind string, s run.InstalledStatus, detail string) {
		k := strings.Join([]string{kind, string(s.Ref.Eco), s.Ref.Name, s.Ref.Version, detail}, "\x00")
		it, ok := groups[k]
		if !ok {
			it = &notify.Item{Kind: kind, Ecosystem: string(s.Ref.Eco), Name: s.Ref.Name, To: s.Ref.Version, Detail: detail, Sites: []string{}}
			groups[k] = it
			order = append(order, k)
		}
		if s.Site != "" {
			it.Sites = append(it.Sites, s.Site)
		}
	}
	for _, s := range statuses {
		pkg := s.Site + "\x00" + s.Ref.Unversioned().String()
		if s.Owners != nil {
			owners[pkg] = s.Owners
			if before, ok := st.Owners[pkg]; ok && !slices.Equal(before, s.Owners) {
				add(notify.KindOwner, s, ownerChange(before, s.Owners))
			}
		} else if before, ok := st.Owners[pkg]; ok {
			owners[pkg] = before // the source didn't say this time; keep what it said
		}
		if s.Closed {
			ck := s.Site + "\x00" + s.Ref.String()
			if !st.Closed[ck] {
				st.Closed[ck] = true
				add(notify.KindClosed, s, cmp.Or(s.ClosedReason, "closed"))
			}
		}
	}
	st.Owners = owners
	for _, k := range order {
		n.items = append(n.items, *groups[k])
	}
}

// ownerChange describes who was added and who left: "added
// growth-partners; removed alice".
func ownerChange(before, after []string) string {
	var added, removed []string
	for _, o := range after {
		if !slices.Contains(before, o) {
			added = append(added, o)
		}
	}
	for _, o := range before {
		if !slices.Contains(after, o) {
			removed = append(removed, o)
		}
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "added "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed "+strings.Join(removed, ", "))
	}
	return strings.Join(parts, "; ")
}

// partialLine is the line a message carries when the run left packages
// out or went wrong, so a short list isn't read as all clear: "Partial:
// 2 not checked, 1 error; see <log>".
func partialLine(gap, log string) string {
	return fmt.Sprintf("Partial: %s; see %s", gap, log)
}
