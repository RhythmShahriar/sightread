// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the integrity and archive detector.
const (
	SigIntegrityMismatch    = "integrity-mismatch"
	SigVersionRepublished   = "version-republished"
	SigLockfileSourceChange = "lockfile-source-change"
	SigArchivePathEscape    = "archive-path-escape"
	SigArchiveLink          = "archive-link"
	SigArchiveCollision     = "archive-collision"
	SigUnanalysed           = "unanalysed"
)

// DemotedOldSide is the Demoted text of an archive finding that comes
// from the installed version's archive, not the candidate's.
const DemotedOldSide = "in the installed version's archive, not the candidate's"

func init() { core.RegisterDetector(integrityDetector{}) }

// integrityDetector reports what verification, the lockfile and the
// archive reader found: bytes that differ from what the source
// publishes, a version republished with other bytes, a lock entry moved
// off the registry, hostile archive entries and code that could not be
// analysed (PRD 11 and 12.1). It reads only the Subject.
type integrityDetector struct{}

func (integrityDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-integrity", Signals: []string{
		SigIntegrityMismatch, SigVersionRepublished, SigLockfileSourceChange,
		SigArchivePathEscape, SigArchiveLink, SigArchiveCollision, SigUnanalysed,
	}}
}

func (integrityDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if f, ok := mismatchFinding(s, s.OldIntegrity, s.Old, true); ok {
		out.send(f)
	}
	if f, ok := mismatchFinding(s, s.NewIntegrity, s.New, false); ok {
		out.send(f)
	}
	for _, f := range republishedFindings(s) {
		out.send(f)
	}
	if f, ok := sourceChangeFinding(s); ok {
		out.send(f)
	}
	if ctx.Err() != nil {
		return
	}
	for _, f := range archiveFindings(s) {
		out.send(f)
	}
}

// mismatchFinding gives integrity-mismatch when a side's verification
// failed. WordPress.org rebuilds readme.txt after a release, so a
// mismatch of readme.txt alone is left to the verify note (PRD 12.1).
func mismatchFinding(s *core.Subject, in core.Integrity, m *core.Meta, old bool) (core.Finding, bool) {
	if in.By != core.ByFailed {
		return core.Finding{}, false
	}
	eco := s.Update.Eco
	wp := eco == core.WPPlugin || eco == core.WPTheme
	if wp && len(in.Mismatch) > 0 && onlyReadme(in.Mismatch) {
		return core.Finding{}, false
	}
	src := sourceName(eco)
	var b strings.Builder
	if old {
		fmt.Fprintf(&b, "installed version %s: ", version(m))
	}
	switch {
	case wp && len(in.Mismatch) > 0:
		fmt.Fprintf(&b, "Archive does not match %s checksums: %s (%s)", src,
			plural(len(in.Mismatch), "file differs", "files differ"), list(in.Mismatch))
	case len(in.Mismatch) > 0:
		verb := "differ"
		if len(in.Mismatch) == 1 {
			verb = "differs"
		}
		fmt.Fprintf(&b, "Archive does not match the hash %s publishes: %s %s", src, list(in.Mismatch), verb)
	default:
		fmt.Fprintf(&b, "Archive does not match the hash %s publishes", src)
	}
	if in.Detail != "" {
		b.WriteString("; " + in.Detail)
	}
	f := newFinding(SigIntegrityMismatch, b.String())
	f.Advice = "Someone between you and " + src + " changed it, or the release was edited; don't install this copy."
	if wp && len(in.Mismatch) > 0 {
		f.File = in.Mismatch[0]
	}
	return f, true
}

// onlyReadme reports whether every path is the root readme.txt.
func onlyReadme(paths []string) bool {
	for _, p := range paths {
		if !strings.EqualFold(p, "readme.txt") {
			return false
		}
	}
	return true
}

// republishedFindings compares each lock entry with what the source now
// says about the same version: an npm integrity or a Composer commit
// other than the lockfile recorded means the version was published
// again with other bytes (b17, b19).
func republishedFindings(s *core.Subject) []core.Finding {
	var out []core.Finding
	for _, side := range []struct {
		lock *core.Installed
		m    *core.Meta
	}{{s.OldLock, s.Old}, {s.NewLock, s.New}} {
		if ev, ok := republished(s.Update.Eco, side.lock, side.m); ok {
			f := newFinding(SigVersionRepublished, ev)
			f.File, f.Line = side.lock.Lockfile, side.lock.LockLine
			out = append(out, f)
		}
	}
	return out
}

// republished compares one lock entry with the source's metadata of the
// version it names and returns the evidence when they disagree. Hashes
// are compared only per algorithm: an old lockfile's sha1 says nothing
// against the registry's sha512.
func republished(eco core.Ecosystem, lock *core.Installed, m *core.Meta) (string, bool) {
	if lock == nil || m == nil {
		return "", false
	}
	if lock.Ref.Version != "" && lock.Ref.Version != m.Ref.Version {
		return "", false
	}
	src := sourceName(eco)
	locked := ParseSRI(lock.Integrity)
	published := ParseSRI(m.Archive.Integrity)
	if eco == core.NPM && m.Archive.Shasum != "" {
		if raw, err := hex.DecodeString(m.Archive.Shasum); err == nil && len(raw) == 20 {
			if _, has := published["sha1"]; !has {
				published["sha1"] = base64.StdEncoding.EncodeToString(raw)
			}
		}
	}
	for _, algo := range []string{"sha512", "sha384", "sha256", "sha1"} {
		a, b := locked[algo], published[algo]
		if a != "" && b != "" && a != b {
			return fmt.Sprintf("%s: the lockfile recorded %s-%s…, %s now serves %s-%s…",
				m.Ref.Version, algo, short(a), src, algo, short(b)), true
		}
	}
	if lock.Reference != "" && m.Archive.Reference != "" && !strings.EqualFold(lock.Reference, m.Archive.Reference) {
		return fmt.Sprintf("%s: the lockfile pins commit %s, %s now points it at %s",
			m.Ref.Version, short(lock.Reference), src, short(m.Archive.Reference)), true
	}
	return "", false
}

// short returns the first 12 characters of a hash or commit, enough to
// tell two apart in a report.
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ParseSRI reads a Subresource Integrity string ("sha512-<base64>",
// several separated by spaces, each maybe with "?options") into a map of
// algorithm to digest. Unknown or malformed entries are skipped: an
// integrity that can't be read is not evidence of anything.
func ParseSRI(sri string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Fields(sri) {
		algo, digest, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		digest, _, _ = strings.Cut(digest, "?")
		algo = strings.ToLower(algo)
		switch algo {
		case "sha1", "sha256", "sha384", "sha512":
		default:
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(digest)
		if err != nil || len(raw) == 0 {
			continue
		}
		out[algo] = base64.StdEncoding.EncodeToString(raw)
	}
	return out
}

// sourceChangeFinding gives lockfile-source-change when a lock entry
// that resolved from the registry now resolves somewhere else (b14). An
// entry that was off the registry already is Not checked (vcs) and stays
// quiet here.
func sourceChangeFinding(s *core.Subject) (core.Finding, bool) {
	o, n := s.OldLock, s.NewLock
	if o == nil || n == nil || o.ResolvedKind != core.ResolvedRegistry ||
		n.ResolvedKind == "" || n.ResolvedKind == core.ResolvedRegistry {
		return core.Finding{}, false
	}
	ev := "the lock entry moved from the registry to " + resolvedWhere(n.ResolvedKind)
	if u := safeURL(n.Resolved); u != "" {
		ev += ": " + u
	}
	f := newFinding(SigLockfileSourceChange, ev)
	f.File, f.Line = n.Lockfile, n.LockLine
	return f, true
}

// resolvedWhere words a ResolvedKind for the evidence.
func resolvedWhere(kind string) string {
	switch kind {
	case core.ResolvedGit:
		return "a git URL"
	case core.ResolvedFile:
		return "a local file"
	case core.ResolvedTarball:
		return "a tarball URL"
	case core.ResolvedForeign:
		return "another host"
	}
	return kind
}

// safeURL drops the user info, query and fragment of a lock URL, where
// tokens live, before it goes into a finding. Text with no host to parse
// ("user:token@host/path", "git@host:owner/repo") loses everything up
// to its last "@" and from its first "?" or "#" the same way; what is
// left goes on for NewSnippet to mask.
func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		return u.String()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	return raw
}

// archiveFindings turns the archive reader's issues and the analyzer's
// unanalysed files into findings. The candidate's issues fire at their
// signal's severity; the installed version's are noted once per signal
// at info, since installing the candidate replaces them. A path escape
// of the old side is left out: the signal can't be lowered and the old
// archive is not what gets installed.
func archiveFindings(s *core.Subject) []core.Finding {
	var groups [][]core.Finding
	bySig := map[string]int{}
	add := func(f core.Finding) {
		i, ok := bySig[f.ID]
		if !ok {
			i = len(groups)
			bySig[f.ID] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], f)
	}
	seen := map[string]bool{}
	if s.NewTree != nil {
		for _, is := range s.NewTree.Issues {
			if f, ok := issueFinding(is); ok {
				if f.ID == SigUnanalysed {
					seen[is.Path] = true
				}
				add(f)
			}
		}
	}
	if s.NewFeatures != nil {
		for _, u := range s.NewFeatures.Unanalysed {
			if seen[u.Path] {
				continue
			}
			seen[u.Path] = true
			reason := u.Reason
			if reason == "" {
				reason = "no reason given"
			}
			f := newFinding(SigUnanalysed, "could not be analysed: "+reason)
			f.File = u.Path
			add(f)
		}
	}
	var out []core.Finding
	for _, g := range groups {
		out = append(out, capped(g)...)
	}
	return append(out, oldIssueNotes(s)...)
}

// issueFinding maps one archive issue of the candidate to its finding.
// Entry names are archive text: NewSnippet makes them safe to print.
func issueFinding(is core.ArchiveIssue) (core.Finding, bool) {
	var f core.Finding
	switch is.Kind {
	case core.IssuePathEscape:
		// The entry was not stored, so it has no File inside the package.
		return withDetail(newFinding(SigArchivePathEscape, fmt.Sprintf("entry %q points outside the package", is.Path)), is), true
	case core.IssueLink:
		ev := is.Path + " is a link or special file"
		if is.Other != "" {
			ev = is.Path + " is a link to " + is.Other
		}
		f = newFinding(SigArchiveLink, ev)
	case core.IssueLinkEscape:
		f = newFinding(SigArchiveLink, is.Path+" links outside the package, to "+is.Other)
		f.Severity = cli.SeverityCritical
	case core.IssueCollision:
		f = newFinding(SigArchiveCollision, is.Path+" and "+is.Other+" are the same name (case or Unicode form)")
	case core.IssueLimit:
		f = newFinding(SigUnanalysed, "archive limit reached at this entry")
	case core.IssueEncrypted:
		f = newFinding(SigUnanalysed, "encrypted entry, can't be read")
	case core.IssueMalformed:
		f = newFinding(SigUnanalysed, "malformed entry, can't be read")
	default:
		return core.Finding{}, false
	}
	f.File = core.NewSnippet(is.Path).String()
	return withDetail(f, is), true
}

// withDetail appends the issue's detail to the evidence.
func withDetail(f core.Finding, is core.ArchiveIssue) core.Finding {
	if is.Detail != "" {
		f.Evidence = core.NewSnippet(f.Evidence.String() + " (" + is.Detail + ")")
	}
	return f
}

// capped keeps the first maxPerSignal findings of one signal and says on
// the last how many were left out.
func capped(fs []core.Finding) []core.Finding {
	if len(fs) <= maxPerSignal {
		return fs
	}
	out := fs[:maxPerSignal]
	last := &out[maxPerSignal-1]
	last.Evidence = core.NewSnippet(fmt.Sprintf("%s (and %d more like it)", last.Evidence, len(fs)-maxPerSignal))
	return out
}

// oldIssueNotes notes the installed version's link and collision issues
// once per signal, at info.
func oldIssueNotes(s *core.Subject) []core.Finding {
	if s.OldTree == nil {
		return nil
	}
	var links, collisions []string
	for _, is := range s.OldTree.Issues {
		switch is.Kind {
		case core.IssueLink, core.IssueLinkEscape:
			links = append(links, is.Path)
		case core.IssueCollision:
			collisions = append(collisions, is.Path)
		}
	}
	var out []core.Finding
	note := func(id string, paths []string, one, many string) {
		if len(paths) == 0 {
			return
		}
		f := newFinding(id, fmt.Sprintf("the installed %s had %s: %s", version(s.Old), plural(len(paths), one, many), list(paths)))
		f.Severity, f.Demoted = cli.SeverityInfo, DemotedOldSide
		f.File = core.NewSnippet(path.Clean(paths[0])).String()
		out = append(out, f)
	}
	note(SigArchiveLink, links, "link entry", "link entries")
	note(SigArchiveCollision, collisions, "colliding entry", "colliding entries")
	return out
}
