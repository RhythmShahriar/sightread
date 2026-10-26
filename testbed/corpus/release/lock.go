// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package release holds the owner-run real-release corpus of
// docs/benchmark.md: the corpus.lock format, where each archive comes
// from and lives in the cache and the section the run writes. It does
// no network and starts no process, so it is tested offline; the
// command in testbed/corpus (build tag corpus) fetches and runs.
package release

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Ecosystems the corpus covers.
const (
	EcoWPPlugin = "wp-plugin"
	EcoNPM      = "npm"
)

// Unpinned is the hash of an archive not fetched and pinned yet.
const Unpinned = "-"

// Entry is one line of corpus.lock: a package and the two versions
// reviewed, with the SHA-256 of each archive.
type Entry struct {
	Ecosystem string
	Name      string
	From, To  string
	// FromSHA and ToSHA are lowercase hex, or Unpinned.
	FromSHA, ToSHA string
}

// Ref names the entry as Sightread does, eco:name.
func (e Entry) Ref() string { return e.Ecosystem + ":" + e.Name }

// Pinned reports whether both hashes are recorded.
func (e Entry) Pinned() bool { return e.FromSHA != Unpinned && e.ToSHA != Unpinned }

var (
	hexSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A WordPress.org slug, an npm name (with an optional scope) and a
	// version, kept strict so a line can never become a path or a URL
	// outside the registry.
	wpSlug  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,199}$`)
	npmName = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$`)
	version = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)
)

// ParseLock reads corpus.lock: one entry per line, # comments and blank
// lines ignored. It rejects unknown ecosystems, malformed names,
// versions or hashes and a package listed twice.
func ParseLock(r io.Reader) ([]Entry, error) {
	var out []Entry
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 6 {
			return nil, fmt.Errorf("line %d: want 6 fields (ecosystem name from to sha256-from sha256-to), got %d", n, len(f))
		}
		e := Entry{Ecosystem: f[0], Name: f[1], From: f[2], To: f[3], FromSHA: f[4], ToSHA: f[5]}
		switch e.Ecosystem {
		case EcoWPPlugin:
			if !wpSlug.MatchString(e.Name) {
				return nil, fmt.Errorf("line %d: %q is not a WordPress.org plugin slug", n, e.Name)
			}
		case EcoNPM:
			if !npmName.MatchString(e.Name) {
				return nil, fmt.Errorf("line %d: %q is not an npm package name", n, e.Name)
			}
		default:
			return nil, fmt.Errorf("line %d: ecosystem %q: want %s or %s", n, e.Ecosystem, EcoWPPlugin, EcoNPM)
		}
		for _, v := range []string{e.From, e.To} {
			if !version.MatchString(v) {
				return nil, fmt.Errorf("line %d: %q is not a version", n, v)
			}
		}
		if e.From == e.To {
			return nil, fmt.Errorf("line %d: %s has the same version twice", n, e.Ref())
		}
		for _, h := range []string{e.FromSHA, e.ToSHA} {
			if h != Unpinned && !hexSHA.MatchString(h) {
				return nil, fmt.Errorf("line %d: %q is not a lowercase SHA-256 or %s", n, h, Unpinned)
			}
		}
		if seen[e.Ref()] {
			return nil, fmt.Errorf("line %d: %s is listed twice", n, e.Ref())
		}
		seen[e.Ref()] = true
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("the lock lists no package")
	}
	return out, nil
}

// FormatLock writes entries back in lock form under header (the comment
// block, kept as it was), WordPress plugins first.
func FormatLock(header string, entries []Entry) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(header, "\n"))
	b.WriteString("\n")
	for _, eco := range []string{EcoWPPlugin, EcoNPM} {
		b.WriteString("\n")
		for _, e := range entries {
			if e.Ecosystem == eco {
				fmt.Fprintf(&b, "%s %s %s %s %s %s\n", e.Ecosystem, e.Name, e.From, e.To, e.FromSHA, e.ToSHA)
			}
		}
	}
	return b.String()
}

// Header returns the leading comment block of a lock file, for
// FormatLock to keep.
func Header(lock string) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(lock, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		b.WriteString(line)
	}
	return b.String()
}

// URL is where an archive is published: downloads.wordpress.org for a
// plugin zip, registry.npmjs.org for a tarball.
func URL(e Entry, v string) string {
	switch e.Ecosystem {
	case EcoWPPlugin:
		return "https://downloads.wordpress.org/plugin/" + url.PathEscape(e.Name) + "." + url.PathEscape(v) + ".zip"
	default:
		base := path.Base(e.Name)
		return "https://registry.npmjs.org/" + e.Name + "/-/" + url.PathEscape(base) + "-" + url.PathEscape(v) + ".tgz"
	}
}

// CachePath is where the fetched archive of v is kept under cache.
func CachePath(cache string, e Entry, v string) string {
	ext := ".tgz"
	if e.Ecosystem == EcoWPPlugin {
		ext = ".zip"
	}
	name := strings.ReplaceAll(e.Name, "/", "__")
	return filepath.Join(cache, e.Ecosystem, name, v+ext)
}
