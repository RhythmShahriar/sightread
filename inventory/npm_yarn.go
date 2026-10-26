// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// parseYarnLock reads yarn.lock: the classic format (version 1, its own
// syntax) or Berry's YAML (with __metadata).
func parseYarnLock(data []byte, m *npmManifest) ([]npmEntry, error) {
	if berryLock(data) {
		return parseBerryLock(data, m)
	}
	return parseYarnClassic(data, m)
}

// berryLock reports whether a yarn.lock is Berry's: it starts its
// entries with a __metadata block.
func berryLock(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		return bytes.HasPrefix(line, []byte("__metadata:"))
	}
	return false
}

// yarnSpecs splits an entry header's specifiers ("a@^1", "a@~1.2")
// into name and ranges. Berry writes "a@npm:^1"; the protocol stays in
// the range.
func yarnSpecs(header string) (name string, ranges []string, err error) {
	for _, spec := range strings.Split(header, ",") {
		spec = strings.TrimSpace(spec)
		if u, uerr := strconv.Unquote(spec); uerr == nil {
			spec = u
		} else {
			spec = strings.Trim(spec, `"`)
		}
		n, r, ok := splitSpec(spec)
		if !ok {
			return "", nil, fmt.Errorf("entry %q has no version range", clipText(spec))
		}
		if name != "" && n != name {
			return "", nil, fmt.Errorf("entry %q names two packages", clipText(header))
		}
		name = n
		ranges = append(ranges, r)
	}
	if name == "" {
		return "", nil, errors.New("empty entry header")
	}
	return name, ranges, nil
}

// yarnConstraint is the parents' ranges joined, or the root's range for
// a direct dependency.
func yarnConstraint(name string, ranges []string, m *npmManifest) (constraint string, direct bool) {
	if m != nil {
		if r, ok := m.deps[name]; ok {
			for _, have := range ranges {
				if have == r || have == "npm:"+r {
					return r, true
				}
			}
		}
	}
	var uniq []string
	for _, r := range ranges {
		r = strings.TrimPrefix(r, "npm:")
		if !containsString(uniq, r) {
			uniq = append(uniq, r)
		}
	}
	return strings.Join(uniq, " || "), false
}

// containsString reports whether list holds s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// parseYarnClassic reads the version 1 format:
//
//	"a@^1.0.0", a@^1.1.0:
//	  version "1.2.3"
//	  resolved "https://registry.yarnpkg.com/a/-/a-1.2.3.tgz#sha1"
//	  integrity sha512-...
//	  dependencies:
//	    b "^2.0.0"
func parseYarnClassic(data []byte, m *npmManifest) ([]npmEntry, error) {
	var out []npmEntry
	var cur *npmEntry
	var ranges []string
	flush := func() {
		if cur == nil {
			return
		}
		cur.constraint, cur.direct = yarnConstraint(cur.name, ranges, m)
		if cur.direct {
			cur.path = "node_modules/" + cur.name
		}
		if real, ok := strings.CutPrefix(ranges[0], "npm:"); ok {
			// An alias: "alias@npm:real@^1" installs real in the alias's
			// folder.
			if n, _, ok := splitSpec(real); ok {
				cur.name = n
			}
		}
		// A file: or link: dependency has no resolved line; its range is
		// the source.
		if r := ranges[0]; cur.resolved == "" && !strings.HasPrefix(r, "npm:") && strings.ContainsAny(r, ":/") {
			cur.resolved = r
		}
		cur.link = strings.HasPrefix(cur.resolved, "link:")
		out = append(out, *cur)
		cur = nil
	}
	for i, raw := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimRight(string(raw), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			flush()
			if !strings.HasSuffix(trimmed, ":") {
				return nil, fmt.Errorf("line %d: want an entry header ending in a colon", i+1)
			}
			name, rs, err := yarnSpecs(strings.TrimSuffix(trimmed, ":"))
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			cur, ranges = &npmEntry{name: name, line: i + 1}, rs
		case indent == 2 && cur != nil:
			key, val, _ := strings.Cut(trimmed, " ")
			val = yarnValue(val)
			switch key {
			case "version":
				cur.version = val
			case "resolved":
				cur.resolved = val
			case "integrity":
				cur.integrity = val
			}
		case cur == nil:
			return nil, fmt.Errorf("line %d: indented line outside an entry", i+1)
		}
	}
	flush()
	return out, nil
}

// yarnValue unquotes a classic value.
func yarnValue(s string) string {
	s = strings.TrimSpace(s)
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return strings.Trim(s, `"`)
}

// parseBerryLock reads Berry's YAML lockfile. A resolution is
// "name@protocol:ref"; only npm: is a registry release. Berry's
// checksum is not npm's SRI, so Integrity stays empty.
func parseBerryLock(data []byte, m *npmManifest) ([]npmEntry, error) {
	root, err := parseYAML(data)
	if err != nil {
		return nil, err
	}
	var out []npmEntry
	for i, key := range root.keys {
		if key == "__metadata" {
			continue
		}
		v := root.vals[i]
		_, ranges, err := yarnSpecs(key)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", root.lines[i], err)
		}
		resolution := v.get("resolution").str()
		name, ref, ok := splitSpec(resolution)
		if !ok {
			return nil, fmt.Errorf("line %d: resolution %q is not name@protocol:ref", root.lines[i], clipText(resolution))
		}
		e := npmEntry{name: name, version: v.get("version").str(), line: root.lines[i]}
		protocol, rest, _ := strings.Cut(ref, ":")
		switch protocol {
		case "npm":
			e.kind = core.ResolvedRegistry
			if strings.Contains(rest, "/") {
				// npm:https://... is a tarball named by URL.
				e.kind, e.resolved = "", rest
			}
		case "workspace":
			e.link = true
		case "patch":
			// A built-in patch is the npm release itself, so it merges
			// with that entry; any other patch is the project's own code.
			if e.kind = berryPatchKind(rest); e.kind != core.ResolvedRegistry {
				e.resolved = "patch:" + rest
			}
		case "http", "https":
			e.resolved = ref
		case "git", "git+ssh", "git+https", "github", "ssh":
			e.resolved = "git+" + ref
		default: // file:, link:, portal:, exec: and plugins' own protocols
			e.resolved = "file:" + rest
			e.kind = core.ResolvedFile
		}
		e.constraint, e.direct = yarnConstraint(name, ranges, m)
		if e.direct {
			e.path = "node_modules/" + name
		}
		out = append(out, e)
	}
	return out, nil
}

// berryPatchKind classifies a patch: resolution. Berry's built-in
// compatibility patches (typescript, fsevents, resolve) of an npm
// release are still that release; any other patch is local code.
func berryPatchKind(rest string) string {
	if strings.Contains(rest, "@npm%3A") && (strings.Contains(rest, "builtin<compat/") || strings.Contains(rest, "~builtin")) {
		return core.ResolvedRegistry
	}
	return core.ResolvedFile
}
