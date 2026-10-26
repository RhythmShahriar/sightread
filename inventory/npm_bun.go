// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"encoding/json"
	"strings"
)

// bunWorkspace is one workspace of bun.lock.
type bunWorkspace struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// bunInfo is the dependency part of a bun.lock package entry.
type bunInfo struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// parseBunLock reads bun.lock, Bun's text lockfile. It is JSON with
// comments and trailing commas (JSONC). A package entry is a list:
// ["name@1.2.3", "<registry or empty>", {info}, "sha512-..."] for an npm
// release; ["name@<url, git or file spec>", {info}, ...] otherwise;
// ["name@workspace:<dir>"] for a workspace. A nested key "parent/child"
// is a second copy under its parent.
func parseBunLock(data []byte) ([]npmEntry, error) {
	data = stripJSONC(data)
	var f struct {
		Workspaces map[string]bunWorkspace      `json:"workspaces"`
		Packages   map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	lines := map[string]int{}
	if err := scanJSONKeys(data, func(p []string, line int) {
		if len(p) == 2 && p[0] == "packages" {
			lines[p[1]] = line
		}
	}); err != nil {
		return nil, err
	}
	declared := map[string]string{}
	devOnly := map[string]bool{}
	for dir, ws := range f.Workspaces {
		for name, r := range ws.DevDependencies {
			if _, ok := declared[name]; !ok || dir == "" {
				declared[name] = r
			}
			devOnly[name] = true
		}
		for _, deps := range []map[string]string{ws.PeerDependencies, ws.OptionalDependencies, ws.Dependencies} {
			for name, r := range deps {
				if _, ok := declared[name]; !ok || dir == "" {
					declared[name] = r
				}
				devOnly[name] = false
			}
		}
	}
	infos := map[string]bunInfo{}
	var out []npmEntry
	var keys []string
	for key, raw := range f.Packages {
		if len(raw) == 0 {
			continue
		}
		var ident string
		if err := json.Unmarshal(raw[0], &ident); err != nil {
			continue // not a package entry Bun writes
		}
		name, ref, _ := splitSpec(ident)
		e := npmEntry{name: name, version: ref, line: lines[key]}
		infoAt := 1
		if !strings.ContainsAny(ref, ":/") {
			// An npm release: the second item is its registry ("" for the
			// default), the fourth its integrity.
			var reg string
			_ = json.Unmarshal(raw[min(1, len(raw)-1)], &reg)
			if reg != "" {
				e.resolved = reg
			}
			if len(raw) > 3 {
				_ = json.Unmarshal(raw[3], &e.integrity)
			}
			infoAt = 2
		} else {
			e.resolved, e.version = ref, ""
			e.link = strings.HasPrefix(ref, "workspace:") || strings.HasPrefix(ref, "link:")
			if strings.HasPrefix(ref, "github:") {
				e.resolved = "git+" + ref
			}
		}
		if len(raw) > infoAt {
			var info bunInfo
			if json.Unmarshal(raw[infoAt], &info) == nil {
				infos[key] = info
			}
		}
		if parent, _ := bunSplit(key); parent == "" {
			// A top-level key: installed at node_modules/<key>.
			e.path = "node_modules/" + key
			if r, ok := declared[key]; ok {
				e.direct, e.constraint, e.dev = true, r, devOnly[key]
			}
		}
		out = append(out, e)
		keys = append(keys, key)
	}
	// A nested copy's range comes from its parent's entry.
	for i, key := range keys {
		if parent, child := bunSplit(key); parent != "" {
			p := infos[parent]
			out[i].constraint = rangeIn(child, p.Dependencies, p.OptionalDependencies, p.PeerDependencies)
		}
	}
	return out, nil
}

// bunSplit splits a packages key into the parent key and the package
// name: "a/@s/b" is @s/b under a, "@s/a/b" is b under @s/a and "@s/a"
// is top-level.
func bunSplit(key string) (parent, child string) {
	segs := strings.Split(key, "/")
	n := 1
	if len(segs) >= 2 && strings.HasPrefix(segs[len(segs)-2], "@") {
		n = 2
	}
	if n >= len(segs) {
		return "", key
	}
	return strings.Join(segs[:len(segs)-n], "/"), strings.Join(segs[len(segs)-n:], "/")
}

// stripJSONC turns JSONC into JSON of the same length: comments and
// trailing commas become spaces, line breaks stay, so a key's line is
// the same in both.
func stripJSONC(in []byte) []byte {
	b := append([]byte(nil), in...)
	inString, escaped := false, false
	lastComma := -1
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString, lastComma = true, -1
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
			i-- // keep the line break
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			b[i], b[i+1] = ' ', ' '
			for i += 2; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i++
					break
				}
				if b[i] != '\n' && b[i] != '\r' {
					b[i] = ' '
				}
			}
		case c == ',':
			lastComma = i
		case c == '}' || c == ']':
			if lastComma >= 0 {
				b[lastComma] = ' '
			}
			lastComma = -1
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			lastComma = -1
		}
	}
	return b
}
