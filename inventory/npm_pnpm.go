// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"path"
	"strconv"
	"strings"
)

// pnpmDirect is one dependency an importer (the root or a workspace)
// declares.
type pnpmDirect struct {
	alias, name, ref, specifier, importer string
	dev                                   bool
}

// parsePnpmLock reads pnpm-lock.yaml: lockfileVersion 5 (/name/1.2.3
// keys), 6 (/name@1.2.3) and 9 (name@1.2.3, with snapshots). Only the
// packages map and the importers are read.
func parsePnpmLock(data []byte) ([]npmEntry, error) {
	root, err := parseYAML(data)
	if err != nil {
		return nil, err
	}
	major := 0
	if v := root.get("lockfileVersion").str(); v != "" {
		major, _ = strconv.Atoi(strings.SplitN(strings.Trim(v, `'"`), ".", 2)[0])
	}
	var directs []pnpmDirect
	if imps := root.get("importers"); imps != nil {
		for i, dir := range imps.keys {
			directs = append(directs, pnpmImporter(imps.vals[i], dir)...)
		}
	} else {
		directs = pnpmImporter(root, ".")
	}
	pkgs := root.get("packages")
	if pkgs == nil {
		return nil, nil
	}
	var out []npmEntry
	keyRefs := make([]string, 0, len(pkgs.keys))
	for i, key := range pkgs.keys {
		v := pkgs.vals[i]
		name, ref := pnpmKey(key, major)
		e := npmEntry{name: name, version: ref, line: pkgs.lines[i]}
		if n := v.get("name").str(); n != "" {
			e.name = n
		}
		if ver := v.get("version").str(); ver != "" {
			e.version = ver
		}
		res := v.get("resolution")
		e.integrity = res.get("integrity").str()
		switch {
		case res.get("tarball").str() != "":
			e.resolved = res.get("tarball").str()
		case res.get("repo").str() != "":
			e.resolved = "git+" + res.get("repo").str() + "#" + res.get("commit").str()
		case res.get("directory").str() != "":
			e.resolved = "file:" + res.get("directory").str()
		}
		if strings.ContainsAny(e.version, ":/") {
			e.version = "" // a URL key with no version field
		}
		switch v.get("dev").str() {
		case "true":
			e.dev, e.devKnown = true, true
		case "false":
			e.devKnown = true
		}
		out = append(out, e)
		keyRefs = append(keyRefs, ref)
	}
	for _, d := range directs {
		for i := range out {
			e := &out[i]
			if e.name != d.name || e.version != d.ref && keyRefs[i] != d.ref && strings.TrimPrefix(pkgs.keys[i], "/") != d.ref {
				continue
			}
			e.direct = true
			if e.constraint == "" {
				e.constraint = d.specifier
			}
			if !e.devKnown {
				e.dev = d.dev
			}
			if e.path == "" {
				e.path = path.Join(d.importer, "node_modules", d.alias)
			}
		}
	}
	return out, nil
}

// pnpmImporter lists the dependencies one importer declares. Version 9
// and 6 write {specifier, version}; version 5 writes the version and
// keeps the ranges in a specifiers map.
func pnpmImporter(n *ynode, dir string) []pnpmDirect {
	var out []pnpmDirect
	specs := n.get("specifiers")
	for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		deps := n.get(sec)
		if deps == nil {
			continue
		}
		for i, alias := range deps.keys {
			v := deps.vals[i]
			d := pnpmDirect{alias: alias, name: alias, importer: dir, dev: sec == "devDependencies"}
			if v.get("version") != nil {
				d.ref, d.specifier = v.get("version").str(), v.get("specifier").str()
			} else {
				d.ref, d.specifier = v.str(), specs.get(alias).str()
			}
			if hasAnyPrefix(d.ref, "link:", "workspace:") {
				continue // a workspace package
			}
			d.ref = stripPeers(d.ref)
			if !strings.Contains(d.ref, "://") {
				// An alias names the real package: "real@1.2.3", or
				// "/real/1.2.3" in version 5.
				if real, ver, ok := splitSpec(strings.TrimPrefix(d.ref, "/")); ok {
					d.name, d.ref = real, ver
				} else if i := strings.LastIndexByte(d.ref, '/'); strings.HasPrefix(d.ref, "/") && i > 0 {
					d.name, d.ref = d.ref[1:i], d.ref[i+1:]
				}
			}
			out = append(out, d)
		}
	}
	return out
}

// pnpmKey splits a packages key into name and version (or URL):
// "/name/1.2.3_peer@1" (version 5), "/name@1.2.3(peer@1)" (6) and
// "name@1.2.3" (9).
func pnpmKey(key string, major int) (name, ref string) {
	s := strings.TrimPrefix(key, "/")
	if major > 0 && major < 6 {
		if i := strings.LastIndexByte(s, '/'); i > 0 {
			name, ref = s[:i], s[i+1:]
			if j := strings.IndexByte(ref, '_'); j >= 0 {
				ref = ref[:j]
			}
			return name, ref
		}
		return s, ""
	}
	if i := strings.IndexByte(s, '('); i > 0 {
		s = s[:i]
	}
	if n, r, ok := splitSpec(s); ok {
		return n, r
	}
	return s, ""
}

// stripPeers drops pnpm's peer suffix: "(react@18.2.0)" in version 6
// and later, "_react@18.2.0" after a version in version 5. A name may
// hold "_", so only a "_" after a version counts.
func stripPeers(s string) string {
	if i := strings.IndexByte(s, '('); i > 0 {
		s = s[:i]
	}
	if strings.Contains(s, "://") {
		return s
	}
	last := s[strings.LastIndexByte(s, '/')+1:]
	if j := strings.IndexByte(last, '_'); j > 0 && last[0] >= '0' && last[0] <= '9' {
		s = s[:len(s)-len(last)+j]
	}
	return s
}
