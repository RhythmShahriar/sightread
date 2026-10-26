// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"encoding/json"
	"errors"
	"strings"
)

// plEntry is one package-lock.json entry: a "packages" value in
// lockfileVersion 2 and 3, a "dependencies" value in version 1.
type plEntry struct {
	Name                 string              `json:"name"`
	Version              string              `json:"version"`
	Resolved             string              `json:"resolved"`
	Integrity            string              `json:"integrity"`
	Link                 bool                `json:"link"`
	Dev                  bool                `json:"dev"`
	DevOptional          bool                `json:"devOptional"`
	InBundle             bool                `json:"inBundle"`
	Bundled              bool                `json:"bundled"`
	Dependencies         json.RawMessage     `json:"dependencies"` // v2+: name to range; v1: nested entries
	OptionalDependencies map[string]string   `json:"optionalDependencies"`
	PeerDependencies     map[string]string   `json:"peerDependencies"`
	DevDependencies      map[string]string   `json:"devDependencies"`
	Requires             json.RawMessage     `json:"requires"` // v1: name to range (true at the top)
	nested               map[string]*plEntry // v1 dependencies, decoded
	ranges               map[string]string   // v2+ dependencies, decoded
}

// plFile is package-lock.json or npm-shrinkwrap.json.
type plFile struct {
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]*plEntry `json:"packages"`
	Dependencies    map[string]*plEntry `json:"dependencies"`
}

// maxLockDepth bounds nesting in a lockfile tree, as SR-16 does for
// YAML: real trees are a handful of levels deep.
const maxLockDepth = 64

// errTooDeep is the error for a lockfile nested past maxLockDepth.
var errTooDeep = errors.New("nested too deep (over 64 levels)")

// parsePackageLock reads lockfileVersion 1 (the dependencies tree), 2
// and 3 (the packages map keyed by node_modules paths).
func parsePackageLock(data []byte, m *npmManifest) ([]npmEntry, error) {
	var f plFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	lines := map[string]int{}
	err := scanJSONKeys(data, func(p []string, line int) {
		switch {
		case len(p) == 2 && p[0] == "packages":
			lines["p\x00"+p[1]] = line
		case len(p) >= 2 && p[0] == "dependencies" && len(p)%2 == 0 && f.Packages == nil:
			// v1: dependencies.<a>.dependencies.<b>...
			for i := 2; i < len(p); i += 2 {
				if p[i] != "dependencies" {
					return
				}
			}
			lines["d\x00"+v1Key(p)] = line
		}
	})
	if err != nil {
		return nil, err
	}
	if f.Packages != nil {
		return packagesV2(f.Packages, lines), nil
	}
	var out []npmEntry
	if err := dependenciesV1(f.Dependencies, "", nil, m, lines, 0, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// v1Key joins the package names of a v1 dependencies path.
func v1Key(p []string) string {
	var names []string
	for i := 1; i < len(p); i += 2 {
		names = append(names, p[i])
	}
	return strings.Join(names, "\x00")
}

// packagesV2 reads the packages map of lockfileVersion 2 and 3.
func packagesV2(pkgs map[string]*plEntry, lines map[string]int) []npmEntry {
	for _, e := range pkgs {
		if e != nil {
			_ = json.Unmarshal(e.Dependencies, &e.ranges) // a v1-shaped value here just has no ranges
		}
	}
	// Names declared by the root and by each workspace folder: those at
	// the top of node_modules are direct dependencies.
	declared := map[string]string{}
	for key, e := range pkgs {
		if e == nil || strings.Contains(key, "node_modules/") {
			continue
		}
		for _, deps := range []map[string]string{e.DevDependencies, e.PeerDependencies, e.OptionalDependencies, e.ranges} {
			for name, r := range deps {
				if _, ok := declared[name]; !ok || key == "" {
					declared[name] = r
				}
			}
		}
	}
	var out []npmEntry
	for key, e := range pkgs {
		i := strings.LastIndex(key, "node_modules/")
		if e == nil || i < 0 {
			continue // the root or a workspace folder
		}
		if e.InBundle {
			continue // shipped inside its parent's tarball
		}
		name := key[i+len("node_modules/"):]
		if e.Name != "" {
			name = e.Name // an alias: node_modules/<alias> holds <name>
		}
		ne := npmEntry{
			name: name, version: e.Version, resolved: e.Resolved, integrity: e.Integrity,
			path: key, line: lines["p\x00"+key], dev: e.Dev || e.DevOptional, devKnown: true, link: e.Link,
		}
		alias := key[i+len("node_modules/"):]
		parentKey := strings.TrimSuffix(key[:i], "/")
		if i == 0 {
			if r, ok := declared[alias]; ok {
				ne.direct, ne.constraint = true, r
			}
		} else if parent := pkgs[parentKey]; parent != nil {
			ne.constraint = rangeIn(alias, parent.ranges, parent.DevDependencies, parent.OptionalDependencies, parent.PeerDependencies)
			// Under a workspace folder rather than another package: the
			// workspace declares it, so it is direct.
			ne.direct = !strings.Contains(parentKey, "node_modules/")
		}
		out = append(out, ne)
	}
	return out
}

// rangeIn finds name's range in the first map that has it.
func rangeIn(name string, maps ...map[string]string) string {
	for _, m := range maps {
		if r, ok := m[name]; ok {
			return r
		}
	}
	return ""
}

// dependenciesV1 walks the lockfileVersion 1 tree. parent is the
// requiring entry, whose requires give a nested entry's range.
func dependenciesV1(deps map[string]*plEntry, prefix string, parentKey []string, m *npmManifest, lines map[string]int, depth int, out *[]npmEntry) error {
	if depth > maxLockDepth {
		return errTooDeep
	}
	for alias, e := range deps {
		if e == nil || e.Bundled {
			continue
		}
		key := append(append([]string(nil), parentKey...), alias)
		path := prefix + "node_modules/" + alias
		name, version := alias, e.Version
		resolved := e.Resolved
		if real, ok := strings.CutPrefix(version, "npm:"); ok {
			// "npm:real@1.2.3": an alias.
			if n, v, ok := splitNameVersion(real); ok {
				name, version = n, v
			}
		} else if strings.ContainsAny(version, ":/") {
			// A git, file or tarball dependency writes its source as the
			// version.
			if resolved == "" {
				resolved = version
			}
			version = ""
		}
		ne := npmEntry{
			name: name, version: version, resolved: resolved, integrity: e.Integrity,
			path: path, line: lines["d\x00"+strings.Join(key, "\x00")], dev: e.Dev, devKnown: true,
		}
		if depth == 0 {
			if m != nil {
				if r, ok := m.deps[alias]; ok {
					ne.direct, ne.constraint = true, r
				}
			}
		}
		*out = append(*out, ne)
		if len(e.Dependencies) > 0 {
			if err := json.Unmarshal(e.Dependencies, &e.nested); err != nil {
				return err
			}
			var requires map[string]string
			_ = json.Unmarshal(e.Requires, &requires)
			before := len(*out)
			if err := dependenciesV1(e.nested, path+"/", key, m, lines, depth+1, out); err != nil {
				return err
			}
			for i := before; i < len(*out); i++ {
				child := &(*out)[i]
				if child.constraint == "" && strings.Count(child.path, "node_modules/") == depth+2 {
					child.constraint = requires[child.path[strings.LastIndex(child.path, "node_modules/")+len("node_modules/"):]]
				}
			}
		}
	}
	return nil
}
