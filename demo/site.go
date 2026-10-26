// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package demo

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/RhythmShahriar/sightread/core"
)

// WriteSite writes the demo site under dir: a WordPress install with the
// old version of each demo plugin, byte for byte as the server publishes
// it so the installed copies verify. An npm project at the same root
// has a lockfile that pins the old version of each demo npm package.
// The review then finds every update as it would on a real site.
func WriteSite(dir string) error {
	files := map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.8.3';\n",
		"wp-content/index.php":    "<?php\n// Silence is golden.\n",
	}
	deps := map[string]string{}
	lock := map[string]any{"": map[string]any{"name": "demo-site", "version": "1.0.0", "dependencies": deps}}
	for _, p := range Packages() {
		if p.Old == nil {
			continue
		}
		switch p.Eco {
		case core.WPPlugin:
			for _, f := range p.Old.Files {
				files[filepath.ToSlash(filepath.Join("wp-content", "plugins", p.Name, f.Path))] = f.Body
			}
		case core.NPM:
			sorted := slices.Clone(p.Old.Files)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
			tgz, err := tarGz(sorted)
			if err != nil {
				return err
			}
			sum := sha512.Sum512(tgz)
			deps[p.Name] = "^" + p.Old.Version
			lock["node_modules/"+p.Name] = map[string]any{"version": p.Old.Version,
				"resolved":  "https://registry.npmjs.org/" + p.Name + "/-/" + tarballName(p.Name, p.Old.Version),
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:])}
		}
	}
	manifest, err := json.MarshalIndent(map[string]any{"name": "demo-site", "version": "1.0.0", "private": true,
		"dependencies": deps}, "", "  ")
	if err != nil {
		return err
	}
	lockfile, err := json.MarshalIndent(map[string]any{"name": "demo-site", "version": "1.0.0", "lockfileVersion": 3,
		"requires": true, "packages": lock}, "", "  ")
	if err != nil {
		return err
	}
	files["package.json"] = string(manifest) + "\n"
	files["package-lock.json"] = string(lockfile) + "\n"
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}
