// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"path/filepath"
	"slices"
	"strings"
)

// remoteRunners are the programs that run a command somewhere other
// than this machine: over SSH, in a container or in a VM. A --wp prefix
// that starts with one of them runs WP-CLI where a zip on this machine
// isn't, so the verified archive can't be handed to it.
var remoteRunners = []string{
	"ssh", "docker", "docker-compose", "podman", "nerdctl", "kubectl", "oc",
	"ddev", "lando", "vagrant", "wp-env", "sail", "devbox", "local",
}

// remotePrefix reports whether the wp command runs elsewhere: its first
// word is a remote runner, or WP-CLI itself is told to go elsewhere with
// --ssh= or an @alias.
func remotePrefix(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(argv[0], `\`, "/")))
	name = strings.TrimSuffix(name, ".exe")
	if slices.Contains(remoteRunners, name) {
		return true
	}
	for _, a := range argv[1:] {
		if a == "--ssh" || strings.HasPrefix(a, "--ssh=") || strings.HasPrefix(a, "--http=") || strings.HasPrefix(a, "@") {
			return true
		}
	}
	return false
}
