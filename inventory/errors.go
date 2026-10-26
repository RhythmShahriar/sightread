// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"fmt"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// lockfileHint is E4's hint (PRD 10).
const lockfileHint = "run your package manager once to write one; Sightread compares versions a lockfile pins"

// noLockfileError is E4: dir holds none of the lockfiles looked for.
// command is the Sightread command ("npm", "composer"), or empty for
// the caller to fill in.
func noLockfileError(command, dir string, looked []string) error {
	return &core.Error{
		Code:    core.ENoLockfile,
		Exit:    2,
		Command: command,
		What:    fmt.Sprintf("no lockfile in %s (looked for %s)", dir, strings.Join(looked, ", ")),
		Hint:    []string{lockfileHint},
	}
}
