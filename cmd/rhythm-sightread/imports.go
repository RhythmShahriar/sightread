// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

// Every package that registers a stage from its init is linked here, so
// the binary has every stage from the first commit on. A lane that adds
// another registering package asks the integrator to add it to this list.
import (
	_ "github.com/RhythmShahriar/sightread/analyze"
	_ "github.com/RhythmShahriar/sightread/archive"
	_ "github.com/RhythmShahriar/sightread/blob"
	_ "github.com/RhythmShahriar/sightread/data"
	_ "github.com/RhythmShahriar/sightread/detect"
	_ "github.com/RhythmShahriar/sightread/detect/code"
	_ "github.com/RhythmShahriar/sightread/detect/meta"
	_ "github.com/RhythmShahriar/sightread/diff"
	_ "github.com/RhythmShahriar/sightread/fetch"
	_ "github.com/RhythmShahriar/sightread/inventory"
	_ "github.com/RhythmShahriar/sightread/inventory/gitref"
	_ "github.com/RhythmShahriar/sightread/policy"
	_ "github.com/RhythmShahriar/sightread/report"
	_ "github.com/RhythmShahriar/sightread/score"
	_ "github.com/RhythmShahriar/sightread/source/github"
	_ "github.com/RhythmShahriar/sightread/source/npm"
	_ "github.com/RhythmShahriar/sightread/source/osv"
	_ "github.com/RhythmShahriar/sightread/source/packagist"
	_ "github.com/RhythmShahriar/sightread/source/wporg"
	_ "github.com/RhythmShahriar/sightread/version"
)
