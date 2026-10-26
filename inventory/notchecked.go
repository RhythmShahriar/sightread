// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import "github.com/RhythmShahriar/sightread/core"

// The Not checked texts and hints of PRD 5.5 for the reasons inventory
// gives. The report prints them as they are.
var notCheckedText = map[core.NotCheckedReason][2]string{
	core.NoHeader:    {"plugin folder has no Plugin Name header", "check the folder by hand or remove it"},
	core.NotWPOrg:    {"not on WordPress.org", "give the vendor's zip with --to-file"},
	core.Private:     {"private registry or repository", "set the registry in .sightread/config.yaml sources"},
	core.VCS:         {"git, path or tarball dependency", "Sightread reviews registry releases only"},
	core.MUPlugin:    {"must-use plugins and drop-ins have no update channel", ""},
	core.Core:        {"WordPress core is out of scope in v1", "WordPress core updates come signed from WordPress.org"},
	core.TooLarge:    {"over --max-size", "raise --max-size"},
	core.FetchFailed: {"could not download", "run again; -v shows the request"},
}

// themeNoHeaderText is no-header's text for a theme folder.
const themeNoHeaderText = "theme folder has no Theme Name header in style.css"

// notChecked builds a Not checked entry with the PRD text and hint.
func notChecked(eco core.Ecosystem, name, version string, reason core.NotCheckedReason) core.NotChecked {
	t := notCheckedText[reason]
	return core.NotChecked{Eco: eco, Name: name, Version: version, Reason: reason, Text: t[0], Hint: t[1]}
}
