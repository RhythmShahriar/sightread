// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/RhythmShahriar/sightread/core"
)

// MaxName is the longest entry name accepted, in bytes (PRD 11).
const MaxName = 1024

// ValidateName checks one archive entry name and returns it in the form
// a tree keeps: slash separated, relative, NFC. A name that fails gives
// the issue it is: IssueMalformed for an empty name, invalid UTF-8, a
// NUL or other control character or more than MaxName bytes;
// IssuePathEscape for a name that could land outside the package on any
// of Linux, macOS or Windows.
//
// The rules run in order. Backslashes become slashes before any path
// check, so a Windows-only escape such as ..\win.php is caught on Linux
// too. Then the name is refused when it starts with a slash (which
// covers UNC //host), a drive letter (C:) or holds any segment that is
// empty, "." or "..". Two platform rules go further than those. Windows
// drops trailing dots and spaces and macOS ignores some invisible
// characters, so a segment made only of dots, spaces and those
// characters ("...", ". ", ".\u200c.") counts as "." or "..". Windows
// also opens a device for names like NUL or COM1.txt and an alternate
// stream for a colon, so both are refused.
func ValidateName(raw string) (clean string, issue core.ArchiveIssueKind, ok bool) {
	if raw == "" || !utf8.ValidString(raw) || len(raw) > MaxName {
		return "", core.IssueMalformed, false
	}
	if strings.ContainsFunc(raw, isControl) {
		return "", core.IssueMalformed, false
	}
	name := norm.NFC.String(strings.ReplaceAll(raw, `\`, "/"))
	if len(name) > MaxName {
		return "", core.IssueMalformed, false
	}
	if strings.HasPrefix(name, "/") || hasDrive(name) || strings.ContainsRune(name, ':') {
		return "", core.IssuePathEscape, false
	}
	for seg := range strings.SplitSeq(name, "/") {
		if dotLike(seg) || reservedWindows(seg) {
			return "", core.IssuePathEscape, false
		}
	}
	return name, "", true
}

// Escape details: why ValidateName refused a name as IssuePathEscape.
const (
	detailOutside = "outside the package"
	detailColon   = "name has a colon, which Windows reads as a stream or drive"
	detailDevice  = "name is a Windows device such as NUL or COM1"
)

// escapeDetail says why ValidateName refused raw as IssuePathEscape. A
// colon or a device name stays inside the package on Linux and macOS,
// so the report names the Windows risk instead of claiming an escape.
func escapeDetail(raw string) string {
	name := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(name, "/") || hasDrive(name) {
		return detailOutside
	}
	for seg := range strings.SplitSeq(name, "/") {
		if dotLike(seg) {
			return detailOutside
		}
	}
	if strings.ContainsRune(name, ':') {
		return detailColon
	}
	for seg := range strings.SplitSeq(name, "/") {
		if reservedWindows(seg) {
			return detailDevice
		}
	}
	return detailOutside
}

// CaseKey is the name two entries collide on when a file system ignores
// case and Unicode normalisation (macOS and Windows defaults).
func CaseKey(name string) string { return strings.ToLower(norm.NFC.String(name)) }

// isControl reports C0 and C1 control characters and DEL.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f }

// hasDrive reports a leading drive letter such as C: or c:/.
func hasDrive(name string) bool {
	return len(name) >= 2 && name[1] == ':' && (name[0] >= 'A' && name[0] <= 'Z' || name[0] >= 'a' && name[0] <= 'z')
}

// dotLike reports a segment that is empty or, once Windows trims
// trailing dots and spaces and macOS drops ignorable characters, "." or
// "..". Any segment made only of those qualifies.
func dotLike(seg string) bool {
	for _, r := range seg {
		if r != '.' && r != ' ' && !hfsIgnorable(r) {
			return false
		}
	}
	return true
}

// hfsIgnorable are the code points HFS+ leaves out when it compares
// names (the set git refuses in .git look-alikes).
func hfsIgnorable(r rune) bool {
	switch {
	case r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x206a && r <= 0x206f, r == 0xfeff:
		return true
	}
	return false
}

// reservedWindows reports a segment Windows opens as a device: CON, PRN,
// AUX, NUL, COM1 to COM9, LPT1 to LPT9 (superscript digits too), CONIN$
// and CONOUT$, with any extension and trailing spaces, as Go's
// filepath.IsLocal treats them on Windows.
func reservedWindows(seg string) bool {
	base := seg
	if i := strings.IndexAny(base, ".:"); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) >= 4 && (base[:3] == "COM" || base[:3] == "LPT") {
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
			return true
		}
	}
	return false
}
