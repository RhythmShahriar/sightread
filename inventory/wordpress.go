// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// The WordPress reader follows Tuner's (tuner/local/wordpress.go:86-135),
// which matches WordPress's get_file_data(). It opens only
// wp-includes/version.php, the top-level PHP files of each plugin and
// mu-plugin, the drop-ins and each theme's style.css. It never opens
// wp-config.php, .env or the database (SR-39) and runs nothing.

// headerBytes is how much of a file WordPress reads for its header.
const headerBytes = 8 << 10

// maxPluginFiles caps the top-level PHP files searched for a plugin's
// main file, as Tuner does: a folder with hundreds is not worth reading.
const maxPluginFiles = 50

// DefaultMaxDepth is how many folders below the given path
// FindWordPress looks for a WordPress root.
const DefaultMaxDepth = 6

var (
	// wpVersionVar finds $wp_version in wp-includes/version.php. The file
	// is read as text, never run.
	wpVersionVar = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"\r\n]{1,64})['"]`)
	// versionToken is the version at the start of a Version: header.
	versionToken = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*`)
)

// wpHeaders are the header names inventory reads.
var wpHeaders = []string{"Plugin Name", "Theme Name", "Version", "Update URI", "Author", "Author URI", "Requires PHP"}

// headerRe holds one get_file_data() pattern per header.
var headerRe = map[string]*regexp.Regexp{}

func init() {
	for _, name := range wpHeaders {
		// As WordPress: optional "<?php", then comment characters, then
		// the name and a colon at the start of a line.
		headerRe[name] = regexp.MustCompile(`(?mi)^(?:[ \t]*<\?php)?[ \t/*#@]*` + regexp.QuoteMeta(name) + `:(.*)$`)
	}
}

// commentEnd is what _cleanup_header_comment() cuts from a value.
var commentEnd = regexp.MustCompile(`\s*(?:\*/|\?>).*`)

// bom is the UTF-8 byte order mark some editors write.
var bom = []byte{0xef, 0xbb, 0xbf}

// WPHeader is a plugin or theme file header.
type WPHeader struct {
	Name        string // Plugin Name or Theme Name
	Version     string // the version token of Version:
	UpdateURI   string
	Author      string
	AuthorURI   string
	RequiresPHP string
	// Line is the 1-based line of the Version: header, or of the name
	// when there is no version. 0 when neither is present.
	Line int
}

// ParseWPHeader reads the header of a plugin's main file (nameKey
// "Plugin Name") or a theme's style.css ("Theme Name") from its first
// bytes. ok is false when the name header is missing. Every value is a
// substring of head.
func ParseWPHeader(head []byte, nameKey string) (h WPHeader, ok bool) {
	head = bytes.TrimPrefix(head, bom)
	if len(head) > headerBytes {
		head = head[:headerBytes]
	}
	// WordPress turns CR into LF so a CRLF or old Mac file reads the same.
	// Values never span lines, so they stay substrings of the input.
	text := bytes.ReplaceAll(head, []byte("\r"), []byte("\n"))
	get := func(name string) (string, int) {
		m := headerRe[name].FindSubmatchIndex(text)
		if m == nil {
			return "", 0
		}
		v := string(text[m[2]:m[3]])
		v = commentEnd.ReplaceAllString(v, "")
		return strings.TrimSpace(v), lineAt(head, m[0])
	}
	var nameLine, versionLine int
	h.Name, nameLine = get(nameKey)
	if nameLine == 0 {
		return WPHeader{}, false
	}
	var raw string
	raw, versionLine = get("Version")
	h.Version = versionToken.FindString(raw)
	h.UpdateURI, _ = get("Update URI")
	h.Author, _ = get("Author")
	h.AuthorURI, _ = get("Author URI")
	h.RequiresPHP, _ = get("Requires PHP")
	h.Line = nameLine
	if versionLine > 0 {
		h.Line = versionLine
	}
	return h, true
}

// OfficialUpdateURI reports whether an Update URI header leaves the
// plugin or theme on WordPress.org: empty, w.org, wordpress.org or
// https://wordpress.org/plugins/<slug>/ (themes/<slug>/ for a theme).
// Any other value names another update channel, so the slug may belong
// to someone else on WordPress.org (PRD 5.5).
func OfficialUpdateURI(uri, slug string, eco core.Ecosystem) bool {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return true
	}
	s := uri
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	switch strings.ToLower(u.Host) {
	case "w.org", "wordpress.org", "www.wordpress.org":
	default:
		return false
	}
	kind := "plugins"
	if eco == core.WPTheme {
		kind = "themes"
	}
	switch strings.TrimSuffix(u.Path, "/") {
	case "", "/" + kind + "/" + slug:
		return true
	}
	return false
}

// skipDirs are never searched for a WordPress root.
var skipDirs = map[string]bool{"node_modules": true, "vendor": true, ".git": true}

// IsWordPressRoot reports whether dir holds wp-includes/version.php and
// a wp-content folder.
func IsWordPressRoot(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, "wp-includes", "version.php"))
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	fi, err = os.Stat(filepath.Join(dir, "wp-content"))
	return err == nil && fi.IsDir()
}

// FindWordPress returns the WordPress roots at or below root, at most
// maxDepth folders down (DefaultMaxDepth when maxDepth is 0 or less).
// It skips node_modules, vendor and .git, does not look inside a root
// it found and never follows a linked folder.
func FindWordPress(ctx context.Context, root string, maxDepth int) ([]string, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", root)
	}
	var found []string
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if IsWordPressRoot(dir) {
			found = append(found, dir)
			return nil
		}
		if depth == maxDepth {
			return nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if dir == root {
				return err
			}
			return nil // an unreadable subfolder is not where the site is
		}
		for _, e := range entries {
			// ReadDir's types come from Lstat, so a linked folder is not
			// a dir here and is never entered.
			if !e.IsDir() || skipDirs[e.Name()] {
				continue
			}
			if err := walk(filepath.Join(dir, e.Name()), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return found, nil
}

// dropIns are the wp-content files WordPress loads as drop-ins
// (_get_dropins()). They have no update channel.
var dropIns = []string{
	"advanced-cache.php", "blog-deleted.php", "blog-inactive.php", "blog-suspended.php",
	"db-error.php", "db.php", "fatal-error-handler.php", "install.php", "maintenance.php",
	"object-cache.php", "php-error.php", "sunrise.php",
}

// wpReader collects what one WordPress root holds.
type wpReader struct {
	ctx  context.Context
	root string
	site *core.Site
}

// ReadWordPress reads the installed plugins and themes of the WordPress
// root. Folders it can't place are listed as Not checked, never dropped.
func ReadWordPress(ctx context.Context, root string) (*core.Site, error) {
	if !IsWordPressRoot(root) {
		return nil, fmt.Errorf("%s is not a WordPress root (no wp-includes/version.php and wp-content)", root)
	}
	r := &wpReader{ctx: ctx, root: root, site: &core.Site{Root: root, Kind: "wordpress"}}
	if b, err := readHead(filepath.Join(root, "wp-includes", "version.php"), headerBytes); err != nil {
		r.warn("couldn't read wp-includes/version.php: %v", errText(err))
	} else if m := wpVersionVar.FindSubmatch(b); m != nil {
		r.site.WordPress = string(m[1])
	}
	r.site.NotChecked = append(r.site.NotChecked, notChecked("", "wordpress", r.site.WordPress, core.Core))
	content := filepath.Join(root, "wp-content")
	r.plugins(filepath.Join(content, "plugins"))
	r.muPlugins(filepath.Join(content, "mu-plugins"))
	r.dropIns(content)
	r.themes(filepath.Join(content, "themes"))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.site, nil
}

// warn adds a warning to the site.
func (r *wpReader) warn(format string, a ...any) {
	r.site.Warnings = append(r.site.Warnings, fmt.Sprintf(format, a...))
}

// rel is p relative to the root, slash separated.
func (r *wpReader) rel(p string) string {
	if s, err := filepath.Rel(r.root, p); err == nil {
		return filepath.ToSlash(s)
	}
	return filepath.ToSlash(p)
}

// entry is a folder entry, with links resolved for the kind but
// remembered.
type entry struct {
	name   string
	path   string
	dir    bool
	file   bool
	linked bool
}

// list reads dir and classifies its entries with Lstat, resolving a
// link only to tell a linked folder from a linked file. Hidden entries
// are left out, as WordPress does.
func (r *wpReader) list(dir string) []entry {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			r.warn("couldn't read %s: %v", r.rel(dir), errText(err))
		}
		return nil
	}
	var out []entry
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		p := filepath.Join(dir, name)
		en := entry{name: name, path: p}
		mode := e.Type()
		if mode&fs.ModeSymlink != 0 {
			en.linked = true
			fi, err := os.Stat(p)
			if err != nil {
				r.warn("%s is a link that can't be followed: %v", r.rel(p), errText(err))
				continue
			}
			mode = fi.Mode()
		}
		en.dir = mode.IsDir()
		en.file = mode.IsRegular()
		if !en.dir && !en.file {
			// Never opened: a FIFO would block, a device never ends.
			r.warn("skipped %s: it is %s, not a regular file", r.rel(p), fileKind(mode))
			continue
		}
		out = append(out, en)
	}
	return out
}

// plugins reads wp-content/plugins: each folder and each single-file
// plugin in its root.
func (r *wpReader) plugins(dir string) {
	for _, e := range r.list(dir) {
		if r.ctx.Err() != nil {
			return
		}
		switch {
		case e.dir:
			if e.linked {
				r.warn("%s is a link to a folder elsewhere; read through the link", r.rel(e.path))
			}
			r.pluginFolder(e)
		case e.file && strings.EqualFold(path.Ext(e.name), ".php") && e.name != "index.php":
			b, err := readHead(e.path, headerBytes)
			if err != nil {
				r.warn("couldn't read %s: %v", r.rel(e.path), errText(err))
				continue
			}
			// A PHP file without a header in the plugins folder is not a
			// plugin to WordPress either (index.php "Silence is golden").
			if h, ok := ParseWPHeader(b, "Plugin Name"); ok {
				r.addPlugin(strings.TrimSuffix(e.name, path.Ext(e.name)), r.rel(e.path), r.rel(e.path), h, core.WPPlugin)
			}
		}
	}
}

// pluginFolder finds the folder's main file, trying <slug>.php first.
func (r *wpReader) pluginFolder(e entry) {
	var files []string
	for _, f := range r.list(e.path) {
		if f.file && strings.EqualFold(path.Ext(f.name), ".php") {
			files = append(files, f.name)
		}
	}
	main := e.name + ".php"
	slices.SortStableFunc(files, func(a, b string) int {
		return boolInt(a != main) - boolInt(b != main)
	})
	for _, f := range files[:min(len(files), maxPluginFiles)] {
		p := filepath.Join(e.path, f)
		b, err := readHead(p, headerBytes)
		if err != nil {
			r.warn("couldn't read %s: %v", r.rel(p), errText(err))
			continue
		}
		if h, ok := ParseWPHeader(b, "Plugin Name"); ok {
			r.addPlugin(e.name, r.rel(e.path), r.rel(p), h, core.WPPlugin)
			return
		}
	}
	r.site.NotChecked = append(r.site.NotChecked, notChecked(core.WPPlugin, e.name, "", core.NoHeader))
}

// addPlugin records a plugin or theme. One whose Update URI points off
// WordPress.org, or whose folder name can't be a WordPress.org slug, is
// marked Private and listed as not-wporg, so its name is never sent to
// WordPress.org (SR-40).
func (r *wpReader) addPlugin(slug, folder, mainFile string, h WPHeader, eco core.Ecosystem) {
	in := core.Installed{
		Ref:       core.Ref{Eco: eco, Name: slug, Version: h.Version},
		Path:      folder,
		Lockfile:  mainFile,
		LockLine:  h.Line,
		UpdateURI: h.UpdateURI,
	}
	if !OfficialUpdateURI(h.UpdateURI, slug, eco) || !wpSlug(slug) {
		in.Private = true
		r.site.NotChecked = append(r.site.NotChecked, notChecked(eco, slug, h.Version, core.NotWPOrg))
	}
	r.site.Installed = append(r.site.Installed, in)
}

// wpSlug reports whether name can be a WordPress.org slug: letters,
// digits, dots, dashes and underscores, at most 200 bytes.
func wpSlug(name string) bool {
	if name == "" || len(name) > 200 {
		return false
	}
	for _, c := range []byte(name) {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// muPlugins lists each top-level PHP file of wp-content/mu-plugins as
// Not checked: WordPress loads them without an update channel. Folders
// there are loaded by those files, so they are not listed again.
func (r *wpReader) muPlugins(dir string) {
	for _, e := range r.list(dir) {
		if !e.file || !strings.EqualFold(path.Ext(e.name), ".php") || e.name == "index.php" {
			continue
		}
		version := ""
		if b, err := readHead(e.path, headerBytes); err == nil {
			if h, ok := ParseWPHeader(b, "Plugin Name"); ok {
				version = h.Version
			}
		}
		r.site.NotChecked = append(r.site.NotChecked, notChecked(core.WPPlugin, strings.TrimSuffix(e.name, path.Ext(e.name)), version, core.MUPlugin))
	}
}

// dropIns lists the drop-ins present in wp-content as Not checked.
func (r *wpReader) dropIns(content string) {
	for _, name := range dropIns {
		fi, err := os.Lstat(filepath.Join(content, name))
		if err != nil || fi.IsDir() {
			continue
		}
		r.site.NotChecked = append(r.site.NotChecked, notChecked(core.WPPlugin, name, "", core.MUPlugin))
	}
}

// themes reads each theme's style.css.
func (r *wpReader) themes(dir string) {
	for _, e := range r.list(dir) {
		if r.ctx.Err() != nil {
			return
		}
		if !e.dir {
			continue
		}
		if e.linked {
			r.warn("%s is a link to a folder elsewhere; read through the link", r.rel(e.path))
		}
		css := filepath.Join(e.path, "style.css")
		b, err := readHead(css, headerBytes)
		if err != nil && !os.IsNotExist(err) {
			r.warn("couldn't read %s: %v", r.rel(css), errText(err))
		}
		h, ok := ParseWPHeader(b, "Theme Name")
		if err != nil || !ok {
			nc := notChecked(core.WPTheme, e.name, "", core.NoHeader)
			nc.Text = themeNoHeaderText
			r.site.NotChecked = append(r.site.NotChecked, nc)
			continue
		}
		r.addPlugin(e.name, r.rel(e.path), r.rel(css), h, core.WPTheme)
	}
}

// errText is an error's text without the path the caller already
// printed.
func errText(err error) string {
	var nr *notRegularError
	if errors.As(err, &nr) {
		return "it is " + nr.kind + ", not a regular file"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// lineAt is the 1-based line of byte offset off in b. CRLF, LF and a
// lone CR each end one line.
func lineAt(b []byte, off int) int {
	line := 1
	for i := 0; i < off && i < len(b); i++ {
		switch b[i] {
		case '\n':
			line++
		case '\r':
			if i+1 >= len(b) || b[i+1] != '\n' {
				line++
			}
		}
	}
	return line
}

// boolInt is 1 for true, 0 for false.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
