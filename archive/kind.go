// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"path"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// extKinds maps a lower-case extension (without the dot) to its kind.
var extKinds = map[string]core.FileKind{}

func init() {
	add := func(k core.FileKind, exts ...string) {
		for _, e := range exts {
			extKinds[e] = k
		}
	}
	add(core.KindPHP, "php", "phtml", "inc", "php3", "php4", "php5", "php7", "php8", "phps")
	add(core.KindJS, "js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx")
	add(core.KindJSON, "json")
	add(core.KindText, "txt", "md", "markdown", "rst", "css", "scss", "sass", "less", "html", "htm",
		"xml", "yml", "yaml", "toml", "ini", "conf", "csv", "tsv", "po", "pot", "sql", "sh", "bash",
		"twig", "vue", "svelte", "lock", "map", "htaccess", "gitignore", "gitattributes", "editorconfig",
		"npmignore", "distignore", "dist", "neon", "env", "log", "tpl", "mustache", "hbs", "graphql", "pem")
	add(core.KindAsset, "png", "jpg", "jpeg", "gif", "ico", "svg", "webp", "avif", "bmp", "tif", "tiff",
		"woff", "woff2", "ttf", "otf", "eot", "mo", "mp3", "mp4", "m4a", "ogg", "wav", "webm", "mov", "pdf")
	add(core.KindArchive, "zip", "tgz", "gz", "tar", "phar", "rar", "7z", "bz2", "xz", "zst", "jar")
}

// textNames are files without an extension that are text.
var textNames = map[string]bool{
	"license": true, "readme": true, "changelog": true, "changes": true,
	"licence": true, //nolint:misspell // the British file name some packages ship
	"history": true, "copying": true, "authors": true, "contributors": true, "notice": true,
	"makefile": true, "dockerfile": true, "procfile": true, "vagrantfile": true,
}

// KindOf is a file's kind from its name alone: PHP and JS by extension
// (.min.js is minified), JSON, known text and asset types and nested
// archives, else binary. The analyzer refines it from the contents.
func KindOf(name string) core.FileKind {
	base := strings.ToLower(path.Base(name))
	if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.mjs") {
		return core.KindMinified
	}
	ext := strings.TrimPrefix(path.Ext(base), ".")
	if k, ok := extKinds[ext]; ok {
		return k
	}
	if ext == "" && textNames[base] {
		return core.KindText
	}
	return core.KindBinary
}
