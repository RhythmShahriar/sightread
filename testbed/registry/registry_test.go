// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// writeScenario writes one scenario folder with meta.yaml and the named
// files under old/ and new/.
func writeScenario(t *testing.T, dir, id, meta string, old, newf map[string]string) {
	t.Helper()
	base := filepath.Join(dir, id)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "meta.yaml"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	for sub, files := range map[string]map[string]string{"old": old, "new": newf} {
		for name, body := range files {
			p := filepath.Join(base, sub, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// fixtureDir builds a packages dir with one scenario per ecosystem.
func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeScenario(t, dir, "example-plugin", strings.TrimSpace(`
ecosystem: wp-plugin
name: example-plugin
versions:
  - version: "1.2.0"
    installed: true
    author: exampleauthor
    committer: exampleauthor
    contributors: [exampleauthor]
  - version: "1.3.0"
    candidate: true
    published: -3h
    author: exampleauthor
    committer: newcommitter
    contributors: [exampleauthor, newcommitter]
`), map[string]string{"example-plugin.php": "<?php // v1.2.0\n", "readme.txt": "stable\n"},
		map[string]string{"example-plugin.php": "<?php // v1.3.0\n", "readme.txt": "stable\n", "extra.php": "<?php // new\n"})

	writeScenario(t, dir, "example-theme", strings.TrimSpace(`
ecosystem: wp-theme
name: example-theme
versions:
  - version: "2.0"
    installed: true
    author: themeauthor
    committer: themeauthor
  - version: "2.1"
    candidate: true
    author: themeauthor
    committer: themeauthor
`), map[string]string{"style.css": "/* 2.0 */\n"}, map[string]string{"style.css": "/* 2.1 */\n"})

	writeScenario(t, dir, "vendor-example", strings.TrimSpace(`
ecosystem: composer
name: vendor/example
repository: github.com/vendor/example
versions:
  - version: "1.0.0"
    installed: true
    reference: aaaaaaabbbbbbbccccccc
    maintainers: [vendoruser]
  - version: "2.0.0"
    candidate: true
    reference: dddddddeeeeeeefffffff
    maintainers: [vendoruser]
`), map[string]string{"composer.json": `{"name":"vendor/example"}`}, map[string]string{"composer.json": `{"name":"vendor/example"}`})

	writeScenario(t, dir, "example-pkg", strings.TrimSpace(`
ecosystem: npm
name: example-pkg
repository: github.com/example/pkg
versions:
  - version: "1.0.0"
    installed: true
    maintainers: [goodmaintainer]
  - version: "2.0.0"
    candidate: true
    published: -3h
    maintainers: [goodmaintainer]
    advisories: [MAL-2026-0001]
    scripts:
      postinstall: node install.js
`), map[string]string{"index.js": "module.exports = 1\n", "package.json": `{"name":"example-pkg","version":"1.0.0"}`},
		map[string]string{"index.js": "module.exports = 2\n", "package.json": `{"name":"example-pkg","version":"2.0.0"}`, "install.js": "// marker\n"})
	return dir
}

// startPlain starts a plain-HTTP registry and returns it with an http
// client and a base-URL maker.
func startPlain(t *testing.T, dir string) (*Registry, *http.Client) {
	t.Helper()
	reg, err := New(Options{PackagesDir: dir, StateDir: t.TempDir(), PlainHTTP: true, AnyPort: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg, &http.Client{}
}

// baseOf is the plain HTTP base URL of the listener documented as port.
func baseOf(reg *Registry, port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", reg.Port(port))
}

// getJSON fetches url and decodes the JSON body into a generic map.
func getJSON(t *testing.T, c *http.Client, url string) map[string]any {
	t.Helper()
	resp, err := c.Get(url) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	return m
}

// recordedKeys loads a recorded example and returns its top-level keys.
func recordedKeys(t *testing.T, name string) []string {
	t.Helper()
	m := recordedJSON(t, name)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// recordedJSON loads a recorded example as a generic map.
func recordedJSON(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// assertMapKeys fails when got is missing a key of the recorded object.
func assertMapKeys(t *testing.T, label string, got, recorded map[string]any) {
	t.Helper()
	for k := range recorded {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: served object missing key %q", label, k)
		}
	}
}

// xmlElements returns the namespace-qualified names of every element in
// an XML document, as "<namespace> <local>", so prefixes do not matter
// (mod_dav_svn writes lp1:creator-displayname, the registry D:).
func xmlElements(t *testing.T, b []byte) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("bad XML: %v\n%s", err, b)
		}
		if se, ok := tok.(xml.StartElement); ok {
			out[se.Name.Space+" "+se.Name.Local] = true
		}
	}
}

// assertKeys fails when got is missing a key the recorded example has.
func assertKeys(t *testing.T, label string, got map[string]any, recorded string) {
	t.Helper()
	for _, k := range recordedKeys(t, recorded) {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: served response missing key %q from %s", label, k, recorded)
		}
	}
}

func TestFixtureRegistry(t *testing.T) {
	dir := fixtureDir(t)
	reg, c := startPlain(t, dir)

	t.Run("wporg info shape and version", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugins/info/1.2/?action=plugin_information&request[slug]=example-plugin")
		assertKeys(t, "wporg", got, "wporg-plugin-info.json")
		if got["version"] != "1.3.0" {
			t.Errorf("bad state: want version 1.3.0, got %v", got["version"])
		}
	})

	t.Run("checksums match the built zip", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugin-checksums/example-plugin/1.3.0.json")
		files, _ := got["files"].(map[string]any)
		if len(files) == 0 {
			t.Fatal("no checksums")
		}
		zipBytes := fetch(t, c, baseOf(reg, ports.WPOrg)+"/plugin/example-plugin.1.3.0.zip")
		if len(zipBytes) == 0 {
			t.Fatal("empty zip")
		}
		// Every checksum entry names a file that is in the zip.
		names := zipNames(t, zipBytes, "example-plugin/")
		for path := range files {
			if !names[path] {
				t.Errorf("checksum names %q but the zip has no such file", path)
			}
		}
	})

	t.Run("wporg theme info shape", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/themes/info/1.2/?action=theme_information&request[slug]=example-theme")
		assertKeys(t, "wporg theme", got, "wporg-theme-info.json")
		author, ok := got["author"].(map[string]any)
		if !ok {
			t.Fatalf("theme author is %T, want an object as the themes API gives", got["author"])
		}
		recorded := recordedJSON(t, "wporg-theme-info.json")["author"].(map[string]any)
		assertMapKeys(t, "wporg theme author", author, recorded)
		if author["user_nicename"] != "themeauthor" {
			t.Errorf("theme author login = %v, want themeauthor", author["user_nicename"])
		}
	})

	t.Run("plugin checksums shape", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugin-checksums/example-plugin/1.3.0.json")
		assertKeys(t, "plugin checksums", got, "wporg-plugin-checksums.json")
		files, _ := got["files"].(map[string]any)
		for name, f := range files {
			entry, _ := f.(map[string]any)
			if _, ok := entry["sha256"].(string); !ok {
				t.Errorf("checksum of %s has no sha256 string: %v", name, f)
			}
		}
	})

	t.Run("packagist maintainers shape", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.Packagist)+"/packages/vendor/example.json")
		assertKeys(t, "packagist packages", got, "packagist-packages.json")
		pkg, ok := got["package"].(map[string]any)
		if !ok {
			t.Fatalf("package is %T, want an object", got["package"])
		}
		assertMapKeys(t, "packagist package", pkg, recordedJSON(t, "packagist-packages.json")["package"].(map[string]any))
		maints, _ := pkg["maintainers"].([]any)
		if len(maints) != 1 || maints[0].(map[string]any)["name"] != "vendoruser" {
			t.Errorf("maintainers = %v, want [vendoruser]", pkg["maintainers"])
		}
	})

	t.Run("propfind shape", func(t *testing.T) {
		body := propfind(t, c, baseOf(reg, ports.WPOrg)+"/svn/plugins/example-plugin/tags/1.3.0/")
		served := xmlElements(t, []byte(body))
		b, err := os.ReadFile(filepath.Join("testdata", "svn-propfind.xml"))
		if err != nil {
			t.Fatal(err)
		}
		for name := range xmlElements(t, b) {
			if !served[name] {
				t.Errorf("PROPFIND answer has no %s element: %s", name, body)
			}
		}
	})

	t.Run("propfind returns the creator", func(t *testing.T) {
		body := propfind(t, c, baseOf(reg, ports.WPOrg)+"/svn/plugins/example-plugin/tags/1.3.0/")
		if !strings.Contains(body, "newcommitter") {
			t.Errorf("PROPFIND missing creator newcommitter: %s", body)
		}
	})

	t.Run("packagist p2 shape", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.Packagist)+"/p2/vendor/example.json")
		assertKeys(t, "packagist", got, "packagist-p2.json")
		if got["minified"] != "composer/2.0" {
			t.Errorf("not minified composer/2.0: %v", got["minified"])
		}
	})

	t.Run("github zipball redirects to codeload", func(t *testing.T) {
		noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := noFollow.Get(baseOf(reg, ports.GitHub) + "/repos/vendor/example/zipball/dddddddeeeeeeefffffff") //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("want 302, got %d", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		// A second host name, so a client that copies Authorization to
		// the same host on another port does not hide a forwarded token.
		if !strings.Contains(loc, fmt.Sprintf("://%s:%d/", CodeloadHost, reg.Port(ports.Codeload))) {
			t.Errorf("redirect not to codeload on %s: %s", CodeloadHost, loc)
		}
		if strings.Contains(loc, "127.0.0.1") {
			t.Errorf("codeload shares the API host name: %s", loc)
		}
		z := fetch(t, c, loc)
		if !zipNames(t, z, "vendor-example-ddddddd/")["composer.json"] {
			t.Errorf("codeload zip missing composer.json under the top folder")
		}
	})

	t.Run("request log keeps auth presence only", func(t *testing.T) {
		token := FakeGitHubToken()
		for _, u := range []struct {
			url  string
			auth bool
		}{
			{baseOf(reg, ports.GitHub) + "/rate_limit", true},
			{fmt.Sprintf("http://%s:%d/vendor/example/legacy.zip/dddddddeeeeeeefffffff", CodeloadHost, reg.Port(ports.Codeload)), false},
		} {
			req, err := http.NewRequest(http.MethodGet, u.url, nil) //nolint:noctx // test
			if err != nil {
				t.Fatal(err)
			}
			if u.auth {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
		b, err := os.ReadFile(filepath.Join(reg.opts.StateDir, "requests.log"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(token)) {
			t.Fatal("the request log holds the token itself")
		}
		var api, codeload *logLine
		for _, raw := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
			var l logLine
			if err := json.Unmarshal(raw, &l); err != nil {
				t.Fatalf("bad log line %s: %v", raw, err)
			}
			switch {
			case l.Service == "github" && l.Path == "/rate_limit" && l.Auth:
				api = &l
			case l.Service == ServiceCodeload && l.Path == "/vendor/example/legacy.zip/dddddddeeeeeeefffffff":
				codeload = &l
			}
		}
		if api == nil {
			t.Error("the API request with a token was not logged with auth true")
		}
		if codeload == nil {
			t.Fatal("the codeload request was not logged")
		}
		if codeload.Auth {
			t.Error("a codeload request without a token was logged with auth true")
		}
	})

	t.Run("github git ref", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.GitHub)+"/repos/vendor/example/git/ref/tags/v2.0.0")
		assertKeys(t, "github-ref", got, "github-ref.json")
	})

	t.Run("npm packument and version doc", func(t *testing.T) {
		got := getJSON(t, c, baseOf(reg, ports.NPM)+"/example-pkg")
		assertKeys(t, "npm packument", got, "npm-packument.json")
		ver := getJSON(t, c, baseOf(reg, ports.NPM)+"/example-pkg/2.0.0")
		assertKeys(t, "npm version", ver, "npm-version.json")
		dist, _ := ver["dist"].(map[string]any)
		if dist["integrity"] == nil {
			t.Error("version doc has no integrity")
		}
	})

	t.Run("osv querybatch and vuln", func(t *testing.T) {
		body := postJSON(t, c, baseOf(reg, ports.OSV)+"/v1/querybatch", `{"queries":[{"package":{"name":"example-pkg","ecosystem":"npm"},"version":"2.0.0"},{"package":{"name":"example-pkg","ecosystem":"npm"},"version":"1.0.0"}]}`)
		if !strings.Contains(body, "MAL-2026-0001") {
			t.Errorf("querybatch did not report the advisory: %s", body)
		}
		got := getJSON(t, c, baseOf(reg, ports.OSV)+"/v1/vulns/MAL-2026-0001")
		assertKeys(t, "osv vuln", got, "osv-vuln.json")
	})

	t.Run("state toggle switches the served version", func(t *testing.T) {
		if err := WriteState(reg.opts.StateDir, "example-plugin", StateGood); err != nil {
			t.Fatal(err)
		}
		got := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugins/info/1.2/?action=plugin_information&request[slug]=example-plugin")
		if got["version"] != "1.2.0" {
			t.Errorf("good state: want version 1.2.0, got %v", got["version"])
		}
		if err := WriteState(reg.opts.StateDir, "example-plugin", StateBad); err != nil {
			t.Fatal(err)
		}
		got = getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugins/info/1.2/?action=plugin_information&request[slug]=example-plugin")
		if got["version"] != "1.3.0" {
			t.Errorf("bad state: want version 1.3.0, got %v", got["version"])
		}
	})
}

func TestArchivesDeterministic(t *testing.T) {
	dir := fixtureDir(t)
	reg1, c1 := startPlain(t, dir)
	tgz1 := fetch(t, c1, baseOf(reg1, ports.NPM)+"/example-pkg/-/example-pkg-2.0.0.tgz")
	ver1 := getJSON(t, c1, baseOf(reg1, ports.NPM)+"/example-pkg/2.0.0")
	_ = reg1.Close()

	reg2, c2 := startPlain(t, dir)
	tgz2 := fetch(t, c2, baseOf(reg2, ports.NPM)+"/example-pkg/-/example-pkg-2.0.0.tgz")
	ver2 := getJSON(t, c2, baseOf(reg2, ports.NPM)+"/example-pkg/2.0.0")
	_ = reg2.Close()

	if !bytes.Equal(tgz1, tgz2) {
		t.Error("tarball bytes differ across starts")
	}
	sig1 := ver1["dist"].(map[string]any)["signatures"].([]any)[0].(map[string]any)["sig"]
	sig2 := ver2["dist"].(map[string]any)["signatures"].([]any)[0].(map[string]any)["sig"]
	if sig1 == sig2 {
		t.Error("npm signature should differ across starts (a fresh key per run)")
	}
}

func TestTLSWithCA(t *testing.T) {
	dir := fixtureDir(t)
	reg, err := New(Options{PackagesDir: dir, StateDir: t.TempDir(), AnyPort: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Start(); err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(reg.CACertPEM()) {
		t.Fatal("could not add CA")
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d/example-pkg", reg.Port(ports.NPM))) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TLS get: status %d", resp.StatusCode)
	}
}

// helpers below.

func fetch(t *testing.T, c *http.Client, url string) []byte {
	t.Helper()
	resp, err := c.Get(url) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func postJSON(t *testing.T, c *http.Client, url, body string) string {
	t.Helper()
	resp, err := c.Post(url, "application/json", strings.NewReader(body)) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// zipNames reads a zip and returns the set of entry names with top
// stripped.
func zipNames(t *testing.T, b []byte, top string) map[string]bool {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[strings.TrimPrefix(f.Name, top)] = true
	}
	return names
}

func propfind(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	req, err := http.NewRequest("PROPFIND", url, nil) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestWithheldOnlyVersion: a package whose one version is the candidate
// (a dependency a bad scenario adds) offers nothing in the good state.
// The packument and the info API say so instead of failing the request,
// which Sightread would report as a network error.
func TestWithheldOnlyVersion(t *testing.T) {
	dir := t.TempDir()
	writeScenario(t, dir, "added-dep", strings.TrimSpace(`
ecosystem: npm
name: added-dep
versions:
  - version: "1.0.0"
    installed: true
    maintainers: [someone]
  - version: "1.0.0"
    candidate: true
    maintainers: [someone]
`), map[string]string{"index.js": "1\n"}, map[string]string{"index.js": "1\n"})
	writeScenario(t, dir, "added-plugin", strings.TrimSpace(`
ecosystem: wp-plugin
name: added-plugin
versions:
  - version: "1.0.0"
    installed: true
    author: someone
    committer: someone
  - version: "1.0.0"
    candidate: true
    author: someone
    committer: someone
`), map[string]string{"added-plugin.php": "<?php\n"}, map[string]string{"added-plugin.php": "<?php\n"})
	reg, c := startPlain(t, dir)
	for _, id := range []string{"added-dep", "added-plugin"} {
		if err := WriteState(reg.opts.StateDir, id, StateGood); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := c.Get(baseOf(reg, ports.NPM) + "/added-dep") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("withheld packument: HTTP %d, want 404", resp.StatusCode)
	}
	info := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugins/info/1.2/?action=plugin_information&request[slug]=added-plugin")
	if info["error"] != "Plugin not found." {
		t.Errorf("withheld plugin info: %v", info)
	}
	if err := WriteState(reg.opts.StateDir, "added-dep", StateBad); err != nil {
		t.Fatal(err)
	}
	if got := getJSON(t, c, baseOf(reg, ports.NPM)+"/added-dep"); got["dist-tags"].(map[string]any)["latest"] != "1.0.0" {
		t.Errorf("bad state packument: %v", got)
	}
}

// TestTamperedArchiveIsValid: b17's bad state serves a zip that opens
// and lists the same files, one of which no longer matches the
// published checksums; readme.txt is left alone.
func TestTamperedArchiveIsValid(t *testing.T) {
	dir := t.TempDir()
	writeScenario(t, dir, "tampered", strings.TrimSpace(`
ecosystem: wp-plugin
name: tampered
versions:
  - version: "1.0.0"
    installed: true
    author: vendor
  - version: "1.0.1"
    candidate: true
    author: vendor
    tamper: true
`), map[string]string{"tampered.php": "<?php // 1.0.0\n"},
		map[string]string{"tampered.php": "<?php // 1.0.1\n", "readme.txt": "=== Tampered ===\n"})
	reg, c := startPlain(t, dir)
	sums := getJSON(t, c, baseOf(reg, ports.WPOrg)+"/plugin-checksums/tampered/1.0.1.json")["files"].(map[string]any)
	zipBytes := fetch(t, c, baseOf(reg, ports.WPOrg)+"/plugin/tampered.1.0.1.zip")
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("the tampered archive does not open: %v", err)
	}
	var differ []string
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(f.Name, "tampered/")
		want := sums[name].(map[string]any)["sha256"]
		if got := sha256hex(b); got != want {
			differ = append(differ, name)
		}
	}
	if len(differ) != 1 || differ[0] != "tampered.php" {
		t.Errorf("files that differ from the checksums: %q, want [tampered.php]", differ)
	}
	p, _ := reg.find("wp-plugin", "tampered")
	if bytes.Equal(p.versions["1.0.1"].archive, zipBytes) {
		t.Error("the bad state served the honest archive")
	}
}

// TestUnpublishedAndMovedTag: an unpublished npm version stays in the
// time map only; a republished Composer version's reference is the
// lockfile's in the good state and the moved one in the bad state.
func TestUnpublishedAndMovedTag(t *testing.T) {
	dir := t.TempDir()
	writeScenario(t, dir, "gone", strings.TrimSpace(`
ecosystem: npm
name: gone
versions:
  - version: "1.0.0"
    installed: true
  - version: "1.0.1"
    candidate: true
    unpublished: true
`), map[string]string{"index.js": "1\n"}, map[string]string{"index.js": "2\n"})
	writeScenario(t, dir, "moved", strings.TrimSpace(`
ecosystem: composer
name: acme/moved
repository: github.com/acme/moved
versions:
  - version: "1.5.0"
    republish: true
    reference: aaaa111bbbb222cccc333
    republish_reference: dddd444eeee555ffff666
`), map[string]string{"composer.json": `{"name":"acme/moved"}`}, map[string]string{"composer.json": `{"name":"acme/moved","x":1}`})
	reg, c := startPlain(t, dir)

	full := getJSON(t, c, baseOf(reg, ports.NPM)+"/gone")
	if _, ok := full["versions"].(map[string]any)["1.0.1"]; ok {
		t.Error("the unpublished version is listed")
	}
	if _, ok := full["time"].(map[string]any)["1.0.1"]; !ok {
		t.Error("the unpublished version left the time map")
	}
	resp, err := c.Get(baseOf(reg, ports.NPM) + "/gone/1.0.1") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unpublished version document: HTTP %d", resp.StatusCode)
	}

	ref := func() string {
		t.Helper()
		got := getJSON(t, c, baseOf(reg, ports.Packagist)+"/p2/acme/moved.json")
		b, _ := json.Marshal(got)
		switch {
		case strings.Contains(string(b), "dddd444eeee555ffff666"):
			return "moved"
		case strings.Contains(string(b), "aaaa111bbbb222cccc333"):
			return "locked"
		}
		return "none"
	}
	if got := ref(); got != "moved" {
		t.Errorf("bad state reference: %s", got)
	}
	if err := WriteState(reg.opts.StateDir, "moved", StateGood); err != nil {
		t.Fatal(err)
	}
	if got := ref(); got != "locked" {
		t.Errorf("good state reference: %s", got)
	}
}
