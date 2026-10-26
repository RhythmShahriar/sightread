// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package testbed_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// The T-51 dynamic check: the HTML report of a package whose text is
// all script, handlers and links, opened from a file in headless Chrome,
// runs no script but its own hashed one and requests nothing. The static
// half (escaping, the CSP) is report's TestHTMLHostileText.

// sinkAddr is where every hostile payload points. It is in this lane's
// loopback port range; nothing else listens there.
const sinkAddr = "127.0.0.1:31121"

// marker is the attribute a payload sets on <html> when it runs. Text
// that merely shows the payload can't produce it: the browser
// serializes a real attribute as data-sr-ran="...", text as escaped
// characters.
const marker = `data-sr-ran="`

// payloads returns hostile package text that, if the page let it run,
// sets marker or fetches from the sink. n numbers the payload so a hit
// says which one got through.
func payloads() []string {
	sink := "http://" + sinkAddr
	ran := func(n int) string { return fmt.Sprintf("document.documentElement.setAttribute('data-sr-ran','%d')", n) }
	return []string{
		`<script>` + ran(1) + `</script>`,
		`</textarea><img src=x onerror="` + ran(2) + `">`,
		`<svg onload="` + ran(3) + `"></svg>`,
		`</pre><script src="` + sink + `/script.js"></script>`,
		`<img src="` + sink + `/img.png">`,
		`<iframe src="` + sink + `/frame"></iframe>`,
		`<link rel="stylesheet" href="` + sink + `/style.css">`,
		`<style>@import url(` + sink + `/import.css);</style>`,
		`<meta http-equiv="refresh" content="0;url=` + sink + `/refresh">`,
		`<a href="javascript:` + ran(4) + `">x</a>`,
		`<body onload="` + ran(5) + `">`,
	}
}

// hostileReport is the sample report with every piece of package text a
// writer shows replaced by the payloads.
func hostileReport() *core.Report {
	p := payloads()
	all := strings.Join(p, " ")
	r := coretest.SampleReport()
	for i := range r.Updates {
		u := &r.Updates[i]
		u.Name = p[i%len(p)]
		u.To.URL = "javascript:" + p[0]
		u.To.Publisher = []string{p[1], p[2]}
		u.Changelog = []core.ChangelogEntry{{Version: u.To.Version, Text: all}}
		for j := range u.Findings {
			f := &u.Findings[j]
			f.File = "lib/" + p[(i+j)%len(p)] + ".js"
			f.Evidence = core.NewSnippet(all)
			f.Advice = p[(i+j+1)%len(p)]
		}
		for j := range u.Hunks {
			u.Hunks[j].Path = p[j%len(p)]
			for _, s := range p {
				u.Hunks[j].Lines = append(u.Hunks[j].Lines, "+"+s)
			}
		}
	}
	r.NotChecked = append(r.NotChecked, core.NotChecked{Name: p[2], Text: all})
	r.Warnings = append(r.Warnings, all)
	r.Notes = append(r.Notes, all)
	return r
}

// findChrome returns a Chrome or Chromium to run headless: $SIGHTREAD_CHROME,
// one on PATH, the usual install folders, or the Chromium rod downloads
// for rhythm-soundcheck. Empty means none.
func findChrome() string {
	if p := os.Getenv("SIGHTREAD_CHROME"); p != "" {
		return p
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	var candidates []string
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium"}
		if m, _ := filepath.Glob(filepath.Join(home, ".cache", "rod", "browser", "chromium-*", "Chromium.app", "Contents", "MacOS", "Chromium")); len(m) > 0 {
			candidates = append(candidates, m...)
		}
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if d := os.Getenv(env); d != "" {
				candidates = append(candidates, filepath.Join(d, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
		if m, _ := filepath.Glob(filepath.Join(os.Getenv("APPDATA"), "rod", "browser", "chromium-*", "chrome.exe")); len(m) > 0 {
			candidates = append(candidates, m...)
		}
	default:
		if m, _ := filepath.Glob(filepath.Join(home, ".cache", "rod", "browser", "chromium-*", "chrome")); len(m) > 0 {
			candidates = append(candidates, m...)
		}
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

// sink counts every request that reaches sinkAddr.
type sink struct {
	mu   sync.Mutex
	hits []string
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits = append(s.hits, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("/* sink */"))
}

func (s *sink) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hits
	s.hits = nil
	return h
}

func startSink(t *testing.T) *sink {
	t.Helper()
	ln, err := net.Listen("tcp", sinkAddr)
	if err != nil {
		t.Fatalf("listen on %s for the payload sink: %v", sinkAddr, err)
	}
	s := &sink{}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

// fileURL is path as a file URL on every OS.
func fileURL(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/... on Windows
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// dumpDOM opens page in headless Chrome, lets it run for a few seconds
// of virtual time and returns the DOM as the page left it.
func dumpDOM(t *testing.T, chrome, page string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{
		"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--disable-extensions", "--disable-background-networking", "--disable-component-update",
		"--disable-sync", "--user-data-dir=" + t.TempDir(),
		"--virtual-time-budget=3000", "--dump-dom", fileURL(page),
	}
	if os.Geteuid() == 0 {
		args = append([]string{"--no-sandbox"}, args...) // Chrome refuses its sandbox as root
	}
	cmd := exec.CommandContext(ctx, chrome, args...) //nolint:gosec // G204: the browser this test found, on a page it wrote
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", chrome, err, stderr.String())
	}
	return string(out)
}

// TestHTMLReportHeadless is T-51's dynamic part. A control page with the
// same payloads unescaped and no CSP must trip both detectors first, so
// a quiet result means the report is quiet, not that the check is blind.
func TestHTMLReportHeadless(t *testing.T) {
	if testing.Short() {
		t.Skip("starts Chrome")
	}
	coretest.NeedWriter(t, core.FormatHTML)
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome or Chromium found (set SIGHTREAD_CHROME); the headless HTML check is not run")
	}
	s := startSink(t)
	dir := t.TempDir()

	t.Run("control", func(t *testing.T) {
		page := filepath.Join(dir, "control.html")
		// Without the refresh, which would navigate the control away
		// before its DOM is read; in the report it would show as a hit
		// and a missing page.
		var live []string
		for _, p := range payloads() {
			if !strings.Contains(p, "http-equiv") {
				live = append(live, p)
			}
		}
		body := "<!doctype html><html><head><meta charset=utf-8></head><body>" + strings.Join(live, "\n") + "</body></html>"
		if err := os.WriteFile(page, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		dom := dumpDOM(t, chrome, page)
		if !strings.Contains(dom, marker) {
			t.Errorf("the control page's scripts left no %s; the check can't see script execution", marker)
		}
		if hits := s.take(); len(hits) == 0 {
			t.Error("the control page reached no sink; the check can't see network requests")
		}
	})

	t.Run("report", func(t *testing.T) {
		page := filepath.Join(dir, "review.html")
		f, err := os.Create(page)
		if err != nil {
			t.Fatal(err)
		}
		if err := core.WriterFor(core.FormatHTML).Write(f, hostileReport(), core.WriteOptions{Version: "test", Program: "rhythm-sightread"}); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		s.take()
		dom := dumpDOM(t, chrome, page)
		if !strings.Contains(dom, "&lt;script&gt;") {
			t.Fatalf("the report didn't render the payloads as text:\n%.2000s", dom)
		}
		if i := strings.Index(dom, marker); i >= 0 {
			t.Errorf("a payload ran: %s", dom[i:min(len(dom), i+40)])
		}
		if hits := s.take(); len(hits) > 0 {
			t.Errorf("the report made %d requests: %q", len(hits), hits)
		}
	})
}
