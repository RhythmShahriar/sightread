// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/fetch"
)

// lanePorts are the 127.0.0.1 ports this package's fixture servers use.
// The cli lane's ports 31100-31119 are split between its test packages,
// because go test ./... runs packages at the same time and two of them
// must never race for one port: cmd 31100-31107, demo 31108-31111,
// notify 31112-31115 and watch 31116-31119.
const lanePortFirst, lanePortLast = 31100, 31107

// laneListener listens on the first free lane port.
func laneListener(t *testing.T) net.Listener {
	t.Helper()
	for p := lanePortFirst; p <= lanePortLast; p++ {
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			t.Cleanup(func() { _ = ln.Close() })
			return ln
		}
	}
	t.Fatal("no free port in 31100-31107")
	return nil
}

// freeLanePort is a lane port nothing listens on.
func freeLanePort(t *testing.T) int {
	t.Helper()
	ln := laneListener(t)
	port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // a TCP listener
	_ = ln.Close()
	return port
}

// chdir moves into dir and returns what moves back. The golden files
// are found from the package folder, so a test moves back before
// comparing.
func chdir(t *testing.T, dir string) (back func()) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	done := false
	back = func() {
		if !done {
			done = true
			_ = os.Chdir(wd)
		}
	}
	t.Cleanup(back)
	return back
}

func TestInitConfig(t *testing.T) {
	w := world(t)
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	w.Install(core.Composer, "monolog/monolog", "3.0.0")
	dir := t.TempDir()
	back := chdir(t, dir)
	code, out, errOut := execute(t, "init")
	if code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	if !strings.HasPrefix(out, "Wrote .sightread/config.yaml: reviews wp-plugin and composer, fails on high or worse.\n") {
		t.Errorf("stdout %q", out)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".sightread", "config.yaml")) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut = execute(t, "init")
	if code != cli.ExitUsage || errOut != "rhythm-sightread init: .sightread/config.yaml exists (use --force to replace it)\n" {
		t.Errorf("overwrite: exit %d %q", code, errOut)
	}
	if code, _, _ := execute(t, "init", "--force"); code != cli.ExitOK {
		t.Errorf("--force: exit %d", code)
	}
	// Nothing found: every ecosystem.
	w.Inventory.Site.Installed = nil
	if got := configYAML(detectEcosystems(context.Background(), dir)); !strings.Contains(got, "ecosystems: [wp-plugin, wp-theme, composer, npm]\n") {
		t.Errorf("empty folder config:\n%s", got)
	}
	back()
	coretest.Golden(t, "init/config.yaml", b)
}

func TestInitCI(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "web")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	back := chdir(t, sub)
	code, out, errOut := execute(t, "init", "ci")
	if code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	path := filepath.Join(root, ".github", "workflows", "sightread.yml")
	b, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	code2, _, errOut2 := execute(t, "init", "ci")
	back()
	coretest.Golden(t, "init/sightread-dev.yml", b)
	coretest.Golden(t, "init/ci-output.txt", []byte(out))
	code, errOut = code2, errOut2
	if code != cli.ExitUsage || errOut != "rhythm-sightread init: ../.github/workflows/sightread.yml exists (use --force to replace it)\n" {
		t.Errorf("overwrite: exit %d %q", code, errOut)
	}
	if code, _, errOut := execute(t, "init", "ci", "--fail-on", "severe"); code != cli.ExitUsage ||
		errOut != "rhythm-sightread: --fail-on \"severe\": want none, info, low, medium, high or critical\n" {
		t.Errorf("bad --fail-on: exit %d %q", code, errOut)
	}
	// A release build pins the Action to its commit; this is PRD 16's file.
	release := ciWorkflow(ciOptions{failOn: "high", comment: true}, "0123456789abcdef0123456789abcdef01234567", "1.0.0")
	coretest.Golden(t, "init/sightread-release.yml", []byte(release))
	sarif := ciWorkflow(ciOptions{failOn: "critical", sarif: true}, "", "dev")
	if !strings.Contains(sarif, "  security-events: write\n") || !strings.Contains(sarif, "          sarif: true\n") ||
		strings.Contains(sarif, "pull-requests") || strings.Contains(sarif, "comment:") {
		t.Errorf("--sarif --comment=false:\n%s", sarif)
	}
}

// loopGetter is a core.Getter over plain HTTP to 127.0.0.1 fixtures:
// the part of fetch doctor needs, with E7 for a host that doesn't
// answer.
type loopGetter struct{ c *http.Client }

func (g loopGetter) do(ctx context.Context, method, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.c.Do(req)
	if err != nil {
		return nil, &core.Error{Code: core.ENetwork, Exit: cli.ExitUnavailable, What: "can't reach " + req.URL.Host + " (connection refused)"}
	}
	if resp.StatusCode >= 400 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func (g loopGetter) JSON(ctx context.Context, url string, v any, kind string) error {
	// The real getter refuses a kind it has no cache for; so does this.
	if _, ok := fetch.TTL(kind); !ok {
		return fmt.Errorf("fetch: unknown cache kind %q", kind)
	}
	resp, err := g.do(ctx, http.MethodGet, url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return json.NewDecoder(resp.Body).Decode(v)
}

func (g loopGetter) Download(context.Context, string, int64, core.BlobStore) (core.Download, error) {
	return core.Download{}, errors.New("loopGetter: no downloads")
}

func (g loopGetter) Text(ctx context.Context, method, url string, _ io.Reader, limit int64) ([]byte, http.Header, error) {
	resp, err := g.do(ctx, method, url)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return b, resp.Header, err
}

// keySource is an npm source that can check its keys.
type keySource struct {
	core.Source
	err error
}

func (k keySource) CheckKeys(context.Context) (string, error) {
	return "2 registry keys, both in the pinned set", k.err
}

// doctorWorld starts a fixture server answering every source and points
// the SIGHTREAD_* variables at it; down names bases that point at a
// port nothing listens on.
func doctorWorld(t *testing.T, down ...string) {
	t.Helper()
	ln := laneListener(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/rate_limit") {
			_, _ = io.WriteString(w, `{"resources":{"core":{"limit":5000,"remaining":4987}}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	base := "http://" + ln.Addr().String()
	dead := fmt.Sprintf("http://127.0.0.1:%d", freeLanePort(t))
	for _, m := range mirrorEnv {
		u := base + "/" + m.base
		for _, d := range down {
			if d == m.base {
				u = dead + "/" + m.base
			}
		}
		t.Setenv(m.env, u)
	}
	client := &http.Client{Transport: coretest.LoopbackOnly(t), Timeout: 5 * time.Second}
	t.Cleanup(core.SwapGetter(func(core.GetterConfig) (core.Getter, error) { return loopGetter{client}, nil }))
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("RHYTHM_GITHUB_TOKEN", "")
	t.Setenv(cli.OfflineEnv, "")
	old := lookPath
	lookPath = func(name string) (string, error) {
		if name == "git" {
			return "/usr/bin/git", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { lookPath = old })
}

func TestDoctorAllOK(t *testing.T) {
	w := world(t)
	doctorWorld(t)
	t.Cleanup(core.SwapSource(core.NPM, func(*core.Env) core.Source { return keySource{Source: w.Sources[core.NPM]} }))
	t.Setenv("GITHUB_TOKEN", coretest.FakeKey(coretest.KeyGitHub))
	code, out, _ := execute(t, "doctor", "--plain")
	if code != cli.ExitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"ok    Config: none here, so every default applies\n",
		"/wporg_api: answers\n", "/osv: answers\n",
		"ok    npm keys: 2 registry keys, both in the pinned set\n",
		"ok    GitHub token: set (sent only to api.github.com); 4987 of 5000 requests left this hour\n",
		"ok    git: /usr/bin/git\n",
		"checks passed, 0 failed.\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, coretest.FakeKey(coretest.KeyGitHub)) {
		t.Errorf("the token reached the output")
	}
}

func TestDoctorOneDown(t *testing.T) {
	w := world(t)
	doctorWorld(t, core.BaseOSV)
	w.Policy.Config = &core.Config{Soundcheck: core.SoundcheckConfig{Staging: "https://staging.shop.test"}}
	code, out, _ := execute(t, "doctor", "--plain")
	if code != cli.ExitFindings {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"/osv: can't reach 127.0.0.1:",
		"warn  npm keys: this build can't check the registry's signing keys\n",
		"warn  GitHub token: not set, so 4987 of 5000 requests left this hour; set GITHUB_TOKEN for Composer packages and tag checks\n",
		"FAIL  Soundcheck: the config has a soundcheck section but rhythm-roadie and rhythm-soundcheck aren't installed: rhythm install roadie soundcheck\n",
		" 2 failed.\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

// TestDoctorOfflineJSON: --offline skips the network and --json writes
// the kind doctor document with every check.
func TestDoctorOfflineJSON(t *testing.T) {
	world(t)
	doctorWorld(t)
	installDocs(t)
	t.Cleanup(core.SwapGetter(func(core.GetterConfig) (core.Getter, error) {
		t.Error("doctor --offline built a Getter")
		return nil, errors.New("offline")
	}))
	code, out, _ := execute(t, "doctor", "--offline", "--json")
	var env struct {
		Schema, Kind, Verdict string
		Data                  struct {
			Checks []struct{ Name, Status, Detail string } `json:"checks"`
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || code != cli.ExitOK {
		t.Fatalf("exit %d (%v) %s", code, err, out)
	}
	if env.Schema != core.Schema || env.Kind != core.KindDoctor || env.Verdict != core.VerdictOK {
		t.Errorf("envelope %+v", env)
	}
	statuses := map[string]string{}
	for _, c := range env.Data.Checks {
		statuses[c.Name] = c.Status
		if c.Name == "" || c.Detail == "" {
			t.Errorf("check %+v lacks a name or detail", c)
		}
		switch c.Status {
		case core.DoctorOK, core.DoctorWarn, core.DoctorFail, core.DoctorSkipped:
		default:
			t.Errorf("check %+v has a status outside the schema", c)
		}
	}
	if statuses["Sources"] != core.DoctorSkipped || statuses["Cache"] != core.DoctorOK || statuses["GitHub token"] != core.DoctorWarn {
		t.Errorf("statuses %v", statuses)
	}
}
