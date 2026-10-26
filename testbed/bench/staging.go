// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec" //nolint:depguard // the benchmark drives WP-CLI in the testbed container
	"path/filepath"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/fsnap"
	"github.com/RhythmShahriar/sightread/testbed/scenario"
	"github.com/RhythmShahriar/sightread/testbed/staging"
)

// wpUp reports whether the Docker WordPress answers on 127.0.0.1:18907.
func wpUp(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, staging.URL+"/", nil)
	if err != nil {
		return false
	}
	c := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

// wp runs testbed/bin/wp with the caller's environment (Docker needs
// it) and returns its trimmed output.
func (h *harness) wp(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(h.tb, "bin", "wp"), args...).CombinedOutput() //nolint:gosec // the testbed's own wrapper
	if err != nil {
		return "", fmt.Errorf("bin/wp %s: %s", strings.Join(args, " "), firstLine(out, err))
	}
	return strings.TrimSpace(string(out)), nil
}

// seed puts the container's WordPress back to its seeded state.
func (h *harness) seed(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", filepath.Join(h.tb, "docker-compose.yml"), //nolint:gosec // fixed argv
		"exec", "-T", "-u", "www-data", "wp", "sh", "/seed/seed.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("seed: %s", firstLine(out, err))
	}
	return nil
}

// pluginVersion is a plugin's version in the container, or "absent".
func (h *harness) pluginVersion(ctx context.Context, slug string) string {
	v, err := h.wp(ctx, "plugin", "get", slug, "--field=version")
	if err != nil {
		return "absent"
	}
	return v
}

// staging runs the e15 cases against the Docker WordPress.
func (h *harness) staging(ctx context.Context) []benchdoc.EnvResult {
	cases := staging.Cases()
	out := make([]benchdoc.EnvResult, 0, len(cases))
	notRun := func(c staging.Case, why string) benchdoc.EnvResult {
		return benchdoc.EnvResult{ID: c.Name, Title: caseTitle(c), Result: benchdoc.ResultNotRun, Notes: []string{why}}
	}
	if !wpUp(ctx) {
		for _, c := range cases {
			out = append(out, notRun(c, "the Docker WordPress is not up (make -C testbed up-wp)"))
		}
		return out
	}
	_, scErr := exec.LookPath("rhythm-soundcheck")
	wrapper := filepath.Join(h.tb, "bin", "wp")
	if strings.ContainsAny(wrapper, " \t'\"") {
		wrapper = "'" + wrapper + "'"
	}
	projects := filepath.Join(h.tb, "projects")

	for _, c := range cases {
		if ctx.Err() != nil {
			break
		}
		if c.NeedsSoundcheck && scErr != nil {
			out = append(out, notRun(c, "rhythm-soundcheck is not on PATH"))
			continue
		}
		start := time.Now()
		r := benchdoc.EnvResult{ID: c.Name, Title: caseTitle(c)}
		var problems []string
		if err := h.seed(ctx); err != nil {
			problems = append(problems, err.Error())
		}
		if err := h.setStates(h.packageFor(c.Slug)); err != nil {
			problems = append(problems, err.Error())
		}
		roadieState := filepath.Join(h.state, "roadie")
		_ = os.Remove(roadieState)
		if c.Roadie != "" {
			if err := os.WriteFile(roadieState, []byte(c.Roadie+"\n"), 0o644); err != nil { //nolint:gosec // test state
				problems = append(problems, err.Error())
			}
		}

		before := h.pluginVersion(ctx, c.Slug)
		hostBefore, _ := fsnap.Take(projects)
		ex := h.run(ctx, c.Args(wrapper), runOpts{id: "e15-" + c.Name, noStub: c.Roadie == ""})
		after := h.pluginVersion(ctx, c.Slug)
		hostAfter, _ := fsnap.Take(projects)
		var changed []string
		for _, d := range fsnap.Diff(hostBefore, hostAfter) {
			changed = append(changed, d.String())
		}
		res := staging.Result{Exit: ex.exit, Output: ex.output(), Before: before, After: after, HostChanged: changed, Elapsed: ex.elapsed}
		problems = append(problems, staging.Judge(c, res)...)
		if ex.err != nil {
			problems = append(problems, "could not start: "+ex.err.Error())
		}

		r.Seconds = time.Since(start).Seconds()
		r.Result = benchdoc.ResultPass
		r.Notes = []string{fmt.Sprintf("exit %d, %s %s to %s", ex.exit, c.Slug, before, after)}
		if len(problems) > 0 {
			r.Result = benchdoc.ResultFail
			r.Notes = append(r.Notes, problems...)
		}
		out = append(out, r)
	}
	_ = os.Remove(filepath.Join(h.state, "roadie"))
	_ = h.seed(ctx)
	return out
}

// packageFor finds the scenario folder that publishes a plugin slug.
func (h *harness) packageFor(slug string) []string {
	for _, id := range h.reg.IDs() {
		if m, ok := h.reg.Meta(id); ok && m.Name == slug {
			return []string{id}
		}
	}
	return nil
}

// caseTitle describes an e15 case for the page.
func caseTitle(c staging.Case) string {
	switch {
	case c.Applies:
		return "update lands in the container only"
	case c.Roadie == "":
		return "refused: rhythm-roadie missing"
	case c.WP != "":
		return "refused: remote --wp prefix"
	default:
		return "refused: " + c.Name
	}
}

// summarizeStaging folds the e15 cases into the e15 row of the
// environment table.
func summarizeStaging(s scenario.Scenario, cases []benchdoc.EnvResult) benchdoc.EnvResult {
	r := benchdoc.EnvResult{ID: s.ID, Title: s.Title, Result: benchdoc.ResultPass}
	var pass, fail, notRun int
	for _, c := range cases {
		r.Seconds += c.Seconds
		switch c.Result {
		case benchdoc.ResultPass:
			pass++
		case benchdoc.ResultFail:
			fail++
			r.Notes = append(r.Notes, c.ID+" failed")
		default:
			notRun++
		}
	}
	switch {
	case fail > 0:
		r.Result = benchdoc.ResultFail
	case pass == 0:
		r.Result = benchdoc.ResultNotRun
	}
	r.Notes = append([]string{fmt.Sprintf("%d of %d cases passed, %d not run (see the e15 table)", pass, len(cases), notRun)}, r.Notes...)
	return r
}
