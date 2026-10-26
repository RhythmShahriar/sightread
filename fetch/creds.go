// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// githubAPI is the one host a GitHub token is sent to.
const githubAPI = "api.github.com:443"

// credentials maps a host:port to the Authorization value it gets. Each
// hop is matched on its own, so a redirect to another host never carries
// the previous host's credential (SR-5).
type credentials struct {
	byAddr map[string]string
	hint   map[string]string // E10 hint per host:port
}

// authHint is the E10 hint of a host that has no known credential.
const authHint = "if the package is private, set its credential (COMPOSER_AUTH, SIGHTREAD_NPM_TOKEN_<SCOPE> or GITHUB_TOKEN); each goes only to its own host"

// composerAuth is the part of COMPOSER_AUTH Sightread reads.
type composerAuth struct {
	HTTPBasic map[string]struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"http-basic"`
	Bearer      map[string]string `json:"bearer"`
	GitHubOAuth map[string]string `json:"github-oauth"`
}

// newCredentials reads the credentials of cfg. githubAddrs are the
// addresses that stand for api.github.com: itself and a loopback
// github_api mirror (the testbed). A token never goes to a remote
// mirror the user named, because a mirror is not GitHub.
func newCredentials(cfg core.GetterConfig, a *allowlist) (*credentials, bool, error) {
	c := &credentials{byAddr: map[string]string{}, hint: map[string]string{}}
	githubAddrs := []string{githubAPI}
	if u, err := url.Parse(cfg.Bases[core.BaseGitHubAPI]); err == nil && u.Host != "" && a.loop[canonical(u)] {
		githubAddrs = append(githubAddrs, canonical(u))
	}
	hasGitHub := false
	setGitHub := func(token string) {
		for _, addr := range githubAddrs {
			c.byAddr[addr] = "Bearer " + token
		}
		hasGitHub = true
	}
	for _, addr := range githubAddrs {
		c.hint[addr] = "set GITHUB_TOKEN; it goes only to api.github.com"
	}

	if s := strings.TrimSpace(cfg.ComposerAuth); s != "" {
		var ca composerAuth
		if err := json.Unmarshal([]byte(s), &ca); err != nil {
			return nil, false, configError("COMPOSER_AUTH is not valid JSON", "give it in the form Composer reads, e.g. {\"http-basic\": {\"repo.example.com\": {\"username\": \"u\", \"password\": \"p\"}}}")
		}
		for host, up := range ca.HTTPBasic {
			addr := hostAddr(host)
			c.byAddr[addr] = "Basic " + base64.StdEncoding.EncodeToString([]byte(up.Username+":"+up.Password))
			c.hint[addr] = composerHint(host)
		}
		for host, tok := range ca.Bearer {
			addr := hostAddr(host)
			c.byAddr[addr] = "Bearer " + tok
			c.hint[addr] = composerHint(host)
		}
		if tok := ca.GitHubOAuth["github.com"]; tok != "" && cfg.GitHubToken == "" {
			setGitHub(tok)
		}
	}
	if cfg.GitHubToken != "" {
		setGitHub(cfg.GitHubToken)
	}
	for scope, tok := range cfg.ScopeTokens {
		u, err := url.Parse(cfg.Bases[core.BaseNPMScope+scope])
		if err != nil || u.Host == "" || tok == "" {
			continue
		}
		addr := canonical(u)
		c.byAddr[addr] = "Bearer " + tok
		c.hint[addr] = "set " + ScopeTokenEnv(scope) + "; it goes only to " + u.Hostname()
	}
	// Private registries without a token yet still get the hint for the
	// variable that would fix them.
	for key, raw := range cfg.Bases {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		addr := canonical(u)
		if _, ok := c.hint[addr]; ok {
			continue
		}
		switch {
		case strings.HasPrefix(key, core.BaseNPMScope):
			c.hint[addr] = "set " + ScopeTokenEnv(strings.TrimPrefix(key, core.BaseNPMScope)) + "; it goes only to " + u.Hostname()
		case strings.HasPrefix(key, core.BaseComposerRepo):
			c.hint[addr] = composerHint(u.Hostname())
		}
	}
	return c, hasGitHub, nil
}

// composerHint is the E10 hint of PRD section 10.
func composerHint(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return "set COMPOSER_AUTH (as Composer reads it); credentials go only to " + host
}

// header is the Authorization value for addr, or "".
func (c *credentials) header(addr string) string { return c.byAddr[addr] }

// authHint is the E10 hint for addr.
func (c *credentials) authHint(addr string) string {
	if h, ok := c.hint[addr]; ok {
		return h
	}
	return authHint
}
