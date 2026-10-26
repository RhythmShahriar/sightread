// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

func init() {
	core.SetTagChecker(func(env *core.Env) core.TagChecker { return New(env) })
}

// ErrNotGitHub is a repository URL that is not on github.com: the tag
// check does not apply and run reports it as not checked.
var ErrNotGitHub = errors.New("not a GitHub repository")

// Checker looks a version's tag up on GitHub: v<version>, <version> and
// the monorepo form <name>@<version>. Its requests count against the
// same api.github.com budget as Composer zipballs. It implements
// core.TagChecker.
type Checker struct {
	env  *core.Env
	base string
}

// New returns the tag checker for env.
func New(env *core.Env) *Checker {
	b := env.Bases[core.BaseGitHubAPI]
	if b == "" {
		b = fetch.DefaultBases()[core.BaseGitHubAPI]
	}
	return &Checker{env: env, base: strings.TrimRight(b, "/")}
}

// Repo returns the owner and repository of a GitHub repository URL in
// any form package.json and composer.json use: https://github.com/o/r,
// git+https://github.com/o/r.git, git://, git+ssh://git@github.com/o/r,
// git@github.com:o/r.git and the github:o/r shorthand.
func Repo(raw string) (owner, repo string, err error) {
	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(s, "github:"):
		s = strings.TrimPrefix(s, "github:")
	case strings.HasPrefix(s, "git@github.com:"):
		s = strings.TrimPrefix(s, "git@github.com:")
	default:
		s = strings.TrimPrefix(s, "git+")
		u, perr := url.Parse(s)
		if perr != nil || !strings.EqualFold(u.Hostname(), "github.com") && !strings.EqualFold(u.Hostname(), "www.github.com") {
			return "", "", ErrNotGitHub
		}
		switch u.Scheme {
		case "https", "http", "git", "ssh":
		default:
			return "", "", ErrNotGitHub
		}
		s = strings.TrimPrefix(u.Path, "/")
	}
	s, _, _ = strings.Cut(s, "#")
	parts := strings.Split(strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git"), "/")
	if len(parts) < 2 || !validPart(parts[0]) || !validPart(parts[1]) {
		return "", "", ErrNotGitHub
	}
	return parts[0], parts[1], nil
}

// validPart reports whether s can be a GitHub owner or repository name.
func validPart(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 100 {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.'
	}) < 0
}

// TagExists reports whether repoURL has a tag for version under any of
// its three usual names. A 404 for all is false; any other failure is
// an error, which run reports as not checked. A repository that is not
// on GitHub is ErrNotGitHub.
func (c *Checker) TagExists(ctx context.Context, repoURL, version, name string) (bool, error) {
	owner, repo, err := Repo(repoURL)
	if err != nil {
		return false, err
	}
	if version == "" {
		return false, errors.New("no version to look for")
	}
	tags := []string{"v" + version, version}
	if name != "" {
		tags = append(tags, name+"@"+version)
	}
	for _, tag := range tags {
		ok, err := c.ref(ctx, owner, repo, tag)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// ref asks for one tag. GitHub answers a missing ref with 404; the ref
// in the answer must be the one asked for.
func (c *Checker) ref(ctx context.Context, owner, repo, tag string) (bool, error) {
	segs := strings.Split(tag, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	u := c.base + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/git/ref/tags/" + strings.Join(segs, "/")
	var raw json.RawMessage
	err := c.env.Get.JSON(ctx, u, &raw, fetch.KindMeta)
	if fetch.StatusOf(err) == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var got struct {
		Ref string `json:"ref"`
	}
	// An array is GitHub's answer for refs that only start with tag.
	if json.Unmarshal(raw, &got) != nil {
		return false, nil
	}
	return got.Ref == "refs/tags/"+tag, nil
}

// Checker is a core.TagChecker.
var _ core.TagChecker = (*Checker)(nil)
