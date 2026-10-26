// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package gitref

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
)

func init() { core.SetGitShow(Show) }

// Timeout bounds each git call. Reading one blob takes milliseconds; a
// huge repository on a slow disk still finishes well inside it.
const Timeout = 60 * time.Second

// MaxBlob caps what git show may print: the inventory's lockfile cap.
const MaxBlob = 64 << 20

// ErrNotAtRef is returned by Show when the path does not exist at the
// ref (a lockfile the change adds). It wraps fs.ErrNotExist.
var ErrNotAtRef = fmt.Errorf("not at the ref: %w", fs.ErrNotExist)

// ErrNoGit is returned when no git binary is on PATH.
var ErrNoGit = errors.New("git was not found on PATH")

// refPattern is what a ref may look like: branch and tag names, remote
// refs, hashes and the ^ ~ @ suffixes. No spaces, colons or braces, so
// "<ref>:<path>" can't be bent into another object name.
var refPattern = regexp.MustCompile(`^[A-Za-z0-9._/@^~-]{1,200}$`)

// ValidRef reports why ref can't be given to git, or nil. A ref that
// starts with "-" would be read as an option and is refused.
func ValidRef(ref string) error {
	switch {
	case ref == "":
		return errors.New("the ref is empty")
	case strings.HasPrefix(ref, "-"):
		return fmt.Errorf("%q starts with -, so git would read it as an option", clip(ref))
	case !refPattern.MatchString(ref):
		return fmt.Errorf("%q is not a git ref (letters, digits and . _ / @ ^ ~ - only, at most 200)", clip(ref))
	case strings.Contains(ref, ".."):
		return fmt.Errorf("%q names a range, not one commit", clip(ref))
	}
	return nil
}

// ValidPath reports why path can't be read at a ref, or nil. It must be
// local to the repository folder: relative, without .. and without
// control characters.
func ValidPath(path string) error {
	p := filepath.ToSlash(path)
	switch {
	case p == "" || len(p) > 1024:
		return fmt.Errorf("%q is not a file path", clip(path))
	case strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fmt.Errorf("%q has a control character", clip(path))
	case !filepath.IsLocal(filepath.FromSlash(p)) || strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q is not inside the repository folder", clip(path))
	}
	return nil
}

// Show returns path at ref in repo, as `git show <ref>:./<path>` prints
// it. path is relative to repo, which may be a folder inside the work
// tree. It implements core.GitShow.
func Show(ctx context.Context, repo, ref, path string) ([]byte, error) {
	if err := ValidRef(ref); err != nil {
		return nil, err
	}
	if err := ValidPath(path); err != nil {
		return nil, err
	}
	obj := ref + ":./" + filepath.ToSlash(filepath.Clean(path))
	res, err := run(ctx, repo, "show", "--no-textconv", obj)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		msg := string(res.Stderr)
		if strings.Contains(msg, "does not exist in") || strings.Contains(msg, "exists on disk, but not in") { // style:ignore git's own message
			return nil, fmt.Errorf("%s at %s: %w", filepath.ToSlash(path), ref, ErrNotAtRef)
		}
		return nil, gitFailed("show "+obj, res)
	}
	return res.Stdout, nil
}

// Commit checks that ref names a commit in repo and returns its hash.
func Commit(ctx context.Context, repo, ref string) (string, error) {
	if err := ValidRef(ref); err != nil {
		return "", err
	}
	res, err := run(ctx, repo, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		if notRepo(res) {
			return "", ErrNotRepo
		}
		return "", fmt.Errorf("%w: %s", ErrUnknownRef, clip(ref))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// ErrUnknownRef is Commit's error for a ref the repository doesn't have.
var ErrUnknownRef = errors.New("no such commit")

// ErrNotRepo is returned when repo is not inside a git work tree.
var ErrNotRepo = errors.New("not in a git repository")

// ResolveBase is the ref a change is compared against: origin/<ref>
// when GITHUB_BASE_REF is set (a pull request on GitHub Actions), else
// the merge base of HEAD and origin/HEAD. env reads the environment
// (os.Getenv when nil).
func ResolveBase(ctx context.Context, repo string, env func(string) string) (string, error) {
	if env == nil {
		env = os.Getenv
	}
	if ref := env("GITHUB_BASE_REF"); ref != "" {
		base := "origin/" + ref
		if err := ValidRef(base); err != nil {
			return "", fmt.Errorf("GITHUB_BASE_REF: %w", err)
		}
		return base, nil
	}
	res, err := run(ctx, repo, "merge-base", "HEAD", "origin/HEAD")
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		if notRepo(res) {
			return "", ErrNotRepo
		}
		return "", fmt.Errorf("%w: git merge-base HEAD origin/HEAD found none", ErrNoBase)
	}
	base := strings.TrimSpace(string(res.Stdout))
	if err := ValidRef(base); err != nil {
		return "", fmt.Errorf("git merge-base printed %w", err)
	}
	return base, nil
}

// ErrNoBase is ResolveBase's error when HEAD and origin/HEAD share no
// commit or origin/HEAD is not set.
var ErrNoBase = errors.New("no base to compare with")

// run starts git in repo with args after the fixed safety options. The
// environment drops every GIT_* variable the caller had (GIT_DIR from a
// hook would point git at another repository) and turns off prompts,
// the system config and optional locks; -c turns off fsmonitor and
// hooks, the two config keys that make git run another program on a
// read.
func run(ctx context.Context, repo string, args ...string) (proc.Result, error) {
	git, err := proc.LookPath("git")
	if err != nil {
		return proc.Result{}, ErrNoGit
	}
	res, err := proc.Run(ctx, proc.Spec{
		Argv:      Argv(git, repo, args...),
		Env:       Env(os.Environ()),
		MaxOutput: MaxBlob,
		Timeout:   Timeout,
		Purpose:   proc.PurposeGit,
	})
	switch {
	case err != nil && ctx.Err() != nil:
		return res, ctx.Err()
	case err != nil && errors.Is(err, proc.ErrOutputTooLarge):
		return res, fmt.Errorf("git %s printed over %d MiB", args[0], MaxBlob>>20)
	case err != nil && errors.Is(err, context.DeadlineExceeded):
		return res, fmt.Errorf("git %s did not finish within %s", args[0], Timeout)
	case err != nil:
		return res, fmt.Errorf("git %s could not run: %s", args[0], clip(err.Error()))
	}
	return res, nil
}

// Argv is the command line of one git call: -C repo, then the -c
// options that keep git from starting fsmonitor or hooks, then args.
func Argv(git, repo string, args ...string) []string {
	argv := []string{git, "-C", repo, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull}
	return append(argv, args...)
}

// Env is environ without GIT_* variables and with the settings every
// git call gets. LC_ALL=C keeps the messages Show matches in English.
func Env(environ []string) []string {
	out := make([]string, 0, len(environ)+4)
	for _, kv := range environ {
		if strings.HasPrefix(kv, "GIT_") || strings.HasPrefix(kv, "LC_ALL=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
}

// notRepo reports whether git said the folder is not in a repository.
func notRepo(res proc.Result) bool {
	return bytes.Contains(res.Stderr, []byte("not a git repository"))
}

// gitFailed is the error for a git call that exited non-zero.
func gitFailed(what string, res proc.Result) error {
	if notRepo(res) {
		return ErrNotRepo
	}
	msg := fmt.Sprintf("git %s failed (exit %d)", what, res.Code)
	if line := firstLine(res.Stderr); line != "" {
		msg += ": " + line
	}
	return errors.New(msg)
}

// firstLine is the first non-empty line of b, clipped.
func firstLine(b []byte) string {
	for line := range strings.SplitSeq(string(b), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return clip(s)
		}
	}
	return ""
}

// clip masks secrets, drops control characters and cuts s to 200 bytes
// for a message.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 {
			return -1
		}
		return r
	}, secrets.Redact(s))
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "") + "..."
	}
	return s
}
