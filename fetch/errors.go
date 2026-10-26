// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// Refusals. Each comes wrapped with the host that was refused, inside a
// *core.Error E7.
var (
	// ErrOffAllowlist is a request or redirect hop to a host that is
	// neither an official registry nor a configured mirror.
	ErrOffAllowlist = errors.New("not an allowed registry host")
	// ErrInsecureScheme is a request or redirect hop that is not https,
	// other than to a configured loopback mirror.
	ErrInsecureScheme = errors.New("only https is allowed")
)

// refusal is a refused hop: which host and why.
type refusal struct {
	host string
	err  error // ErrOffAllowlist or ErrInsecureScheme
}

func (r *refusal) Error() string { return r.host + ": " + r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

// ErrRateLimited is a host that still answered 429 after every retry.
type ErrRateLimited struct {
	Host    string
	Status  int
	Retries int
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("%s answered %d after %s", e.Host, e.Status, retries(e.Retries))
}

// ErrAuth is a host that refused the request for want of credentials.
type ErrAuth struct {
	Host   string
	Status int
}

func (e *ErrAuth) Error() string { return fmt.Sprintf("%s answered %d", e.Host, e.Status) }

// StatusError is any other answer that is not 2xx. Sources turn a 404
// into E2 or E3 and a 5xx on a checksum file into E5.
type StatusError struct {
	Host   string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s answered %d", e.Host, e.Status) }

// StatusOf returns the HTTP status of the first StatusError, ErrAuth or
// ErrRateLimited in err's chain, or 0.
func StatusOf(err error) int {
	var s *StatusError
	var a *ErrAuth
	var r *ErrRateLimited
	switch {
	case errors.As(err, &s):
		return s.Status
	case errors.As(err, &a):
		return a.Status
	case errors.As(err, &r):
		return r.Status
	}
	return 0
}

// ErrGitHubBudget is an anonymous run that ran out of api.github.com
// requests. Limit is GitHub's hourly allowance, Needed the run's
// estimate (see Client.ExpectGitHub).
type ErrGitHubBudget struct {
	Limit, Needed int
}

func (e *ErrGitHubBudget) Error() string {
	return fmt.Sprintf("api.github.com allows %d requests an hour without a token and this run needs about %d", e.Limit, e.Needed)
}

// SizeError is a limit counted on bytes read: a download over --max-size
// (Unpacked false) or an archive whose entries add up to more than the
// uncompressed cap (Unpacked true). It unwraps to core.ErrTooLarge.
type SizeError struct {
	Limit    int64
	Unpacked bool
}

func (e *SizeError) Error() string {
	if e.Unpacked {
		return "unpacks to over " + Size(e.Limit)
	}
	return "is over " + Size(e.Limit)
}

// Unwrap returns core.ErrTooLarge.
func (e *SizeError) Unwrap() error { return core.ErrTooLarge }

// Size formats a byte count the way limits are written: "256 MiB",
// "1 GiB", else bytes.
func Size(n int64) string {
	const kib, mib, gib = int64(1) << 10, int64(1) << 20, int64(1) << 30
	switch {
	case n >= gib && n%gib == 0:
		return strconv.FormatInt(n/gib, 10) + " GiB"
	case n >= mib && n%mib == 0:
		return strconv.FormatInt(n/mib, 10) + " MiB"
	case n >= kib && n%kib == 0:
		return strconv.FormatInt(n/kib, 10) + " KiB"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// retries is "2 retries" or "1 retry".
func retries(n int) string {
	if n == 1 {
		return "1 retry"
	}
	return strconv.Itoa(n) + " retries"
}

// The hints of PRD section 10.
const (
	hintNetwork   = "check the connection or HTTPS_PROXY"
	hintOffline   = "with --offline only cached data and archives are used; run once without it to fill the cache"
	hintAllowlist = "Sightread fetches only from the official registries and the mirrors you configure (the SIGHTREAD_* variables)"
	hintInsecure  = "plain http could let anyone in between swap the package; mirrors on 127.0.0.1 are the only exception"
	hintRateLimit = "run again in a few minutes or lower --jobs"
	hintTooLarge  = "raise --max-size if you expect that; a size jump this big is worth a look on its own"
	hintGitHub    = "set GITHUB_TOKEN (sent only to api.github.com)"
)

// networkError is E7 for host with a short reason.
func networkError(host, reason, hint string, err error) *core.Error {
	return &core.Error{
		Code: core.ENetwork, Exit: cli.ExitUnavailable,
		What: fmt.Sprintf("can't reach %s (%s)", host, reason),
		Hint: []string{hint}, Err: err,
	}
}

// refusedError is E7 for a refused hop.
func refusedError(r *refusal) *core.Error {
	if errors.Is(r.err, ErrInsecureScheme) {
		return networkError(r.host, ErrInsecureScheme.Error(), hintInsecure, r)
	}
	return networkError(r.host, ErrOffAllowlist.Error(), hintAllowlist, r)
}

// rateLimitError is E9.
func rateLimitError(e *ErrRateLimited) *core.Error {
	return &core.Error{
		Code: core.ERateLimited, Exit: cli.ExitUnavailable,
		What: fmt.Sprintf("%s asked us to slow down (%d) and still did after %s", e.Host, e.Status, retries(e.Retries)),
		Hint: []string{hintRateLimit}, Err: e,
	}
}

// authError is E10 with the hint for the credential the host takes.
func authError(e *ErrAuth, hint string) *core.Error {
	return &core.Error{
		Code: core.EAuth, Exit: cli.ExitUnavailable,
		What: e.Error(), Hint: []string{hint}, Err: e,
	}
}

// GitHubLimitError is E16 as run prints it once it knows how far it got:
// reviewed of total packages.
func GitHubLimitError(command string, limit, needed, reviewed, total int) *core.Error {
	e := &ErrGitHubBudget{Limit: limit, Needed: needed}
	return &core.Error{
		Code: core.EGitHubLimit, Exit: cli.ExitUnavailable, Command: command,
		What: e.Error(),
		Hint: []string{fmt.Sprintf("%s; %d of %d packages were reviewed", hintGitHub, reviewed, total)},
		Err:  e,
	}
}

// budgetError is E16 as the Getter returns it, before run adds counts.
func budgetError(e *ErrGitHubBudget) *core.Error {
	return &core.Error{
		Code: core.EGitHubLimit, Exit: cli.ExitUnavailable,
		What: e.Error(), Hint: []string{hintGitHub}, Err: e,
	}
}

// tooLargeError is E11 for a download or answer past its cap. what names
// it until Package.Wrap says which package it was.
func tooLargeError(what string, e *SizeError) *core.Error {
	return &core.Error{
		Code: core.ETooLarge, Exit: cli.ExitUnavailable,
		What: what + " " + e.Error(),
		Hint: []string{hintTooLarge}, Err: e,
	}
}

// TooLarge is E11 for an archive whose entries add up to more than limit
// (package archive returns it; Package.Wrap names the package).
func TooLarge(limit int64) *core.Error {
	return tooLargeError("the archive", &SizeError{Limit: limit, Unpacked: true})
}

// Package names the package a request was for, so a Getter or archive
// error can say so in the words of PRD section 10.
type Package struct {
	Command string // "plugin", "composer"; the *core.Error's Command when it has none
	Name    string
	Version string
	Archive string // "zip" or "tarball"
}

// Wrap returns err with the package named: E10 gains " for <name>" and
// E11 reads "the <version> <archive> of <name> is over 256 MiB" (or
// "the <version> archive of <name> unpacks to over 1 GiB"). Other errors
// gain the command only. err itself is not changed.
func (p Package) Wrap(err error) error {
	var ce *core.Error
	if !errors.As(err, &ce) {
		return err
	}
	out := *ce
	out.Hint = append([]string(nil), ce.Hint...)
	if out.Command == "" {
		out.Command = p.Command
	}
	var size *SizeError
	switch {
	case out.Code == core.EAuth && p.Name != "":
		out.What += " for " + p.Name
	case out.Code == core.ETooLarge && p.Name != "" && errors.As(err, &size):
		noun := p.Archive
		if size.Unpacked || noun == "" {
			noun = "archive"
		}
		out.What = fmt.Sprintf("the %s %s of %s %s", p.Version, noun, p.Name, size.Error())
	}
	return &out
}
