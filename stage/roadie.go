// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
)

// roadieSchema is the only verify document stage accepts
// (docs/roadie-contract.md).
const roadieSchema = "rhythm-roadie/v1"

// roadieTimeout bounds rhythm-roadie verify.
const roadieTimeout = 10 * time.Minute

// verifyDoc is rhythm-roadie verify --json.
type verifyDoc struct {
	Schema  string `json:"schema"`
	Kind    string `json:"kind"`
	Verdict string `json:"verdict"`
	Data    struct {
		Target        string    `json:"target"`
		ProductionURL string    `json:"production_url"`
		Signed        bool      `json:"signed"`
		Sealed        bool      `json:"sealed"`
		CopyCreated   time.Time `json:"copy_created"`
		VerifiedAt    time.Time `json:"verified_at"`
		Problems      []struct {
			Kind  string `json:"kind"`
			Count int    `json:"count"`
			Text  string `json:"text"`
		} `json:"problems"`
	} `json:"data"`
}

// roadieVerify runs rhythm-roadie verify on the staging copy and checks
// its answer (PRD 15 step 3). It returns the production URL the copy was
// made from, for the E14 check.
func (s *stager) roadieVerify(ctx context.Context) (string, error) {
	argv := []string{s.roadie, "verify", "--target", s.p.Staging}
	if len(s.p.WP) > 0 {
		argv = append(argv, "--wp", strings.Join(s.p.WP, " "))
	}
	argv = append(argv, "--json")
	res, err := proc.Run(ctx, proc.Spec{Argv: argv, Purpose: proc.PurposeRoadie, Timeout: roadieTimeout, MaxOutput: 4 << 20, Log: s.p.Log})
	if err != nil {
		return "", s.ranBadly("rhythm-roadie verify", -1, res.Stderr, err)
	}
	var doc verifyDoc
	jsonErr := json.Unmarshal(bytes.TrimSpace(res.Stdout), &doc)
	if res.Code > 1 || jsonErr != nil || doc.Schema != roadieSchema || doc.Kind != "verify" {
		return "", s.ranBadly("rhythm-roadie verify", res.Code, res.Stderr, jsonErr)
	}
	d := doc.Data
	var why []string
	for _, p := range d.Problems {
		if t := term.SafeText(strings.TrimSpace(p.Text)); t != "" {
			why = append(why, t)
		}
	}
	switch {
	case len(why) > 0:
	case doc.Verdict != "ok" || res.Code != 0:
		why = append(why, "verdict "+term.SafeText(doc.Verdict))
	case !d.Signed:
		why = append(why, "the copy has no signed Roadie marker")
	case !d.Sealed:
		why = append(why, "outbound mail is not sealed")
	case d.CopyCreated.IsZero() || d.VerifiedAt.IsZero() || !d.VerifiedAt.After(d.CopyCreated):
		why = append(why, "the check is older than the copy")
	}
	if len(why) > 0 {
		return "", &core.Error{Code: core.ESoundcheckMissing, Exit: cli.ExitUnavailable,
			What: fmt.Sprintf("%s failed rhythm roadie verify (%s)", s.host, strings.Join(why, ", ")),
			Hint: []string{"fix it with rhythm roadie prepare, or --skip-roadie-verify (the report says it was skipped)"}}
	}
	return d.ProductionURL, nil
}

// ranBadly is the error for a helper that didn't run to a usable answer:
// it couldn't start, stopped or printed something else than its JSON.
// Its stderr goes to -v only, masked: an install command or a helper
// can print a token.
func (s *stager) ranBadly(what string, code int, stderr []byte, cause error) error {
	if s.p.Log != nil && len(stderr) > 0 {
		fmt.Fprintf(s.p.Log, "%s: %s\n", what, secrets.Redact(term.SafeLines(string(bytes.TrimSpace(stderr)))))
	}
	e := &core.Error{Code: core.ESoundcheckMissing, Exit: cli.ExitUnavailable, Command: s.p.Command, Err: cause}
	if code >= 0 {
		e.What = fmt.Sprintf("%s couldn't run (exit %d)", what, code)
	} else {
		e.What = what + " couldn't run"
	}
	e.Hint = []string{"-v shows its output; nothing was installed on " + s.host}
	if s.applied {
		e.Hint = []string{"-v shows its output; " + s.ref() + " is installed on " + s.host + ", so check the site yourself"}
	}
	return e
}
