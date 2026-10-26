// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wpcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
)

// DefaultTimeout bounds each WP-CLI call. A listing takes a second or
// two; a remote prefix (ssh, docker) adds a little.
const DefaultTimeout = 60 * time.Second

// maxOutput caps what each call may print. A plugin list of a few
// hundred plugins is tens of KiB.
const maxOutput = 16 << 20

// The only WP-CLI calls Sightread makes. They are read-only listings.
// Nothing else can be run: List walks this fixed table and no caller
// can add a subcommand.
var (
	pluginList = []string{"plugin", "list", "--format=json", "--fields=name,status,version,update_version,auto_update"}
	themeList  = []string{"theme", "list", "--format=json", "--fields=name,status,version,update_version,auto_update"}
	coreVer    = []string{"core", "version"}
	autoOption = []string{"option", "get", "auto_update_plugins", "--format=json"}
)

// Calls returns the WP-CLI subcommands List runs, in order, for docs
// and tests.
func Calls() [][]string {
	return [][]string{slices.Clone(pluginList), slices.Clone(themeList), slices.Clone(coreVer), slices.Clone(autoOption)}
}

// Item is one row of `plugin list` or `theme list`.
type Item struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	UpdateVersion string `json:"update_version"`
	AutoUpdate    string `json:"auto_update"` // "on" or "off"
}

// Statuses WP-CLI gives plugins that have no update channel.
const (
	StatusMustUse = "must-use"
	StatusDropIn  = "dropin"
)

// Listing is what the user's wp command reports about the site.
type Listing struct {
	Core    string
	Plugins []Item
	Themes  []Item
	// AutoUpdatePlugins is the auto_update_plugins option: plugin files
	// such as "akismet/akismet.php". Empty when the option is not set.
	AutoUpdatePlugins []string
	Warnings          []string
}

// Options tune List.
type Options struct {
	// Command is the Sightread command the error names ("plugin",
	// "all"); empty for a tool-wide error.
	Command string
	// Timeout bounds each call; 0 means DefaultTimeout.
	Timeout time.Duration
	// Log receives one line per call (-v), secrets masked.
	Log io.Writer
}

// List runs the user's wp command prefix with each listing call and
// decodes the output. A call that fails gives E1 with the --wp hint.
// The auto_update_plugins option is optional: when it can't be read the
// listing just has none.
func List(ctx context.Context, prefix []string, opt Options) (*Listing, error) {
	if len(prefix) == 0 || prefix[0] == "" {
		return nil, wpError(opt.Command, prefix, "", "the --wp command is empty", nil)
	}
	if _, err := proc.LookPath(prefix[0]); err != nil {
		return nil, wpError(opt.Command, prefix, "", fmt.Sprintf("%s was not found", clip(prefix[0])), err)
	}
	l := &Listing{}
	out, err := call(ctx, prefix, pluginList, opt)
	if err != nil {
		return nil, err
	}
	if l.Plugins, err = decodeItems(out, l); err != nil {
		return nil, badOutput(opt.Command, prefix, pluginList, err)
	}
	if out, err = call(ctx, prefix, themeList, opt); err != nil {
		return nil, err
	}
	if l.Themes, err = decodeItems(out, l); err != nil {
		return nil, badOutput(opt.Command, prefix, themeList, err)
	}
	if out, err = call(ctx, prefix, coreVer, opt); err != nil {
		return nil, err
	}
	v := strings.TrimSpace(string(out))
	if !coreVersion.MatchString(v) {
		return nil, badOutput(opt.Command, prefix, coreVer, fmt.Errorf("%q is not a version", clip(v)))
	}
	l.Core = v
	// A site that never turned auto-updates on has no such option and
	// WP-CLI exits 1, so a failure here means "none", not an error.
	if out, err = call(ctx, prefix, autoOption, opt); err == nil {
		files, derr := decodeOption(out)
		if derr != nil {
			l.Warnings = append(l.Warnings, fmt.Sprintf("couldn't read the auto_update_plugins option: %s", clip(derr.Error())))
		}
		l.AutoUpdatePlugins = files
	} else if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return l, nil
}

// coreVersion is what `wp core version` prints: 6.6.2, 6.7-RC1.
var coreVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,63}$`)

// call runs one listing and returns stdout. A start failure, a timeout
// or a non-zero exit is E1.
func call(ctx context.Context, prefix, args []string, opt Options) ([]byte, error) {
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res, err := proc.Run(ctx, proc.Spec{
		Argv:      wpArgv(prefix, args...),
		MaxOutput: maxOutput,
		Timeout:   timeout,
		Purpose:   proc.PurposeWPCLI,
		Log:       opt.Log,
	})
	sub := strings.Join(args[:2], " ")
	switch {
	case err != nil && errors.Is(err, proc.ErrOutputTooLarge):
		return nil, wpError(opt.Command, prefix, sub, fmt.Sprintf("%s printed over 16 MiB", sub), err)
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil && errors.Is(err, context.DeadlineExceeded):
		return nil, wpError(opt.Command, prefix, sub, fmt.Sprintf("%s did not finish within %s", sub, timeout), err)
	case err != nil:
		return nil, wpError(opt.Command, prefix, sub, fmt.Sprintf("%s could not run: %s", sub, clip(err.Error())), err)
	case res.Code != 0:
		what := fmt.Sprintf("%s failed (exit %d)", sub, res.Code)
		if line := firstLine(res.Stderr); line != "" {
			what += ": " + line
		}
		return nil, wpError(opt.Command, prefix, sub, what, nil)
	}
	return res.Stdout, nil
}

// decodeItems reads a plugin or theme list. Lines before the JSON (PHP
// notices some hosts print to stdout) are skipped with a warning; the
// JSON itself is decoded strictly: unknown fields, trailing data or an
// auto_update value other than on and off are refused.
func decodeItems(out []byte, l *Listing) ([]Item, error) {
	body, skipped := jsonStart(out, '[')
	if skipped != "" {
		l.Warnings = append(l.Warnings, "the wp command printed text before its JSON: "+skipped)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var items []Item
	if err := dec.Decode(&items); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("more data after the JSON list")
	}
	for _, it := range items {
		switch it.AutoUpdate {
		case "on", "off", "":
		default:
			return nil, fmt.Errorf("auto_update %q: want on or off", clip(it.AutoUpdate))
		}
		if it.Name == "" {
			return nil, errors.New("an entry has no name")
		}
	}
	return items, nil
}

// decodeOption reads the auto_update_plugins option: a JSON list of
// plugin files, or an object when PHP's array has gaps in its keys.
func decodeOption(out []byte) ([]string, error) {
	body := bytes.TrimSpace(out)
	if len(body) == 0 || string(body) == "false" || string(body) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(body, &list); err == nil {
		return list, nil
	}
	var obj map[string]string
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, errors.New("want a JSON list of plugin files")
	}
	for _, v := range obj {
		list = append(list, v)
	}
	slices.Sort(list)
	return list, nil
}

// jsonStart returns out from the first line that starts with open plus
// the first skipped line (masked and clipped) when lines came before it.
func jsonStart(out []byte, open byte) (body []byte, skipped string) {
	rest := out
	for len(rest) > 0 {
		trimmed := bytes.TrimLeft(rest, " \t\r\n")
		if len(trimmed) > 0 && trimmed[0] == open {
			if skipped == "" && len(rest) != len(out) {
				skipped = firstLine(out)
			}
			return trimmed, skipped
		}
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
	}
	return out, ""
}

// firstLine is the first non-empty line of b, masked and clipped, for
// an error or warning.
func firstLine(b []byte) string {
	for line := range strings.SplitSeq(string(b), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return clip(s)
		}
	}
	return ""
}

// clip masks secrets in s, drops control characters and cuts it to 200
// bytes, so output from the user's command can't flood or style the
// terminal.
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

// Display is the prefix as one line, masked, for messages.
func Display(prefix []string) string {
	return clip(strings.Join(prefix, " "))
}

// badOutput is E1 for output that isn't what the call should print.
func badOutput(command string, prefix, args []string, err error) error {
	sub := strings.Join(args[:2], " ")
	what := "the JSON Sightread reads"
	if slices.Equal(args, coreVer) {
		what = "a WordPress version"
	}
	return wpError(command, prefix, sub, fmt.Sprintf("%s did not print %s: %s", sub, what, clip(err.Error())), err)
}

// wpError is E1 for a --wp failure.
// The hint names sub, the listing that failed ("theme list"), or
// "plugin list", the first one, when none ran yet.
func wpError(command string, prefix []string, sub, what string, cause error) error {
	cmd := Display(prefix)
	if sub == "" {
		sub = "plugin list"
	}
	return &core.Error{
		Code:    core.ENothingInstalled,
		Exit:    2,
		Command: command,
		What:    fmt.Sprintf("--wp %q: %s", cmd, what),
		Hint: []string{
			fmt.Sprintf("check that %s %s works on its own", cmd, sub),
			"or name the site with --path /var/www/site, or give the version: --from <version>",
		},
		Err: cause,
	}
}
