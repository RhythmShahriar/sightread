// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the WordPress behaviour detector.
const (
	SigAdminUserCreate     = "admin-user-create"
	SigAdminUserHidden     = "admin-user-hidden"
	SigCapabilityChange    = "capability-change"
	SigUpdateSuppression   = "update-suppression"
	SigBotCloaking         = "bot-cloaking"
	SigRestOpenRoute       = "rest-open-route"
	SigCronNewHook         = "cron-new-hook"
	SigInputUnserialize    = "input-unserialize"
	SigWriteOutsidePackage = "write-outside-package"
)

// More feature attributes, read by the WordPress detector.
const (
	// AttrRole is the role a user is created with or set to, when the
	// analyzer could fold it.
	AttrRole = "role"
	// AttrGrants is "true" on a user_has_cap or map_meta_cap filter
	// whose callback adds capabilities.
	AttrGrants = "grants"
	// AttrScope is "own" on an update filter that touches only the
	// plugin's own entry.
	AttrScope = "scope"
	// AttrPrints is what a user agent or login branch prints:
	// "fetched", "encoded" or "literal".
	AttrPrints = "prints"
	// AttrPermission is "open" on a REST route anyone can call.
	AttrPermission = "permission"
	// AttrAllowedClasses is "false" when unserialize is called with
	// allowed_classes => false.
	AttrAllowedClasses = "allowed_classes"
)

func init() { core.RegisterDetector(wpDetector{}) }

// wpDetector finds WordPress behaviour new in the candidate: admin
// users, capabilities, update filters, cloaking, open REST routes,
// cron hooks, unserialize of outside data and writes outside the
// package (PRD 12.1).
type wpDetector struct{}

func (wpDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "code-wordpress", Signals: []string{
		SigAdminUserCreate, SigAdminUserHidden, SigCapabilityChange, SigUpdateSuppression, SigBotCloaking,
		SigRestOpenRoute, SigCronNewHook, SigInputUnserialize, SigWriteOutsidePackage,
	}}
}

func (wpDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	feats := newFeatures(s)
	for _, f := range feats {
		if ctx.Err() != nil {
			return
		}
		switch f.Kind {
		case core.FRoute:
			if f.Attrs[AttrPermission] == "open" {
				out.send(openRoute(f, feats))
			}
		case core.FCron:
			out.send(cronHook(s, f, feats))
		default:
			if id := wpSignal(f); id != "" {
				fd := newFinding(id, f)
				if id == SigWriteOutsidePackage && criticalTargets[writeTarget(f.Key)] {
					fd.Severity = cli.SeverityCritical
				}
				out.send(fd)
			}
		}
	}
}

// wpSignal returns the signal a new feature raises on its own, or "".
// Routes and cron hooks depend on the rest of their file and are handled by
// Detect.
func wpSignal(f core.Feature) string {
	switch f.Kind {
	case core.FUserCreate:
		if adminUser(f) {
			return SigAdminUserCreate
		}
	case core.FCall:
		if f.Key == "set_role" && strings.Contains(strings.ToLower(f.Attrs[AttrArg]), "administrator") || f.Key == "grant_super_admin" {
			return SigAdminUserCreate
		}
	case core.FUserHide:
		return SigAdminUserHidden
	case core.FCap:
		if capGrant(f) {
			return SigCapabilityChange
		}
	case core.FUpdateFilter:
		if f.Attrs[AttrScope] != "own" {
			return SigUpdateSuppression
		}
	case core.FUACheck:
		if p := f.Attrs[AttrPrints]; p == "fetched" || p == "encoded" {
			return SigBotCloaking
		}
	case core.FFlow, core.FUnserialize:
		if outsideUnserialize(f) {
			return SigInputUnserialize
		}
	case core.FWrite:
		if t := writeTarget(f.Key); t != "" && !insideTargets[t] {
			return SigWriteOutsidePackage
		}
	}
	return ""
}

// adminUser reports whether a user-create feature makes an
// administrator: a folded role of administrator, grant_super_admin, or
// a direct wp_capabilities write whose role is not a known lesser one.
func adminUser(f core.Feature) bool {
	role := strings.ToLower(f.Attrs[AttrRole])
	switch f.Key {
	case "grant_super_admin":
		return true
	case "wp_capabilities":
		return role == "" || role == "administrator"
	}
	return role == "administrator"
}

// adminCaps are the capabilities that, given to a lesser role, hand over
// the site.
var adminCaps = map[string]bool{
	"administrator": true, "manage_options": true, "unfiltered_html": true, "unfiltered_upload": true,
	"edit_plugins": true, "install_plugins": true, "activate_plugins": true, "update_plugins": true, "delete_plugins": true,
	"edit_themes": true, "install_themes": true, "switch_themes": true, "update_themes": true, "delete_themes": true,
	"edit_files": true, "update_core": true, "promote_users": true, "create_users": true, "edit_users": true,
	"delete_users": true, "manage_network": true, "manage_network_options": true, "manage_network_plugins": true,
	"manage_sites": true,
}

// adminRoles may hold admin capabilities.
var adminRoles = map[string]bool{"administrator": true, "super_admin": true}

// capGrant reports whether a capability feature gives admin rights to
// another role. Keys are "<op>:<role>:<cap>" (add_cap, add_role) or
// "cap:filter:<hook>" for user_has_cap and map_meta_cap filters, which
// count when their callback grants (AttrGrants).
func capGrant(f core.Feature) bool {
	parts := strings.SplitN(f.Key, ":", 3)
	if len(parts) != 3 {
		return false
	}
	switch parts[0] {
	case "cap":
		return parts[1] == "filter" && f.Attrs[AttrGrants] == "true"
	case "add_cap", "add_role":
		return !adminRoles[strings.ToLower(parts[1])] && adminCaps[strings.ToLower(parts[2])]
	}
	return false
}

// outsideUnserialize reports whether request or remote data reaches
// unserialize, unless allowed_classes is false or the argument is only
// the plugin's own option. A request or remote flow is never excused by
// an option: unserialize($_REQUEST['d'] ?: get_option('x')) still fires.
func outsideUnserialize(f core.Feature) bool {
	if f.Attrs[AttrAllowedClasses] == "false" {
		return false
	}
	if f.Kind == core.FFlow {
		return f.Key == "request->unserialize" || f.Key == "remote->unserialize"
	}
	if onlyCall(f.Attrs[AttrArg], "get_option") {
		return false
	}
	src := f.Attrs[AttrSource]
	return src == SrcRequest || src == SrcRemote
}

// onlyCall reports whether arg is one call of fn and nothing else: the
// parenthesis after fn closes at the end of the text.
func onlyCall(arg, fn string) bool {
	a := strings.ToLower(strings.TrimSpace(arg))
	if !strings.HasPrefix(a, fn+"(") {
		return false
	}
	depth := 0
	for i, r := range a[len(fn):] {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return len(fn)+i == len(a)-1
			}
		}
	}
	return false
}

// Write target classes (FWrite keys). insideTargets are where a package
// may write; criticalTargets make the finding critical.
var (
	insideTargets   = map[string]bool{"own": true, "uploads": true, "temp": true, "unknown": true}
	criticalTargets = map[string]bool{
		"wp-config": true, "htaccess": true, "mu-plugins": true, "plugins-dir": true,
		"npmrc": true, "ssh": true, "git": true, "ci": true,
	}
)

// writeTarget normalises an FWrite key: ".npmrc" and "npmrc" are one
// class, as are ".ssh", ".git" and "ci-files" with theirs.
func writeTarget(key string) string {
	k := strings.TrimPrefix(strings.ToLower(key), ".")
	switch k {
	case "ci-files", "github-workflows":
		return "ci"
	case "wp-config.php":
		return "wp-config"
	case ".htaccess":
		return "htaccess"
	}
	return k
}

// openRoute is a rest-open-route finding, raised to high when the same
// file gains code execution, unserialize of outside data, writes
// outside the package or admin users.
func openRoute(f core.Feature, feats []core.Feature) core.Finding {
	fd := newFinding(SigRestOpenRoute, f)
	var by []string
	for _, o := range feats {
		if o.Ev.Path != f.Ev.Path {
			continue
		}
		id := execSignal(o)
		if id == "" {
			switch w := wpSignal(o); w {
			case SigInputUnserialize, SigWriteOutsidePackage, SigAdminUserCreate, SigAdminUserHidden:
				id = w
			}
		}
		if id != "" && !slices.Contains(by, id) {
			by = append(by, id)
		}
	}
	if len(by) > 0 {
		slices.Sort(by)
		fd.Severity = cli.SeverityHigh
		fd.RaisedBy = by
	}
	return fd
}

// cronHook is a cron-new-hook finding: low, medium when the file of the
// hook's callback (where add_action names the hook, else the scheduling
// file) gains a network send, a data flow or an eval.
func cronHook(s *core.Subject, f core.Feature, feats []core.Feature) core.Finding {
	fd := newFinding(SigCronNewHook, f)
	files := []string{f.Ev.Path}
	for _, h := range s.NewFeatures.ByKey[string(core.FHook)+":"+f.Key] {
		files = append(files, h.Ev.Path)
	}
	for _, o := range feats {
		if slices.Contains(files, o.Ev.Path) && (o.Kind == core.FSend || o.Kind == core.FFlow || o.Kind == core.FEval) {
			fd.Severity = cli.SeverityMedium
			break
		}
	}
	return fd
}
