// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"path"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// PHP feature extraction. Calls come from the flow pass with folded
// arguments; statements the evaluator does not report as calls (an if
// on the user agent, $_ENV, __halt_compiler) come from a scan of the
// token stream at the end of the file.

// phpWatch are the calls every PHP file reports as FCall, keyed by the
// function name. preg_replace counts only with the /e modifier and
// error_reporting only with 0.
var phpWatch = map[string]bool{
	"eval": true, "assert": true, "create_function": true, "preg_replace": true, "system": true,
	"exec": true, "shell_exec": true, "passthru": true, "proc_open": true, "popen": true,
	"unserialize": true, "maybe_unserialize": true, "base64_decode": true, "gzinflate": true,
	"gzuncompress": true, "str_rot13": true, "hex2bin": true, "file_put_contents": true,
	"fopen": true, "fwrite": true, "rename": true, "copy": true, "unlink": true,
	"wp_insert_user": true, "wp_create_user": true, "wp_update_user": true, "set_role": true,
	"add_role": true, "add_cap": true, "remove_cap": true, "grant_super_admin": true,
	"register_rest_route": true, "wp_schedule_event": true, "wp_schedule_single_event": true,
	"fsockopen": true, "mail": true, "wp_mail": true, "header": true, "setcookie": true,
	"ini_set": true, "error_reporting": true, "__halt_compiler": true,
}

// phpWatchPrefixes are families of watched calls.
var phpWatchPrefixes = []string{"as_schedule_", "wp_remote_", "curl_"}

// methodWatch are the watched names that are methods (of WP_Role,
// WP_User and WP_Roles).
var methodWatch = map[string]bool{"add_cap": true, "remove_cap": true, "set_role": true, "add_role": true}

func phpWatched(name string) bool {
	if phpWatch[name] {
		return true
	}
	for _, p := range phpWatchPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// phpSends are the PHP calls that send data over the network.
var phpSends = map[string]string{
	"wp_remote_get": "http", "wp_remote_post": "http", "wp_remote_request": "http", "wp_remote_head": "http",
	"wp_safe_remote_get": "http", "wp_safe_remote_post": "http", "wp_safe_remote_request": "http",
	"wp_safe_remote_head": "http", "curl_exec": "http", "curl_multi_exec": "http", "fsockopen": "socket",
	"pfsockopen": "socket", "stream_socket_client": "socket", "socket_connect": "socket",
	"ftp_put": "ftp", "ftp_fput": "ftp", "mail": "mail", "wp_mail": "mail",
}

// phpUserReads are calls whose result is user data.
var phpUserReads = map[string]bool{
	"get_users": true, "get_user_by": true, "get_userdata": true, "get_users_of_blog": true,
	"wp_user_query": true, "get_user_meta": true,
}

// phpOptionReads are calls whose result is an option.
var phpOptionReads = map[string]bool{
	"get_option": true, "get_site_option": true, "get_blog_option": true, "wp_load_alloptions": true,
	"get_network_option": true,
}

// phpHooks are the hooks reported as FHook when a file adds a callback
// to them: the ones detectors and reviewers care about.
var phpHooks = map[string]bool{
	"init": true, "wp_loaded": true, "plugins_loaded": true, "muplugins_loaded": true, "admin_init": true,
	"wp_head": true, "wp_footer": true, "admin_footer": true, "login_head": true, "login_footer": true,
	"template_redirect": true, "shutdown": true, "all": true, "wp_login": true, "authenticate": true,
	"user_register": true, "set_logged_in_cookie": true, "wp_authenticate_user": true,
	"rest_api_init": true, "cron_schedules": true, "pre_user_query": true, "pre_get_users": true,
	"views_users": true, "users_list_table_query_args": true, "user_has_cap": true,
	"map_meta_cap": true, "role_has_cap": true, "site_transient_update_plugins": true,
	"automatic_updater_disabled": true, "upgrader_process_complete": true, "activated_plugin": true,
	"all_plugins": true, "show_advanced_plugins": true, "option_active_plugins": true,
	"wp_mail": true, "phpmailer_init": true, "the_content": true, "posts_where": true,
	"auth_cookie_valid": true, "determine_current_user": true, "xmlrpc_methods": true,
}

var phpHookPrefixes = []string{"wp_ajax_nopriv_", "pre_site_transient_update_", "auto_update_", "pre_option_", "pre_update_option_"}

func phpHookWatched(hook string) bool {
	if phpHooks[hook] {
		return true
	}
	for _, p := range phpHookPrefixes {
		if strings.HasPrefix(hook, p) {
			return true
		}
	}
	return false
}

// userHideHooks are hooks a callback can use to hide users from the
// Users screen.
var userHideHooks = map[string]bool{
	"pre_user_query": true, "pre_get_users": true, "users_list_table_query_args": true, "views_users": true,
}

// updateHooks are hooks that can hide or block updates.
var updateHooks = map[string]bool{
	"site_transient_update_plugins": true, "site_transient_update_themes": true,
	"pre_site_transient_update_plugins": true, "pre_site_transient_update_themes": true,
	"pre_site_transient_update_core": true, "auto_update_plugin": true, "auto_update_theme": true,
	"automatic_updater_disabled": true, "auto_update_core": true,
}

// capFilters are hooks that decide capabilities at run time.
var capFilters = map[string]bool{"user_has_cap": true, "map_meta_cap": true, "role_has_cap": true}

// crawlerWords are the user agent pieces a cloaking check compares
// with.
var crawlerWords = []string{"bot", "crawl", "spider", "slurp", "google", "bing", "yandex", "baidu", "duckduck", "facebookexternalhit", "lighthouse"}

// phpCodeExts are the extensions PHP code is normally included from.
var phpCodeExts = map[string]bool{
	".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true,
	".php8": true, ".inc": true, ".phar": true, ".module": true, ".tpl": true,
}

func (e *extractor) phpCall(s *scope, c *callSite) {
	name := c.name
	if c.recv != nil && c.method != "" && strings.Contains(name, "::") {
		name = "" // a static call reads as a method below
	}
	e.phpDynCall(c)
	e.phpReads(c, name)
	watch := name
	if watch == "" && methodWatch[c.method] {
		watch = c.method
	}
	if watch != "" && phpWatched(watch) && (watch != "preg_replace" || evalModifier(c.arg(0).v)) &&
		(watch != "error_reporting" || isZero(c.arg(0).v)) && !e.col.has(e.col.ctx, core.FCall, watch, c.line) {
		a := argAttrs(c)
		if c.via != "" {
			a["via"] = c.via
		}
		e.callFeature(core.FCall, watch, c, a)
	}
	if kind, ok := phpSends[name]; ok {
		e.send(c, name, map[string]string{"channel": kind})
	}
	method := c.method
	switch {
	case name == "eval" || name == "assert" || name == "create_function":
		e.phpEval(c, name)
	case name == "preg_replace" && evalModifier(c.arg(0).v):
		e.phpEval(c, "preg_replace /e")
	case name == "wp_insert_user" || name == "wp_update_user":
		e.userCreate(c, name)
	case name == "wp_create_user":
		e.callFeature(core.FUserCreate, name, c, map[string]string{"role": "default"})
	case name == "grant_super_admin":
		e.callFeature(core.FUserCreate, name, c, map[string]string{"role": "super-admin"})
	case name == "update_user_meta" || name == "add_user_meta" || name == "update_usermeta" || name == "update_user_option":
		e.capabilitiesMeta(c)
	case name == "add_role" && c.recv == nil:
		e.addRole(c)
	case name == "register_rest_route":
		e.route(c)
	case name == "wp_schedule_event":
		e.cron(c, 2, name, 1)
	case name == "wp_schedule_single_event":
		e.cron(c, 1, name, -1)
	case name == "as_schedule_single_action":
		e.cron(c, 1, name, -1)
	case name == "as_schedule_recurring_action" || name == "as_schedule_cron_action":
		e.cron(c, 2, name, 1)
	case name == "as_enqueue_async_action":
		e.cron(c, 0, name, -1)
	case name == "add_action" || name == "add_filter":
		e.phpHook(c, strings.TrimPrefix(name, "add_"))
	case name == "getenv":
		e.envRead(c)
	case name == "file_put_contents":
		e.write(c, 0, name)
	case name == "fopen":
		mode, _ := argStr(c, 1)
		if strings.ContainsAny(mode, "waxc+") {
			e.write(c, 0, name)
		} else {
			e.credRead(c, name)
		}
	case name == "rename" || name == "copy" || name == "move_uploaded_file" || name == "symlink" || name == "link":
		e.write(c, 1, name)
	case name == "file_get_contents" || name == "file" || name == "readfile" || name == "parse_ini_file" ||
		name == "highlight_file" || name == "show_source":
		e.credRead(c, name)
	case method == "set_role" || (method == "add_role" && len(c.args) == 1):
		role, ok := argStr(c, 0)
		if !ok {
			role = "?"
		}
		e.callFeature(core.FUserCreate, method, c, map[string]string{"role": attrText(role)})
	case method == "add_cap" || method == "remove_cap":
		e.capChange(c, method)
	case method == "put_contents" && e.recvHas(c, "wp_filesystem"):
		e.write(c, 0, "WP_Filesystem::put_contents")
	case (method == "copy" || method == "move") && e.recvHas(c, "wp_filesystem"):
		e.write(c, 1, "WP_Filesystem::"+method)
	case method == "insert" || method == "update" || method == "query" || method == "replace":
		e.wpdbUser(c)
	}
}

func isZero(v value) bool {
	n, ok := v.num()
	return ok && n == 0
}

// phpDynCall records a call whose callee is not a written name.
func (e *extractor) phpDynCall(c *callSite) {
	if !c.dynamic && !c.folded {
		return
	}
	src := sourceAttr(c.callee.t)
	key := c.name
	switch {
	case key != "" && c.folded:
		if src == "" {
			src = "folded"
		}
	case key != "":
		return // call_user_func('trim'): a plain callback by name
	case c.via != "":
		key = c.via
	case c.recv != nil:
		key = "variable method"
	default:
		key = "variable function"
	}
	if src == "" {
		src = "unknown"
	}
	a := map[string]string{"source": src}
	if c.via != "" {
		a["via"] = c.via
	}
	e.callFeature(core.FDynCall, key, c, a)
}

// phpReads notes what a call reads for the sends of its body.
func (e *extractor) phpReads(c *callSite, name string) {
	switch {
	case phpUserReads[name]:
		e.note(c.pos, readUsers)
	case phpOptionReads[name]:
		e.note(c.pos, readOptions)
		if v, _ := argStr(c, 0); v == "admin_email" || v == "new_admin_email" {
			e.note(c.pos, readAdminEmail)
		}
	case name == "get_bloginfo":
		if v, _ := argStr(c, 0); v == "admin_email" {
			e.note(c.pos, readAdminEmail)
		}
	case name == "getenv":
		e.note(c.pos, readEnv)
	}
}

// phpEval records eval, assert, create_function and preg_replace /e
// with how their code argument is built.
func (e *extractor) phpEval(c *callSite, name string) {
	i := 0
	switch name {
	case "create_function":
		i = 1
	case "preg_replace /e":
		i = 1
	}
	sp := e.span(c, i)
	if name == "assert" && e.boolExpr(sp) {
		return // assert($x > 0) checks a condition, it runs no code
	}
	a := map[string]string{"arg": e.argKind(c, i)}
	if src := sourceAttr(c.arg(i).t); src != "" {
		a["source"] = src
	}
	if e.contains(sp, func(t tok) bool { return t.k == tName && (decodeFuncs[t.text] || t.text == "atob") }) {
		a["decode"] = "true"
	}
	if c.via != "" {
		a["via"] = c.via
	}
	e.callFeature(core.FEval, name, c, a)
}

// argKind says how argument i is written: one literal, a value folding
// could build, or data.
func (e *extractor) argKind(c *callSite, i int) string {
	sp := e.span(c, i)
	if sp[1]-sp[0] == 1 && e.toks[sp[0]].k == tStr && e.toks[sp[0]].known {
		return "literal"
	}
	if _, ok := c.arg(i).v.str(); ok {
		return "folded"
	}
	return "dynamic"
}

// boolExpr reports whether a range is a condition: a comparison, a
// negation, a boolean literal or an is_* check.
func (e *extractor) boolExpr(sp [2]int) bool {
	if sp[1] <= sp[0] {
		return true
	}
	return e.contains(sp, func(t tok) bool {
		switch t.k {
		case tPunct:
			switch t.text {
			case "==", "!=", "===", "!==", "<", ">", "<=", ">=", "!", "&&", "||", "<>":
				return true
			}
		case tName:
			return t.text == "true" || t.text == "false" || t.text == "null" || t.text == "instanceof" ||
				strings.HasPrefix(t.text, "is_") || t.text == "isset" || t.text == "empty" || t.text == "function_exists" ||
				t.text == "class_exists" || t.text == "defined"
		}
		return false
	})
}

// phpInclude records an include of a file that is not PHP code by its
// extension: an image or text file run as code.
func (e *extractor) phpInclude(_ *scope, r res, sp [2]int, line int, kind string) {
	target, ok := r.v.str()
	if !ok {
		h := e.hints(sp, r.v)
		if len(h.lits) == 0 {
			return
		}
		target = h.lits[len(h.lits)-1]
	}
	target = strings.TrimSpace(target)
	ext := strings.ToLower(path.Ext(target))
	if ext == "" || phpCodeExts[ext] || strings.ContainsAny(ext, "/\\") {
		return
	}
	key := strings.TrimLeft(path.Clean("/"+strings.ReplaceAll(target, `\`, "/")), "/")
	end := line
	if sp[1] > sp[0] && sp[1]-1 < len(e.toks) {
		end = e.toks[sp[1]-1].line
	}
	e.col.add(core.FInclude, attrText(key), line, end, e.fnAt(sp[0]), map[string]string{"ext": ext, "kind": kind})
}

// userCreate records wp_insert_user and wp_update_user with the role
// they set, when it is written or folded.
func (e *extractor) userCreate(c *callSite, name string) {
	role, ok := e.roleOf(c, 0)
	if !ok {
		if name == "wp_update_user" {
			return // an update that sets no role creates nothing
		}
		role = "default"
	}
	e.callFeature(core.FUserCreate, name, c, map[string]string{"role": attrText(role)})
}

// roleOf reads the 'role' entry of the user data in argument i: an
// array literal, or a variable built as one or given $x['role'] = ...
func (e *extractor) roleOf(c *callSite, i int) (string, bool) {
	sp := e.span(c, i)
	if sp[1] <= sp[0] {
		return "", false
	}
	if sp[1]-sp[0] == 1 && e.toks[sp[0]].k == tVar {
		if r, ok := e.indexAssigned(sp[0], e.toks[sp[0]].text, "role"); ok {
			return e.foldRange(r)
		}
	}
	vr := e.valueRange(sp)
	if r, ok := e.keyValue(vr, "role"); ok {
		return e.foldRange(r)
	}
	return "", false
}

// foldRange folds a range with no scope: literals and concatenation.
func (e *extractor) foldRange(sp [2]int) (string, bool) {
	return e.rangeStr(&scope{env: map[string]value{}}, sp)
}

// capabilitiesMeta records a direct write of a user's capabilities
// meta (wp_capabilities), the way to make an administrator without
// wp_insert_user.
func (e *extractor) capabilitiesMeta(c *callSite) {
	h := e.hints(e.span(c, 1), c.arg(1).v)
	found := false
	for _, l := range h.lits {
		if strings.HasSuffix(l, "capabilities") {
			found = true
		}
	}
	if !found {
		return
	}
	role := "?"
	vr := e.valueRange(e.span(c, 2))
	for j := vr[0]; j+1 < vr[1]; j++ {
		if t := e.toks[j]; t.k == tStr && t.known && e.toks[j+1].punct("=>") {
			role = t.val
			break
		}
	}
	if v, ok := argStr(c, 2); ok {
		role = v
	}
	e.callFeature(core.FUserCreate, "wp_capabilities", c, map[string]string{"role": attrText(role)})
}

// wpdbUser records $wpdb writes that create users or set capabilities
// in SQL, which bypass every user API.
func (e *extractor) wpdbUser(c *callSite) {
	if !e.recvHas(c, "$wpdb") {
		return
	}
	var lits []string
	for i := range c.args {
		lits = append(lits, e.hints(e.span(c, i), c.arg(i).v).lits...)
	}
	caps, admin, users := false, false, false
	for _, l := range lits {
		caps = caps || strings.Contains(l, "capabilities")
		admin = admin || strings.Contains(l, "administrator")
		users = users || (strings.Contains(l, "insert into") && strings.Contains(l, "users"))
	}
	if c.method == "insert" && e.contains(e.span(c, 0), func(t tok) bool { return t.is(tName, "users") }) {
		users = true
	}
	role := "?"
	if admin {
		role = "administrator"
	}
	switch {
	case caps:
		e.callFeature(core.FUserCreate, "wp_capabilities", c, map[string]string{"role": role, "via": "$wpdb->" + c.method})
	case users:
		e.callFeature(core.FUserCreate, "wpdb-insert-user", c, map[string]string{"role": role, "via": "$wpdb->" + c.method})
	}
}

// recvRange is the token range of a method call's receiver.
func (e *extractor) recvRange(c *callSite) [2]int {
	for j := c.pos; j < len(e.toks) && j < c.pos+callWindow; j++ {
		t := e.toks[j]
		if t.k == tName && t.text == strings.ToLower(c.method) {
			if p := at(e.toks, j-1); p.punct("->") || p.punct("?->") || p.punct("::") || p.punct(".") || p.punct("?.") {
				return [2]int{c.pos, j - 1}
			}
		}
	}
	return [2]int{c.pos, c.pos}
}

// recvHas reports whether a method call's receiver, or what it was
// assigned, names want.
func (e *extractor) recvHas(c *callSite, want string) bool {
	for _, h := range e.hints(e.recvRange(c), value{}).all {
		if h == want || strings.Contains(h, want) {
			return true
		}
	}
	return false
}

// capChange records add_cap and remove_cap as <method>:<role>:<cap>.
func (e *extractor) capChange(c *callSite, method string) {
	role, capIdx := "", 0
	if len(c.args) >= 2 {
		// WP_Roles::add_cap($role, $cap).
		if r, ok := argStr(c, 0); ok {
			role, capIdx = r, 1
		}
	}
	if role == "" {
		role = e.recvRole(c)
	}
	cp, ok := argStr(c, capIdx)
	if !ok {
		cp = "?"
	}
	e.callFeature(core.FCap, method+":"+attrText(role)+":"+attrText(cp), c, map[string]string{"cap": attrText(cp), "role": attrText(role)})
}

// recvRole finds the role a receiver holds: get_role('editor'), or a
// variable assigned from it. A user object gives "user".
func (e *extractor) recvRole(c *callSite) string {
	rr := e.recvRange(c)
	ranges := [][2]int{rr}
	if rr[1]-rr[0] == 1 && e.toks[rr[0]].k == tVar {
		if r, ok := e.assigned(rr[0], e.toks[rr[0]].text); ok {
			ranges = append(ranges, r)
		}
	}
	for _, r := range ranges {
		for j := r[0]; j < r[1]; j++ {
			t := e.toks[j]
			switch {
			case t.k == tName && (t.text == "get_role" || t.text == "wp_role") && at(e.toks, j+1).punct("(") &&
				at(e.toks, j+2).k == tStr:
				return at(e.toks, j+2).val
			case t.k == tName && (t.text == "wp_get_current_user" || t.text == "get_user_by" || t.text == "get_userdata" || t.text == "wp_user"):
				return "user"
			}
		}
	}
	return "unknown"
}

// addRole records add_role($role, $name, $caps): each capability the
// new role gets is an FCap like add_cap.
func (e *extractor) addRole(c *callSite) {
	role, ok := argStr(c, 0)
	if !ok {
		role = "?"
	}
	role = attrText(role)
	vr := e.valueRange(e.span(c, 2))
	n := 0
	for j := vr[0]; j+2 < vr[1]+1 && j+1 < len(e.toks); j++ {
		t := e.toks[j]
		if t.k != tStr || !t.known || !e.toks[j+1].punct("=>") {
			continue
		}
		v := at(e.toks, j+2)
		if v.is(tName, "true") || (v.k == tNum && v.text == "1") {
			cp := attrText(t.val)
			e.callFeature(core.FCap, "add_cap:"+role+":"+cp, c, map[string]string{"cap": cp, "role": role, "via": "add_role"})
			n++
		}
	}
	if n == 0 {
		e.callFeature(core.FCap, "add_role:"+role, c, map[string]string{"role": role})
	}
}

// route records register_rest_route with whether anyone may call it.
func (e *extractor) route(c *callSite) {
	ns, ok1 := argStr(c, 0)
	rt, ok2 := argStr(c, 1)
	if !ok1 {
		ns = "?"
	}
	if !ok2 {
		rt = "?"
	}
	key := attrText(strings.Trim(ns, "/") + "/" + strings.TrimPrefix(rt, "/"))
	a := map[string]string{"permission": e.routePermission(c)}
	if vr := e.valueRange(e.span(c, 2)); vr[1] > vr[0] {
		if r, ok := e.keyValue(vr, "methods"); ok {
			if m, ok := e.foldRange(r); ok {
				a["methods"] = attrText(m)
			}
		}
	}
	e.callFeature(core.FRoute, key, c, a)
}

// routePermission is "open" when an endpoint of the route has no
// permission_callback, uses __return_true or a function that returns
// true; "callback" when every endpoint has a real check; "unknown"
// when the arguments are not written in the call.
func (e *extractor) routePermission(c *callSite) string {
	sp := e.span(c, 2)
	if sp[1] <= sp[0] {
		return "open"
	}
	vr := e.valueRange(sp)
	if !e.literalRange(vr) {
		return "unknown"
	}
	endpoints, perms := 0, 0
	open := false
	for j := vr[0]; j+1 < vr[1]; j++ {
		t := e.toks[j]
		if t.k != tStr || !t.known || !e.toks[j+1].punct("=>") {
			continue
		}
		switch t.val {
		case "callback":
			endpoints++
		case "permission_callback":
			perms++
			r := [2]int{j + 2, e.exprStop(j+2, vr[1])}
			if e.alwaysTrue(r) {
				open = true
			}
		}
	}
	if open || perms < endpoints || perms == 0 {
		return "open"
	}
	return "callback"
}

// alwaysTrue reports whether a callback range always allows:
// '__return_true', function () { return true; } or fn () => true.
func (e *extractor) alwaysTrue(r [2]int) bool {
	if v, ok := e.foldRange(r); ok {
		return strings.TrimPrefix(v, `\`) == "__return_true"
	}
	toks := e.toks
	for j := r[0]; j < r[1]; j++ {
		t := toks[j]
		switch {
		case t.punct("{"):
			return at(toks, j+1).is(tName, "return") && at(toks, j+2).is(tName, "true") &&
				at(toks, j+3).punct(";") && at(toks, j+4).punct("}")
		case t.punct("=>"):
			return at(toks, j+1).is(tName, "true") && j+2 >= r[1]
		}
	}
	return false
}

// cron records a scheduled event by its hook name.
func (e *extractor) cron(c *callSite, hookIdx int, name string, recIdx int) {
	hook, ok := argStr(c, hookIdx)
	if !ok {
		hook = "?"
	}
	a := map[string]string{"fn": name}
	if recIdx >= 0 {
		if r, ok := argStr(c, recIdx); ok {
			a["recurrence"] = attrText(r)
		}
	}
	e.callFeature(core.FCron, attrText(hook), c, a)
}

// phpHook records add_action and add_filter: FHook for watched hooks
// and the specialised features of user hiding, update filters,
// capability filters and cron schedules.
func (e *extractor) phpHook(c *callSite, kind string) {
	hook, ok := argStr(c, 0)
	if !ok {
		return
	}
	hook = strings.ToLower(hook)
	a := map[string]string{"kind": kind}
	cb, cbName, found := e.callbackBody(c, 1)
	if cbName != "" {
		a["callback"] = attrText(cbName)
	}
	if phpHookWatched(hook) {
		e.callFeature(core.FHook, attrText(hook), c, a)
	}
	switch {
	case userHideHooks[hook]:
		if found && e.hidesUsers(cb, hook) {
			e.callFeature(core.FUserHide, hook, c, map[string]string{"callback": a["callback"]})
		}
	case updateHooks[hook] || strings.HasPrefix(hook, "pre_site_transient_update_"):
		scope := "all"
		if found && e.ownScope(cb) {
			scope = "own"
		}
		u := map[string]string{"scope": scope}
		if cbName != "" {
			u["callback"] = attrText(cbName)
		}
		e.callFeature(core.FUpdateFilter, hook, c, u)
	case capFilters[hook]:
		e.callFeature(core.FCap, "cap:filter:"+hook, c, map[string]string{"callback": a["callback"]})
	case hook == "cron_schedules":
		e.callFeature(core.FCron, "cron_schedules", c, map[string]string{"fn": "add_filter"})
	}
}

// hidesUsers reports whether a callback on a user query or the Users
// views changes them in a way that hides users: it rewrites the WHERE
// clause, excludes IDs or logins, unsets entries or rewrites counts.
func (e *extractor) hidesUsers(r [2]int, hook string) bool {
	toks := e.toks
	for j := r[0]; j < r[1] && j < len(toks); j++ {
		t := toks[j]
		switch {
		case t.k == tName && (t.text == "query_where" || t.text == "query_from") && assignOps[at(toks, j+1).text]:
			return true
		case t.k == tName && t.text == "unset", t.k == tName && (t.text == "str_replace" || t.text == "preg_replace") && hook == "views_users":
			return true
		case t.k == tStr && t.known && (t.val == "exclude" || strings.HasSuffix(t.val, "__not_in")):
			return true
		case t.k == tName && t.text == "set" && at(toks, j-1).punct("->") && at(toks, j+2).k == tStr &&
			(at(toks, j+2).val == "exclude" || strings.HasSuffix(at(toks, j+2).val, "__not_in")):
			return true
		}
	}
	return false
}

// ownScope reports whether an update filter callback limits itself to
// the plugin's own entry: it names its basename or its own file.
func (e *extractor) ownScope(r [2]int) bool {
	return e.contains(r, func(t tok) bool {
		switch t.k {
		case tName:
			return t.text == "plugin_basename" || t.text == "__file__" || strings.Contains(t.text, "basename") ||
				strings.Contains(t.text, "slug") || strings.HasSuffix(t.text, "_file")
		case tVar:
			return strings.Contains(t.text, "basename") || strings.Contains(t.text, "slug")
		case tStr:
			return strings.HasSuffix(t.val, ".php") && strings.Contains(t.val, "/")
		}
		return false
	})
}

// envRead records getenv of a credential-like name, or of the whole
// environment.
func (e *extractor) envRead(c *callSite) {
	if len(c.args) == 0 {
		e.callFeature(core.FEnvRead, "*", c, map[string]string{"fn": "getenv"})
		return
	}
	if n, ok := argStr(c, 0); ok && tokenLike(n) {
		e.callFeature(core.FEnvRead, attrText(n), c, map[string]string{"fn": "getenv"})
	}
}

// write records a file write by where its target lands.
func (e *extractor) write(c *callSite, i int, fn string) {
	h := e.hints(e.span(c, i), c.arg(i).v)
	a := map[string]string{"fn": fn}
	if ext := pathExt(h.lits); ext != "" {
		a["ext"] = ext
	}
	e.callFeature(core.FWrite, writeTarget(h.all), c, a)
}

// credRead records a read of a credential file.
func (e *extractor) credRead(c *callSite, fn string) {
	h := e.hints(e.span(c, 0), c.arg(0).v)
	if t := credTarget(h.lits); t != "" {
		e.note(c.pos, readCreds)
		e.callFeature(core.FCredRead, t, c, map[string]string{"fn": fn})
	}
}

// phpScan reads what the token stream says outside calls: $_ENV,
// $wpdb->users, __halt_compiler and user agent cloaking.
func (e *extractor) phpScan() {
	toks := e.toks
	e.uaVars = e.userAgentVars()
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.k == tVar && t.text == "$_ENV":
			e.note(i, readEnv)
			key := "*"
			if at(toks, i+1).punct("[") && at(toks, i+2).k == tStr {
				key = at(toks, i+2).val
				if !tokenLike(key) {
					continue
				}
			}
			e.col.addAt(t.off, core.FEnvRead, attrText(key), t.line, t.line, e.fnAt(i), map[string]string{"fn": "$_ENV"})
		case t.k == tName && at(toks, i-1).punct("->") && at(toks, i-2).is(tVar, "$wpdb"):
			switch t.text {
			case "users", "usermeta":
				e.note(i, readUsers)
			case "options", "sitemeta":
				e.note(i, readOptions)
			}
		case t.k == tName && t.text == "__halt_compiler":
			// The data starts after "();" or "();?>".
			j := i + 1
			if at(toks, j).punct("(") {
				j = e.st.close(j) + 1
			}
			start := len(e.col.lines.src)
			if n := at(toks, j); n.punct(";") {
				start = n.off + 1
			} else if n.k == tTag {
				start = n.off + len(n.text)
			}
			n := max(len(e.col.lines.src)-start, 0)
			e.col.addAt(t.off, core.FHalt, "__halt_compiler", t.line, t.line, e.fnAt(i), map[string]string{"trailing": strconv.Itoa(n)})
		case t.k == tName && (t.text == "if" || t.text == "elseif") && at(toks, i+1).punct("("):
			e.uaCheck(i)
		}
	}
}

// userAgentVars finds the variables assigned from the user agent, or
// from a variable that was: $ua = $_SERVER['HTTP_USER_AGENT'] and
// $is_bot = preg_match('/bot/i', $ua).
func (e *extractor) userAgentVars() map[string]bool {
	toks := e.toks
	vars := map[string]bool{}
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].k != tVar || !toks[i+1].punct("=") {
			continue
		}
		end := e.exprStop(i+2, len(toks))
		for j := i + 2; j < end; j++ {
			if t := toks[j]; t.k == tStr && strings.EqualFold(t.val, "HTTP_USER_AGENT") || t.k == tVar && vars[t.text] {
				vars[toks[i].text] = true
				break
			}
		}
	}
	return vars
}

// uaCheck reads the if at i: a branch on the user agent naming a
// crawler, or on is_user_logged_in, that prints something is FUACheck
// with what it prints.
func (e *extractor) uaCheck(i int) {
	toks := e.toks
	ce := e.st.close(i + 1)
	if ce >= len(toks) {
		return
	}
	cond := [2]int{i + 2, ce}
	// Most conditions have nothing to do with the user agent: decide that
	// without following variables.
	if !e.contains(cond, func(t tok) bool {
		return t.k == tStr && strings.EqualFold(t.val, "HTTP_USER_AGENT") || t.is(tName, "is_user_logged_in") ||
			t.k == tVar && e.uaVars[t.text]
	}) {
		return
	}
	h := e.hints(cond, value{})
	ua, crawler := false, false
	for _, l := range h.lits {
		ua = ua || strings.Contains(l, "http_user_agent")
		for _, w := range crawlerWords {
			crawler = crawler || strings.Contains(l, w)
		}
	}
	logged := e.contains(cond, func(t tok) bool { return t.is(tName, "is_user_logged_in") })
	key := ""
	switch {
	case ua && crawler:
		key = "user-agent"
	case logged:
		key = "logged-in"
	default:
		return
	}
	then, next := e.branch(ce + 1)
	prints := e.printsOf(then)
	if at(toks, next).is(tName, "else") {
		els, _ := e.branch(next + 1)
		prints = strongerPrint(prints, e.printsOf(els))
		then[1] = els[1]
	}
	if prints == "" {
		return
	}
	end := toks[max(min(then[1], len(toks))-1, i)].line
	e.col.addAt(toks[i].off, core.FUACheck, key, toks[i].line, end, e.fnAt(i), map[string]string{"prints": prints})
}

// branch is the statement or block starting at i and the index after.
func (e *extractor) branch(i int) ([2]int, int) {
	toks := e.toks
	switch {
	case at(toks, i).punct("{"):
		ce := e.st.close(i)
		return [2]int{i + 1, min(ce, len(toks))}, ce + 1
	case at(toks, i).punct(":"):
		for j := i + 1; j < len(toks); j++ {
			if t := toks[j]; t.is(tName, "endif") || t.is(tName, "else") || t.is(tName, "elseif") {
				return [2]int{i + 1, j}, j
			}
			if c := toks[j]; c.punct("(") || c.punct("[") || c.punct("{") {
				j = e.st.close(j)
			}
		}
		return [2]int{i + 1, len(toks)}, len(toks)
	}
	j := e.exprStop(i, len(toks))
	for j < len(toks) && !toks[j].punct(";") && toks[j].k != tTag {
		j = e.exprStop(j+1, len(toks))
	}
	return [2]int{i, j}, j + 1
}

// The values of FUACheck's prints attribute, weakest first.
var printRank = map[string]int{"": 0, "literal": 1, "redirect": 2, "encoded": 3, "fetched": 4}

func strongerPrint(a, b string) string {
	if printRank[b] > printRank[a] {
		return b
	}
	return a
}

// printsOf says what a branch shows: content fetched from the network,
// decoded content, a redirect, literal output, or nothing ("").
func (e *extractor) printsOf(r [2]int) string {
	toks := e.toks
	out, fetched, encoded, redirect := false, false, false, false
	h := e.hints(r, value{})
	for _, n := range h.all {
		switch {
		case phpRemote[n]:
			fetched = true
		case decodeFuncs[n]:
			encoded = true
		}
	}
	for _, l := range h.lits {
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			for _, n := range h.all {
				if phpURLReaders[n] {
					fetched = true
				}
			}
		}
	}
	for j := r[0]; j < r[1] && j < len(toks); j++ {
		t := toks[j]
		switch t.k {
		case tTag:
			out = true
		case tName:
			switch t.text {
			case "echo", "print", "printf", "vprintf", "print_r", "die", "exit", "wp_die", "readfile", "fpassthru", "var_dump":
				out = true
			case "wp_redirect", "wp_safe_redirect":
				redirect = true
			case "header":
				if s := at(toks, j+2); s.k == tStr && strings.HasPrefix(strings.ToLower(s.val), "location") {
					redirect = true
				}
			}
		}
	}
	switch {
	case out && fetched:
		return "fetched"
	case out && encoded:
		return "encoded"
	case redirect:
		return "redirect"
	case out:
		return "literal"
	}
	return ""
}
