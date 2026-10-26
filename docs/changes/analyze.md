# Changes: analyze lane

What the analyzer reads from a package and what users see because of
it: the features detectors fire on, the `unanalysed` reasons and the
limits. The analyzer lexes PHP and JavaScript with its own Go lexers
(`lex/php`, `lex/js`). It never runs package code (no PHP, Node, npm or
Composer, no script engine) and never reaches the network.

## Which files are read

| File | What the analyzer does |
|---|---|
| PHP (`.php`, `.phtml`, `.inc` and the other PHP extensions) | lexed and analysed as code |
| JavaScript (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts` and friends, `.min.js`) | lexed and analysed as code; checked for minification |
| `package.json` | install scripts and hosts; a `binding.gyp` next to it counts |
| other `.json` (including `composer.json`) | hosts in string values |
| documentation (`readme*`, `changelog*`, `docs/`, `.md`, `.rst`, `.txt`) | hosts only, in context `doc` |
| style sheets (`.css`, `.scss`, `.sass`, `.less`) and `.svg` | data URIs; CSS is checked for minification |
| images, fonts, media, unknown binary files and data text files (`.txt` outside documentation, `.log`, `.csv`, `.po`, `.pot`, `.ini`, `.map` and similar) | checked for hidden code |
| config text (`.yml`, `.env`, `.ini` and the like) and JSON | checked for hard-coded secrets |
| nested archives | listed, never opened |

Links and special files are skipped here; the archive checks report
them.

## What is extracted

Each feature has a kind and a key; a detector fires on a kind and key
present in the new version and absent in the old one. Every feature
carries the path, line, end line, enclosing function and a snippet with
secrets masked and control characters escaped.

- PHP: calls on the watch list (`eval`, `assert`, `system`, `unserialize`,
  `base64_decode`, `file_put_contents`, `wp_insert_user`, `add_cap`,
  `register_rest_route`, `wp_schedule_event`, `wp_remote_*`, `curl_*`,
  `mail`, `__halt_compiler` and the rest), user creation with the role,
  hiding users from the admin list, capability changes, REST routes
  with `permission=open` when anyone may call them, cron hooks, file
  writes by target (`wp-config`, `htaccess`, `mu-plugins`, `plugins-dir`,
  `uploads`, `parent-dir`, `own`, `temp` and more), update filters with
  `scope=own` or `all` (`own` only when the callback uses
  `plugin_basename(__FILE__)`, a name assigned from it, or a
  `folder/file.php` literal whose folder is the package's own top folder
  or main file name; another plugin's entry anywhere in the callback
  makes it `all`), user agent and logged-in checks that print
  content, environment and credential file reads, network sends with
  what the same function reads (`users`, `options`, `admin_email`,
  `env`, `creds`), calls by a built or variable name, eval-like calls,
  includes of files that are not code plus hooks.
- JavaScript: imports of `child_process`, `fs`, `net`, `http`, `https`,
  `dns`, `os`, `vm` and `worker_threads`; process starts; file writes
  and credential reads by target (home folder, `.npmrc`, `.ssh`, `.git`,
  CI files, parent folder); token-like `process.env` reads; network
  sends; `eval`, `Function`, `vm.run*`, timers with a string, dynamic
  `require`. The bundler shim `new Function("return this")` is not
  reported.
- npm: `preinstall`, `install`, `postinstall`, `prepare` and
  `prepublish` scripts (key `npm:<script>`, the masked script text
  attached) and an implicit `node-gyp rebuild`. Script text is read as
  shell: a download piped into a shell is `remote->exec`; `node <file>`
  names the file it runs.
- Data flow inside each function: remote, request, decoded and
  environment data reaching `eval`, `include`, `unserialize`, a dynamic
  call, a code file write or a process start, keyed like
  `remote->eval`, `decode->eval`, `request->unserialize`. Built names
  and strings are folded first, so `'ev'.'al'`, `str_rot13`, `strrev`,
  `chr()` lists, `['e','v','a','l'].join('')` and
  `String.fromCharCode(101,118,97,108)` read as the real name.
- Hosts: URLs and bare hosts from string literals, folded strings,
  comments (context `comment`), JSON values, documentation (context
  `doc`) and npm scripts. Hosts are lower-cased, IDNs turned to
  punycode, ports dropped; the key is the registrable domain (eTLD+1)
  or the IP address. Loopback, private use, reserved and `example.*`
  names are skipped.
- Host categories: `raw-ip`, `blockchain-rpc` (Infura, Alchemy,
  Etherscan, Ankr, QuickNode, PublicNode, BscScan, any `rpc.` host and
  more), `paste` (Pastebin, paste.ee, Hastebin, Ghostbin, Rentry and
  more), `shortener` (bit.ly, TinyURL, t.co, is.gd, cutt.ly and more),
  `dyndns` (DuckDNS, No-IP, ddns.net, ngrok, trycloudflare.com and
  more) and `raw-github` (raw.githubusercontent.com,
  gist.githubusercontent.com).
- Encoded blobs: literals of 512 bytes or more in base64, hex, `\x`
  escapes or character codes, with their entropy, size, the layers
  undone and whether the decoded bytes are code. Decoded code is
  analysed again and its features count in context `decoded`. Data
  URIs are context `asset`: an embedded image or font is not code.
- Minified files: a JavaScript or CSS file is minified when its average
  line is over 500 bytes, more than 90% of its bytes sit on lines over
  1,000 bytes, it carries a source map comment
  (`//# sourceMappingURL=`) or a bundler runtime (`__webpack_require__`,
  `webpackChunk`, `__esbuild`, rollup's helpers), or the archive named
  it `.min.js`. Detectors use the list to keep bundles from looking
  obfuscated; code features in a minified file still count.
- Unicode tricks in code: bidi controls (U+202A to U+202E, U+2066 to
  U+2069) are key `bidi`; zero-width characters (U+200B to U+200D plus
  U+FEFF past the start of the file) are key `zero-width`; a name that
  mixes Latin letters with Cyrillic ones (or with Greek letters that
  look Latin) is key `homoglyph`. The `in` attribute says where:
  `comment`, `string`, `identifier` or `code`. Text in a right to left
  script, joiners inside emoji or Persian and Indic words, a string
  holding only a byte order mark and PHP inline HTML are left alone.
  Translation files are not code and give no Unicode feature.
- Code in assets: PHP (an open tag followed by a statement) in an
  image, font, binary or data text file, or JavaScript making up an
  image or following its end, is `code-in-asset` keyed by the file's
  path with `lang` (`php` or `js`) and `ext`. What that code does is
  analysed too. `<?xml` headers, documentation samples and random
  bytes that spell `<?` do not count.
- Secrets: hard-coded credentials found by kit secrets are `secret`
  features, one per line and secret, keyed by the rule and the masked
  value. In PHP and JavaScript only rules that know a token's format
  count (a Stripe key, a GitHub token, a private key); rules that judge
  a value by its name (`password = ...`, `X-Api-Key: ...`) apply to
  configuration files only. The raw value never appears in a key,
  attribute or snippet. The analyzer reports every secret in the new
  version; the detector keeps those new in this update.

## Unanalysed reasons

A file the analyzer could not read whole is listed with one of these
reasons, exactly. Each becomes an `unanalysed` finding (high), so
padding or a broken construct can never hide code silently.

| Reason | When |
|---|---|
| `file over 4 MiB` | a code file, `package.json` or `composer.json` over the analysis limit (the size follows the limit: `file over <n> MiB`, `KiB` or `bytes`); also an oversized asset whose start or last 1 MiB holds code |
| `analysis time limit` | analysing one file took longer than its budget (2 s); features found before the limit are kept |
| `unterminated <construct> at line <n>` | a PHP string, heredoc, nowdoc, comment, attribute or shell string, or a JavaScript comment or template, never ends; the code before it is still analysed. A JavaScript quote that does not close on its line is not reported: the lexer reads the rest of that line as code, so nothing on it is hidden |
| `decode limit reached` | a blob needed more than 8 decode layers, decoded past 1 MiB or the package passed 16 MiB of decoded output |
| `could not read the file` | the file's bytes could not be read back from the cache |

## Limits

- 4 MiB analysed per file (Limits.EntryAnalysed). Bigger code files are
  `unanalysed`; bigger images, media and other non-code files are
  listed, not flagged, unless they hold code.
- 2 s of analysis per file (Limits.FileBudget), checked every 64Ki
  tokens of the walk and between phases.
- Decoding: at most 8 layers, 1 MiB of output per blob, 16 MiB per
  package. The package budget is counted in path order, so the same
  files pass it on every run.
- Folding: 16 steps and 64 KiB of result per expression.
- Results are the same on every run: files are analysed on one worker
  per CPU and merged sorted by path, line, kind and key.

## How the lexers read tricky input

- PHP ends a line at `\r\n`, `\n` or a bare `\r`; heredoc and nowdoc
  headers and closing labels follow all three, as PHP does.
- JavaScript ends lines (line comments, the hashbang, regular
  expressions) at `\n`, `\r`, U+2028 or U+2029. It reads U+00A0,
  U+FEFF and the other Unicode spaces as whitespace between tokens.
- A slash after the head of `if`, `while`, `for` or `with` starts a
  regular expression.

## No host is ever resolved

The analyzer extracts hosts from text only. It never looks a name up in
DNS and never connects to a host. For parsing it uses only `net/url`,
`net/netip`, `golang.org/x/net/idna` and the embedded public suffix
list of `golang.org/x/net/publicsuffix`; a test of the import graph
holds that.
