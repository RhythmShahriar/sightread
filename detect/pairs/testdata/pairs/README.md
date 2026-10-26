# Fixture pairs

Every signal has at least 3 positive and 3 negative cases here, and at
least one negative case that looks like the bad one and is benign
(`lookalike: true`). `TestEverySignalHasFixtures` fails the build
otherwise.

A case is `<signal-id>/<pos|neg>-<n>/case.yaml`. A `pos` case must
expect its signal. A `neg` case must forbid it, or expect it with a
`max_severity` below its default when the guard lowers it rather than
silencing it.

```yaml
eco: wp-plugin              # required: wp-plugin, wp-theme, composer or npm
note: what the case shows   # for people only
old:                        # path to file contents; or old_dir: <folder next to case.yaml>
  plugin.php: "<?php echo 1;"
new:                        # same; or new_dir
  plugin.php: "<?php eval($_POST['x']);"
meta_old: {ref: {version: 1.0.0}, maintainers: [{name: ann}]}   # core.Meta, snake_case keys
meta_new: {publisher: {name: bob}, requires_php: "8.1"}
lock_old: {integrity: sha512-...}                               # core.Installed
lock_new: {resolved_kind: foreign}
integrity_old: {by: checksums}                                  # core.Integrity
integrity_new: {by: failed, mismatch: [includes/loader.php]}
issues_old: []                                                  # core.ArchiveIssue of the old tree
issues: [{kind: collision, path: a.php, other: A.php}]          # of the new tree
drift: {differ: [plugin.php]}                                   # core.Drift
config: {signals: {domains_ok: ["*.acme.test"]}}                # core.Config (its yaml keys)
now: 2026-10-26T12:00:00Z
lookalike: true             # neg only
features_old: []            # skip the analyzer for this side; a list, or
features_new:               # {found: [...], minified: [...], unanalysed: [{path, reason}]}
  - {kind: eval, key: eval, path: plugin.php, line: 1, context: code,
     attrs: {source: request}, snippet: "eval($_POST['x'])", func: run}
expect:
  - {id: eval-dynamic, min_severity: high}
  - {id: outbound-new-domain, max_severity: info}
forbid: [decode-exec]
```

Fake secrets are written as `{{fakekey:npm}}` (also `github`, `stripe`,
`aws`, `slack`) and expanded at load with `coretest.FakeKey`, so no
case holds a literal key that push protection would block.

A case with files and no `features_old`/`features_new` needs the
analyzer: it is skipped until the analyzer is linked, and fails then
under `SIGHTREAD_REQUIRE_LINKED=1`. A side without `old`, `meta_old`
or `lock_old` is an added package. Names default to `fixture` (or
`acme/fixture` for Composer), versions to 1.0.0 and 2.0.0.
