#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Tests the Action's helper scripts offline: action-run.sh with a fake
# rhythm-sightread and a fake git that record their arguments,
# action-install.sh with a fake curl that serves a local mirror. CI runs
# it; so can you: scripts/action-test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin" "$work/mirror"

# The fake Sightread: each call's arguments go to $FAKE_ARGS, one per
# line, then a line "--end--". Every -o file is written: .json from
# FAKE_JSON, the others a stub. FAKE_EXIT is the exit code, FAKE_STDERR
# its stderr, FAKE_NO_REPORT writes nothing.
cat > "$work/bin/rhythm-sightread" <<'FAKE'
#!/usr/bin/env bash
{ printf '%s\n' "$@"; echo --end--; } >> "$FAKE_ARGS"
if [ -z "${FAKE_NO_REPORT:-}" ]; then
  while [ $# -gt 0 ]; do
    if [ "$1" = -o ]; then
      case "$2" in
      *.json) cp "$FAKE_JSON" "$2" ;;
      *.md) printf '## Sightread\n\nfake review\n' > "$2" ;;
      *) printf 'stub\n' > "$2" ;;
      esac
    fi
    shift
  done
fi
[ -z "${FAKE_STDERR:-}" ] || printf '%s\n' "$FAKE_STDERR" >&2
exit "${FAKE_EXIT:-0}"
FAKE
cat > "$work/bin/git" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_GIT"
exit "${FAKE_GIT_EXIT:-0}"
FAKE
# The fake curl answers the latest-release lookup and serves
# https://mirror.test/<file> from $FAKE_MIRROR.
cat > "$work/bin/curl" <<'FAKE'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
  -fsSLI) printf 'https://github.com/RhythmShahriar/sightread/releases/tag/v9.8.7'; exit 0 ;;
  https://mirror.test/*) f=${a#https://mirror.test/}; f=${f#v9.9.9/}; [ -f "$FAKE_MIRROR/$f" ] || exit 22; cp "$FAKE_MIRROR/$f" "$(basename "$a")" ;;
  esac
done
FAKE
chmod +x "$work/bin/rhythm-sightread" "$work/bin/git" "$work/bin/curl"
export PATH="$work/bin:$PATH" FAKE_ARGS="$work/args" FAKE_GIT="$work/git" FAKE_JSON="$work/report.json" FAKE_MIRROR="$work/mirror"

cat > "$work/report.json" <<'JSON'
{"schema": "rhythm-sightread/v1", "kind": "review", "complete": true,
 "summary": {"updates": 3, "hold": 1, "review": 1, "routine": 1, "allowed": 0, "unverified": 0,
             "critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0},
 "verdict": "findings",
 "data": {"updates": [{"name": "a", "verdict": "routine"}, {"name": "b", "verdict": "hold"}, {"name": "c", "verdict": "review"}]}}
JSON

fail=0
ok() { echo "ok   $1"; }
bad() {
  echo "FAIL $1"
  sed 's/^/     /' "$work/log"
  fail=1
}

# act SCRIPT ARG [VAR=value...] runs a helper with a fresh runner
# environment and the given inputs. Its status is in $code.
act() {
  local script=$1 arg=$2
  shift 2
  rm -rf "$work/runner" "$work/args" "$work/git"
  mkdir -p "$work/runner/temp" "$work/site"
  : > "$work/runner/output"
  : > "$work/runner/summary"
  : > "$work/runner/path"
  (
    cd "$work/site" || exit 99
    env GITHUB_OUTPUT="$work/runner/output" GITHUB_STEP_SUMMARY="$work/runner/summary" \
      GITHUB_PATH="$work/runner/path" RUNNER_TEMP="$work/runner/temp" "$@" \
      "$here/$script" "$arg"
  ) > "$work/log" 2>&1
  code=$?
}
has() { grep -qxF -- "$2" "$1" 2> /dev/null; }      # has FILE LINE
contains() { grep -qF -- "$2" "$1" 2> /dev/null; } # contains FILE TEXT
out() { has "$work/runner/output" "$1"; }
# calls counts the fake Sightread's runs.
calls() { grep -cx -- --end-- "$work/args" 2> /dev/null || echo 0; }
temp="$work/runner/temp"

# A pull request: mode changes against the fetched base.
act action-run.sh run GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF=main
if [ "$code" = 0 ] && has "$work/args" changes && has "$work/args" --base && has "$work/args" origin/main &&
  contains "$work/git" "fetch --no-tags --quiet origin +refs/heads/main:refs/remotes/origin/main" &&
  has "$work/args" --fail-on && has "$work/args" high && has "$work/args" --plain && ! has "$work/args" --trust-pr-allow; then
  ok "a pull request runs changes against its fetched base"
else bad "a pull request runs changes against its fetched base"; fi
if out exit-code=0 && out verdict=hold && out updates=3 && out findings=4 && out "report=$temp/sightread-report/sightread.json" &&
  out "html=$temp/sightread-report/sightread.html" && out "summary=$temp/sightread-summary.md" && ! contains "$work/runner/output" sarif-file &&
  contains "$work/runner/summary" "fake review"; then
  ok "the outputs and the job summary"
else bad "the outputs and the job summary"; fi

# Two uses of the Action in one job upload under different names.
rm -rf "$work/runner" && mkdir -p "$work/runner/temp"
: > "$work/runner/output"
for _ in 1 2 3; do
  (cd "$work/site" && GITHUB_OUTPUT="$work/runner/output" GITHUB_STEP_SUMMARY=/dev/null RUNNER_TEMP="$work/runner/temp" MODE=all \
    "$here/action-run.sh" run > "$work/log" 2>&1)
done
if [ "$(grep '^artifact=' "$work/runner/output" | tr '\n' ' ')" = "artifact=sightread-report artifact=sightread-report-2 artifact=sightread-report-3 " ]; then
  ok "each use of the Action in a job gets its own artifact name"
else
  cp "$work/runner/output" "$work/log"
  bad "each use of the Action in a job gets its own artifact name"
fi

act action-run.sh run GITHUB_EVENT_NAME=push SR_PATH=web
if [ "$code" = 0 ] && [ "$(sed -n 1,2p "$work/args" | tr '\n' ' ')" = "all web " ] && [ ! -e "$work/git" ]; then
  ok "a push runs all on the path"
else bad "a push runs all on the path"; fi

act action-run.sh run MODE=changes BASE=release/2.x TRUST_PR_ALLOW=true FAIL_ON=none MIN_CONFIDENCE=confirmed \
  ALLOW_PARTIAL=true ALLOW_UNVERIFIED=true BASELINE=old.json TRANSITIVE=true ARGS="--only wp-plugin:* --jobs 2" SARIF=true SUMMARY=false
if [ "$code" = 0 ] && has "$work/args" origin/release/2.x && has "$work/args" --trust-pr-allow && has "$work/args" none &&
  has "$work/args" confirmed && has "$work/args" --allow-partial && has "$work/args" --allow-unverified && has "$work/args" old.json &&
  has "$work/args" --transitive && has "$work/args" 'wp-plugin:*' && has "$work/args" "$temp/sightread-report/sightread.sarif" &&
  out "sarif-file=$temp/sightread-report/sightread.sarif" && [ ! -s "$work/runner/summary" ]; then
  ok "every input reaches Sightread, args unglobbed, SARIF on, summary off"
else bad "every input reaches Sightread, args unglobbed, SARIF on, summary off"; fi

act action-run.sh run MODE=changes FAKE_GIT_EXIT=1 BASE=main
if [ "$code" = 0 ] && contains "$work/log" "::warning::Sightread: couldn't fetch origin/main" && has "$work/args" changes; then
  ok "a failed fetch warns and still runs"
else bad "a failed fetch warns and still runs"; fi

act action-run.sh run MODE=changes
if [ "$code" = 0 ] && out exit-code=2 && contains "$work/runner/summary" "mode changes needs a base branch" && [ ! -e "$work/args" ]; then
  ok "changes without a base says so"
else bad "changes without a base says so"; fi

act action-run.sh run MODE=changes BASE="-x;rm"
if out exit-code=2 && contains "$work/runner/summary" "isn't a branch name" && [ ! -e "$work/git" ]; then
  ok "a base that isn't a branch name is refused before git runs"
else bad "a base that isn't a branch name is refused before git runs"; fi

act action-run.sh run MODE=nope
if out exit-code=2 && contains "$work/runner/summary" 'unknown mode "nope"'; then
  ok "an unknown mode"
else bad "an unknown mode"; fi

# Findings at fail-on: exit 1 is passed on as the exit-code output.
act action-run.sh run MODE=all FAKE_EXIT=1
if [ "$code" = 0 ] && out exit-code=1 && out verdict=hold; then
  ok "exit 1 is passed on"
else bad "exit 1 is passed on"; fi

# Exit 3 without a report: the summary says why, with the last lines,
# in a fence that registry text can't close.
act action-run.sh run MODE=all FAKE_EXIT=3 FAKE_NO_REPORT=1 FAKE_STDERR=$'registry said:\n~~~\n[click](https://evil.example)\nrhythm-sightread: can'"'"'t reach registry.npmjs.org (no such host)'
md="$temp/sightread-summary.md"
if out exit-code=3 && out verdict=none && contains "$work/runner/summary" "Sightread could not review:" &&
  contains "$work/log" "::error::Sightread could not review: rhythm-sightread: can't reach registry.npmjs.org (no such host)" &&
  has "$md" '~~~~text' && [ "$(tail -n 1 "$md")" = '~~~~' ] && [ "$(grep -cx '~~~~' "$md")" = 1 ]; then
  ok "exit 3 writes 'could not review' to the summary"
else bad "exit 3 writes 'could not review' to the summary"; fi

# Package mode: one call per line, then the reports merged.
act action-run.sh run MODE=package SR_PATH=site PACKAGE=$'wp-plugin:akismet@5.3.5\n\n# a comment\ntheme:astra@4.8.1\r\ncomposer:monolog/monolog@3.8.0\nnpm:@acme/ui@2.0.0'
if [ "$code" = 0 ] && [ "$(calls)" = 5 ] && contains "$work/args" $'plugin\nakismet\n--to\n5.3.5\n--path\nsite' &&
  contains "$work/args" $'theme\nastra\n--to\n4.8.1' && contains "$work/args" $'composer\nmonolog/monolog\n--to\n3.8.0' &&
  contains "$work/args" $'npm\n@acme/ui\n--to\n2.0.0' && contains "$work/args" $'report\n'"$temp/sightread-report/package-1.json" &&
  out verdict=hold && [ ! -e "$temp/sightread-report/package-1.json" ]; then
  ok "package mode reviews each line and merges the reports"
else bad "package mode reviews each line and merges the reports"; fi

act action-run.sh run MODE=package PACKAGE=$'npm:left-pad@1.4.0\nnpm:axios@1.8.0' FAKE_EXIT=1
if out exit-code=1; then ok "package mode keeps the worst exit code"; else bad "package mode keeps the worst exit code"; fi

# A package already at the requested version: Sightread writes a report
# with no updates and exits 0, which is a pass, not "could not review".
cat > "$work/empty.json" <<'JSON'
{"schema": "rhythm-sightread/v1", "kind": "review", "complete": true,
 "summary": {"updates": 0}, "notes": ["akismet 5.3.5 is already the latest: nothing to compare"], "data": {"updates": []}}
JSON
act action-run.sh run MODE=package PACKAGE=wp-plugin:akismet@5.3.5 FAKE_JSON="$work/empty.json"
if [ "$code" = 0 ] && out exit-code=0 && out verdict=none && out updates=0 && ! contains "$work/log" "::error::"; then
  ok "a package already at its version passes"
else bad "a package already at its version passes"; fi

act action-run.sh run MODE=package PACKAGE="left-pad 1.4.0"
if out exit-code=2 && contains "$work/runner/summary" "package: line 1 isn't eco:name@version" && [ ! -e "$work/args" ]; then
  ok "a package line without eco:name@version is refused"
else bad "a package line without eco:name@version is refused"; fi

act action-run.sh run MODE=package PACKAGE="pypi:requests@2.0.0"
if out exit-code=2 && contains "$work/runner/summary" 'unknown ecosystem "pypi"'; then
  ok "an unknown ecosystem is refused"
else bad "an unknown ecosystem is refused"; fi

act action-run.sh run MODE=package
if out exit-code=2 && contains "$work/runner/summary" "mode package needs the package input"; then
  ok "package mode without packages"
else bad "package mode without packages"; fi

# Install: the version follows the action's tag, a matching install is reused.
act action-install.sh check ACTION_REF=v2.3.4
if [ "$code" = 0 ] && out version=2.3.4 && out skip=false && grep -qE '^day=[0-9]{4}-[0-9]{2}-[0-9]{2}$' "$work/runner/output" &&
  ! contains "$work/log" "::warning::"; then
  ok "the action's tag picks the version"
else bad "the action's tag picks the version"; fi

act action-install.sh check ACTION_REF=v1
if [ "$code" = 0 ] && out version=9.8.7 && contains "$work/log" '::warning::Sightread'"'"'s version isn'"'"'t pinned: the action ref "v1"'; then
  ok "a major tag takes the latest release and warns"
else bad "a major tag takes the latest release and warns"; fi

# init ci pins the Action by commit and writes the version input with it.
act action-install.sh check ACTION_REF=0123456789abcdef0123456789abcdef01234567 VERSION=1.0.0
if [ "$code" = 0 ] && out version=1.0.0 && ! contains "$work/log" "::warning::"; then
  ok "a commit pin with the version input installs that release"
else bad "a commit pin with the version input installs that release"; fi

act action-install.sh check ACTION_REF=0123456789abcdef0123456789abcdef01234567
if [ "$code" = 0 ] && out version=9.8.7 && contains "$work/log" "is pinned to commit 0123456789abcdef0123456789abcdef01234567" &&
  contains "$work/log" "Set the version input"; then
  ok "a commit pin without the version input warns how to pin it"
else bad "a commit pin without the version input warns how to pin it"; fi

act action-install.sh check VERSION=v1.0.0 ACTION_REF=v2.3.4
if out version=1.0.0; then ok "the version input wins"; else bad "the version input wins"; fi

act action-install.sh check VERSION="1.0.0; rm -rf /"
if [ "$code" = 2 ]; then ok "a malformed version is refused"; else bad "a malformed version is refused"; fi

act action-install.sh check DOWNLOAD_URL=https://mirror.test/ ACTION_REF=main
if [ "$code" = 2 ] && contains "$work/log" "download-url needs the version input"; then
  ok "a mirror needs a version"
else bad "a mirror needs a version"; fi

installed() { # installed VERSION ARGS... runs check with VERSION already installed
  local v=$1
  shift
  rm -rf "$work/runner"
  mkdir -p "$work/runner/temp/sightread-bin"
  printf '#!/bin/sh\necho "rhythm-sightread %s"\n' "$v" > "$work/runner/temp/sightread-bin/rhythm-sightread"
  chmod +x "$work/runner/temp/sightread-bin/rhythm-sightread"
  : > "$work/runner/output"
  : > "$work/runner/path"
  env GITHUB_OUTPUT="$work/runner/output" GITHUB_PATH="$work/runner/path" RUNNER_TEMP="$work/runner/temp" "$@" \
    "$here/action-install.sh" check > "$work/log" 2>&1
  code=$?
}
installed 1.2.3 VERSION=1.2.3
if [ "$code" = 0 ] && out skip=true && contains "$work/log" "Sightread 1.2.3 is already installed; skipping the download." &&
  has "$work/runner/path" "$work/runner/temp/sightread-bin"; then
  ok "a matching install is reused"
else bad "a matching install is reused"; fi
installed 1.2.2 VERSION=1.2.3
if out skip=false; then ok "another version is replaced"; else bad "another version is replaced"; fi

# install from a mirror: the archive must match checksums.txt; a changed
# checksums.txt or archive is refused, never installed.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; *) arch=arm64 ;; esac
archive="rhythm-sightread_${os}_${arch}.tar.gz"
mirror() { # mirror [tamper]
  rm -rf "$work/pkg" "$work/mirror"/*
  mkdir -p "$work/pkg"
  printf '#!/bin/sh\necho "rhythm-sightread 9.9.9"\n' > "$work/pkg/rhythm-sightread"
  chmod +x "$work/pkg/rhythm-sightread"
  tar -czf "$work/mirror/$archive" -C "$work/pkg" rhythm-sightread
  (cd "$work/mirror" && sha256sum "$archive" > checksums.txt)
  [ "${1:-}" != tamper ] || printf 'extra\n' >> "$work/mirror/$archive"
}
mirror
act action-install.sh install VERSION=9.9.9 DOWNLOAD_URL='https://mirror.test/v{version}' VERIFY_SIGNATURE=false
if [ "$code" = 0 ] && contains "$work/log" "rhythm-sightread 9.9.9" && has "$work/runner/path" "$temp/sightread-bin" &&
  contains "$work/log" "verify-signature is false"; then
  ok "install from a mirror checks the checksum"
else bad "install from a mirror checks the checksum"; fi
mirror tamper
act action-install.sh install VERSION=9.9.9 DOWNLOAD_URL='https://mirror.test/v{version}' VERIFY_SIGNATURE=false
if [ "$code" != 0 ] && contains "$work/log" "doesn't match its signed checksum; refusing to install" && [ ! -e "$temp/sightread-bin/rhythm-sightread" ] &&
  [ ! -s "$work/runner/path" ]; then
  ok "a changed archive is refused"
else bad "a changed archive is refused"; fi
# A Windows runner gets a clear error, not a 404 for a .tar.gz.
printf '#!/bin/sh\n[ "$1" = -s ] && echo MINGW64_NT-10.0-20348 || echo x86_64\n' > "$work/bin/uname"
chmod +x "$work/bin/uname"
act action-install.sh install VERSION=9.9.9 DOWNLOAD_URL='https://mirror.test/v{version}' VERIFY_SIGNATURE=false
rm -f "$work/bin/uname"
if [ "$code" = 1 ] && contains "$work/log" "::error::the Sightread Action runs on Linux and macOS runners, not Windows" &&
  [ ! -e "$temp/sightread-bin/rhythm-sightread" ]; then
  ok "a Windows runner is refused with a clear error"
else bad "a Windows runner is refused with a clear error"; fi
mirror
act action-install.sh install VERSION=9.9.9 DOWNLOAD_URL='https://mirror.test/v{version}'
if [ "$code" != 0 ] && [ ! -e "$temp/sightread-bin/rhythm-sightread" ]; then
  ok "without the signature bundle nothing is installed"
else bad "without the signature bundle nothing is installed"; fi

exit "$fail"
