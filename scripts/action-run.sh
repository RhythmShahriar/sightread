#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Runs Sightread for the GitHub Action (action.yml).
#
#   action-run.sh run
#
# It reads the Action's inputs from the environment: MODE, PACKAGE,
# SR_PATH, BASE, FAIL_ON, MIN_CONFIDENCE, ALLOW_PARTIAL,
# ALLOW_UNVERIFIED, BASELINE, TRUST_PR_ALLOW, TRANSITIVE, SARIF, SUMMARY
# and ARGS. It runs in the working-directory input.
#
#   mode changes   every version a lockfile change moves, against the
#                  pull request's base (BASE, else GITHUB_BASE_REF), which
#                  is fetched first so origin/<base> exists
#   mode all       every available update under SR_PATH
#   mode package   PACKAGE: one eco:name@version per line, each reviewed
#                  with the plugin, theme, composer or npm command and the
#                  reports merged
#
# It writes the JSON and HTML reports into $RUNNER_TEMP/sightread-report
# (the SARIF file too when SARIF is true) and the Markdown to
# $RUNNER_TEMP/sightread-summary.md (and to the job summary when SUMMARY
# is true). Its outputs are exit-code, verdict, updates, findings,
# report, html, sarif-file, summary and artifact (the upload's name).
# The step itself exits 0: the
# Action passes the exit code on in its last step, after the upload,
# SARIF and comment steps had their turn.
set -uo pipefail

: "${GITHUB_OUTPUT:?}" "${RUNNER_TEMP:?}"
jobsummary=${GITHUB_STEP_SUMMARY:-/dev/null}
out="$RUNNER_TEMP/sightread-report"
markdown="$RUNNER_TEMP/sightread-summary.md"
errlog="$RUNNER_TEMP/sightread-stderr.log"
json="$out/sightread.json"
html="$out/sightread.html"
sarif="$out/sightread.sarif"

# couldnt CODE TEXT tells the job summary, the comment and the log why
# Sightread couldn't review, then exits 0 with exit-code CODE.
couldnt() {
  local code=$1 text=$2 last fence
  # The text can carry what a registry or a lockfile said. A fence
  # longer than any run of tildes in it can't be closed from inside, so
  # none of it renders as Markdown in the summary or the comment.
  fence=$(printf '%s\n' "$text" | grep -o '~*' | awk '{ if (length($0) > n) n = length($0) } END { n = n < 3 ? 3 : n + 1; while (n--) printf "~" }')
  {
    printf '## Sightread\n\nSightread could not review:\n\n%stext\n' "$fence"
    printf '%s\n' "$text"
    printf '%s\n' "$fence"
  } > "$markdown"
  [ "${SUMMARY:-true}" != true ] || cat "$markdown" >> "$jobsummary"
  last=$(printf '%s\n' "$text" | sed '/^[[:space:]]*$/d' | tail -n 1)
  # Workflow commands need % escaped.
  echo "::error::Sightread could not review: ${last//%/%25}"
  {
    echo "exit-code=$code"
    echo "verdict=none"
    echo "updates=0"
    echo "findings=0"
    echo "summary=$markdown"
  } >> "$GITHUB_OUTPUT"
  exit 0
}

# pick_mode sets m: the mode input, else changes on pull requests and
# all otherwise.
pick_mode() {
  m=${MODE:-}
  if [ -z "$m" ]; then
    case "${GITHUB_EVENT_NAME:-}" in
    pull_request | pull_request_target) m=changes ;;
    *) m=all ;;
    esac
  fi
  case "$m" in
  changes | all | package) ;;
  *) couldnt 2 "unknown mode \"$m\": use changes, all or package" ;;
  esac
}

# sightread runs one review command, its stderr to the log as it happens
# and to $errlog for the summary. Its exit code is in $code: with
# pipefail the pipeline fails with rhythm-sightread's code, as tee
# doesn't fail.
sightread() {
  { rhythm-sightread "$@" --plain 2>&1 1>&3 3>&- | tee -a "$errlog" >&2; } 3>&1
  code=$?
}

# artifact_name prints the report artifact's name. The first use of the
# Action in a job uploads sightread-report, later ones sightread-report-2,
# -3 and so on: artifact names are unique in a workflow run.
artifact_name() {
  local count="$RUNNER_TEMP/sightread-artifacts" n=0
  [ -f "$count" ] && n=$(cat "$count")
  [[ $n =~ ^[0-9]+$ ]] || n=0
  n=$((n + 1))
  echo "$n" > "$count"
  if [ "$n" = 1 ]; then echo sightread-report; else echo "sightread-report-$n"; fi
}

# worst combines exit codes the way a review does: findings (1) beat a
# run that couldn't check everything (3); a usage error (2) beats both.
worst() {
  local a=$1 b=$2
  for c in 2 1 3 130; do
    if [ "$a" = "$c" ] || [ "$b" = "$c" ]; then
      printf '%s' "$c"
      return
    fi
  done
  printf '%s' "$a"
}

run() {
  local m code=0
  pick_mode
  mkdir -p "$out"
  : > "$errlog"
  rm -f "$json" "$html" "$sarif" "$markdown"

  # Flags every review gets. ARGS is split on whitespace only: read does
  # no globbing, so --only wp-plugin:* reaches Sightread as written.
  local flags=() extra=()
  local fail=${FAIL_ON:-high}
  flags+=(--fail-on "$fail")
  [ -z "${MIN_CONFIDENCE:-}" ] || flags+=(--min-confidence "$MIN_CONFIDENCE")
  [ "${ALLOW_PARTIAL:-false}" != true ] || flags+=(--allow-partial)
  [ "${ALLOW_UNVERIFIED:-false}" != true ] || flags+=(--allow-unverified)
  [ -z "${BASELINE:-}" ] || flags+=(--baseline "$BASELINE")
  [ "${TRANSITIVE:-false}" != true ] || flags+=(--transitive)
  read -r -d '' -a extra <<< "${ARGS:-}" || true
  local outputs=(-o "$json" -o "$html" -o "$markdown")
  [ "${SARIF:-false}" != true ] || outputs+=(-o "$sarif")
  local path=${SR_PATH:-.}

  case "$m" in
  changes)
    local base=${BASE:-${GITHUB_BASE_REF:-}}
    [ -n "$base" ] || couldnt 2 "mode changes needs a base branch: run it on pull_request or set the base input"
    [[ $base =~ ^[A-Za-z0-9._/-]+$ && $base != *..* && $base != -* ]] || couldnt 2 "base \"$base\" isn't a branch name"
    # actions/checkout fetches only the pull request; the base branch is
    # what lockfiles and allow entries are read from.
    git fetch --no-tags --quiet origin "+refs/heads/$base:refs/remotes/origin/$base" ||
      echo "::warning::Sightread: couldn't fetch origin/$base; with fetch-depth: 0 on actions/checkout it is already there"
    local trust=()
    [ "${TRUST_PR_ALLOW:-false}" != true ] || trust=(--trust-pr-allow)
    sightread changes --base "origin/$base" --path "$path" "${trust[@]}" "${flags[@]}" "${outputs[@]}" "${extra[@]}"
    ;;
  all)
    sightread all "$path" "${flags[@]}" "${outputs[@]}" "${extra[@]}"
    ;;
  package)
    local line n=0 parts=() total=0 cmd name ver eco
    while IFS= read -r line || [ -n "$line" ]; do
      line=${line%$'\r'}
      line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
      [[ -z $line || $line == \#* ]] && continue
      n=$((n + 1))
      [[ $line =~ ^([a-z-]+):(.+)@([^@[:space:]]+)$ ]] || couldnt 2 "package: line $n isn't eco:name@version, e.g. npm:left-pad@1.4.0"
      eco=${BASH_REMATCH[1]} name=${BASH_REMATCH[2]} ver=${BASH_REMATCH[3]}
      # A name or version starting with - would read as a flag.
      [[ $name != -* && $ver != -* ]] || couldnt 2 "package: line $n: a name or version can't start with -"
      case "$eco" in
      wp-plugin | plugin) cmd=plugin ;;
      wp-theme | theme) cmd=theme ;;
      composer | npm) cmd=$eco ;;
      *) couldnt 2 "package: line $n: unknown ecosystem \"$eco\" (want wp-plugin, wp-theme, composer or npm)" ;;
      esac
      sightread "$cmd" "$name" --to "$ver" --path "$path" "${flags[@]}" -o "$out/package-$n.json" "${extra[@]}"
      total=$(worst "$total" "$code")
      [ ! -f "$out/package-$n.json" ] || parts+=("$out/package-$n.json")
    done <<< "${PACKAGE:-}"
    [ "$n" -gt 0 ] || couldnt 2 "mode package needs the package input: one eco:name@version per line"
    if [ "${#parts[@]}" -gt 0 ]; then
      rhythm-sightread report "${parts[@]}" "${outputs[@]}" > /dev/null 2>> "$errlog" || true
      rm -f "${parts[@]}"
    fi
    code=$total
    ;;
  esac

  if [ ! -f "$json" ]; then
    local lines
    lines=$(sed '/^[[:space:]]*$/d' "$errlog" | tail -n 5)
    couldnt "$(worst "$code" 3)" "${lines:-rhythm-sightread exited with $code}"
  fi

  # The outputs scripts read: the worst verdict, counts and file paths.
  # Worst first in the reports' order: an update that couldn't be
  # verified is worse than one with nothing to say.
  local verdict updates findings
  verdict=$(jq -r '[.data.updates[]?.verdict] as $v | first(("hold", "review", "unverified", "allowed", "routine") as $w | select($v | index($w)) | $w) // "none"' "$json" 2> /dev/null || echo none)
  updates=$(jq -r '.summary.updates // 0' "$json" 2> /dev/null || echo 0)
  findings=$(jq -r '[.summary.critical, .summary.high, .summary.medium, .summary.low, .summary.info] | map(. // 0) | add' "$json" 2> /dev/null || echo 0)
  [ "${SUMMARY:-true}" != true ] || cat "$markdown" >> "$jobsummary" 2> /dev/null || true
  {
    echo "exit-code=$code"
    echo "verdict=$verdict"
    echo "updates=$updates"
    echo "findings=$findings"
    echo "report=$json"
    [ ! -f "$html" ] || echo "html=$html"
    [ ! -f "$sarif" ] || echo "sarif-file=$sarif"
    echo "summary=$markdown"
    echo "artifact=$(artifact_name)"
  } >> "$GITHUB_OUTPUT"
}

case "${1:-}" in
run) run ;;
*)
  echo "usage: action-run.sh run" >&2
  exit 2
  ;;
esac
