#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Tests comment.sh offline: the body built from fixture Markdown (marker,
# report, links, the size limit) and posting through a fake gh that
# records each call. CI runs it; so can you: scripts/comment-test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"

# The fake gh: FAKE_COMMENTS is the JSON list of existing comments; each
# call is logged, a POST or PATCH body is saved, FAKE_GH_FAIL fails writes
# the way a read-only token does (403).
cat > "$work/bin/gh" <<'FAKE'
#!/usr/bin/env bash
echo "gh $*" >> "$FAKE_LOG"
method=GET input= jq= path=
while [ $# -gt 0 ]; do
  case "$1" in
  api | --paginate) ;;
  -X) method=$2; shift ;;
  --input) input=$2; shift ;;
  --jq) jq=$2; shift ;;
  *) path=$1 ;;
  esac
  shift
done
if [ "$method" != GET ]; then
  [ -z "${FAKE_GH_FAIL:-}" ] || { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
  cp "$input" "$FAKE_SENT"
  if [ -n "$jq" ]; then echo '{"id": 4242}' | jq -r "$jq"; else echo '{}'; fi
  exit 0
fi
case "$path" in
user)
  [ -n "${FAKE_USER:-}" ] || { echo '{"message": "Resource not accessible by integration"}'; exit 1; }
  printf '{"login": "%s"}' "$FAKE_USER" | jq -r "$jq"
  ;;
*/comments) printf '%s' "${FAKE_COMMENTS:-[]}" | jq -r "$jq" ;;
esac
FAKE
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH" FAKE_LOG="$work/gh.log" FAKE_SENT="$work/sent.json"
export GITHUB_REPOSITORY=acme/site GITHUB_SERVER_URL=https://github.com GITHUB_RUN_ID=42

fail=0
ok() { echo "ok   $1"; }
bad() {
  echo "FAIL $1"
  sed 's/^/     /' "$work/out" | head -40
  fail=1
}
contains() { grep -sqF -- "$2" "$1"; }

cat > "$work/report.md" <<'MD'
## ♪ Sightread

**HOLD** 1 of 3 updates. Read-only: Sightread never ran the code it reviewed.

| Update | Verdict | Findings |
|---|---|---|
| wpforms-lite 1.9.1 → 1.9.2 | HOLD | 1 critical |

### wpforms-lite 1.9.1 → 1.9.2

- **critical** Fetches remote code and runs it, `includes/class-loader.php:88`

<sub>rhythm-sightread 1.0.0 · 2026-10-26 09:05 UTC</sub>
MD

"$here/comment.sh" body "$work/report.md" https://github.com/acme/site/actions/runs/42/artifacts/7 > "$work/out"
if [ "$(head -n 1 "$work/out")" = '<!-- rhythm-sightread -->' ] && contains "$work/out" '| wpforms-lite 1.9.1 → 1.9.2 | HOLD | 1 critical |' &&
  contains "$work/out" '[Full report (JSON and HTML)](https://github.com/acme/site/actions/runs/42/artifacts/7)' &&
  contains "$work/out" '[Workflow run](https://github.com/acme/site/actions/runs/42)' && ! contains "$work/out" 'cut here'; then
  ok "the body has the marker, the verdicts and the links"
else bad "the body has the marker, the verdicts and the links"; fi

# A report far over the limit: 5,000 finding rows and open details.
{
  sed -n '1,9p' "$work/report.md"
  for i in $(seq 5000); do echo "- **high** New outbound domain cdn$i.example in \`src/file-$i.js:1\`"; done
  printf '\n<details><summary>2 notes</summary>\n\n- one\n'
} > "$work/big.md"
"$here/comment.sh" body "$work/big.md" > "$work/out"
chars=$(wc -m < "$work/out")
if [ "$chars" -le 65536 ] && [ "$(head -n 1 "$work/out")" = '<!-- rhythm-sightread -->' ] && contains "$work/out" 'cut here to fit a comment; the full report has every finding' &&
  [ "$(grep -c '^- \*\*high\*\*' "$work/out")" -gt 100 ] && [ "$(tail -n 3 "$work/out" | grep -c '^- \*\*high')" = 0 ]; then
  ok "a long report is cut at a line, under GitHub's limit ($chars characters)"
else bad "a long report is cut at a line, under GitHub's limit ($chars characters)"; fi

# Cut inside <details>: the tag is closed.
{ printf '<details><summary>notes</summary>\n\n'; for i in $(seq 3000); do echo "- note $i, long enough to need some room in the comment body"; done; } > "$work/notes.md"
"$here/comment.sh" body "$work/notes.md" > "$work/out"
if [ "$(grep -c '<details>' "$work/out")" = "$(grep -c '</details>' "$work/out")" ]; then
  ok "a cut inside the notes closes <details>"
else bad "a cut inside the notes closes <details>"; fi

# post: no comment yet, so one is created on the event's pull request and
# its id becomes the comment-id output.
post() {
  rm -f "$work/gh.log" "$work/sent.json"
  : > "$work/output"
  env GITHUB_OUTPUT="$work/output" "$@" "$here/comment.sh" post "$work/report.md" > "$work/out" 2>&1
  code=$?
}
echo '{"pull_request": {"number": 7}}' > "$work/pr.json"
post GITHUB_EVENT_PATH="$work/pr.json" FAKE_COMMENTS='[{"id": 1, "body": "LGTM", "user": {"login": "dev"}}]'
if [ "$code" = 0 ] && contains "$work/gh.log" "-X POST repos/acme/site/issues/7/comments" && ! contains "$work/gh.log" PATCH &&
  [ "$(jq -r .body "$work/sent.json" | head -n 1)" = '<!-- rhythm-sightread -->' ] && grep -qx 'comment-id=4242' "$work/output"; then
  ok "the first run creates the comment and outputs its id"
else bad "the first run creates the comment and outputs its id"; fi

# post again: our comment exists (found by the hidden marker), so it is
# updated, not duplicated.
post GITHUB_EVENT_PATH="$work/pr.json" FAKE_COMMENTS='[{"id": 1, "body": "LGTM", "user": {"login": "dev"}}, {"id": 99, "body": "<!-- rhythm-sightread -->\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}}]'
if [ "$code" = 0 ] && contains "$work/gh.log" "-X PATCH repos/acme/site/issues/comments/99" && ! contains "$work/gh.log" POST &&
  jq -r .body "$work/sent.json" | grep -qF 'Fetches remote code' && grep -qx 'comment-id=99' "$work/output"; then
  ok "a later run updates the same comment"
else bad "a later run updates the same comment"; fi

# Someone else's comment that starts with the marker is never ours.
planted='[{"id": 5, "body": "<!-- rhythm-sightread -->\nAll clear", "user": {"login": "mallory", "type": "User"}}'
post GITHUB_EVENT_PATH="$work/pr.json" FAKE_COMMENTS="$planted]"
if [ "$code" = 0 ] && contains "$work/gh.log" "-X POST repos/acme/site/issues/7/comments" && ! contains "$work/gh.log" PATCH; then
  ok "a comment with the marker from another user is ignored"
else bad "a comment with the marker from another user is ignored"; fi
post GITHUB_EVENT_PATH="$work/pr.json" FAKE_COMMENTS="$planted"', {"id": 99, "body": "<!-- rhythm-sightread -->\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}}]'
if [ "$code" = 0 ] && contains "$work/gh.log" "-X PATCH repos/acme/site/issues/comments/99" && ! contains "$work/gh.log" comments/5; then
  ok "ours is updated, not the planted one before it"
else bad "ours is updated, not the planted one before it"; fi

# A personal access token comments as its user, found through /user.
post GITHUB_EVENT_PATH="$work/pr.json" FAKE_USER=rhythm FAKE_COMMENTS='[{"id": 98, "body": "<!-- rhythm-sightread -->\nold", "user": {"login": "github-actions[bot]"}}, {"id": 99, "body": "<!-- rhythm-sightread -->\nold", "user": {"login": "rhythm"}}]'
if [ "$code" = 0 ] && contains "$work/gh.log" "-X PATCH repos/acme/site/issues/comments/99"; then
  ok "a personal token finds the comment it posted"
else bad "a personal token finds the comment it posted"; fi

# Another app's token: SIGHTREAD_COMMENT_AUTHOR names its bot.
post GITHUB_EVENT_PATH="$work/pr.json" SIGHTREAD_COMMENT_AUTHOR='acme-ci[bot]' FAKE_COMMENTS='[{"id": 97, "body": "<!-- rhythm-sightread -->\nold", "user": {"login": "acme-ci[bot]"}}]'
if [ "$code" = 0 ] && contains "$work/gh.log" "-X PATCH repos/acme/site/issues/comments/97"; then
  ok "SIGHTREAD_COMMENT_AUTHOR names the bot"
else bad "SIGHTREAD_COMMENT_AUTHOR names the bot"; fi

# A schedule or push run has no pull request: a notice, nothing posted.
echo '{}' > "$work/push.json"
post GITHUB_EVENT_PATH="$work/push.json" GITHUB_EVENT_NAME=schedule
if [ "$code" = 0 ] && contains "$work/out" "no pull request for this run (event schedule)" && ! contains "$work/gh.log" POST &&
  [ ! -s "$work/output" ]; then
  ok "no pull request, no comment"
else bad "no pull request, no comment"; fi

# issue_comment on a pull request comments there; on a plain issue, not.
echo '{"issue": {"number": 21, "pull_request": {"url": "https://api.github.com/repos/acme/site/pulls/21"}}}' > "$work/prcomment.json"
post GITHUB_EVENT_PATH="$work/prcomment.json" GITHUB_EVENT_NAME=issue_comment
if [ "$code" = 0 ] && contains "$work/gh.log" "-X POST repos/acme/site/issues/21/comments"; then
  ok "a comment on a pull request is answered there"
else bad "a comment on a pull request is answered there"; fi
echo '{"issue": {"number": 22}}' > "$work/issue.json"
post GITHUB_EVENT_PATH="$work/issue.json" GITHUB_EVENT_NAME=issue_comment
if [ "$code" = 0 ] && contains "$work/out" "no pull request for this run (event issue_comment)" && ! contains "$work/gh.log" POST; then
  ok "a comment on a plain issue gets no comment"
else bad "a comment on a plain issue gets no comment"; fi

# A read-only token (Dependabot, forks) answers 403: a warning, the step
# still succeeds and no comment-id is set.
post GITHUB_EVENT_PATH="$work/pr.json" FAKE_GH_FAIL=1
if [ "$code" = 0 ] && contains "$work/out" '::warning::Sightread: couldn'"'"'t comment on the pull request' &&
  contains "$work/out" 'pull-requests: write' && [ ! -s "$work/output" ]; then
  ok "a read-only token warns and goes on"
else bad "a read-only token warns and goes on"; fi

exit "$fail"
