#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Installs Sightread for the GitHub Action (action.yml).
#
#   action-install.sh check     picks the version and says whether it's installed
#   action-install.sh install   downloads, verifies and installs that version
#
# check reads VERSION (the version input) and ACTION_REF (github.action_ref)
# and writes version=X.Y.Z, skip=true|false and day=YYYY-MM-DD (the cache
# key of the data packs and archives) to $GITHUB_OUTPUT. With no version
# input it installs the release that matches the action's own tag, so
# RhythmShahriar/sightread@v1.2.3 always runs Sightread 1.2.3 and a new
# release can't change a pinned workflow's results. A branch, a commit or
# a major tag such as @v1 doesn't name a release; then it takes the
# latest one and warns. Every step of a job installs into the same folder,
# so a second Sightread step finds the version already there and skips
# the download.
#
# install reads VERSION (the X.Y.Z from check), DOWNLOAD_URL (the
# download-url input: a folder holding the release files, {version}
# replaced by the version, for mirrors and tests) and VERIFY_SIGNATURE.
# It never builds from source: an archive that fails verify-release.sh is
# not installed.
set -euo pipefail

repo=https://github.com/RhythmShahriar/sightread
dir="${RUNNER_TEMP:?}/sightread-bin"
here=$(cd "$(dirname "$0")" && pwd)

# latest asks GitHub which release /releases/latest redirects to.
latest() {
  local url
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest") || {
    echo "::error::couldn't look up Sightread's latest release at $repo/releases/latest" >&2
    return 1
  }
  case "$url" in
  */releases/tag/v*) printf '%s\n' "${url##*/releases/tag/v}" ;;
  *)
    echo "::error::couldn't tell Sightread's latest release from $url" >&2
    return 1
    ;;
  esac
}

check() {
  local v=${VERSION:-} ref=${ACTION_REF:-}
  if [ -z "$v" ]; then
    if [[ $ref =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      v=$ref
    else
      echo "::warning::Sightread's version isn't pinned: the action ref \"${ref:-none}\" isn't a release tag such as v1.2.3, so the latest release is installed and a new one can change your results. Use the action at a release tag or set the version input."
      v=latest
    fi
  fi
  if [ "$v" = latest ]; then
    if [ -n "${DOWNLOAD_URL:-}" ]; then
      echo "::error::download-url needs the version input: a mirror has no latest release to look up"
      exit 2
    fi
    v=$(latest)
  fi
  v=${v#v}
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]] || {
    echo "::error::version \"$v\" isn't a Sightread version such as 1.2.3 or latest"
    exit 2
  }
  local skip=false
  if [ -x "$dir/rhythm-sightread" ] && [ "$("$dir/rhythm-sightread" --version 2> /dev/null)" = "rhythm-sightread $v" ]; then
    skip=true
    echo "Sightread $v is already installed; skipping the download."
    echo "$dir" >> "${GITHUB_PATH:?}"
  fi
  {
    echo "version=$v"
    echo "skip=$skip"
    echo "day=$(date -u +%Y-%m-%d)"
  } >> "${GITHUB_OUTPUT:?}"
}

install() {
  local v=${VERSION:?} arch os
  case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *)
    echo "::error::unsupported CPU $(uname -m)"
    exit 1
    ;;
  esac
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  local base="$repo/releases/download/v$v" archive="rhythm-sightread_${os}_${arch}.tar.gz"
  if [ -n "${DOWNLOAD_URL:-}" ]; then
    base=${DOWNLOAD_URL//\{version\}/$v}
    base=${base%/}
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  cd "$dir"
  curl -fsSLO "$base/$archive"
  curl -fsSLO "$base/checksums.txt"
  [ "${VERIFY_SIGNATURE:-true}" = false ] || curl -fsSLO "$base/checksums.txt.sigstore.json"
  # The signature, then the checksum: see verify-release.sh.
  "$here/verify-release.sh" "$archive"
  tar -xzf "$archive" rhythm-sightread
  rm -f "$archive" checksums.txt checksums.txt.sigstore.json
  ./rhythm-sightread --version
}

case "${1:-}" in
check) check ;;
install)
  install
  echo "$dir" >> "${GITHUB_PATH:?}"
  ;;
*)
  echo "usage: action-install.sh check|install" >&2
  exit 2
  ;;
esac
