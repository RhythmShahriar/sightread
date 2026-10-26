#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Derived from soundcheck/scripts/verify-release.sh

# Checks a downloaded Sightread release before anything runs it.
#
#   verify-release.sh ARCHIVE
#
# Run it in the folder that holds ARCHIVE, checksums.txt and
# checksums.txt.sigstore.json. A checksum from the same release only
# proves the download is intact, not who published it, so first cosign
# checks that checksums.txt was signed by Rhythm's release workflow
# (keyless Sigstore, through GitHub's OIDC issuer) running for the
# sightread repository, called at master as rhythm update requires.
# Then the archive must match its line in it. The release workflow can
# be called from any public repository, which is why the repository is
# checked as well as the workflow.
#
# VERIFY_SIGNATURE=false skips the cosign step (the Action's
# verify-signature input, for mirrors without the bundle) with a warning;
# the checksum is still checked.
set -euo pipefail

archive=${1:?usage: verify-release.sh ARCHIVE}
signer=https://github.com/RhythmShahriar/.github/.github/workflows/release-go.yml@refs/heads/master

files=("$archive" checksums.txt)
[ "${VERIFY_SIGNATURE:-true}" = false ] || files+=(checksums.txt.sigstore.json)
for f in "${files[@]}"; do
  [ -f "$f" ] || { echo "::error::verify-release: $f is missing"; exit 1; }
done

if [ "${VERIFY_SIGNATURE:-true}" = false ]; then
  echo "::warning::verify-release: verify-signature is false, so only the checksum of $archive was checked, not who signed it"
elif ! cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "$signer" \
  --certificate-github-workflow-repository RhythmShahriar/sightread \
  checksums.txt; then
  echo "::error::verify-release: checksums.txt isn't signed by Sightread's release workflow; refusing to install"
  exit 1
fi

line=$(awk -v a="$archive" '$2 == a' checksums.txt)
if [ -z "$line" ]; then
  echo "::error::verify-release: checksums.txt has no line for $archive"
  exit 1
fi
# macOS runners ship shasum, not always sha256sum.
if command -v sha256sum > /dev/null; then
  sum=(sha256sum -c -)
elif command -v shasum > /dev/null; then
  sum=(shasum -a 256 -c -)
else
  echo "::error::verify-release: neither sha256sum nor shasum is installed"
  exit 1
fi
if ! printf '%s\n' "$line" | "${sum[@]}"; then
  echo "::error::verify-release: $archive doesn't match its signed checksum; refusing to install"
  exit 1
fi
