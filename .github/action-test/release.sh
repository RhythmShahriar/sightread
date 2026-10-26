#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Makes the release folders action-test.yml serves to the Action's
# install step through its download-url input, laid out like a GitHub
# release: rhythm-sightread_linux_amd64.tar.gz and checksums.txt, plus
# checksums.txt.sigstore.json where a signature is part of the case.
#
#   release.sh build DIR VERSION   this checkout built as VERSION, unsigned
#                                  (the Action runs with verify-signature false)
#   release.sh bad-sum DIR         checksums.txt no longer matches the archive
#   release.sh swap DIR ARCHIVE    replaces the archive with ARCHIVE and
#                                  rewrites its checksums.txt line to match,
#                                  as someone replacing both files would; the
#                                  signature over the old checksums.txt stays
#   release.sh junk-sig DIR        adds a checksums.txt.sigstore.json that
#                                  signs nothing, so only a skipped check passes
#
# Run it from the repository root.
set -euo pipefail

archive=rhythm-sightread_linux_amd64.tar.gz

build() {
	local dir=${1:?usage: release.sh build DIR VERSION} v=${2:?usage: release.sh build DIR VERSION}
	local work
	work=$(mktemp -d)
	mkdir -p "$dir"
	# The flags .goreleaser.yaml builds a release with.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK=off go build -trimpath \
		-ldflags "-s -w -X main.version=$v" -o "$work/rhythm-sightread" ./cmd/rhythm-sightread
	cp README.md LICENSE "$work/"
	tar -czf "$dir/$archive" -C "$work" rhythm-sightread README.md LICENSE
	rm -rf "$work"
	(cd "$dir" && sha256sum "$archive" >checksums.txt)
	echo "built $v into $dir"
}

bad_sum() {
	local dir=${1:?usage: release.sh bad-sum DIR}
	# Flip the hash to all zeros: the archive is the one that was built,
	# the published checksum isn't its own any more.
	printf '%064d  %s\n' 0 "$archive" >"$dir/checksums.txt"
}

swap() {
	local dir=${1:?usage: release.sh swap DIR ARCHIVE} other=${2:?usage: release.sh swap DIR ARCHIVE}
	local sum
	[ "$other" -ef "$dir/$archive" ] || cp "$other" "$dir/$archive"
	sum=$(sha256sum "$dir/$archive" | cut -d' ' -f1)
	grep -v " $archive\$" "$dir/checksums.txt" >"$dir/checksums.new" || true
	echo "$sum  $archive" >>"$dir/checksums.new"
	mv "$dir/checksums.new" "$dir/checksums.txt"
}

junk_sig() {
	local dir=${1:?usage: release.sh junk-sig DIR}
	printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' >"$dir/checksums.txt.sigstore.json"
}

case "${1:-}" in
build)
	shift
	build "$@"
	;;
bad-sum)
	shift
	bad_sum "$@"
	;;
swap)
	shift
	swap "$@"
	;;
junk-sig)
	shift
	junk_sig "$@"
	;;
*)
	echo "usage: release.sh build DIR VERSION | bad-sum DIR | swap DIR ARCHIVE | junk-sig DIR" >&2
	exit 2
	;;
esac
