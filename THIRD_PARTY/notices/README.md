# Apache License 2.0 notices

The `rhythm-sightread` binary links Go modules released under the Apache
License 2.0. That license asks that a module's NOTICE file travel with any
binary built from it, so `NOTICE` next to this file holds each of them,
unchanged, under the module path and version from `go.mod`.

Most of these modules come in through `github.com/RhythmShahriar/rhythm/kit/sigverify`,
which checks the Sigstore signature of a release before `rhythm-sightread update`
trusts a data pack from it.

`internal/kitcheck` fails when a linked module has a NOTICE file that is not
here. To refresh the file after a dependency update, copy each NOTICE again.
