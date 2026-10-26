// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package data holds the data packs and registers them with
// core.SetDataPacks:
//
//   - sightread-names: the popular package names typosquat compares new
//     dependencies with (names/*.json);
//   - sightread-signals: the rule files of detect/code, the known-safe
//     hosts outbound-new-domain treats as known (domains-ok.json) and the
//     pack's version marker (signals/pack.json).
//
// Both are embedded. `rhythm-sightread update` fetches newer ones from
// the latest Sightread release, checks the Sigstore signature over its
// checksums.txt and each asset against it, then keeps them in the cache;
// a newer verified copy there wins over the embedded one unless
// UseEmbedded is on (--no-signal-updates). The packs are data only:
// nothing in them is ever run.
//
// go run ./data/gen refreshes the name lists from public sources (by
// hand, at release prep); go run ./data/gen --pack writes the two
// release assets to data/release/ without touching the network.
package data
