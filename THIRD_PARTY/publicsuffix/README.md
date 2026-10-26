# Public Suffix List

The `rhythm-sightread` binary embeds the Public Suffix List through
`golang.org/x/net/publicsuffix`, which compiles the list into a table. Sightread
uses it to tell a site's registrable domain from its host when it reads the
domains an update contacts.

The list is published by the Mozilla Foundation and its contributors under the
Mozilla Public License 2.0, whose text is in `LICENSE` next to this file.

- Source of the list: https://publicsuffix.org/list/public_suffix_list.dat
- Its repository: https://github.com/publicsuffix/list
- The Go package that embeds it: https://pkg.go.dev/golang.org/x/net/publicsuffix

Sightread does not change the list. The table in the binary is the one in the
`golang.org/x/net` version named in `go.mod`.
