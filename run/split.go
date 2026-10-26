// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"errors"
	"runtime"
	"strings"
)

// SplitCommand splits a command line such as --wp "ssh deploy@host -- wp
// --path='/srv/my site'" into argv the way a POSIX shell splits words,
// without running a shell: blanks separate words, single quotes keep
// everything literal, double quotes keep blanks and let a backslash
// escape " and \; a backslash outside quotes escapes the next
// character. Nothing is expanded ($, *, ~ and ; are plain characters), so
// a value can never start a second command.
//
// On Windows a backslash is a path separator, so it is literal
// everywhere except before a double quote: --wp "C:\tools\wp.bat
// --path=C:\site" keeps its paths.
func SplitCommand(s string) ([]string, error) { return splitCommand(s, runtime.GOOS == "windows") }

// splitCommand is SplitCommand with Windows' backslash rule when windows
// is set.
func splitCommand(s string, windows bool) ([]string, error) {
	var (
		args    []string
		cur     strings.Builder
		inWord  bool
		quote   byte
		escaped bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' && !windows):
				i++
				cur.WriteByte(s[i])
			default:
				cur.WriteByte(c)
			}
		case c == '\\' && windows && (i+1 == len(s) || s[i+1] != '"'):
			cur.WriteByte(c)
			inWord = true
		case c == '\\':
			escaped, inWord = true, true
		case c == '\'' || c == '"':
			quote, inWord = c, true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	switch {
	case quote != 0:
		return nil, errors.New("a quote is not closed")
	case escaped:
		return nil, errors.New("it ends with a backslash")
	}
	if inWord {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("it is empty")
	}
	return args, nil
}
