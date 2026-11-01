package main

import (
	"bytes"
	"errors"
	"fmt"
)

// renderIdentityFile returns the identity file `new` prints for key.
// created is an RFC 3339 timestamp.
func renderIdentityFile(key keyID, created string) string {
	return fmt.Sprintf("# created: %s\n# key: %s\n%s\n", created, key, key.identity())
}

// identityFileRecipients returns the recipient for every rypt identity in an
// identity file, in order.
//
// Comments, blank lines and identities of other types are skipped. It is an
// error for a rypt identity not to decode or to be one age would refuse,
// and for the file to hold no rypt identity at all.
//
// The file is passed as bytes, and lines are looked at in place, because
// other lines may be secret keys: the caller clears the bytes afterwards,
// and no copy of them is made here.
func identityFileRecipients(file []byte) ([]string, error) {
	var recipients []string
	// Split as age does: lines end at "\n", and one "\r" before it, or at
	// the end of a last line without one, is dropped. A second "\r", as in
	// "\r\r\n", stays part of the line.
	number := 0
	for rest := file; len(rest) > 0; {
		number++
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))

		trimmed := bytes.TrimSpace(line)
		if !isRyptIdentity(trimmed) {
			continue
		}
		if len(trimmed) != len(line) {
			return nil, fmt.Errorf("line %d: identity has surrounding whitespace, which age does not accept", number)
		}
		key, err := decodeIdentity(string(line))
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", number, err)
		}
		recipients = append(recipients, key.recipient())
	}
	if len(recipients) == 0 {
		return nil, errors.New("no rypt identity found")
	}
	return recipients, nil
}

// isRyptIdentity reports whether a line is meant as a rypt identity: its
// Bech32 prefix, everything before the last "1", is that of a rypt
// identity, in either case.
func isRyptIdentity(line []byte) bool {
	i := bytes.LastIndexByte(line, '1')
	return i >= 0 && asciiEqualFold(line[:i], identityHRP)
}

// asciiEqualFold reports whether a and b are equal ignoring the case of
// ASCII letters only, unlike bytes.EqualFold, which also folds some
// non-ASCII letters to ASCII ones.
func asciiEqualFold(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
