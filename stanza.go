package main

import "filippo.io/age"

// The rypt recipient stanza:
//
//	-> rypt 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47
//	<the rypt ciphertext of the file key>
//
// The argument is the key id in canonical form, and the body is the raw
// ciphertext rypt returned.

// stanzaType is the type, or tag, of the rypt stanza.
const stanzaType = "rypt"

// newStanza returns the stanza for a file key that rypt encrypted under key.
func newStanza(key keyID, ciphertext []byte) *age.Stanza {
	return &age.Stanza{Type: stanzaType, Args: []string{key.String()}, Body: ciphertext}
}

// stanzaKind is what a stanza in an age header is to this plugin.
type stanzaKind int

const (
	// otherStanza is a stanza of another type, to be ignored.
	otherStanza stanzaKind = iota
	// malformedStanza is a rypt stanza that does not follow the format,
	// which makes the whole header invalid.
	malformedStanza
	// ryptStanza is a rypt stanza made under the key returned with it.
	ryptStanza
)

// parseStanza classifies a stanza. A rypt stanza must have exactly one
// argument, the key id in canonical form, and a body, since rypt never
// returns an empty ciphertext. Stanza types are case-sensitive.
func parseStanza(s *age.Stanza) (stanzaKind, keyID) {
	if s.Type != stanzaType {
		return otherStanza, keyID{}
	}
	if len(s.Args) != 1 || len(s.Body) == 0 {
		return malformedStanza, keyID{}
	}
	key, ok := parseCanonicalUUID(s.Args[0])
	if !ok {
		return malformedStanza, keyID{}
	}
	return ryptStanza, key
}
