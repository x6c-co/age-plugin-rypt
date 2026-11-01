package main

import (
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestNewStanzaUsesTheCanonicalKeyID(t *testing.T) {
	s := newStanza(testKey, []byte("ciphertext"))
	if s.Type != "rypt" || !slices.Equal(s.Args, []string{"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47"}) ||
		string(s.Body) != "ciphertext" {
		t.Errorf("newStanza = %+v", s)
	}
}

func TestNewStanzaParsesBack(t *testing.T) {
	kind, key := parseStanza(newStanza(testKey, make([]byte, 40)))
	if kind != ryptStanza || key != testKey {
		t.Errorf("parseStanza = %v, %v", kind, key)
	}
}

func TestOtherStanzaTypesAreIgnored(t *testing.T) {
	key := testKey.String()
	for _, typ := range []string{"X25519", "ssh-ed25519", "RYPT", "Rypt", "rypt-x", "piv-p256"} {
		s := &age.Stanza{Type: typ, Args: []string{key}, Body: []byte{1, 2, 3}}
		if kind, _ := parseStanza(s); kind != otherStanza {
			t.Errorf("parseStanza(%q) = %v, want otherStanza", typ, kind)
		}
	}
}

func TestRyptStanzasOffTheFormatAreMalformed(t *testing.T) {
	key := testKey.String()
	simple := strings.ReplaceAll(key, "-", "")
	for _, s := range []*age.Stanza{
		{Type: "rypt", Body: []byte{1}},
		{Type: "rypt", Args: []string{key, "extra"}, Body: []byte{1}},
		{Type: "rypt", Args: []string{"not-a-uuid"}, Body: []byte{1}},
		{Type: "rypt", Args: []string{strings.ToUpper(key)}, Body: []byte{1}},
		{Type: "rypt", Args: []string{simple}, Body: []byte{1}},
		{Type: "rypt", Args: []string{"{" + key + "}"}, Body: []byte{1}},
		{Type: "rypt", Args: []string{"urn:uuid:" + key}, Body: []byte{1}},
		{Type: "rypt", Args: []string{key}},
		{Type: "rypt", Args: []string{key}, Body: []byte{}},
	} {
		if kind, _ := parseStanza(s); kind != malformedStanza {
			t.Errorf("parseStanza(%+v) = %v, want malformedStanza", s, kind)
		}
	}
}
