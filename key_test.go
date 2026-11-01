package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

// testKey is the key id in the README's examples.
var testKey = mustParseUUID("3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47")

func mustParseUUID(s string) keyID {
	k, err := parseUUID(s)
	if err != nil {
		panic(err)
	}
	return k
}

// Files encrypted with 0.1.0 depend on these exact strings.
var goldenKeys = []struct {
	key, recipient, identity string
}{
	{
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
		"age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g",
		"AGE-PLUGIN-RYPT-18U4FC8NMF48Z48CSDJX452C7GU098V2X",
	},
	{
		"670ef9c3-1a6e-4117-ae6e-ffc92329ff7b",
		"age1rypt1vu80nsc6deq30tnwllyjx20l0vah96qf",
		"AGE-PLUGIN-RYPT-1VU80NSC6DEQ30TNWLLYJX20L0VH9Y308",
	},
}

func TestGoldenEncodings(t *testing.T) {
	for _, g := range goldenKeys {
		key := mustParseUUID(g.key)
		if got := key.String(); got != g.key {
			t.Errorf("String() = %q, want %q", got, g.key)
		}
		if got := key.recipient(); got != g.recipient {
			t.Errorf("recipient(%s) = %q, want %q", g.key, got, g.recipient)
		}
		if got := key.identity(); got != g.identity {
			t.Errorf("identity(%s) = %q, want %q", g.key, got, g.identity)
		}
		if got, err := decodeIdentity(g.identity); err != nil || got != key {
			t.Errorf("decodeIdentity(%q) = %v, %v", g.identity, got, err)
		}
		name, data, err := plugin.ParseRecipient(g.recipient)
		if err != nil || name != "rypt" || !bytes.Equal(data, key[:]) {
			t.Errorf("ParseRecipient(%q) = %q, %x, %v", g.recipient, name, data, err)
		}
	}
}

func TestParseUUIDForms(t *testing.T) {
	for _, s := range []string{
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
		"3F2A9C1E-7B4D-4E2A-9F10-6C8D5A2B1E47",
		"3f2a9c1e7b4d4e2a9f106c8d5a2b1e47",
		"3F2A9C1E7B4D4E2A9F106C8D5A2B1E47",
		"{3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47}",
		"urn:uuid:3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
		"URN:UUID:3F2A9C1E-7B4D-4E2A-9F10-6C8D5A2B1E47",
	} {
		if got, err := parseUUID(s); err != nil || got != testKey {
			t.Errorf("parseUUID(%q) = %v, %v", s, got, err)
		}
	}
}

func TestParseUUIDRejects(t *testing.T) {
	for _, s := range []string{
		"",
		"not-a-uuid",
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e4",
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e477",
		"3f2a9c1e7b4d-4e2a-9f10-6c8d5a2b1e47-",
		"3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47",
		"3f2a9c1g-7b4d-4e2a-9f10-6c8d5a2b1e47",
		"+f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
		" 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47 ",
		"{3f2a9c1e7b4d4e2a9f106c8d5a2b1e47}",
		"(3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47)",
		"urn:uuid:3f2a9c1e7b4d4e2a9f106c8d5a2b1e47",
		"3f2a9c1e7b4d4e2a9f106c8d5a2b1e4é",
	} {
		if got, err := parseUUID(s); err == nil {
			t.Errorf("parseUUID(%q) = %v, want an error", s, got)
		}
	}
}

func TestParseCanonicalUUID(t *testing.T) {
	if got, ok := parseCanonicalUUID(testKey.String()); !ok || got != testKey {
		t.Errorf("parseCanonicalUUID(%q) = %v, %v", testKey.String(), got, ok)
	}
	for _, s := range []string{
		strings.ToUpper(testKey.String()),
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2B1e47",
		"3f2a9c1e7b4d4e2a9f106c8d5a2b1e47",
		"{3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47}",
		"urn:uuid:3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
	} {
		if _, ok := parseCanonicalUUID(s); ok {
			t.Errorf("parseCanonicalUUID(%q) accepted a non-canonical form", s)
		}
	}
}

func TestKeyFromPayloadLength(t *testing.T) {
	if got, err := keyFromPayload(testKey[:]); err != nil || got != testKey {
		t.Errorf("keyFromPayload = %v, %v", got, err)
	}
	for _, n := range []int{0, 1, 15, 17, 32} {
		_, err := keyFromPayload(make([]byte, n))
		want := "key id must be 16 bytes, got " + strconv.Itoa(n)
		if err == nil || err.Error() != want {
			t.Errorf("keyFromPayload(%d bytes) = %v, want %q", n, err, want)
		}
	}
}

func TestDecodeIdentityRejects(t *testing.T) {
	identity := testKey.identity()
	// The last character changed: the checksum no longer matches.
	last := "Q"
	if strings.HasSuffix(identity, last) {
		last = "P"
	}
	corrupt := identity[:len(identity)-1] + last
	for _, tt := range []struct{ in, want string }{
		{strings.ToLower(identity), "identity must be uppercase"},
		{strings.Replace(identity, "AGE", "age", 1), "identity must be uppercase"},
		{corrupt, "invalid Bech32 encoding"},
		{identity[:len(identity)-1], "invalid Bech32 encoding"},
		{"AGE-PLUGIN-RYPT-1", "invalid Bech32 encoding"},
		{strings.ToUpper(testKey.recipient()), "not a rypt identity"},
		{plugin.EncodeIdentity("yubikey", testKey[:]), "not a rypt identity"},
		{"", "not a rypt identity"},
		{plugin.EncodeIdentity("rypt", make([]byte, 15)), "key id must be 16 bytes, got 15"},
		{plugin.EncodeIdentity("rypt", make([]byte, 32)), "key id must be 16 bytes, got 32"},
	} {
		_, err := decodeIdentity(tt.in)
		if err == nil || err.Error() != tt.want {
			t.Errorf("decodeIdentity(%q) = %v, want %q", tt.in, err, tt.want)
		}
	}
}

func TestRecipientAndIdentityCarryTheSamePayload(t *testing.T) {
	r := testKey.recipient()
	i := strings.ToLower(testKey.identity())
	rData := strings.TrimPrefix(r, "age1rypt1")
	iData := strings.TrimPrefix(i, "age-plugin-rypt-1")
	// Same bytes, different checksum: only the six checksum characters differ.
	if rData[:len(rData)-6] != iData[:len(iData)-6] {
		t.Errorf("payloads differ: %q, %q", rData, iData)
	}
}
