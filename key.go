package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age/plugin"
)

// pluginName is the plugin's name. age maps the recipient prefix age1rypt
// and the identity prefix AGE-PLUGIN-RYPT- to the binary age-plugin-rypt.
const pluginName = "rypt"

// identityHRP is the Bech32 prefix of every rypt identity.
const identityHRP = "AGE-PLUGIN-RYPT-"

// keyID is a rypt key id: the 16 bytes of its UUID.
//
// The recipient and the identity of a key both encode these 16 bytes, and
// nothing else. Neither is secret: they only say which rypt key to ask for,
// and the rypt API token is what authorizes the request.
type keyID [16]byte

// String returns the key id in canonical form: lowercase hexadecimal in
// 8-4-4-4-12 groups.
func (k keyID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], k[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], k[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], k[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], k[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], k[10:16])
	return string(b[:])
}

// recipient returns the key's age1rypt1... recipient.
func (k keyID) recipient() string {
	return plugin.EncodeRecipient(pluginName, k[:])
}

// identity returns the key's AGE-PLUGIN-RYPT-1... identity.
func (k keyID) identity() string {
	return plugin.EncodeIdentity(pluginName, k[:])
}

// errNotUUID is the error for a string that is not a UUID.
var errNotUUID = errors.New("not a UUID")

// parseUUID reads a key id written as a UUID in any of the usual forms:
// 8-4-4-4-12 hexadecimal groups, the same in braces or after "urn:uuid:",
// or 32 hexadecimal digits. Letters may be in either case.
func parseUUID(s string) (keyID, error) {
	switch {
	case len(s) == 38 && s[0] == '{' && s[37] == '}':
		s = s[1:37]
	case len(s) == 45 && strings.EqualFold(s[:9], "urn:uuid:"):
		s = s[9:]
	}
	var hexDigits string
	switch len(s) {
	case 32:
		hexDigits = s
	case 36:
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return keyID{}, errNotUUID
		}
		hexDigits = s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	default:
		return keyID{}, errNotUUID
	}
	var k keyID
	// hex.Decode accepts both cases and refuses anything but hex digits.
	if n, err := hex.Decode(k[:], []byte(hexDigits)); err != nil || n != len(k) {
		return keyID{}, errNotUUID
	}
	return k, nil
}

// parseCanonicalUUID reads a key id in canonical form only, as String
// writes it.
func parseCanonicalUUID(s string) (keyID, bool) {
	if len(s) != 36 || strings.ToLower(s) != s {
		return keyID{}, false
	}
	k, err := parseUUID(s)
	return k, err == nil
}

// keyFromPayload reads a key id from a decoded Bech32 payload.
func keyFromPayload(data []byte) (keyID, error) {
	var k keyID
	if len(data) != len(k) {
		return keyID{}, fmt.Errorf("key id must be 16 bytes, got %d", len(data))
	}
	copy(k[:], data)
	return k, nil
}

// decodeIdentity reads the key id from an AGE-PLUGIN-RYPT-1... identity.
//
// Bech32 itself also allows all-lowercase strings, but age clients only
// recognize plugin identities in uppercase, so lowercase is refused.
func decodeIdentity(s string) (keyID, error) {
	if strings.ToUpper(s) != s {
		return keyID{}, errors.New("identity must be uppercase")
	}
	if i := strings.LastIndexByte(s, '1'); i < 0 || s[:i] != identityHRP {
		return keyID{}, errors.New("not a rypt identity")
	}
	name, data, err := plugin.ParseIdentity(s)
	if err != nil || name != pluginName {
		return keyID{}, errors.New("invalid Bech32 encoding")
	}
	return keyFromPayload(data)
}
