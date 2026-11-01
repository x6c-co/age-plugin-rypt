// Whole files encrypted and decrypted by real age clients, which find
// age-plugin-rypt on PATH and drive it over the plugin protocol:
//
//   - TestAgeLibrary…: filippo.io/age, whose plugin package runs the plugin
//     with this process's environment (ported from tests/age_library.rs);
//   - TestAgeCLI…: the age command, or rage, found on PATH, or the one of
//     them that AGE_PLUGIN_RYPT_CLI names (ported from tests/age_cli.rs);
//   - TestAgeCompat…: another implementation named by
//     AGE_PLUGIN_RYPT_COMPAT_BINARY, such as the Rust 0.1.0 build, wrapping
//     what this one unwraps and the other way round.
package e2e

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// ---------------------------------------------------------------------------
// Shared by the three groups

// Keys of these tests: the first golden key, then the Rust 0.1.0 tests'
// second and third keys.
var (
	ageKeyA = MustParseUUID(goldenKeyA)
	ageKeyB = MustParseUUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
	ageKeyC = MustParseUUID("11111111-2222-4333-8444-555555555555")
)

// ageWrongToken is a token the mock refuses with 401. It is long enough for
// the leak checks to look for it.
const ageWrongToken = "ry_Wrong999_abcdefghijklmnopqrstuvwxyz012345"

// agePlaintext returns a payload of three full 64 KiB chunks and part of a
// fourth.
func agePlaintext() []byte {
	p := make([]byte, 200_000)
	for i := range p {
		p[i] = byte(i * 7919 % 251)
	}
	return p
}

// ageHeaderStanzas returns the recipient stanzas of an age file's header, in
// order. It fails the test unless the file starts with a v1 header whose
// stanzas are well formed.
func ageHeaderStanzas(t testing.TB, file []byte) []Stanza {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(file))
	if line, err := r.ReadString('\n'); err != nil || line != "age-encryption.org/v1\n" {
		t.Fatalf("the file does not start with an age v1 header: %q", line)
	}
	var stanzas []Stanza
	for {
		next, err := r.Peek(3)
		if err != nil {
			t.Fatalf("the header ends after %d stanzas: %v", len(stanzas), err)
		}
		if string(next) == "---" {
			return stanzas
		}
		s, err := readStanza(r)
		if err != nil {
			t.Fatalf("reading stanza %d of the header: %v", len(stanzas), err)
		}
		stanzas = append(stanzas, s)
	}
}

// ageStanzaTypes returns the types of an age file's recipient stanzas, in
// order.
func ageStanzaTypes(t testing.TB, file []byte) []string {
	t.Helper()
	var types []string
	for _, s := range ageHeaderStanzas(t, file) {
		types = append(types, s.Type)
	}
	return types
}

// ageCheckRyptStanzas checks the header of a file encrypted with the plugin
// and the mock: it holds a "-> rypt <key>" line for each of keys, those
// keys' rypt stanzas in that order and no other rypt stanza, and each body is
// the mock's ciphertext of one 16-byte file key, the same for all. Other
// stanza types are ignored.
func ageCheckRyptStanzas(t testing.TB, file []byte, keys ...UUID) {
	t.Helper()
	for _, key := range keys {
		if line := "-> rypt " + key.String(); !bytes.Contains(file, []byte("\n"+line+"\n")) {
			t.Errorf("the header has no %q line", line)
		}
	}
	var named []string
	var fileKey []byte
	for _, s := range ageHeaderStanzas(t, file) {
		if s.Type != "rypt" {
			continue
		}
		arg := strings.Join(s.Args, " ")
		named = append(named, arg)
		key, err := ParseUUID(arg)
		if err != nil {
			continue // The comparison of named below reports it.
		}
		opened, ok := toyOpen(key, s.Body)
		if !ok || len(opened) != 16 {
			t.Errorf("the body of the rypt stanza for %s is not the mock's ciphertext of a 16-byte file key", key)
			continue
		}
		if fileKey != nil && !bytes.Equal(opened, fileKey) {
			t.Errorf("the rypt stanza for %s wraps another file key than the one before it", key)
		}
		fileKey = opened
	}
	want := make([]string, len(keys))
	for i, key := range keys {
		want[i] = key.String()
	}
	if !slices.Equal(named, want) {
		t.Errorf("the header's rypt stanzas name %q, want %q", named, want)
	}
}

// ageCheckCalls checks the requests the mock received: encrypts to an
// encrypt path, decrypts to a decrypt path, and nothing else.
func ageCheckCalls(t testing.TB, m *Mock, encrypts, decrypts int) {
	t.Helper()
	e, d, all := m.EncryptCalls(), m.DecryptCalls(), m.Calls()
	if e != encrypts || d != decrypts || all != e+d {
		t.Errorf("the mock got %d encrypt, %d decrypt and %d other requests, want %d encrypt and %d decrypt",
			e, d, all-e-d, encrypts, decrypts)
	}
}

// ageEncrypt encrypts plaintext to recipients with filippo.io/age.
func ageEncrypt(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ageDecrypt decrypts a file with identities with filippo.io/age.
func ageDecrypt(file []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(file), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// ageCrafted is an age recipient run in this process, without the plugin,
// that writes the one stanza its function makes from the file key. It makes
// files with stanzas the plugin would write (ageRyptStanza) or never would.
type ageCrafted func(fileKey []byte) *age.Stanza

func (c ageCrafted) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{c(fileKey)}, nil
}

// ageRyptStanza writes the stanza the plugin writes for key: its canonical
// form as the argument, and the mock's ciphertext of the file key as the
// body.
func ageRyptStanza(key UUID) ageCrafted {
	return func(fileKey []byte) *age.Stanza {
		return &age.Stanza{Type: "rypt", Args: []string{key.String()}, Body: toySeal(key, fileKey)}
	}
}

// ageCraftFile encrypts plaintext to crafted recipients, without the plugin.
func ageCraftFile(t testing.TB, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	file, err := ageEncrypt(plaintext, recipients...)
	if err != nil {
		t.Fatalf("crafting a file: %v", err)
	}
	return file
}

// ---------------------------------------------------------------------------
// (a) filippo.io/age's plugin client
//
// The library runs age-plugin-rypt from PATH, once per recipient or identity,
// with this process's environment. So these tests set the environment with
// t.Setenv and cannot be parallel.

// ageLibEnv starts a mock and points the library's plugin client at the
// built plugin: PATH starts with the plugin's directory, RYPT_TOKEN and
// RYPT_API_URL are the mock's, and the proxy variables and AGEDEBUG (which
// would copy the protocol to stderr) are unset. The test's cleanup restores
// the environment.
func ageLibEnv(t *testing.T) *Mock {
	t.Helper()
	bin := pluginBin(t)
	m := NewMock(t)
	t.Setenv("PATH", bin.Dir()+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RYPT_TOKEN", mockToken)
	t.Setenv("RYPT_API_URL", m.URL())
	for _, name := range []string{
		"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
		"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "AGEDEBUG",
	} {
		ageLibUnsetenv(t, name)
	}
	return m
}

// ageLibUnsetenv removes a variable from this process's environment until
// the test ends.
func ageLibUnsetenv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "") // So that the cleanup restores it.
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// ageLibUI is the library's user interface for the plugin. The rypt plugin
// never shows a message or asks anything, so each callback fails the test.
func ageLibUI(t *testing.T) *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			t.Errorf("the %s plugin showed a message: %q", name, message)
			return nil
		},
		RequestValue: func(name, prompt string, secret bool) (string, error) {
			t.Errorf("the %s plugin asked for a value (secret %v): %q", name, secret, prompt)
			return "", errors.New("no user interface")
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			t.Errorf("the %s plugin asked for a confirmation: %q", name, prompt)
			return false, errors.New("no user interface")
		},
	}
}

// ageLibRecipientFor is the library's recipient for an age1rypt1… string.
func ageLibRecipientFor(t *testing.T, s string) *plugin.Recipient {
	t.Helper()
	r, err := plugin.NewRecipient(s, ageLibUI(t))
	if err != nil {
		t.Fatalf("plugin.NewRecipient(%q): %v", s, err)
	}
	return r
}

// ageLibIdentityFor is the library's identity for an AGE-PLUGIN-RYPT-1…
// string.
func ageLibIdentityFor(t *testing.T, s string) *plugin.Identity {
	t.Helper()
	i, err := plugin.NewIdentity(s, ageLibUI(t))
	if err != nil {
		t.Fatalf("plugin.NewIdentity(%q): %v", s, err)
	}
	return i
}

// ageLibRecipient is the library's recipient for key.
func ageLibRecipient(t *testing.T, key UUID) *plugin.Recipient {
	t.Helper()
	return ageLibRecipientFor(t, recipient(key))
}

// ageLibIdentity is the library's identity for key.
func ageLibIdentity(t *testing.T, key UUID) *plugin.Identity {
	t.Helper()
	return ageLibIdentityFor(t, identity(key))
}

// ageLibIdentities are the library's identities for keys, in order.
func ageLibIdentities(t *testing.T, keys ...UUID) []age.Identity {
	t.Helper()
	var identities []age.Identity
	for _, key := range keys {
		identities = append(identities, ageLibIdentity(t, key))
	}
	return identities
}

// ageLibMustEncrypt encrypts plaintext to recipients, failing the test on an
// error.
func ageLibMustEncrypt(t *testing.T, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	file, err := ageEncrypt(plaintext, recipients...)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	return file
}

// ageLibCheckDecrypts checks that identities decrypt file to plaintext.
func ageLibCheckDecrypts(t *testing.T, file, plaintext []byte, identities ...age.Identity) {
	t.Helper()
	got, err := ageDecrypt(file, identities...)
	if err != nil {
		t.Errorf("decrypting with %d identities: %v", len(identities), err)
	} else if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypting with %d identities gave %d bytes that are not the plaintext", len(identities), len(got))
	}
}

// ageLibCheckNoMatch checks that none of identities matches file: the
// plugin, run once for each, reports no error and no file key.
func ageLibCheckNoMatch(t *testing.T, file []byte, identities ...age.Identity) {
	t.Helper()
	_, err := ageDecrypt(file, identities...)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Errorf("decrypting with %d identities that do not match: %v, want age.NoIdentityMatchError", len(identities), err)
	} else if len(noMatch.Errors) != len(identities) {
		t.Errorf("decrypting with %d identities that do not match: %d of them were tried", len(identities), len(noMatch.Errors))
	}
}

// ageLibCheckError checks that err is the plugin's message as the library
// reports it: "rypt plugin: <message>", after the library's own context if
// it adds any, such as "failed to wrap key for recipient #0: ". The text
// must leak no token, ciphertext or mock response body.
func ageLibCheckError(t *testing.T, err error, message string, ciphertexts ...[]byte) {
	t.Helper()
	want := "rypt plugin: " + message
	if err == nil {
		t.Errorf("no error, want %q", want)
		return
	}
	text := err.Error()
	if text != want && !strings.HasSuffix(text, ": "+want) {
		t.Errorf("error %q, want %q", text, want)
	}
	var noMatch *age.NoIdentityMatchError
	if errors.As(err, &noMatch) {
		t.Errorf("the error is an age.NoIdentityMatchError: %v", err)
	}
	secrets := [][]byte{[]byte(mockToken), []byte(ageWrongToken)}
	checkTextNoLeaks(t, "the error", []byte(text), secrets, ciphertexts)
}

func TestAgeLibraryEncryptsToARecipient(t *testing.T) {
	m := ageLibEnv(t)
	plaintext := agePlaintext()
	file := ageLibMustEncrypt(t, plaintext, ageLibRecipient(t, ageKeyA))
	ageCheckRyptStanzas(t, file, ageKeyA)
	if types := ageStanzaTypes(t, file); !slices.Equal(types, []string{"rypt"}) {
		t.Errorf("stanza types %q, want one rypt stanza", types)
	}
	ageCheckCalls(t, m, 1, 0)
	ageLibCheckDecrypts(t, file, plaintext, ageLibIdentity(t, ageKeyA))
	ageCheckCalls(t, m, 1, 1)
}

func TestAgeLibraryEncryptsToAnIdentity(t *testing.T) {
	m := ageLibEnv(t)
	plaintext := agePlaintext()
	// An identity as a recipient reaches the plugin as add-identity.
	file := ageLibMustEncrypt(t, plaintext, ageLibRecipient(t, ageKeyA), ageLibIdentity(t, ageKeyB).Recipient())
	ageCheckRyptStanzas(t, file, ageKeyA, ageKeyB)
	ageCheckCalls(t, m, 2, 0)

	// Either key decrypts, with one request.
	ageLibCheckDecrypts(t, file, plaintext, ageLibIdentity(t, ageKeyB))
	ageCheckCalls(t, m, 2, 1)
	ageLibCheckDecrypts(t, file, plaintext, ageLibIdentities(t, ageKeyC, ageKeyA)...)
	ageCheckCalls(t, m, 2, 2)

	// An identity for another key does not match, and costs nothing.
	ageLibCheckNoMatch(t, file, ageLibIdentity(t, ageKeyC))
	ageCheckCalls(t, m, 2, 2)
}

func TestAgeLibraryEncryptsToSeveralRecipients(t *testing.T) {
	m := ageLibEnv(t)
	plaintext := agePlaintext()
	keys := []UUID{ageKeyA, ageKeyB, ageKeyC}
	var recipients []age.Recipient
	for _, key := range keys {
		recipients = append(recipients, ageLibRecipient(t, key))
	}
	file := ageLibMustEncrypt(t, plaintext, recipients...)
	ageCheckRyptStanzas(t, file, keys...)
	ageCheckCalls(t, m, 3, 0)

	// Each key decrypts alone, with one request: the stanzas for the other
	// keys cost nothing.
	for i, key := range keys {
		ageLibCheckDecrypts(t, file, plaintext, ageLibIdentity(t, key))
		ageCheckCalls(t, m, 3, i+1)
	}
}

func TestAgeLibraryPicksTheMatchingIdentity(t *testing.T) {
	m := ageLibEnv(t)
	plaintext := agePlaintext()
	file := ageLibMustEncrypt(t, plaintext, ageLibRecipient(t, ageKeyA))

	// The library runs the plugin once per identity. The runs for C and B
	// find no stanza of theirs, cost nothing and report nothing, and the
	// one for A decrypts.
	ageLibCheckDecrypts(t, file, plaintext, ageLibIdentities(t, ageKeyC, ageKeyB, ageKeyA)...)
	ageCheckCalls(t, m, 1, 1)
	ageLibCheckNoMatch(t, file, ageLibIdentities(t, ageKeyC, ageKeyB)...)
	ageCheckCalls(t, m, 1, 1)

	// Identities with no stanza of theirs need no token.
	ageLibUnsetenv(t, "RYPT_TOKEN")
	ageLibCheckNoMatch(t, file, ageLibIdentities(t, ageKeyC, ageKeyB)...)
	ageCheckCalls(t, m, 1, 1)
}

func TestAgeLibraryMixesWithX25519(t *testing.T) {
	m := ageLibEnv(t)
	plaintext := agePlaintext()
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Mixing works only if the plugin's labels (none) equal X25519's.
	file := ageLibMustEncrypt(t, plaintext, ageLibRecipient(t, ageKeyA), x25519.Recipient())
	ageCheckRyptStanzas(t, file, ageKeyA)
	if types := ageStanzaTypes(t, file); !slices.Equal(types, []string{"rypt", "X25519"}) {
		t.Errorf("stanza types %q, want rypt then X25519", types)
	}
	ageCheckCalls(t, m, 1, 0)

	// Either identity decrypts; the X25519 one needs no rypt request.
	ageLibCheckDecrypts(t, file, plaintext, x25519)
	ageCheckCalls(t, m, 1, 0)
	ageLibCheckDecrypts(t, file, plaintext, ageLibIdentity(t, ageKeyA))
	ageCheckCalls(t, m, 1, 1)

	// With the X25519 recipient first.
	file = ageLibMustEncrypt(t, plaintext, x25519.Recipient(), ageLibRecipient(t, ageKeyA))
	if types := ageStanzaTypes(t, file); !slices.Equal(types, []string{"X25519", "rypt"}) {
		t.Errorf("stanza types %q, want X25519 then rypt", types)
	}
	ageCheckRyptStanzas(t, file, ageKeyA)
	ageLibCheckDecrypts(t, file, plaintext, ageLibIdentity(t, ageKeyA))
	ageCheckCalls(t, m, 2, 2)
}

func TestAgeLibraryReportsEncryptErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		// token is RYPT_TOKEN, or "" to unset it.
		token      string
		recipients func(t *testing.T) []age.Recipient
		message    string
		// encrypts is how many encrypt requests the mock gets.
		encrypts int
	}{
		{
			name:  "a key rypt does not have",
			token: mockToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibRecipient(t, statusKey(404))}
			},
			message:  "rypt: key not found",
			encrypts: 1,
		},
		{
			name:  "an identity for a key rypt does not have",
			token: mockToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibIdentity(t, statusKey(404)).Recipient()}
			},
			message:  "rypt: key not found",
			encrypts: 1,
		},
		{
			name:  "the second recipient fails",
			token: mockToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibRecipient(t, ageKeyA), ageLibRecipient(t, statusKey(404))}
			},
			message:  "rypt: key not found",
			encrypts: 2,
		},
		{
			name:  "a token rypt refuses",
			token: ageWrongToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibRecipient(t, ageKeyA)}
			},
			message:  "rypt: unauthorized",
			encrypts: 1,
		},
		{
			name:  "a server error",
			token: mockToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibRecipient(t, statusKey(500))}
			},
			message:  "rypt: 500",
			encrypts: 1,
		},
		{
			name: "no token",
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibRecipient(t, ageKeyA)}
			},
			message: "RYPT_TOKEN is not set",
		},
		{
			name:  "a recipient that is not 16 bytes",
			token: mockToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibRecipientFor(t, rawRecipient(ageKeyA[:15]))}
			},
			message: "key id must be 16 bytes, got 15",
		},
		{
			name:  "an identity that is not 16 bytes",
			token: mockToken,
			recipients: func(t *testing.T) []age.Recipient {
				return []age.Recipient{ageLibIdentityFor(t, rawIdentity(append(ageKeyA[:], 0))).Recipient()}
			},
			message: "key id must be 16 bytes, got 17",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ageLibEnv(t)
			if tc.token == "" {
				ageLibUnsetenv(t, "RYPT_TOKEN")
			} else {
				t.Setenv("RYPT_TOKEN", tc.token)
			}
			file, err := ageEncrypt(agePlaintext(), tc.recipients(t)...)
			if err == nil {
				t.Fatalf("encrypting succeeded with a %d-byte file", len(file))
			}
			ageLibCheckError(t, err, tc.message)
			ageCheckCalls(t, m, tc.encrypts, 0)
		})
	}
}

func TestAgeLibraryReportsDecryptErrors(t *testing.T) {
	// The files are made in this process, without the plugin, so that they
	// can hold stanzas rypt refuses to unwrap or the plugin never writes.
	upper := ageCrafted(func(fileKey []byte) *age.Stanza {
		return &age.Stanza{Type: "rypt", Args: []string{strings.ToUpper(ageKeyA.String())}, Body: toySeal(ageKeyA, fileKey)}
	})
	underAnotherKey := ageCrafted(func(fileKey []byte) *age.Stanza {
		return &age.Stanza{Type: "rypt", Args: []string{ageKeyA.String()}, Body: toySeal(ageKeyC, fileKey)}
	})
	for _, tc := range []struct {
		name string
		// token is RYPT_TOKEN, or "" to unset it.
		token      string
		recipients []age.Recipient
		identity   UUID
		message    string
		// decrypts is how many decrypt requests the mock gets.
		decrypts int
	}{
		{
			name:       "a key rypt does not have",
			token:      mockToken,
			recipients: []age.Recipient{ageRyptStanza(statusKey(404))},
			identity:   statusKey(404),
			message:    "rypt: key not found",
			decrypts:   1,
		},
		{
			name:       "a ciphertext rypt refuses",
			token:      mockToken,
			recipients: []age.Recipient{underAnotherKey},
			identity:   ageKeyA,
			message:    "rypt: 400",
			decrypts:   1,
		},
		{
			name:       "a file key that is not 16 bytes",
			token:      mockToken,
			recipients: []age.Recipient{ageRyptStanza(shortKey)},
			identity:   shortKey,
			message:    "rypt: decrypted file key is not 16 bytes",
			decrypts:   1,
		},
		{
			name:       "a token rypt refuses",
			token:      ageWrongToken,
			recipients: []age.Recipient{ageRyptStanza(ageKeyA)},
			identity:   ageKeyA,
			message:    "rypt: unauthorized",
			decrypts:   1,
		},
		{
			name:       "no token",
			recipients: []age.Recipient{ageRyptStanza(ageKeyA)},
			identity:   ageKeyA,
			message:    "RYPT_TOKEN is not set",
		},
		{
			// Even though the well-formed stanza would unwrap.
			name:       "a malformed rypt stanza",
			token:      mockToken,
			recipients: []age.Recipient{ageRyptStanza(ageKeyA), upper},
			identity:   ageKeyA,
			message:    "rypt: invalid stanza",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ageLibEnv(t)
			if tc.token == "" {
				ageLibUnsetenv(t, "RYPT_TOKEN")
			} else {
				t.Setenv("RYPT_TOKEN", tc.token)
			}
			file := ageCraftFile(t, agePlaintext(), tc.recipients...)
			var bodies [][]byte
			for _, s := range ageHeaderStanzas(t, file) {
				bodies = append(bodies, s.Body)
			}
			got, err := ageDecrypt(file, ageLibIdentity(t, tc.identity))
			if err == nil {
				t.Fatalf("decrypting succeeded with %d bytes", len(got))
			}
			ageLibCheckError(t, err, tc.message, bodies...)
			ageCheckCalls(t, m, 0, tc.decrypts)
		})
	}
}

// ---------------------------------------------------------------------------
// (b) The age command, or rage
//
// The client runs with exactly the Env it is given: the mock's variables and
// PATH set to the plugin's directory alone, so it finds no other
// age-plugin-rypt. These tests can be parallel.
//
// age uses filippo.io/age's plugin client, like the library tests above.
// rage uses the Rust age crate's, which, for one, waits for done after an
// error. Set AGE_PLUGIN_RYPT_CLI=rage to test with rage where both are
// installed.

// ageCLIRequireEnvVar, when set, makes the tests of an age client fail
// instead of skip when neither age nor rage is on PATH. CI sets it, where a
// skip would hide that these tests never ran.
const ageCLIRequireEnvVar = "AGE_PLUGIN_RYPT_REQUIRE_CLI"

// ageCLIEnvVar names the age client to test with, "age" or "rage", when it
// is set. rage is built on the Rust age crate, whose plugin client differs
// from age's, so it is worth testing with even where age is installed.
const ageCLIEnvVar = "AGE_PLUGIN_RYPT_CLI"

// ageCLIClient returns the age client to test with. When ageCLIEnvVar names
// one, it is that one from PATH, and the test fails if it is not there.
// Otherwise it is age from PATH, or else rage, and without either the test
// is skipped, or fails if ageCLIRequireEnvVar is set.
func ageCLIClient(t *testing.T) Bin {
	t.Helper()
	names := []string{"age", "rage"}
	chosen, set := os.LookupEnv(ageCLIEnvVar)
	if set {
		if !slices.Contains(names, chosen) {
			t.Fatalf("%s is %q, want age or rage", ageCLIEnvVar, chosen)
		}
		names = []string{chosen}
	}
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return Bin(abs)
	}
	if set {
		t.Fatalf("%s is %s, but %s is not on PATH", ageCLIEnvVar, chosen, chosen)
	}
	if _, required := os.LookupEnv(ageCLIRequireEnvVar); required {
		t.Fatalf("%s is set, but neither age nor rage is on PATH", ageCLIRequireEnvVar)
	}
	t.Skip("neither age nor rage is on PATH")
	return ""
}

// ageCLIFixture is a directory of files for an age client to work on, and a
// mock for the plugin it runs.
type ageCLIFixture struct {
	t      *testing.T
	client Bin
	mock   *Mock
	// env is the client's environment: the mock's, with PATH set to the
	// plugin's directory.
	env       Env
	dir       string
	plaintext []byte
}

// newAgeCLIFixture finds the client and starts a mock. In a new directory it
// writes plain.bin, holding agePlaintext, and identity.txt, the identity
// file the plugin's new command prints for ageKeyA.
func newAgeCLIFixture(t *testing.T) *ageCLIFixture {
	t.Helper()
	client := ageCLIClient(t)
	t.Logf("the age client is %s", client)
	m := NewMock(t)
	f := &ageCLIFixture{
		t:         t,
		client:    client,
		mock:      m,
		env:       ForMock(m).WithPath(pluginBin(t).Dir()),
		dir:       t.TempDir(),
		plaintext: agePlaintext(),
	}
	f.write("plain.bin", f.plaintext)
	f.writeIdentityFile("identity.txt", ageKeyA)
	return f
}

func (f *ageCLIFixture) path(name string) string {
	return filepath.Join(f.dir, name)
}

func (f *ageCLIFixture) write(name string, data []byte) {
	f.t.Helper()
	if err := os.WriteFile(f.path(name), data, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *ageCLIFixture) read(name string) []byte {
	f.t.Helper()
	data, err := os.ReadFile(f.path(name))
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

// writeIdentityFile writes the identity file the plugin's new command prints
// for key.
func (f *ageCLIFixture) writeIdentityFile(name string, key UUID) {
	f.t.Helper()
	got := runCLI(f.t, Env{}, nil, "new", "--key", key.String())
	if got.ExitCode != 0 || got.Stderr != "" || !strings.HasSuffix(got.Stdout, "\n"+identity(key)+"\n") {
		f.t.Fatalf("new --key %s: exit %d, stdout %q, stderr %q", key, got.ExitCode, got.Stdout, got.Stderr)
	}
	f.write(name, []byte(got.Stdout))
}

// recipient returns the recipient the plugin's recipient command prints for
// an identity file.
func (f *ageCLIFixture) recipient(identityFile string, key UUID) string {
	f.t.Helper()
	got := runCLI(f.t, Env{}, nil, "recipient", f.path(identityFile))
	if want := recipient(key) + "\n"; got.ExitCode != 0 || got.Stderr != "" || got.Stdout != want {
		f.t.Fatalf("recipient %s: exit %d, stdout %q, stderr %q; want stdout %q", identityFile, got.ExitCode, got.Stdout, got.Stderr, want)
	}
	return recipient(key)
}

// run runs the client with env and args. What it prints must leak no token
// and no mock response body.
func (f *ageCLIFixture) run(env Env, args ...string) CLIResult {
	f.t.Helper()
	got := f.client.RunCLI(f.t, env, nil, args...)
	checkTextNoLeaks(f.t, filepath.Base(string(f.client))+"'s stderr", []byte(got.Stderr), envSecrets(env), nil)
	checkTextNoLeaks(f.t, filepath.Base(string(f.client))+"'s stdout", []byte(got.Stdout), envSecrets(env), nil)
	return got
}

// mustRun runs the client with f.env and args, failing the test unless it
// succeeds.
func (f *ageCLIFixture) mustRun(args ...string) {
	f.t.Helper()
	if got := f.run(f.env, args...); got.ExitCode != 0 {
		f.t.Fatalf("%s %q: exit %d, stderr %q", filepath.Base(string(f.client)), args, got.ExitCode, got.Stderr)
	}
}

// checkDecrypts checks that the client decrypts an encrypted file with an
// identity file to the plaintext.
func (f *ageCLIFixture) checkDecrypts(encrypted, identityFile string) {
	f.t.Helper()
	out := encrypted + ".out"
	f.mustRun("-d", "-i", f.path(identityFile), "-o", f.path(out), f.path(encrypted))
	if got := f.read(out); !bytes.Equal(got, f.plaintext) {
		f.t.Errorf("decrypting %s with %s gave %d bytes that are not the plaintext", encrypted, identityFile, len(got))
	}
}

// checkFailure checks that the client failed and reported the plugin's
// message at the end of a line. age prints it as "rypt plugin: <message>".
// rage prints "couldn't use recipient <recipient>: <message>", "couldn't use
// an identity: <message>" or "(stanza 0 0) <message>"; when the plugin does
// not end its turn with done, it prints only that the plugin died.
func (f *ageCLIFixture) checkFailure(got CLIResult, message string) {
	f.t.Helper()
	wants := []string{": " + message + "\n", ") " + message + "\n"}
	if filepath.Base(string(f.client)) == "age" {
		wants = []string{"rypt plugin: " + message + "\n"}
	}
	reported := slices.ContainsFunc(wants, func(want string) bool { return strings.Contains(got.Stderr, want) })
	if got.ExitCode == 0 || !reported {
		f.t.Errorf("exit %d, stderr %q; want a failure that reports %q", got.ExitCode, got.Stderr, message)
	}
}

func TestAgeCLIEncryptsToARecipient(t *testing.T) {
	t.Parallel()
	f := newAgeCLIFixture(t)
	f.mustRun("-e", "-r", f.recipient("identity.txt", ageKeyA), "-o", f.path("r.age"), f.path("plain.bin"))
	ageCheckRyptStanzas(t, f.read("r.age"), ageKeyA)
	ageCheckCalls(t, f.mock, 1, 0)
	f.checkDecrypts("r.age", "identity.txt")
	ageCheckCalls(t, f.mock, 1, 1)
}

func TestAgeCLIEncryptsToAnIdentityFile(t *testing.T) {
	t.Parallel()
	f := newAgeCLIFixture(t)
	f.mustRun("-e", "-i", f.path("identity.txt"), "-o", f.path("i.age"), f.path("plain.bin"))
	ageCheckRyptStanzas(t, f.read("i.age"), ageKeyA)
	ageCheckCalls(t, f.mock, 1, 0)
	f.checkDecrypts("i.age", "identity.txt")
	ageCheckCalls(t, f.mock, 1, 1)
}

func TestAgeCLIMixesRecipients(t *testing.T) {
	t.Parallel()
	f := newAgeCLIFixture(t)
	f.writeIdentityFile("identity-b.txt", ageKeyB)
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f.write("x25519.txt", []byte(x25519.String()+"\n"))

	f.mustRun("-e",
		"-r", f.recipient("identity.txt", ageKeyA),
		"-r", f.recipient("identity-b.txt", ageKeyB),
		"-r", x25519.Recipient().String(),
		"-o", f.path("m.age"), f.path("plain.bin"))
	file := f.read("m.age")
	ageCheckRyptStanzas(t, file, ageKeyA, ageKeyB)
	// In any order: age writes the stanzas in the order of the recipients,
	// rage its own X25519 stanza first. rage also adds grease stanzas, of
	// a random type ending in -grease, which are left out.
	var types []string
	for _, typ := range ageStanzaTypes(t, file) {
		if !strings.HasSuffix(typ, "-grease") {
			types = append(types, typ)
		}
	}
	slices.Sort(types)
	if want := []string{"X25519", "rypt", "rypt"}; !slices.Equal(types, want) {
		t.Errorf("stanza types %q apart from grease, want %q in any order", types, want)
	}
	ageCheckCalls(t, f.mock, 2, 0)

	// The X25519 key needs no rypt request; each rypt key needs one.
	f.checkDecrypts("m.age", "x25519.txt")
	ageCheckCalls(t, f.mock, 2, 0)
	f.checkDecrypts("m.age", "identity-b.txt")
	ageCheckCalls(t, f.mock, 2, 1)
	f.checkDecrypts("m.age", "identity.txt")
	ageCheckCalls(t, f.mock, 2, 2)
}

func TestAgeCLIReportsPluginErrors(t *testing.T) {
	t.Parallel()
	f := newAgeCLIFixture(t)

	// Encrypting to a key rypt does not have.
	got := f.run(f.env, "-e", "-r", recipient(statusKey(404)), "-o", f.path("missing.age"), f.path("plain.bin"))
	f.checkFailure(got, "rypt: key not found")
	ageCheckCalls(t, f.mock, 1, 0)

	// Encrypting with a token rypt refuses.
	got = f.run(f.env.WithToken(ageWrongToken), "-e", "-r", f.recipient("identity.txt", ageKeyA), "-o", f.path("refused.age"), f.path("plain.bin"))
	f.checkFailure(got, "rypt: unauthorized")
	ageCheckCalls(t, f.mock, 2, 0)

	// Encrypting without a token.
	got = f.run(f.env.WithoutToken(), "-e", "-i", f.path("identity.txt"), "-o", f.path("no-token.age"), f.path("plain.bin"))
	f.checkFailure(got, "RYPT_TOKEN is not set")
	ageCheckCalls(t, f.mock, 2, 0)

	// Decrypting without a token, to standard output: nothing is written.
	f.mustRun("-e", "-r", f.recipient("identity.txt", ageKeyA), "-o", f.path("r.age"), f.path("plain.bin"))
	ageCheckCalls(t, f.mock, 3, 0)
	got = f.run(f.env.WithoutToken(), "-d", "-i", f.path("identity.txt"), f.path("r.age"))
	f.checkFailure(got, "RYPT_TOKEN is not set")
	if got.Stdout != "" {
		t.Errorf("decrypting without a token wrote %d bytes to stdout", len(got.Stdout))
	}
	ageCheckCalls(t, f.mock, 3, 0)

	// Decrypting a file for a key rypt does not have.
	f.write("missing.age", ageCraftFile(t, f.plaintext, ageRyptStanza(statusKey(404))))
	f.write("identity-404.txt", []byte(identity(statusKey(404))+"\n"))
	got = f.run(f.env, "-d", "-i", f.path("identity-404.txt"), f.path("missing.age"))
	f.checkFailure(got, "rypt: key not found")
	if got.Stdout != "" {
		t.Errorf("a failed decryption wrote %d bytes to stdout", len(got.Stdout))
	}
	ageCheckCalls(t, f.mock, 3, 1)

	// Encrypting to a recipient that is not 16 bytes, and with an identity
	// file whose identity is not: the plugin refuses each as it reads it.
	got = f.run(f.env, "-e", "-r", rawRecipient(ageKeyA[:15]), "-o", f.path("short.age"), f.path("plain.bin"))
	f.checkFailure(got, "key id must be 16 bytes, got 15")
	f.write("identity-short.txt", []byte(rawIdentity(ageKeyA[:15])+"\n"))
	got = f.run(f.env, "-e", "-i", f.path("identity-short.txt"), "-o", f.path("short.age"), f.path("plain.bin"))
	f.checkFailure(got, "key id must be 16 bytes, got 15")
	ageCheckCalls(t, f.mock, 3, 1)

	// Decrypting with rypt's default identity, which it does not have.
	got = f.run(f.env, "-d", "-j", "rypt", f.path("r.age"))
	f.checkFailure(got, "rypt has no default identity: use -i with a file from age-plugin-rypt new")
	ageCheckCalls(t, f.mock, 3, 1)
}

// ---------------------------------------------------------------------------
// (c) Compatibility with another implementation
//
// Skipped unless AGE_PLUGIN_RYPT_COMPAT_BINARY names one, such as the Rust
// 0.1.0 build. The formats are frozen, so files and identity files made by
// either implementation work with the other.

// ageCompatImpl is one implementation under comparison.
type ageCompatImpl struct {
	name string
	bin  Bin
}

// ageCompatImpls returns the built plugin and the other implementation, in
// that order. It skips the test if AGE_PLUGIN_RYPT_COMPAT_BINARY is unset.
func ageCompatImpls(t *testing.T) []ageCompatImpl {
	t.Helper()
	other := compatBin(t)
	return []ageCompatImpl{{"the built plugin", pluginBin(t)}, {"the compat binary " + string(other), other}}
}

// ageCompatGolden are the spec's golden vectors.
var ageCompatGolden = []struct{ key, recipient, identity string }{
	{goldenKeyA, goldenRecipientA, goldenIdentityA},
	{goldenKeyB, goldenRecipientB, goldenIdentityB},
}

// ageCompatFileKey returns a 16-byte file key that differs with n.
func ageCompatFileKey(n int) []byte {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(n*61 + i*97 + 13)
	}
	return key
}

func TestAgeCompatWrapsAndUnwrapsAcross(t *testing.T) {
	impls := ageCompatImpls(t)
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m)
	keyA, keyB := MustParseUUID(goldenKeyA), MustParseUUID(goldenKeyB)
	fileKeys := [][]byte{ageCompatFileKey(1), ageCompatFileKey(2)}

	// Each wraps two file keys for a recipient and an identity. The mock's
	// cipher is deterministic, so the stanzas are fully predictable.
	wrapped := make([][][]Stanza, len(impls))
	for i, impl := range impls {
		before := m.EncryptCalls()
		o := impl.bin.Wrap(t, env, []string{goldenRecipientA}, []string{goldenIdentityB}, fileKeys...)
		if errs := o.Errors(); len(errs) != 0 || !o.Done || o.ExitCode != 0 {
			t.Fatalf("%s: wrapping: errors %q, done %v, exit %d", impl.name, errs, o.Done, o.ExitCode)
		}
		if n := m.EncryptCalls() - before; n != 2*len(fileKeys) {
			t.Errorf("%s: wrapping made %d encrypt requests, want %d", impl.name, n, 2*len(fileKeys))
		}
		for file, fileKey := range fileKeys {
			got := o.Stanzas(file)
			want := []Stanza{
				{Type: "rypt", Args: []string{goldenKeyA}, Body: toySeal(keyA, fileKey)},
				{Type: "rypt", Args: []string{goldenKeyB}, Body: toySeal(keyB, fileKey)},
			}
			if !slices.EqualFunc(got, want, Stanza.Equal) {
				t.Errorf("%s: file %d: stanzas %+v, want %+v", impl.name, file, got, want)
			}
			wrapped[i] = append(wrapped[i], got)
		}
	}

	// The stanzas are byte-identical: tag, arguments and body.
	for file := range fileKeys {
		a, b := wrapped[0][file], wrapped[1][file]
		sameHeader := func(x, y Stanza) bool { return x.Type == y.Type && slices.Equal(x.Args, y.Args) }
		if !slices.EqualFunc(a, b, sameHeader) {
			t.Errorf("file %d: %s wrote stanzas %+v, %s wrote %+v", file, impls[0].name, a, impls[1].name, b)
		} else if !slices.EqualFunc(a, b, Stanza.Equal) {
			t.Errorf("file %d: the stanza bodies of %s and %s differ", file, impls[0].name, impls[1].name)
		}
	}

	// What each wrapped, the other unwraps, with either key.
	for i, wrapper := range impls {
		unwrapper := impls[1-i]
		for _, id := range []string{goldenIdentityA, goldenIdentityB} {
			before := m.DecryptCalls()
			o := unwrapper.bin.Unwrap(t, env, []string{id}, wrapped[i]...)
			what := unwrapper.name + " unwrapping what " + wrapper.name + " wrapped, with " + id
			if errs := o.Errors(); len(errs) != 0 || !o.Done || o.ExitCode != 0 {
				t.Errorf("%s: errors %q, done %v, exit %d", what, errs, o.Done, o.ExitCode)
				continue
			}
			got := o.FileKeys()
			if len(got) != len(fileKeys) {
				t.Errorf("%s: %d file keys, want %d", what, len(got), len(fileKeys))
			}
			for file, fileKey := range fileKeys {
				if !bytes.Equal(got[file], fileKey) {
					t.Errorf("%s: file %d: wrong file key", what, file)
				}
			}
			if n := m.DecryptCalls() - before; n != len(fileKeys) {
				t.Errorf("%s: %d decrypt requests, want %d", what, n, len(fileKeys))
			}
		}
	}
}

func TestAgeCompatNewKey(t *testing.T) {
	impls := ageCompatImpls(t)
	t.Parallel()
	for _, v := range ageCompatGolden {
		key := MustParseUUID(v.key)
		for _, form := range []string{v.key, strings.ToUpper(v.key), key.Hex(), "{" + v.key + "}", "urn:uuid:" + v.key} {
			var outputs []string
			for _, impl := range impls {
				got := impl.bin.RunCLI(t, Env{}, nil, "new", "--key", form)
				created, rest, _ := strings.Cut(got.Stdout, "\n")
				if got.ExitCode != 0 || got.Stderr != "" || !strings.HasPrefix(created, "# created: ") {
					t.Errorf("%s: new --key %s: exit %d, stdout %q, stderr %q", impl.name, form, got.ExitCode, got.Stdout, got.Stderr)
					continue
				}
				if want := "# key: " + v.key + "\n" + v.identity + "\n"; rest != want {
					t.Errorf("%s: new --key %s: after the created line %q, want %q", impl.name, form, rest, want)
				}
				outputs = append(outputs, rest)
			}
			if len(outputs) == len(impls) && outputs[0] != outputs[1] {
				t.Errorf("new --key %s: after the created line, %s printed %q, %s printed %q",
					form, impls[0].name, outputs[0], impls[1].name, outputs[1])
			}
		}
	}
}

func TestAgeCompatRecipient(t *testing.T) {
	impls := ageCompatImpls(t)
	t.Parallel()
	dir := t.TempDir()

	// recipient prints the same, for each golden key on standard input and
	// for both in one file given by its path.
	both := filepath.Join(dir, "both.txt")
	var bothText, bothWant strings.Builder
	type run struct {
		name  string
		stdin []byte
		args  []string
		want  string
	}
	var runs []run
	for _, v := range ageCompatGolden {
		file := "# created: 2026-10-06T14:21:00-05:00\n# key: " + v.key + "\n" + v.identity + "\n"
		runs = append(runs, run{"the identity file for " + v.key, []byte(file), []string{"recipient"}, v.recipient + "\n"})
		bothText.WriteString(file + "\n")
		bothWant.WriteString(v.recipient + "\n")
	}
	if err := os.WriteFile(both, []byte(bothText.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	runs = append(runs, run{"a file with both identities", nil, []string{"recipient", both}, bothWant.String()})

	for _, r := range runs {
		var outputs []string
		for _, impl := range impls {
			got := impl.bin.RunCLI(t, Env{}, r.stdin, r.args...)
			if got.ExitCode != 0 || got.Stderr != "" || got.Stdout != r.want {
				t.Errorf("%s: recipient, %s: exit %d, stdout %q, stderr %q; want stdout %q",
					impl.name, r.name, got.ExitCode, got.Stdout, got.Stderr, r.want)
			}
			outputs = append(outputs, got.Stdout)
		}
		if outputs[0] != outputs[1] {
			t.Errorf("recipient, %s: %s printed %q, %s printed %q", r.name, impls[0].name, outputs[0], impls[1].name, outputs[1])
		}
	}
}
