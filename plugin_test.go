package main

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"filippo.io/age"
)

// testRing returns a keyring for keys whose client talks to f, and a
// pointer to how many times it was connected.
func testRing(t *testing.T, f *fakeRypt, keys ...keyID) (*keyring, []*identity, *int) {
	t.Helper()
	connects := 0
	ring := &keyring{api: &lazyClient{connect: func() (*apiClient, error) {
		connects++
		return newTestClient(t, f.URL, 5*time.Second), nil
	}}}
	var ids []*identity
	for _, k := range keys {
		ids = append(ids, ring.add(k))
	}
	return ring, ids, &connects
}

// sealed returns a stanza the fake rypt decrypts to fileKey.
func sealed(key keyID, fileKey []byte) *age.Stanza {
	return newStanza(key, append([]byte("ct:"), fileKey...))
}

var fileKey = bytes.Repeat([]byte{0x42}, 16)

func TestUnwrapsTheStanzaForALoadedKey(t *testing.T) {
	f := newFakeRypt(t, nil)
	_, ids, _ := testRing(t, f, testKey)
	other := &age.Stanza{Type: "X25519", Args: []string{"abc"}, Body: []byte{1}}
	got, err := ids[0].Unwrap([]*age.Stanza{other, sealed(otherKey, nil), sealed(testKey, fileKey)})
	if err != nil || !bytes.Equal(got, fileKey) {
		t.Fatalf("Unwrap = %x, %v", got, err)
	}
	// The stanza for a key that is not loaded cost nothing.
	if n := f.requests.Load(); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

func TestOnlyTheFirstIdentityUnwraps(t *testing.T) {
	f := newFakeRypt(t, nil)
	_, ids, _ := testRing(t, f, otherKey, testKey)
	if !ids[0].first || ids[1].first {
		t.Fatalf("first = %v, %v", ids[0].first, ids[1].first)
	}
	stanzas := []*age.Stanza{sealed(testKey, fileKey)}
	if _, err := ids[1].Unwrap(stanzas); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Errorf("second identity: err = %v", err)
	}
	// The first identity unwraps for the second identity's key too.
	if got, err := ids[0].Unwrap(stanzas); err != nil || !bytes.Equal(got, fileKey) {
		t.Errorf("first identity: %x, %v", got, err)
	}
}

func TestNoMatchingStanzaNeedsNoClient(t *testing.T) {
	ring := &keyring{api: &lazyClient{connect: func() (*apiClient, error) {
		t.Error("connected without a matching stanza")
		return nil, errors.New(msgTokenNotSet)
	}}}
	id := ring.add(testKey)
	for _, stanzas := range [][]*age.Stanza{
		nil,
		{sealed(otherKey, fileKey)},
		{{Type: "X25519", Args: []string{"abc"}, Body: []byte{1}}},
		{{Type: "RYPT", Args: []string{testKey.String()}, Body: []byte{1}}},
	} {
		if _, err := id.Unwrap(stanzas); !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("err = %v, want ErrIncorrectIdentity", err)
		}
	}
}

func TestAMissingTokenFailsOnlyAMatchingFile(t *testing.T) {
	ring := &keyring{api: &lazyClient{connect: func() (*apiClient, error) {
		return nil, errors.New(msgTokenNotSet)
	}}}
	id := ring.add(testKey)
	if _, err := id.Unwrap([]*age.Stanza{sealed(otherKey, fileKey)}); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Errorf("other key: err = %v", err)
	}
	if _, err := id.Unwrap([]*age.Stanza{sealed(testKey, fileKey)}); errText(err) != msgTokenNotSet {
		t.Errorf("matching key: err = %v", err)
	}
}

func TestAMalformedStanzaBlocksTheFile(t *testing.T) {
	f := newFakeRypt(t, nil)
	_, ids, connects := testRing(t, f, testKey)
	malformed := &age.Stanza{Type: "rypt", Args: []string{"not-a-uuid"}, Body: []byte{1}}
	for _, stanzas := range [][]*age.Stanza{
		{sealed(testKey, fileKey), malformed},
		{malformed, sealed(testKey, fileKey)},
		// Even when no stanza is for a loaded key.
		{malformed},
		{sealed(otherKey, fileKey), malformed},
	} {
		if _, err := ids[0].Unwrap(stanzas); errText(err) != "rypt: invalid stanza" {
			t.Errorf("err = %v", err)
		}
	}
	if n := f.requests.Load(); n != 0 || *connects != 0 {
		t.Errorf("%d requests, %d connects, want none", n, *connects)
	}
}

func TestTriesStanzasInHeaderOrderAndStopsAtTheFirstSuccess(t *testing.T) {
	f := newFakeRypt(t, nil)
	bad := statusKey(400)
	_, ids, _ := testRing(t, f, testKey, bad)
	stanzas := []*age.Stanza{sealed(bad, fileKey), sealed(testKey, fileKey), sealed(testKey, fileKey)}
	got, err := ids[0].Unwrap(stanzas)
	if err != nil || !bytes.Equal(got, fileKey) {
		t.Fatalf("Unwrap = %x, %v", got, err)
	}
	if n := f.requests.Load(); n != 2 {
		t.Errorf("%d requests, want 2", n)
	}
}

func TestFailuresAreJoinedOnce(t *testing.T) {
	f := newFakeRypt(t, nil)
	k400, k404, k409 := statusKey(400), statusKey(404), statusKey(409)
	_, ids, connects := testRing(t, f, k400, k404, k409)
	stanzas := []*age.Stanza{sealed(k404, fileKey), sealed(k400, fileKey), sealed(k404, fileKey), sealed(k409, fileKey)}
	_, err := ids[0].Unwrap(stanzas)
	if want := "rypt: key not found; rypt: 400; rypt: 409"; errText(err) != want {
		t.Errorf("err = %q, want %q", errText(err), want)
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		t.Error("a failure must not read as ErrIncorrectIdentity")
	}
	if *connects != 1 {
		t.Errorf("%d connects, want 1", *connects)
	}
}

func TestRecipientWrapsWithOneRequest(t *testing.T) {
	f := newFakeRypt(t, nil)
	api := &lazyClient{connect: func() (*apiClient, error) { return newTestClient(t, f.URL, 5*time.Second), nil }}
	r := &recipient{key: testKey, api: api}
	stanzas, err := r.Wrap(fileKey)
	if err != nil || len(stanzas) != 1 {
		t.Fatalf("Wrap = %v, %v", stanzas, err)
	}
	if kind, key := parseStanza(stanzas[0]); kind != ryptStanza || key != testKey {
		t.Errorf("stanza = %+v", stanzas[0])
	}
	if f.requests.Load() != 1 {
		t.Errorf("%d requests", f.requests.Load())
	}
}

func TestLazyClientConnectsOnce(t *testing.T) {
	n := 0
	l := &lazyClient{connect: func() (*apiClient, error) { n++; return nil, errors.New("no") }}
	for range 3 {
		if _, err := l.get(); errText(err) != "no" {
			t.Errorf("err = %v", err)
		}
	}
	if n != 1 {
		t.Errorf("connected %d times", n)
	}
}
