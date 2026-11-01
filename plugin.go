package main

import (
	"errors"
	"slices"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// The messages for stanzas and identities age's framework cannot judge.
const (
	msgInvalidStanza     = "rypt: invalid stanza"
	msgNoDefaultIdentity = "rypt has no default identity: use -i with a file from age-plugin-rypt new"
)

// newPlugin returns age's plugin framework set up for rypt recipients and
// identities. connect builds the API client; it is called at most once,
// and only when a file key has to be wrapped or a stanza for a loaded key
// unwrapped, so a run that needs no request needs no token either.
func newPlugin(connect func() (*apiClient, error)) (*plugin.Plugin, error) {
	p, err := plugin.New(pluginName)
	if err != nil {
		return nil, err
	}
	api := &lazyClient{connect: connect}
	newRecipient := func(data []byte) (age.Recipient, error) {
		key, err := keyFromPayload(data)
		if err != nil {
			return nil, err
		}
		return &recipient{key: key, api: api}, nil
	}
	p.HandleRecipient(newRecipient)
	// age -e -i <identity file> encrypts to the identity's key.
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		if len(data) == 0 {
			return nil, errors.New(msgNoDefaultIdentity)
		}
		return newRecipient(data)
	})
	ring := &keyring{api: api}
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		if len(data) == 0 {
			return nil, errors.New(msgNoDefaultIdentity)
		}
		key, err := keyFromPayload(data)
		if err != nil {
			return nil, err
		}
		return ring.add(key), nil
	})
	return p, nil
}

// lazyClient builds the API client on first use and keeps it, or the error.
type lazyClient struct {
	connect func() (*apiClient, error)
	client  *apiClient
	err     error
	done    bool
}

func (l *lazyClient) get() (*apiClient, error) {
	if !l.done {
		l.client, l.err = l.connect()
		l.done = true
	}
	return l.client, l.err
}

// recipient wraps file keys with one rypt key.
type recipient struct {
	key keyID
	api *lazyClient
}

// Wrap encrypts the file key with rypt and returns the rypt stanza.
func (r *recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	client, err := r.api.get()
	if err != nil {
		return nil, err
	}
	ciphertext, err := client.encrypt(r.key, fileKey)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{newStanza(r.key, ciphertext)}, nil
}

// keyring holds the keys of every rypt identity a run of the plugin was
// given.
//
// age's framework asks each identity in turn to unwrap a file, and stops at
// the first one that fails. The plugin should instead try every stanza for
// any loaded key, in header order, and only fail when none unwraps. So the
// first identity does the work for all the loaded keys, and the others
// leave it to the first.
type keyring struct {
	keys []keyID
	api  *lazyClient
}

// add adds a key and returns the identity for it.
func (r *keyring) add(key keyID) *identity {
	r.keys = append(r.keys, key)
	return &identity{ring: r, first: len(r.keys) == 1}
}

// identity is one of a keyring's identities.
type identity struct {
	ring  *keyring
	first bool
}

// Unwrap recovers a file key from the stanzas of one file, for any key in
// the keyring.
func (id *identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if !id.first {
		return nil, age.ErrIncorrectIdentity
	}
	return id.ring.unwrap(stanzas)
}

// unwrap tries each rypt stanza for a loaded key in header order and
// returns the first file key recovered. If every attempt fails, the error
// lists each distinct failure. If no stanza is for a loaded key, it returns
// age.ErrIncorrectIdentity.
func (r *keyring) unwrap(stanzas []*age.Stanza) ([]byte, error) {
	type candidate struct {
		key        keyID
		ciphertext []byte
	}
	var candidates []candidate
	for _, s := range stanzas {
		kind, key := parseStanza(s)
		switch {
		case kind == malformedStanza:
			// A malformed rypt stanza makes the header invalid. The plugin
			// protocol requires an error for it, and nothing unwrapped
			// from the file, even by another stanza.
			return nil, errors.New(msgInvalidStanza)
		case kind == ryptStanza && slices.Contains(r.keys, key):
			candidates = append(candidates, candidate{key, s.Body})
		}
	}
	if len(candidates) == 0 {
		return nil, age.ErrIncorrectIdentity
	}

	client, err := r.api.get()
	if err != nil {
		return nil, err
	}
	var failures []string
	for _, c := range candidates {
		fileKey, err := client.decrypt(c.key, c.ciphertext)
		if err == nil {
			return fileKey, nil
		}
		if !slices.Contains(failures, err.Error()) {
			failures = append(failures, err.Error())
		}
	}
	return nil, errors.New(strings.Join(failures, "; "))
}
