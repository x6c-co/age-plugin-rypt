package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

var otherKey = mustParseUUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")

func TestRenderIdentityFile(t *testing.T) {
	file := renderIdentityFile(testKey, "2026-09-29T20:32:00-05:00")
	want := "# created: 2026-09-29T20:32:00-05:00\n" +
		"# key: 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47\n" +
		"AGE-PLUGIN-RYPT-18U4FC8NMF48Z48CSDJX452C7GU098V2X\n"
	if file != want {
		t.Errorf("renderIdentityFile = %q, want %q", file, want)
	}
}

func recipientsOf(t *testing.T, file string) ([]string, string) {
	t.Helper()
	got, err := identityFileRecipients([]byte(file))
	if err != nil {
		return got, err.Error()
	}
	return got, ""
}

func TestRecipientsReadsARenderedFile(t *testing.T) {
	got, err := recipientsOf(t, renderIdentityFile(testKey, "2026-09-29T20:32:00Z"))
	if err != "" || !slices.Equal(got, []string{testKey.recipient()}) {
		t.Errorf("got %q, %q", got, err)
	}
}

func TestRecipientsReadsEveryRyptIdentityAndSkipsOthers(t *testing.T) {
	file := "# a comment 1\n\n" + testKey.identity() + "\r\n" +
		"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n" +
		"AGE-PLUGIN-RYPT-1FOO-1QQQQQQQQQQ\n" +
		"AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQ\n" +
		otherKey.identity() + "\r"
	got, err := recipientsOf(t, file)
	if err != "" || !slices.Equal(got, []string{testKey.recipient(), otherKey.recipient()}) {
		t.Errorf("got %q, %q", got, err)
	}
}

func TestRecipientsRejectsACorruptRyptIdentity(t *testing.T) {
	identity := testKey.identity()
	_, err := recipientsOf(t, "# key: "+testKey.String()+"\n"+identity[:len(identity)-1]+"\n")
	if err != "line 2: invalid Bech32 encoding" {
		t.Errorf("err = %q", err)
	}
}

func TestRecipientsRejectsAPaddedRyptIdentity(t *testing.T) {
	for _, pad := range []string{" %", "% ", "\t%", "%\t", " %"} {
		file := "# key\n" + strings.Replace(pad, "%", testKey.identity(), 1) + "\n"
		_, err := recipientsOf(t, file)
		if err != "line 2: identity has surrounding whitespace, which age does not accept" {
			t.Errorf("%q: err = %q", pad, err)
		}
	}
}

func TestRecipientsStripsOnlyOneCarriageReturn(t *testing.T) {
	identity := testKey.identity()
	if got, err := recipientsOf(t, identity+"\r"); err != "" || len(got) != 1 {
		t.Errorf("got %q, %q", got, err)
	}
	if got, err := recipientsOf(t, identity); err != "" || len(got) != 1 {
		t.Errorf("no final newline: got %q, %q", got, err)
	}
	_, err := recipientsOf(t, "# key\n"+identity+"\r\r\n")
	if err != "line 2: identity has surrounding whitespace, which age does not accept" {
		t.Errorf("err = %q", err)
	}
}

func TestRecipientsRejectsALowercaseRyptIdentity(t *testing.T) {
	_, err := recipientsOf(t, "# key\n"+strings.ToLower(testKey.identity())+"\n")
	if err != "line 2: identity must be uppercase" {
		t.Errorf("err = %q", err)
	}
	_, err = recipientsOf(t, "Age-Plugin-Rypt-1"+strings.TrimPrefix(testKey.identity(), identityHRP+"1")+"\n")
	if err != "line 1: identity must be uppercase" {
		t.Errorf("mixed case: err = %q", err)
	}
}

func TestRecipientsRejectsAWrongLengthPayload(t *testing.T) {
	for _, n := range []int{0, 15, 17} {
		identity := plugin.EncodeIdentity("rypt", make([]byte, n))
		_, err := recipientsOf(t, identity+"\n")
		if want := fmt.Sprintf("line 1: key id must be 16 bytes, got %d", n); err != want {
			t.Errorf("%d bytes: err = %q, want %q", n, err, want)
		}
	}
}

func TestRecipientsRequiresARyptIdentity(t *testing.T) {
	for _, file := range []string{"", "\n", "# only a comment\nAGE-SECRET-KEY-1QQQQ\n", "AGE-PLUGIN-RYPT-\n"} {
		if _, err := recipientsOf(t, file); err != "no rypt identity found" {
			t.Errorf("%q: err = %q", file, err)
		}
	}
}

func TestIsRyptIdentityMatchesASCIICaseOnly(t *testing.T) {
	for _, line := range []string{"AGE-PLUGIN-RYPT-1X", "age-plugin-rypt-1x", "Age-Plugin-Rypt-1"} {
		if !isRyptIdentity([]byte(line)) {
			t.Errorf("isRyptIdentity(%q) = false", line)
		}
	}
	for _, line := range []string{"AGE-PLUGIN-RYPT1X", "AGE-PLUGIN-RYPT-X", "XAGE-PLUGIN-RYPT-1", "AGE-PLUGIN-RYPT-\u00e9-1"} {
		if isRyptIdentity([]byte(line)) {
			t.Errorf("isRyptIdentity(%q) = true", line)
		}
	}
}
