// Tests of the commands people run by hand: new, recipient, --version, help,
// usage errors and --age-plugin with an unknown state machine. Ported from
// the Rust 0.1.0 tests/cli.rs and extended to the 0.2.0 spec's CLI section.
package e2e

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// cliErrorPrefix starts every error the commands print on stderr.
const cliErrorPrefix = "age-plugin-rypt: "

// cliVersionLine is what --version and -V print.
const cliVersionLine = "age-plugin-rypt 0.2.0\n"

// cliPadded is recipient's error for an identity line with whitespace around it.
const cliPadded = "identity has surrounding whitespace, which age does not accept"

// cliOtherKey is a second key, for files with several identities.
var cliOtherKey = MustParseUUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")

// cliCheck reports a test error unless a run exited with code and printed
// exactly stdout and stderr.
func cliCheck(t *testing.T, got CLIResult, code int, stdout, stderr string) {
	t.Helper()
	if got.ExitCode != code || got.Stdout != stdout || got.Stderr != stderr {
		t.Errorf("got exit %d, stdout %q, stderr %q\nwant exit %d, stdout %q, stderr %q",
			got.ExitCode, got.Stdout, got.Stderr, code, stdout, stderr)
	}
}

// cliCheckError reports a test error unless a run exited with code, printed
// nothing on stdout and exactly the error message on stderr.
func cliCheckError(t *testing.T, got CLIResult, code int, message string) {
	t.Helper()
	cliCheck(t, got, code, "", cliErrorPrefix+message+"\n")
}

// cliCheckUsageError reports a test error unless a run exited with 2, printed
// nothing on stdout, and printed two lines on stderr: an error that mentions
// each of words, then the hint to the help of command, which is "" for the
// program, " new" or " recipient". The error names a command it is about,
// as in "age-plugin-rypt: new: ...".
func cliCheckUsageError(t *testing.T, got CLIResult, command string, words ...string) {
	t.Helper()
	hint := "Run age-plugin-rypt" + command + " --help for usage.\n"
	start := cliErrorPrefix
	if command != "" {
		start += strings.TrimSpace(command) + ": "
	}
	message, ok := strings.CutSuffix(got.Stderr, "\n"+hint)
	if got.ExitCode != 2 || got.Stdout != "" || !ok || !strings.HasPrefix(message, start) || strings.Contains(message, "\n") {
		t.Errorf("got exit %d, stdout %q, stderr %q; want exit 2, no stdout, and on stderr a line starting with %q, then %q",
			got.ExitCode, got.Stdout, got.Stderr, start, hint)
	}
	for _, word := range words {
		if !strings.Contains(message, word) {
			t.Errorf("the error %q does not mention %q", message, word)
		}
	}
}

// cliHelp returns what a run that should print help printed on stdout. It
// reports a test error unless the run exited with 0, printed nothing on
// stderr, and printed help on stdout.
func cliHelp(t *testing.T, args ...string) string {
	t.Helper()
	got := runCLI(t, Env{}, nil, args...)
	if got.ExitCode != 0 || got.Stderr != "" || !strings.Contains(got.Stdout, "Usage: age-plugin-rypt") {
		t.Errorf("%q: got exit %d, stdout %q, stderr %q; want exit 0, help on stdout, no stderr", args, got.ExitCode, got.Stdout, got.Stderr)
	}
	return got.Stdout
}

// cliCheckIdentityFile checks that a run of `new` succeeded and printed the
// identity file for key, whose identity is identity. It returns the time
// stamp of the "# created:" line, which it checks is RFC 3339 to the second,
// with Z for UTC, and within a minute of now.
func cliCheckIdentityFile(t *testing.T, got CLIResult, key, identity string) string {
	t.Helper()
	if got.ExitCode != 0 || got.Stderr != "" {
		t.Fatalf("new: exit %d, stderr %q, stdout %q", got.ExitCode, got.Stderr, got.Stdout)
	}
	// SplitAfter leaves "" after the last newline.
	lines := strings.SplitAfter(got.Stdout, "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("new printed %q, want three lines, each ending in a newline", got.Stdout)
	}
	if want := "# key: " + key + "\n"; lines[1] != want {
		t.Errorf("second line %q, want %q", lines[1], want)
	}
	if want := identity + "\n"; lines[2] != want {
		t.Errorf("third line %q, want %q", lines[2], want)
	}
	created, ok := strings.CutPrefix(strings.TrimSuffix(lines[0], "\n"), "# created: ")
	if !ok {
		t.Fatalf("first line %q does not start with %q", lines[0], "# created: ")
	}
	stamp, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatalf("created %q: %v", created, err)
	}
	// Parse also takes fractional seconds and +00:00; formatting again
	// gives neither.
	if again := stamp.Format(time.RFC3339); again != created {
		t.Errorf("created %q is not RFC 3339 to the second with Z for UTC, which would be %q", created, again)
	}
	if skew := time.Since(stamp).Abs(); skew > time.Minute {
		t.Errorf("created %q is %v from now", created, skew)
	}
	return created
}

// cliHasZone reports whether the time zone database where a Go program looks
// for the zone TZ names holds name. Without it, Go silently uses UTC.
func cliHasZone(name string) bool {
	for _, dir := range []string{"/usr/share/zoneinfo", "/usr/share/lib/zoneinfo", "/usr/lib/locale/TZ", "/etc/zoneinfo"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// cliZeros is an endless input of zero bytes.
type cliZeros struct{}

func (cliZeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// cliRunBounded runs the binary with args and stdin (nil for empty input) in
// an empty environment, like runCLI, but fails the test if it has not
// finished within 30 seconds: given endless input, only a read that stops at
// the size limit finishes.
func cliRunBounded(t *testing.T, stdin io.Reader, args ...string) CLIResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := pluginBin(t).command(ctx, Env{}, args...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("%q kept reading endless input; stderr %q", args, stderr.String())
	case err != nil && !errors.As(err, &exitErr):
		t.Fatalf("running %q: %v", args, err)
	}
	return CLIResult{ExitCode: cmd.ProcessState.ExitCode(), Stdout: stdout.String(), Stderr: stderr.String()}
}

// cliCorruptChecksum changes the last character of a Bech32 string to another
// valid one, which breaks its checksum.
func cliCorruptChecksum(s string) string {
	c := "Q"
	if strings.HasSuffix(s, c) {
		c = "P"
	}
	return s[:len(s)-1] + c
}

// ---------------------------------------------------------------------------
// new

func TestCLINewPrintsAnIdentityFile(t *testing.T) {
	t.Parallel()
	for _, v := range []struct{ key, identity string }{
		{goldenKeyA, goldenIdentityA},
		{goldenKeyB, goldenIdentityB},
	} {
		t.Run(v.key, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, nil, "new", "--key", v.key)
			cliCheckIdentityFile(t, got, v.key, v.identity)
		})
	}
}

func TestCLINewStampsTheLocalTime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tz, suffix string
		// needsZone is whether the zone must come from the time zone
		// database. Go does not read POSIX TZ strings such as "<-05>5".
		needsZone bool
	}{
		// POSIX signs: Etc/GMT+5 is five hours west of UTC.
		{tz: "Etc/GMT+5", suffix: "-05:00", needsZone: true},
		{tz: "UTC", suffix: "Z"},
	} {
		t.Run(tc.tz, func(t *testing.T) {
			t.Parallel()
			if tc.needsZone && !cliHasZone(tc.tz) {
				t.Skipf("the time zone database has no %s", tc.tz)
			}
			got := runCLI(t, Env{}.WithVar("TZ", tc.tz), nil, "new", "--key", goldenKeyA)
			created := cliCheckIdentityFile(t, got, goldenKeyA, goldenIdentityA)
			if !strings.HasSuffix(created, tc.suffix) {
				t.Errorf("with TZ=%s, created %q does not end in %q", tc.tz, created, tc.suffix)
			}
		})
	}
}

func TestCLINewCanonicalizesTheKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, form string }{
		{"hyphenated", goldenKeyA},
		{"uppercase", strings.ToUpper(goldenKeyA)},
		{"mixed case", strings.ToUpper(goldenKeyA[:18]) + goldenKeyA[18:]},
		{"32 hex digits", MustParseUUID(goldenKeyA).Hex()},
		{"braced", "{" + goldenKeyA + "}"},
		{"URN", "urn:uuid:" + goldenKeyA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, nil, "new", "--key", tc.form)
			cliCheckIdentityFile(t, got, goldenKeyA, goldenIdentityA)
		})
	}
	t.Run("--key=", func(t *testing.T) {
		t.Parallel()
		got := runCLI(t, Env{}, nil, "new", "--key="+strings.ToUpper(goldenKeyB))
		cliCheckIdentityFile(t, got, goldenKeyB, goldenIdentityB)
	})
}

func TestCLINewRejectsABadKey(t *testing.T) {
	t.Parallel()
	hexKey := MustParseUUID(goldenKeyA).Hex()
	for _, tc := range []struct{ name, key string }{
		{"not a UUID", "not-a-uuid"},
		{"empty", ""},
		{"a digit short", goldenKeyA[:35]},
		{"a digit long", goldenKeyA + "0"},
		{"not hex", "g" + goldenKeyA[1:]},
		{"hyphen misplaced", goldenKeyA[:8] + goldenKeyA[9:10] + "-" + goldenKeyA[10:]},
		{"31 hex digits", hexKey[:31]},
		{"33 hex digits", hexKey + "0"},
		{"unclosed brace", "{" + goldenKeyA},
		{"braced 32 hex digits", "{" + hexKey + "}"},
		{"URN of 32 hex digits", "urn:uuid:" + hexKey},
		{"leading space", " " + goldenKeyA},
		{"trailing newline", goldenKeyA + "\n"},
		{"two keys", goldenKeyA + "," + goldenKeyB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, nil, "new", "--key", tc.key)
			cliCheckUsageError(t, got, " new", "--key")
		})
	}
	t.Run("no key", func(t *testing.T) {
		t.Parallel()
		got := runCLI(t, Env{}, nil, "new")
		cliCheckUsageError(t, got, " new", "--key")
	})
	t.Run("no value", func(t *testing.T) {
		t.Parallel()
		got := runCLI(t, Env{}, nil, "new", "--key")
		cliCheckUsageError(t, got, " new", "key")
	})
}

// The standard flag package would keep the last --key, and so print an
// identity file for a key the user may not have meant.
func TestCLINewRefusesASecondKey(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--key", goldenKeyA, "--key", goldenKeyB},
		{"--key=" + goldenKeyA, "--key=" + goldenKeyB},
		{"--key", goldenKeyA, "--key=" + goldenKeyB},
		{"-key", goldenKeyA, "-key", goldenKeyB},
		// Even the same key twice.
		{"--key", goldenKeyA, "--key", goldenKeyA},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, nil, append([]string{"new"}, args...)...)
			cliCheckUsageError(t, got, " new", "--key may be given only once")
		})
	}
}

// new and recipient never call the API, so they need no token and do not
// mind a bad API URL.
func TestCLINeedsNoAPI(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	for _, tc := range []struct {
		name string
		env  Env
	}{
		{"token", ForMock(m)},
		{"no token", ForMock(m).WithoutToken()},
		{"empty token", ForMock(m).WithToken("")},
		{"token not UTF-8", ForMock(m).WithToken("ry_\xff")},
		{"token with a space", ForMock(m).WithToken("ry_a b")},
		{"API URL not valid", Env{}.WithToken(mockToken).WithAPIURL("ftp://example.invalid")},
		{"API URL not https", Env{}.WithToken(mockToken).WithAPIURL("http://127.0.0.2:1")},
	} {
		// Not parallel: the request count below must come after every run.
		t.Run(tc.name, func(t *testing.T) {
			got := runCLI(t, tc.env, nil, "new", "--key", goldenKeyA)
			cliCheckIdentityFile(t, got, goldenKeyA, goldenIdentityA)
			got = runCLI(t, tc.env, []byte(goldenIdentityA+"\n"), "recipient")
			cliCheck(t, got, 0, goldenRecipientA+"\n", "")
		})
	}
	if n := m.Calls(); n != 0 {
		t.Errorf("the mock received %d requests, want none", n)
	}
}

// ---------------------------------------------------------------------------
// recipient

func TestCLIRecipientReadsStandardInput(t *testing.T) {
	t.Parallel()
	file := runCLI(t, Env{}, nil, "new", "--key", goldenKeyA)
	cliCheckIdentityFile(t, file, goldenKeyA, goldenIdentityA)
	for _, args := range [][]string{{"recipient"}, {"recipient", "-"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, []byte(file.Stdout), args...)
			cliCheck(t, got, 0, goldenRecipientA+"\n", "")
		})
	}
}

func TestCLIRecipientReadsAPath(t *testing.T) {
	t.Parallel()
	file := runCLI(t, Env{}, nil, "new", "--key", goldenKeyA)
	cliCheckIdentityFile(t, file, goldenKeyA, goldenIdentityA)
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(file.Stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	// Standard input is ignored when a path is given.
	got := runCLI(t, Env{}, []byte(goldenIdentityB+"\n"), "recipient", path)
	cliCheck(t, got, 0, goldenRecipientA+"\n", "")
}

// An empty FILE is most likely an unset shell variable, as in `recipient
// "$FILE"`. recipient refuses it instead of reading standard input, which
// here holds an identity it would print a recipient for.
func TestCLIRecipientRefusesAnEmptyFileName(t *testing.T) {
	t.Parallel()
	got := runCLI(t, Env{}, []byte(goldenIdentityA+"\n"), "recipient", "")
	cliCheckUsageError(t, got, " recipient", "FILE must not be empty")
}

func TestCLIRecipientPrintsOneLinePerRyptIdentity(t *testing.T) {
	t.Parallel()
	a, b := MustParseUUID(goldenKeyA), MustParseUUID(goldenKeyB)
	for _, tc := range []struct{ name, file, want string }{
		{"golden A", goldenIdentityA + "\n", goldenRecipientA + "\n"},
		{"golden B", goldenIdentityB + "\n", goldenRecipientB + "\n"},
		{"golden A and B", goldenIdentityA + "\n" + goldenIdentityB + "\n", goldenRecipientA + "\n" + goldenRecipientB + "\n"},
		{"in file order", goldenIdentityB + "\n" + goldenIdentityA + "\n", goldenRecipientB + "\n" + goldenRecipientA + "\n"},
		{"twice", goldenIdentityA + "\n" + goldenIdentityA + "\n", goldenRecipientA + "\n" + goldenRecipientA + "\n"},
		{
			"two keys",
			"# two keys\n" + identity(a) + "\n" + identity(cliOtherKey) + "\n",
			recipient(a) + "\n" + recipient(cliOtherKey) + "\n",
		},
		{
			"three keys",
			identity(a) + "\n" + identity(cliOtherKey) + "\n" + identity(b) + "\n",
			recipient(a) + "\n" + recipient(cliOtherKey) + "\n" + recipient(b) + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, []byte(tc.file), "recipient")
			cliCheck(t, got, 0, tc.want, "")
		})
	}
}

func TestCLIRecipientSkipsOtherLines(t *testing.T) {
	t.Parallel()
	secret, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	file := strings.Join([]string{
		"# created: 2026-11-01T12:00:00Z",
		"# key: " + goldenKeyA,
		"# 1 AGE-PLUGIN-RYPT-1 in a comment",
		"",
		secret.String() + "\r",
		goldenIdentityA,
		// Everything before its last 1 is not the rypt prefix.
		"AGE-PLUGIN-RYPT-1FOO-1QQQQQQQQQQ",
		plugin.EncodeIdentity("other", make([]byte, 16)),
		goldenRecipientB,
		"   ",
		"# key: " + goldenKeyB,
		goldenIdentityB + "\r",
	}, "\n") + "\n"
	got := runCLI(t, Env{}, []byte(file), "recipient")
	cliCheck(t, got, 0, goldenRecipientA+"\n"+goldenRecipientB+"\n", "")
}

func TestCLIRecipientLineEndings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, file string }{
		{"no newline at the end", goldenIdentityA},
		{"a carriage return at the end", goldenIdentityA + "\r"},
		{"CRLF", "# comment\r\n" + goldenIdentityA + "\r\n"},
		{"CRLF, then a carriage return at the end", "# comment\r\n" + goldenIdentityA + "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, []byte(tc.file), "recipient")
			cliCheck(t, got, 0, goldenRecipientA+"\n", "")
		})
	}
	for _, tc := range []struct{ name, file, message string }{
		// Only one carriage return is part of the line ending.
		{"CR CR LF", "# key\n" + goldenIdentityA + "\r\r\n", "line 2: " + cliPadded},
		{"two carriage returns at the end", goldenIdentityA + "\r\r", "line 1: " + cliPadded},
		// A carriage return alone does not end a line, so the identity is
		// part of a comment.
		{"a carriage return alone", "# comment\r" + goldenIdentityA + "\n", "no rypt identity found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, []byte(tc.file), "recipient")
			cliCheckError(t, got, 1, tc.message)
		})
	}
}

func TestCLIRecipientRejectsABadFile(t *testing.T) {
	t.Parallel()
	secret, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	upper := goldenIdentityA
	lower := strings.ToLower(upper)
	for _, tc := range []struct{ name, file, message string }{
		{"no rypt identity", "# nothing here\n", "no rypt identity found"},
		{"empty", "", "no rypt identity found"},
		{"only an X25519 identity", secret.String() + "\n", "no rypt identity found"},
		{"a recipient", goldenRecipientA + "\n", "no rypt identity found"},
		{"lowercase", lower + "\n", "line 1: identity must be uppercase"},
		{"lowercase prefix", strings.ToLower(upper[:17]) + upper[17:] + "\n", "line 1: identity must be uppercase"},
		{"lowercase data", upper[:17] + strings.ToLower(upper[17:]) + "\n", "line 1: identity must be uppercase"},
		{"leading spaces", "  " + upper + "\n", "line 1: " + cliPadded},
		{"trailing space", upper + " \n", "line 1: " + cliPadded},
		{"leading tab", "\t" + upper + "\n", "line 1: " + cliPadded},
		// The checks run in order: whitespace, case, Bech32, length.
		{"padded and lowercase", " " + lower + "\n", "line 1: " + cliPadded},
		{"lowercase and truncated", lower[:len(lower)-1] + "\n", "line 1: identity must be uppercase"},
		{"truncated", "# key\n" + upper[:len(upper)-1] + "\n", "line 2: invalid Bech32 encoding"},
		{"bad checksum", cliCorruptChecksum(upper) + "\n", "line 1: invalid Bech32 encoding"},
		{"not a Bech32 character", upper[:20] + "B" + upper[21:] + "\n", "line 1: invalid Bech32 encoding"},
		{"15-byte key id", rawIdentity(make([]byte, 15)) + "\n", "line 1: key id must be 16 bytes, got 15"},
		{"17-byte key id", rawIdentity(make([]byte, 17)) + "\n", "line 1: key id must be 16 bytes, got 17"},
		{"empty key id", rawIdentity(nil) + "\n", "line 1: key id must be 16 bytes, got 0"},
		// Nothing is printed for the good line before a bad one.
		{"good line, then a bad one", goldenIdentityA + "\n" + strings.ToLower(goldenIdentityB) + "\n", "line 2: identity must be uppercase"},
		{"lines counted from 1, all of them", "# a\n\n# b\r\n\t" + upper + "\n", "line 4: " + cliPadded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, []byte(tc.file), "recipient")
			cliCheckError(t, got, 1, tc.message)
		})
	}
}

func TestCLIRecipientRequiresUTF8(t *testing.T) {
	t.Parallel()
	file := []byte("# caf\xe9\n" + goldenIdentityA + "\n")
	t.Run("standard input", func(t *testing.T) {
		t.Parallel()
		got := runCLI(t, Env{}, file, "recipient")
		cliCheckError(t, got, 1, "standard input: not valid UTF-8")
	})
	t.Run("path", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "identity.txt")
		if err := os.WriteFile(path, file, 0o600); err != nil {
			t.Fatal(err)
		}
		got := runCLI(t, Env{}, nil, "recipient", path)
		cliCheckError(t, got, 1, path+": not valid UTF-8")
	})
}

func TestCLIRecipientNamesTheFileItCannotRead(t *testing.T) {
	t.Parallel()
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		got := runCLI(t, Env{}, nil, "recipient", "/nonexistent/identity.txt")
		cliCheckError(t, got, 1, "/nonexistent/identity.txt: no such file or directory")
	})
	t.Run("directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		got := runCLI(t, Env{}, nil, "recipient", dir)
		// The reason is the operating system's. The path is named once,
		// not again inside a Go error such as "read <dir>: ...".
		ok := got.ExitCode == 1 && got.Stdout == "" &&
			strings.HasPrefix(got.Stderr, cliErrorPrefix+dir+": ") &&
			strings.Count(got.Stderr, dir) == 1 &&
			strings.Count(got.Stderr, "\n") == 1 && strings.HasSuffix(got.Stderr, "\n")
		if !ok {
			t.Errorf("got exit %d, stdout %q, stderr %q; want exit 1, one line naming %s", got.ExitCode, got.Stdout, got.Stderr, dir)
		}
	})
}

func TestCLIRecipientRefusesAHugeInput(t *testing.T) {
	t.Parallel()
	const limit = 1 << 20
	// A file of exactly 1 MiB, and one a byte over.
	full := []byte(goldenIdentityA + "\n" + strings.Repeat("#", limit-len(goldenIdentityA)-1))
	over := append(full[:len(full):len(full)], '#')
	if len(full) != limit {
		t.Fatalf("the full file is %d bytes", len(full))
	}

	t.Run("standard input of 1 MiB", func(t *testing.T) {
		t.Parallel()
		cliCheck(t, runCLI(t, Env{}, full, "recipient"), 0, goldenRecipientA+"\n", "")
	})
	t.Run("standard input over 1 MiB", func(t *testing.T) {
		t.Parallel()
		cliCheckError(t, runCLI(t, Env{}, over, "recipient"), 1, "standard input: larger than 1 MiB")
	})
	t.Run("a file of 1 MiB", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "identity.txt")
		if err := os.WriteFile(path, full, 0o600); err != nil {
			t.Fatal(err)
		}
		cliCheck(t, runCLI(t, Env{}, nil, "recipient", path), 0, goldenRecipientA+"\n", "")
	})
	t.Run("a file over 1 MiB", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "identity.txt")
		if err := os.WriteFile(path, over, 0o600); err != nil {
			t.Fatal(err)
		}
		cliCheckError(t, runCLI(t, Env{}, nil, "recipient", path), 1, path+": larger than 1 MiB")
	})
}

// recipient stops reading at its size limit, so endless input ends.
func TestCLIRecipientStopsReadingAtTheSizeLimit(t *testing.T) {
	t.Parallel()
	t.Run("standard input", func(t *testing.T) {
		t.Parallel()
		got := cliRunBounded(t, cliZeros{}, "recipient")
		cliCheckError(t, got, 1, "standard input: larger than 1 MiB")
	})
	t.Run("/dev/zero", func(t *testing.T) {
		t.Parallel()
		if _, err := os.Stat("/dev/zero"); err != nil {
			t.Skip(err)
		}
		got := cliRunBounded(t, nil, "recipient", "/dev/zero")
		cliCheckError(t, got, 1, "/dev/zero: larger than 1 MiB")
	})
}

// A closed stdout makes recipient fail, not panic. A Go program dies of
// SIGPIPE when it writes to a broken pipe on stdout, which is fine; so is
// exiting with an error.
func TestCLIAClosedStdoutIsNotAPanic(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	cmd := pluginBin(t).command(ctx, Env{}, "recipient")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Close our end of stdout before the binary writes to it: recipient
	// reads all of its input before it prints anything.
	stdout.Close()
	// The binary may be gone already; Wait tells.
	_, _ = io.WriteString(stdin, goldenIdentityA+"\n")
	stdin.Close()
	err = cmd.Wait()

	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("recipient did not finish within %v; stderr %q", runTimeout, stderr.String())
	case err != nil && !errors.As(err, &exitErr):
		t.Fatalf("running recipient: %v", err)
	}
	state := cmd.ProcessState
	if state.Success() {
		t.Errorf("recipient succeeded with its stdout closed; stderr %q", stderr.String())
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() != syscall.SIGPIPE {
		t.Errorf("recipient died of %v, want SIGPIPE or an exit code; stderr %q", status.Signal(), stderr.String())
	}
	text := stderr.String()
	for _, sign := range []string{"panic", "goroutine ", "fatal error"} {
		if strings.Contains(text, sign) {
			t.Errorf("stderr shows a crash (%q): %q", sign, text)
		}
	}
	if text != "" && !strings.HasPrefix(text, cliErrorPrefix) {
		t.Errorf("stderr %q does not start with %q", text, cliErrorPrefix)
	}
}

// ---------------------------------------------------------------------------
// Version, help and usage errors

func TestCLIPrintsTheVersion(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"--version", "-V"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			cliCheck(t, runCLI(t, Env{}, nil, arg), 0, cliVersionLine, "")
		})
	}
}

func TestCLIPrintsHelp(t *testing.T) {
	t.Parallel()
	help := cliHelp(t, "--help")
	for _, word := range []string{"Usage:", "new", "recipient"} {
		if !strings.Contains(help, word) {
			t.Errorf("help %q does not mention %q", help, word)
		}
	}
	// The help command and -h print the same.
	for _, args := range [][]string{{"-h"}, {"help"}} {
		if got := cliHelp(t, args...); got != help {
			t.Errorf("%q printed %q, want what --help prints, %q", args, got, help)
		}
	}
}

func TestCLINoArgumentsPrintsHelpToStderr(t *testing.T) {
	t.Parallel()
	help := cliHelp(t, "--help")
	got := runCLI(t, Env{}, nil)
	cliCheck(t, got, 2, "", help)
}

func TestCLIPrintsCommandHelp(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		command string
		mention string
	}{
		{"new", "--key"},
		{"recipient", "[FILE]"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			t.Parallel()
			help := cliHelp(t, tc.command, "--help")
			if !strings.Contains(help, "Usage: age-plugin-rypt "+tc.command) || !strings.Contains(help, tc.mention) {
				t.Errorf("%s --help printed %q, which is not its help", tc.command, help)
			}
			if general := cliHelp(t, "--help"); help == general {
				t.Errorf("%s --help printed the general help", tc.command)
			}
			// -h and the help command print the same.
			for _, args := range [][]string{{tc.command, "-h"}, {"help", tc.command}} {
				if got := cliHelp(t, args...); got != help {
					t.Errorf("%q printed %q, want what %s --help prints, %q", args, got, tc.command, help)
				}
			}
		})
	}
}

func TestCLIHelpRefusesAnUnknownCommand(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		// unknown is the argument the error names: the last one.
		unknown string
	}{
		{[]string{"help", "foo"}, "foo"},
		{[]string{"help", "recipient", "extra"}, "extra"},
		{[]string{"help", "new", "recipient"}, "recipient"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, Env{}, nil, tc.args...)
			cliCheck(t, got, 2, "", cliErrorPrefix+`unknown command "`+tc.unknown+"\"\nRun age-plugin-rypt --help for usage.\n")
		})
	}
}

func TestCLIRejectsBadUsage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		// command is the command whose help the hint names: "", " new" or
		// " recipient".
		command string
		// mentions are words the error must name, if any.
		mentions []string
	}{
		{"unknown command", []string{"bogus"}, "", []string{`unknown command "bogus"`}},
		{"unknown command with arguments", []string{"bogus", "--key", goldenKeyA}, "", []string{`unknown command "bogus"`}},
		{"unknown flag", []string{"--bogus"}, "", []string{"bogus"}},
		{"unknown short flag", []string{"-x"}, "", []string{"-x"}},
		{"unknown flag of new", []string{"new", "--key", goldenKeyA, "--bogus"}, " new", []string{"bogus"}},
		{"unknown flag of recipient", []string{"recipient", "--bogus"}, " recipient", []string{"bogus"}},
		{"extra argument to new", []string{"new", "--key", goldenKeyA, "extra"}, " new", []string{"extra"}},
		{"extra argument to recipient", []string{"recipient", "a", "b"}, " recipient", []string{`"b"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Valid input, so that only the usage is wrong.
			got := runCLI(t, Env{}, []byte(goldenIdentityA+"\n"), tc.args...)
			cliCheckUsageError(t, got, tc.command, tc.mentions...)
		})
	}
}

func TestCLIRejectsAnUnknownStateMachine(t *testing.T) {
	t.Parallel()
	got := runCLI(t, Env{}, nil, "--age-plugin=bogus-v1")
	if got.ExitCode != 4 || got.Stdout != "" || !strings.Contains(got.Stderr, `unknown state machine "bogus-v1"`) {
		t.Errorf("got exit %d, stdout %q, stderr %q; want exit 4, no stdout, %q on stderr",
			got.ExitCode, got.Stdout, got.Stderr, `unknown state machine "bogus-v1"`)
	}
}
