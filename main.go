// Command age-plugin-rypt is an age plugin that wraps file keys with
// rypt.dev keys.
//
// age runs it with --age-plugin to encrypt to age1rypt1... recipients and
// decrypt with AGE-PLUGIN-RYPT-1... identities. People run its new and
// recipient commands to make those. See the README for the details.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"filippo.io/age/plugin"

	// Mozilla's root certificates, used only when the system has none, as
	// in a minimal container.
	_ "golang.org/x/crypto/x509roots/fallback"
)

// version is this release's version. The release workflow checks that the
// tag matches it.
const version = "0.2.0"

// maxIdentityFile is the size of the largest identity file recipient reads.
const maxIdentityFile = 1 << 20

const usage = `age plugin that wraps file keys with rypt.dev keys

Usage: age-plugin-rypt <command> [arguments]

Commands:
  new --key <UUID>  Print an identity file for a rypt key. Does not call the
                    rypt API.
  recipient [FILE]  Print the recipient for each rypt identity in an identity
                    file. Reads standard input when FILE is omitted or -.

Options:
  -h, --help        Print help
  -V, --version     Print version

age runs this program itself, with --age-plugin, to encrypt and decrypt.
`

const newUsage = `Print an identity file for a rypt key. Does not call the rypt API.

Usage: age-plugin-rypt new --key <UUID>

Options:
  --key <UUID>  The rypt key id
  -h, --help    Print help
`

const recipientUsage = `Print the recipient for each rypt identity in an identity file.

Usage: age-plugin-rypt recipient [FILE]

Arguments:
  [FILE]      The identity file. Reads standard input when omitted or -.

Options:
  -h, --help  Print help
`

func main() {
	// net/http logs some events through the standard logger, which writes
	// to standard error: with GODEBUG=http2debug set, every request header,
	// the token among them, and otherwise any bytes a server sends after
	// its response. Nothing in this program logs on purpose.
	log.SetOutput(io.Discard)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run runs the command line args and returns the exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	p, err := newPlugin(func() (*apiClient, error) { return clientFromEnv(os.Getenv) })
	if err != nil {
		return fail(stderr, err)
	}
	flags := newFlagSet("age-plugin-rypt")
	showVersion := flags.Bool("version", false, "")
	flags.BoolVar(showVersion, "V", false, "")
	p.RegisterFlags(flags)
	if err := flags.Parse(args); err != nil {
		return usageError(stdout, stderr, err, usage, "")
	}
	if isSet(flags, "age-plugin") {
		return runPlugin(p, stdin, stdout, stderr)
	}
	if *showVersion {
		return write(stdout, stderr, "age-plugin-rypt "+version+"\n")
	}

	rest := flags.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch rest[0] {
	case "new":
		return runNew(rest[1:], stdout, stderr)
	case "recipient":
		return runRecipient(rest[1:], stdin, stdout, stderr)
	case "help":
		return runHelp(rest[1:], stdout, stderr)
	}
	return unknownCommand(stderr, rest[0])
}

// runPlugin runs the age plugin protocol and returns the exit code.
func runPlugin(p *plugin.Plugin, stdin io.Reader, stdout, stderr io.Writer) int {
	// A write to a closed pipe should fail with an error, not kill the
	// process: age may hang up before reading the "done" written below.
	signal.Ignore(syscall.SIGPIPE)
	p.SetIO(stdin, stdout, stderr)
	code := p.Main()
	if code == 3 {
		// age's framework returns 3 after it sends an error about a
		// recipient or an identity and reads the client's "ok". It does not
		// send "done", which ends the plugin's turn. The age command does
		// not need it, but rage and other clients built on the Rust age
		// crate wait for it, and without it report only that the plugin
		// died, losing the message. A client that hung up already does not
		// read it, so a failed write does not matter.
		io.WriteString(stdout, "-> done\n\n")
	}
	return code
}

// runHelp prints the help for the command named in args, or the general
// help when there is none.
func runHelp(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return write(stdout, stderr, usage)
	}
	if len(args) == 1 {
		switch args[0] {
		case "new":
			return write(stdout, stderr, newUsage)
		case "recipient":
			return write(stdout, stderr, recipientUsage)
		}
	}
	return unknownCommand(stderr, args[len(args)-1])
}

// unknownCommand reports a command that does not exist and returns the
// exit code.
func unknownCommand(stderr io.Writer, name string) int {
	fmt.Fprintf(stderr, "age-plugin-rypt: unknown command %q\nRun age-plugin-rypt --help for usage.\n", name)
	return 2
}

// runNew prints an identity file for the key given with --key.
func runNew(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("new")
	var keyArg string
	keyCount := 0
	flags.Func("key", "", func(value string) error {
		keyArg = value
		keyCount++
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return usageError(stdout, stderr, err, newUsage, " new")
	}
	switch {
	case flags.NArg() > 0:
		return usageError(stdout, stderr, fmt.Errorf("unexpected argument %q", flags.Arg(0)), newUsage, " new")
	case keyCount == 0:
		return usageError(stdout, stderr, errors.New("--key <UUID> is required"), newUsage, " new")
	case keyCount > 1:
		// The standard flag package would keep the last one silently, and
		// so make an identity file for a key the user may not have meant.
		return usageError(stdout, stderr, errors.New("--key may be given only once"), newUsage, " new")
	}
	key, err := parseUUID(keyArg)
	if err != nil {
		return usageError(stdout, stderr, fmt.Errorf("invalid value %q for --key: %v", keyArg, err), newUsage, " new")
	}
	return write(stdout, stderr, renderIdentityFile(key, time.Now().Format(time.RFC3339)))
}

// runRecipient prints the recipients of the identity file named in args,
// or of standard input.
func runRecipient(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet("recipient")
	if err := flags.Parse(args); err != nil {
		return usageError(stdout, stderr, err, recipientUsage, " recipient")
	}
	switch {
	case flags.NArg() > 1:
		return usageError(stdout, stderr, fmt.Errorf("unexpected argument %q", flags.Arg(1)), recipientUsage, " recipient")
	case flags.NArg() == 1 && flags.Arg(0) == "":
		// Most likely an unset shell variable: reading standard input
		// instead would wait on the terminal or read the wrong data.
		return usageError(stdout, stderr, errors.New("FILE must not be empty"), recipientUsage, " recipient")
	}
	file, err := readIdentityFile(flags.Arg(0), stdin)
	if err != nil {
		return fail(stderr, err)
	}
	// The file may hold other identities, secret keys among them.
	defer clear(file)
	recipients, err := identityFileRecipients(file)
	if err != nil {
		return fail(stderr, err)
	}
	return write(stdout, stderr, strings.Join(recipients, "\n")+"\n")
}

// readIdentityFile reads the identity file at path, or standard input when
// path is "" or "-". The caller should clear the result.
func readIdentityFile(path string, stdin io.Reader) ([]byte, error) {
	name, r := "standard input", stdin
	if path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", path, reason(err))
		}
		defer f.Close()
		name, r = path, f
	}
	// One buffer, allocated up front and never grown, so that no copy of
	// the file is left behind; and the byte past the limit, if it arrives,
	// shows the file is too large.
	buf := make([]byte, maxIdentityFile+1)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(buf)
		return nil, fmt.Errorf("%s: %v", name, reason(err))
	}
	if n > maxIdentityFile {
		clear(buf)
		return nil, fmt.Errorf("%s: larger than 1 MiB", name)
	}
	if !utf8.Valid(buf[:n]) {
		clear(buf)
		return nil, fmt.Errorf("%s: not valid UTF-8", name)
	}
	return buf[:n], nil
}

// reason returns the operating system's reason for a failed file operation,
// without the operation and path a *fs.PathError adds.
func reason(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// newFlagSet returns a flag set that reports errors to its caller and
// prints nothing itself.
func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	return flags
}

// isSet reports whether the flag called name was given.
func isSet(flags *flag.FlagSet, name string) bool {
	set := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// usageError prints help for -h, or else err and a pointer to the help,
// and returns the exit code. command is " new", " recipient" or "".
func usageError(stdout, stderr io.Writer, err error, help, command string) int {
	if errors.Is(err, flag.ErrHelp) {
		return write(stdout, stderr, help)
	}
	name := strings.TrimSpace(command)
	if name != "" {
		name += ": "
	}
	fmt.Fprintf(stderr, "age-plugin-rypt: %s%v\nRun age-plugin-rypt%s --help for usage.\n", name, err, command)
	return 2
}

// write writes text to stdout and returns the exit code.
func write(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// fail reports err and returns the exit code for a failure.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "age-plugin-rypt: %v\n", err)
	return 1
}
