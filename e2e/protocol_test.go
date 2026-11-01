// Black-box tests of the plugin protocol against the mock rypt API: age's
// recipient-v1 and identity-v1 state machines, how HTTP answers and network
// failures are reported, retries, the environment (token, API URL, proxies)
// and TLS. Ported from the Rust 0.1.0 tests/protocol.rs and adapted to the
// 0.2.0 spec where they differ.
//
// Every run but one, which hangs up on the plugin, goes through wrap or
// unwrap, which check that the plugin wrote nothing to stderr and leaked no
// token, file key, ciphertext or response body.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age/plugin"
)

var (
	protoKeyA = MustParseUUID(goldenKeyA)
	protoKeyB = MustParseUUID(goldenKeyB)
	// protoKeyC is never wrapped to, so its identity matches no stanza.
	protoKeyC = MustParseUUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")

	protoFileKey      = []byte("0123456789abcdef")
	protoOtherFileKey = []byte("fedcba9876543210")
)

const (
	// protoRemoteURL is an https API URL whose host never resolves (.test
	// is reserved), so a request to it can only get as far as a proxy.
	protoRemoteURL = "https://rypt.example.test"
	// protoRemoteTarget is where a proxy is asked to connect for it.
	protoRemoteTarget = "rypt.example.test:443"

	protoInvalidStanza     = "rypt: invalid stanza"
	protoInvalidResponse   = "rypt: invalid response"
	protoConnectionFailed  = "rypt: connection failed"
	protoTokenNotSet       = "RYPT_TOKEN is not set"
	protoTokenInvalid      = "RYPT_TOKEN contains invalid characters"
	protoTokenNotUTF8      = "RYPT_TOKEN is not valid UTF-8"
	protoMustUseHTTPS      = "RYPT_API_URL must use https"
	protoNotAValidURL      = "RYPT_API_URL is not a valid URL"
	protoNoDefaultIdentity = "rypt has no default identity: use -i with a file from age-plugin-rypt new"
)

// protoStatusCases maps each status the mock is made to answer to what the
// plugin reports. A 2xx answer is judged by its body, and the mock's error
// envelope is not the documented answer.
var protoStatusCases = []struct {
	status  int
	message string
}{
	{200, protoInvalidResponse},
	{201, protoInvalidResponse},
	{204, protoInvalidResponse},
	{301, "rypt: 301"},
	{302, "rypt: 302"},
	{307, "rypt: 307"},
	{308, "rypt: 308"},
	{400, "rypt: 400"},
	{401, "rypt: unauthorized"},
	{402, "rypt: 402"},
	{403, "rypt: unauthorized"},
	{404, "rypt: key not found"},
	{409, "rypt: 409"},
	{429, "rypt: rate limit or op cap reached"},
	{500, "rypt: 500"},
	{502, "rypt: 502"},
	{503, "rypt: 503"},
	{504, "rypt: 504"},
}

// protoUnusableAnswerKeys are the keys the mock answers with 200 and a body
// the plugin cannot use.
var protoUnusableAnswerKeys = []struct {
	name string
	key  UUID
}{
	{"not JSON", notJSONKey},
	{"missing field", missingFieldKey},
	{"bad base64", badBase64Key},
	{"larger than 8 MiB", oversizedKey},
	{"empty", emptyCiphertextKey},
}

// ---------------------------------------------------------------------------
// Stanzas and checks

// protoStanza is fileKey wrapped to key as the plugin writes it: the key in
// canonical form, and the ciphertext the mock returns as the body.
func protoStanza(key UUID, fileKey []byte) Stanza {
	return Stanza{Type: "rypt", Args: []string{key.String()}, Body: toySeal(key, fileKey)}
}

// protoOpaque is a well-formed rypt stanza for key whose body no key opens.
// It is enough for keys the mock answers before it reads the body.
func protoOpaque(key UUID) Stanza {
	return Stanza{Type: "rypt", Args: []string{key.String()}, Body: bytes.Repeat([]byte{9}, 40)}
}

// protoX25519 is a stanza of another type.
func protoX25519() Stanza {
	return Stanza{Type: "X25519", Args: []string{"abc"}, Body: bytes.Repeat([]byte{1}, 32)}
}

// protoWrapped wraps protoFileKey to key with the plugin and returns the
// file's stanzas.
func protoWrapped(t *testing.T, env Env, key UUID) []Stanza {
	t.Helper()
	o := wrap(t, env, []string{recipient(key)}, nil, protoFileKey)
	protoWantWrapped(t, o)
	return o.Stanzas(0)
}

// protoWantWrapped checks a recipient-v1 run that succeeded: no error, done,
// exit code 0.
func protoWantWrapped(t *testing.T, o *Outcome) {
	t.Helper()
	if errs := o.Errors(); len(errs) != 0 || !o.Done || o.ExitCode != 0 {
		t.Fatalf("wrapping failed: errors %q, done %v, exit code %d", errs, o.Done, o.ExitCode)
	}
}

// protoWantStanzas checks one file's recipient stanzas.
func protoWantStanzas(t *testing.T, o *Outcome, file int, want ...Stanza) {
	t.Helper()
	if got := o.Stanzas(file); !slices.EqualFunc(got, want, Stanza.Equal) {
		t.Errorf("file %d has stanzas %+v, want %+v", file, got, want)
	}
}

// protoWantFailure checks a run that ended at its first recipient or
// identity error, as age's framework does: that one error command, the last
// the plugin sent, no stanza or file key, and exit code 3. It also checks
// that done followed the error. age's framework does not send it, but the
// plugin does, because rage and other clients built on the Rust age crate
// wait for it and otherwise lose the message.
func protoWantFailure(t *testing.T, o *Outcome, args, message string) {
	t.Helper()
	if got, want := o.Errors(), []PluginError{{args, message}}; !slices.Equal(got, want) {
		t.Errorf("errors %q, want %q", got, want)
	}
	for _, c := range o.Commands {
		if c.Type == "recipient-stanza" || c.Type == "file-key" {
			t.Errorf("a %s command %q came with the error", c.Type, c.Args)
		}
	}
	if n := len(o.All); n > 0 && o.All[n-1].Type != "error" {
		t.Errorf("a %s command came after the error", o.All[n-1].Type)
	}
	if !o.Done || o.ExitCode != 3 {
		t.Errorf("done %v, exit code %d; want done and exit code 3", o.Done, o.ExitCode)
	}
}

// protoWantUnwrap checks an identity-v1 run that went through every file:
// done, exit code 0, exactly fileKeys unwrapped, and exactly errs reported,
// in order.
func protoWantUnwrap(t *testing.T, o *Outcome, fileKeys map[int][]byte, errs ...PluginError) {
	t.Helper()
	if !o.Done || o.ExitCode != 0 {
		t.Errorf("done %v, exit code %d; want done and exit code 0", o.Done, o.ExitCode)
	}
	if got := o.Errors(); !slices.Equal(got, errs) {
		t.Errorf("errors %q, want %q", got, errs)
	}
	if got := o.FileKeys(); !maps.EqualFunc(got, fileKeys, bytes.Equal) {
		t.Errorf("file keys %x, want %x", got, fileKeys)
	}
}

// protoWantNothing checks an identity-v1 run that had nothing to do: no
// command at all, done, exit code 0.
func protoWantNothing(t *testing.T, o *Outcome) {
	t.Helper()
	if len(o.Commands) != 0 || !o.Done || o.ExitCode != 0 {
		t.Errorf("commands %+v, done %v, exit code %d; want none, done and exit code 0", o.Commands, o.Done, o.ExitCode)
	}
}

// protoWantCount checks a request count.
func protoWantCount(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: %d, want %d", what, got, want)
	}
}

// ---------------------------------------------------------------------------
// Raw TCP servers: proxies, and servers that misbehave

// protoServer is a TCP server on a random 127.0.0.1 port. It handles every
// connection with its handler, in a loop, and keeps what the handler
// records. The test's cleanup stops it.
type protoServer struct {
	listener net.Listener

	mu    sync.Mutex
	conns int
	seen  []string
}

// protoListen starts a protoServer. handle serves one connection, and calls
// record before it answers, so that the record is there by the time the
// plugin hears back. Each connection has a 10 s deadline.
func protoListen(t *testing.T, handle func(conn net.Conn, record func(string))) *protoServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &protoServer{listener: l}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Counted before the handler answers, so the count is up to
			// date by the time the plugin hears back.
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				handle(conn, s.record)
			}()
		}
	}()
	return s
}

// URL is the server's address with scheme, such as http://127.0.0.1:port.
func (s *protoServer) URL(scheme string) string {
	return scheme + "://" + s.listener.Addr().String()
}

func (s *protoServer) record(seen string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, seen)
}

// Conns counts the connections accepted so far.
func (s *protoServer) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// Seen returns what the handler recorded, in order.
func (s *protoServer) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

// protoHangUp ends a connection after an answer without resetting it: it
// closes the writing side, then reads until the client closes. A close with
// unread data would send a reset, which could destroy the answer.
func protoHangUp(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	io.Copy(io.Discard, conn)
}

// protoHTTPProxy is an HTTP proxy that records the head of every request,
// such as "CONNECT host:443 HTTP/1.1\r\n...", and refuses it with 403.
func protoHTTPProxy(t *testing.T) *protoServer {
	t.Helper()
	return protoListen(t, func(conn net.Conn, record func(string)) {
		r := bufio.NewReader(io.LimitReader(conn, 64<<10))
		var head strings.Builder
		for {
			line, err := r.ReadString('\n')
			head.WriteString(line)
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		record(head.String())
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		protoHangUp(conn)
	})
}

// protoSOCKSProxy is a SOCKS5 proxy that records the host:port of every
// CONNECT request and refuses it as not allowed by its ruleset. It records
// anything else it gets as "not SOCKS5 ...".
func protoSOCKSProxy(t *testing.T) *protoServer {
	t.Helper()
	return protoListen(t, func(conn net.Conn, record func(string)) {
		target, ok := protoSOCKSRequest(conn)
		if !ok {
			record("not SOCKS5: " + target)
			return
		}
		record(target)
		// Reply 2: connection not allowed by ruleset.
		conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		protoHangUp(conn)
	})
}

// protoSOCKSRequest reads a SOCKS5 greeting, accepts it without
// authentication, and reads a CONNECT request. It returns the host:port asked
// for, or what was wrong.
func protoSOCKSRequest(conn net.Conn) (string, bool) {
	r := bufio.NewReader(conn)
	read := func(n int) ([]byte, bool) {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err == nil
	}
	greeting, ok := read(2)
	if !ok || greeting[0] != 5 {
		return fmt.Sprintf("greeting % x", greeting), false
	}
	if _, ok := read(int(greeting[1])); !ok {
		return "short greeting", false
	}
	// No authentication.
	conn.Write([]byte{5, 0})
	request, ok := read(4)
	if !ok || request[0] != 5 || request[1] != 1 {
		return fmt.Sprintf("request % x", request), false
	}
	var host string
	switch request[3] {
	case 1, 4:
		size := map[byte]int{1: 4, 4: 16}[request[3]]
		ip, ok := read(size)
		if !ok {
			return "short address", false
		}
		host = net.IP(ip).String()
	case 3:
		size, ok := read(1)
		if !ok {
			return "short name", false
		}
		name, ok := read(int(size[0]))
		if !ok {
			return "short name", false
		}
		host = string(name)
	default:
		return fmt.Sprintf("address type %d", request[3]), false
	}
	port, ok := read(2)
	if !ok {
		return "short port", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1]))), true
}

// protoPlainHTTPServer answers whatever it gets with a plain-HTTP error, as
// a web server does when it is spoken TLS to.
func protoPlainHTTPServer(t *testing.T) *protoServer {
	t.Helper()
	return protoListen(t, func(conn net.Conn, record func(string)) {
		conn.Read(make([]byte, 1024))
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		protoHangUp(conn)
	})
}

// protoDroppingServer reads each request in full, then closes the
// connection without answering.
func protoDroppingServer(t *testing.T) *protoServer {
	t.Helper()
	return protoListen(t, func(conn net.Conn, record func(string)) {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			record("unreadable request: " + err.Error())
			return
		}
		io.Copy(io.Discard, req.Body)
		record(req.Method + " " + req.URL.Path)
	})
}

// protoRemoteEnv is an Env for an API that only a proxy could reach.
func protoRemoteEnv() Env {
	return Env{}.WithToken(mockToken).WithAPIURL(protoRemoteURL)
}

// protoSkipUnlessLinux skips a test that trusts the TLS mock through
// SSL_CERT_FILE, which the plugin is specified to honor on Linux; macOS
// ignores it.
func protoSkipUnlessLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the plugin honors SSL_CERT_FILE on Linux only")
	}
}

// ---------------------------------------------------------------------------
// Wrapping and unwrapping

func TestProtocolWrapsAndUnwrapsAFileKey(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m)

	wrapped := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
	protoWantWrapped(t, wrapped)
	// No labels, offered or not.
	if len(wrapped.Commands) == 0 || !wrapped.Commands[0].Equal(Stanza{Type: "labels"}) {
		t.Errorf("no empty labels command first: %+v", wrapped.Commands)
	}
	// The argument is the key in canonical form, and the body is the raw
	// ciphertext rypt returned, nothing more.
	protoWantStanzas(t, wrapped, 0, Stanza{Type: "rypt", Args: []string{goldenKeyA}, Body: toySeal(protoKeyA, protoFileKey)})

	unwrapped := unwrap(t, env, []string{identity(protoKeyA)}, wrapped.Stanzas(0))
	protoWantUnwrap(t, unwrapped, map[int][]byte{0: protoFileKey})
	protoWantCount(t, "encrypt requests", m.EncryptCalls(), 1)
	protoWantCount(t, "decrypt requests", m.DecryptCalls(), 1)
	protoWantCount(t, "requests", m.Calls(), 2)
}

func TestProtocolWrapsToIdentitiesToo(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m)

	wrapped := wrap(t, env, nil, []string{identity(protoKeyB)}, protoFileKey)
	protoWantWrapped(t, wrapped)
	protoWantStanzas(t, wrapped, 0, protoStanza(protoKeyB, protoFileKey))

	unwrapped := unwrap(t, env, []string{identity(protoKeyB)}, wrapped.Stanzas(0))
	protoWantUnwrap(t, unwrapped, map[int][]byte{0: protoFileKey})
}

func TestProtocolWrapsEveryFileKeyToEveryRecipientAndIdentity(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m)

	wrapped := wrap(t, env, []string{recipient(protoKeyA)}, []string{identity(protoKeyB)}, protoFileKey, protoOtherFileKey)
	protoWantWrapped(t, wrapped)
	for i, fileKey := range [][]byte{protoFileKey, protoOtherFileKey} {
		protoWantStanzas(t, wrapped, i, protoStanza(protoKeyA, fileKey), protoStanza(protoKeyB, fileKey))
	}
	// For each file key, each recipient, then each identity.
	var keys []string
	for _, r := range m.Requests() {
		keys = append(keys, r.Operation+" "+r.Key)
	}
	a, b := "encrypt "+goldenKeyA, "encrypt "+goldenKeyB
	if want := []string{a, b, a, b}; !slices.Equal(keys, want) {
		t.Errorf("requests %q, want %q", keys, want)
	}

	// Either key alone unwraps both files.
	files := [][]Stanza{wrapped.Stanzas(0), wrapped.Stanzas(1)}
	for _, key := range []UUID{protoKeyA, protoKeyB} {
		unwrapped := unwrap(t, env, []string{identity(key)}, files...)
		protoWantUnwrap(t, unwrapped, map[int][]byte{0: protoFileKey, 1: protoOtherFileKey})
	}
}

func TestProtocolIgnoresStanzasForOtherKeysAndTypes(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	file := []Stanza{
		protoX25519(),
		// Stanza types are case-sensitive: this is not a rypt stanza.
		{Type: "RYPT", Args: []string{strings.ToUpper(goldenKeyA)}, Body: bytes.Repeat([]byte{1}, 8)},
		{Type: "rypt-x", Args: []string{goldenKeyA}, Body: toySeal(protoKeyA, protoFileKey)},
		protoStanza(protoKeyB, protoFileKey),
	}

	protoWantNothing(t, unwrap(t, ForMock(m), []string{identity(protoKeyA)}, file))
	protoWantCount(t, "requests", m.Calls(), 0)
}

func TestProtocolMalformedRyptStanzaBlocksItsFile(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte{1}, 8)
	for _, tc := range []struct {
		name string
		bad  Stanza
	}{
		{"no argument", Stanza{Type: "rypt", Body: body}},
		{"two arguments", Stanza{Type: "rypt", Args: []string{goldenKeyA, "extra"}, Body: body}},
		{"not a UUID", Stanza{Type: "rypt", Args: []string{"not-a-uuid"}, Body: body}},
		{"uppercase", Stanza{Type: "rypt", Args: []string{strings.ToUpper(goldenKeyA)}, Body: body}},
		{"32 hex digits", Stanza{Type: "rypt", Args: []string{protoKeyA.Hex()}, Body: body}},
		{"braced", Stanza{Type: "rypt", Args: []string{"{" + goldenKeyA + "}"}, Body: body}},
		{"URN", Stanza{Type: "rypt", Args: []string{"urn:uuid:" + goldenKeyA}, Body: body}},
		{"empty body", Stanza{Type: "rypt", Args: []string{goldenKeyA}}},
		{"uppercase key that is not loaded", Stanza{Type: "rypt", Args: []string{strings.ToUpper(goldenKeyB)}, Body: body}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			// No token: a malformed stanza is reported before anything
			// needs one.
			env := ForMock(m).WithoutToken()
			good := protoStanza(protoKeyA, protoFileKey)
			invalid := PluginError{"stanza 0 0", protoInvalidStanza}

			// A stanza for the loaded key before and after the bad one.
			file := []Stanza{good, protoX25519(), tc.bad, good}
			protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), nil, invalid)

			// Even when the loaded key matches nothing in the file.
			file = []Stanza{protoX25519(), tc.bad}
			protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyC)}, file), nil, invalid)

			protoWantCount(t, "requests", m.Calls(), 0)
		})
	}
}

func TestProtocolMalformedRyptStanzasAreReportedOncePerFile(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	files := [][]Stanza{
		{
			{Type: "rypt", Body: bytes.Repeat([]byte{1}, 8)},
			protoX25519(),
			{Type: "rypt", Args: []string{"x", "y"}, Body: bytes.Repeat([]byte{1}, 8)},
		},
		{protoStanza(protoKeyA, protoFileKey)},
	}
	o := unwrap(t, ForMock(m), []string{identity(protoKeyA)}, files...)
	// One error for the first file; the second is unaffected.
	protoWantUnwrap(t, o, map[int][]byte{1: protoFileKey}, PluginError{"stanza 0 0", protoInvalidStanza})
	protoWantCount(t, "decrypt requests", m.DecryptCalls(), 1)
}

func TestProtocolFailedStanzaDoesNotStopTheNext(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	failing := statusKey(500)
	file := []Stanza{protoOpaque(failing), protoStanza(protoKeyA, protoFileKey)}

	o := unwrap(t, ForMock(m), []string{identity(failing), identity(protoKeyA)}, file)
	protoWantUnwrap(t, o, map[int][]byte{0: protoFileKey})
	protoWantCount(t, "decrypt requests", m.DecryptCalls(), 2)
}

func TestProtocolTriesStanzasInHeaderOrderAndStopsAtTheFirstThatUnwraps(t *testing.T) {
	t.Parallel()
	a := protoStanza(protoKeyA, protoFileKey)
	b := protoStanza(protoKeyB, protoFileKey)
	for _, tc := range []struct {
		name  string
		file  []Stanza
		first UUID
	}{
		{"A then B", []Stanza{a, b}, protoKeyA},
		{"B then A", []Stanza{b, a}, protoKeyB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			// The identities in the other order: the header decides.
			for _, ids := range [][]string{
				{identity(protoKeyA), identity(protoKeyB)},
				{identity(protoKeyB), identity(protoKeyA)},
			} {
				o := unwrap(t, ForMock(m), ids, tc.file)
				protoWantUnwrap(t, o, map[int][]byte{0: protoFileKey})
			}
			for _, r := range m.Requests() {
				if r.Operation != "decrypt" || r.Key != tc.first.String() {
					t.Errorf("a %s request for %s, want only decrypt requests for %s", r.Operation, r.Key, tc.first)
				}
			}
			protoWantCount(t, "requests", m.Calls(), 2)
		})
	}
}

func TestProtocolReportsOneStanzaErrorPerFile(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	missing := statusKey(404)
	limited := statusKey(429)
	refused := statusKey(400)

	files := [][]Stanza{
		// Stanzas of other types count, but errors name stanza 0.
		{protoX25519(), protoOpaque(missing)},
		// Distinct messages in header order, joined.
		{protoOpaque(limited), protoOpaque(missing)},
		{protoOpaque(refused), protoX25519(), protoOpaque(missing)},
		// A message is given once, however many stanzas failed with it.
		{protoOpaque(missing), protoOpaque(limited), protoOpaque(missing)},
		// Unaffected.
		{protoStanza(protoKeyA, protoFileKey)},
	}
	ids := []string{identity(missing), identity(limited), identity(refused), identity(protoKeyA)}

	o := unwrap(t, ForMock(m), ids, files...)
	protoWantUnwrap(t, o, map[int][]byte{4: protoFileKey},
		PluginError{"stanza 0 0", "rypt: key not found"},
		PluginError{"stanza 1 0", "rypt: rate limit or op cap reached; rypt: key not found"},
		PluginError{"stanza 2 0", "rypt: 400; rypt: key not found"},
		PluginError{"stanza 3 0", "rypt: key not found; rypt: rate limit or op cap reached"},
	)
	// Every matching stanza was tried: none of these is retried.
	protoWantCount(t, "decrypt requests", m.DecryptCalls(), 1+2+2+3+1)
}

func TestProtocolStanzaErrorInOneFileDoesNotAffectAnother(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	failing := statusKey(503)
	files := [][]Stanza{
		{protoOpaque(failing)},
		{protoStanza(protoKeyA, protoFileKey)},
	}

	o := unwrap(t, ForMock(m), []string{identity(failing), identity(protoKeyA)}, files...)
	protoWantUnwrap(t, o, map[int][]byte{1: protoFileKey}, PluginError{"stanza 0 0", "rypt: 503"})
	// 503 is tried three times.
	protoWantCount(t, "decrypt requests", m.DecryptCalls(), 3+1)
}

// ---------------------------------------------------------------------------
// HTTP answers

func TestProtocolMapsHTTPStatusesWhenWrapping(t *testing.T) {
	t.Parallel()
	for _, tc := range protoStatusCases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			env := ForMock(m)
			key := statusKey(tc.status)

			o := wrap(t, env, []string{recipient(key)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", tc.message)

			// A failing identity is named by its own index.
			o = wrap(t, env, []string{recipient(protoKeyA)}, []string{identity(protoKeyB), identity(key)}, protoFileKey)
			protoWantFailure(t, o, "identity 1", tc.message)
		})
	}
}

func TestProtocolMapsHTTPStatusesWhenUnwrapping(t *testing.T) {
	t.Parallel()
	for _, tc := range protoStatusCases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			key := statusKey(tc.status)

			o := unwrap(t, ForMock(m), []string{identity(key)}, []Stanza{protoOpaque(key)})
			protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", tc.message})
		})
	}
}

func TestProtocolRetriesOnlyTransientFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status   int
		requests int
		message  string
	}{
		{502, 3, "rypt: 502"},
		{503, 3, "rypt: 503"},
		{504, 3, "rypt: 504"},
		{500, 1, "rypt: 500"},
		{429, 1, "rypt: rate limit or op cap reached"},
		{404, 1, "rypt: key not found"},
		{400, 1, "rypt: 400"},
		{401, 1, "rypt: unauthorized"},
		// A redirect is neither followed nor retried.
		{302, 1, "rypt: 302"},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			env := ForMock(m)
			key := statusKey(tc.status)

			o := wrap(t, env, []string{recipient(key)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", tc.message)
			// Calls counts every path, so a followed redirect would show.
			protoWantCount(t, "requests after wrapping", m.Calls(), tc.requests)
			protoWantCount(t, "encrypt requests", m.EncryptCalls(), tc.requests)

			o = unwrap(t, env, []string{identity(key)}, []Stanza{protoOpaque(key)})
			protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", tc.message})
			protoWantCount(t, "decrypt requests", m.DecryptCalls(), tc.requests)
			protoWantCount(t, "requests in all", m.Calls(), 2*tc.requests)
		})
	}

	t.Run("dropped connection", func(t *testing.T) {
		t.Parallel()
		server := protoDroppingServer(t)
		env := Env{}.WithToken(mockToken).WithAPIURL(server.URL("http"))

		o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
		protoWantFailure(t, o, "recipient 0", protoConnectionFailed)
		protoWantCount(t, "connections after wrapping", server.Conns(), 3)

		o = unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
		protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", protoConnectionFailed})
		protoWantCount(t, "connections in all", server.Conns(), 6)

		encrypt := "POST /v1/keys/" + goldenKeyA + "/encrypt"
		decrypt := "POST /v1/keys/" + goldenKeyA + "/decrypt"
		seen := server.Seen()
		if want := []string{encrypt, encrypt, encrypt, decrypt, decrypt, decrypt}; !slices.Equal(seen, want) {
			t.Errorf("the server saw %q, want %q", seen, want)
		}
	})
}

func TestProtocolStopsWrappingAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	missing := statusKey(404)

	t.Run("one file key", func(t *testing.T) {
		t.Parallel()
		m := NewMock(t)
		o := wrap(t, ForMock(m), []string{recipient(missing), recipient(protoKeyA)}, nil, protoFileKey)
		protoWantFailure(t, o, "recipient 0", "rypt: key not found")
		protoWantCount(t, "encrypt requests", m.EncryptCalls(), 1)
	})
	t.Run("two file keys", func(t *testing.T) {
		t.Parallel()
		m := NewMock(t)
		o := wrap(t, ForMock(m), []string{recipient(missing), recipient(statusKey(500))}, nil, protoFileKey, protoOtherFileKey)
		protoWantFailure(t, o, "recipient 0", "rypt: key not found")
		protoWantCount(t, "encrypt requests", m.EncryptCalls(), 1)
	})
	t.Run("an identity", func(t *testing.T) {
		t.Parallel()
		m := NewMock(t)
		o := wrap(t, ForMock(m), []string{recipient(protoKeyA)}, []string{identity(missing), identity(protoKeyB)}, protoFileKey, protoOtherFileKey)
		protoWantFailure(t, o, "identity 0", "rypt: key not found")
		protoWantCount(t, "encrypt requests", m.EncryptCalls(), 2)
	})
}

func TestProtocolReportsUnusableAnswersAsInvalidResponses(t *testing.T) {
	t.Parallel()
	for _, tc := range protoUnusableAnswerKeys {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			env := ForMock(m)

			o := wrap(t, env, []string{recipient(tc.key)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", protoInvalidResponse)

			// A real ciphertext, so that the mock's decrypt answers as
			// the key says.
			o = unwrap(t, env, []string{identity(tc.key)}, []Stanza{protoStanza(tc.key, protoFileKey)})
			protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", protoInvalidResponse})

			// An unusable answer is not retried.
			protoWantCount(t, "requests", m.Calls(), 2)
		})
	}
}

func TestProtocolRejectsADecryptedFileKeyThatIsNot16Bytes(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m)
	// The mock's encrypt for shortKey is ordinary; its decrypt drops a byte.
	file := protoWrapped(t, env, shortKey)

	o := unwrap(t, env, []string{identity(shortKey)}, file)
	protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", "rypt: decrypted file key is not 16 bytes"})
}

func TestProtocolCiphertextForAnotherKeyIsRefusedByRypt(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	stanza := protoStanza(protoKeyB, protoFileKey)
	stanza.Args = []string{goldenKeyA}

	o := unwrap(t, ForMock(m), []string{identity(protoKeyA)}, []Stanza{stanza})
	protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", "rypt: 400"})
}

// ---------------------------------------------------------------------------
// Recipients and identities

func TestProtocolRejectsRecipientsAndIdentitiesThatAreNotRyptKeys(t *testing.T) {
	t.Parallel()
	foreignRecipient := plugin.EncodeRecipient("other", protoKeyA[:])
	foreignIdentity := plugin.EncodeIdentity("other", protoKeyA[:])

	// Each runs with and without a token: recipients and identities are
	// parsed before the token is read, so a bad one is what is reported.
	envs := []struct {
		name string
		env  func(*Mock) Env
	}{
		{"with a token", ForMock},
		{"without a token", func(m *Mock) Env { return ForMock(m).WithoutToken() }},
	}

	// age's framework stops at the first bad one, so each is alone after a
	// good one, which gives it index 1.
	for _, tc := range []struct {
		name       string
		recipients []string
		identities []string
		args       string
		message    string
	}{
		{"15-byte recipient", []string{recipient(protoKeyA), rawRecipient(make([]byte, 15))}, nil, "recipient 1", "key id must be 16 bytes, got 15"},
		{"17-byte recipient", []string{recipient(protoKeyA), rawRecipient(make([]byte, 17))}, nil, "recipient 1", "key id must be 16 bytes, got 17"},
		{"empty recipient", []string{recipient(protoKeyA), rawRecipient(nil)}, nil, "recipient 1", "key id must be 16 bytes, got 0"},
		{"other plugin's recipient", []string{recipient(protoKeyA), foreignRecipient}, nil, "recipient 1", `unsupported plugin name: "other"`},
		{"15-byte identity", []string{recipient(protoKeyA)}, []string{identity(protoKeyB), rawIdentity(make([]byte, 15))}, "identity 1", "key id must be 16 bytes, got 15"},
		// What `age -e -j rypt` sends.
		{"empty identity", []string{recipient(protoKeyA)}, []string{identity(protoKeyB), rawIdentity(nil)}, "identity 1", protoNoDefaultIdentity},
		{"other plugin's identity", []string{recipient(protoKeyA)}, []string{identity(protoKeyB), foreignIdentity}, "identity 1", `unsupported plugin name: "other"`},
		// Identities alone, as `age -e -i` sends them.
		{"15-byte identity after a good one", nil, []string{identity(protoKeyA), rawIdentity(make([]byte, 15))}, "identity 1", "key id must be 16 bytes, got 15"},
	} {
		for _, e := range envs {
			t.Run("wrapping/"+tc.name+"/"+e.name, func(t *testing.T) {
				t.Parallel()
				m := NewMock(t)
				o := wrap(t, e.env(m), tc.recipients, tc.identities, protoFileKey)
				protoWantFailure(t, o, tc.args, tc.message)
				protoWantCount(t, "requests", m.Calls(), 0)
			})
		}
	}

	for _, tc := range []struct {
		name    string
		bad     string
		message string
	}{
		{"15-byte identity", rawIdentity(make([]byte, 15)), "key id must be 16 bytes, got 15"},
		{"17-byte identity", rawIdentity(make([]byte, 17)), "key id must be 16 bytes, got 17"},
		// What `age -d -j rypt` sends.
		{"empty identity", rawIdentity(nil), protoNoDefaultIdentity},
		{"other plugin's identity", foreignIdentity, `unsupported plugin name: "other"`},
	} {
		for _, e := range envs {
			t.Run("unwrapping/"+tc.name+"/"+e.name, func(t *testing.T) {
				t.Parallel()
				m := NewMock(t)
				file := []Stanza{protoStanza(protoKeyA, protoFileKey)}
				o := unwrap(t, e.env(m), []string{identity(protoKeyA), tc.bad}, file)
				protoWantFailure(t, o, "identity 1", tc.message)
				protoWantCount(t, "requests", m.Calls(), 0)
			})
		}
	}
}

// ---------------------------------------------------------------------------
// The token

func TestProtocolChecksTheToken(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		env  func(Env) Env
		// message is "" when the token works.
		message string
	}{
		{"unset", Env.WithoutToken, protoTokenNotSet},
		{"empty", func(e Env) Env { return e.WithToken("") }, protoTokenNotSet},
		{"blank", func(e Env) Env { return e.WithToken(" \t\r\n") }, protoTokenNotSet},
		// A token read from a file, newline and all.
		{"padded", func(e Env) Env { return e.WithToken(" \t" + mockToken + "\r\n") }, ""},
		// The ASCII whitespace WHATWG defines, as 0.1.0 trimmed: a form
		// feed is among it, a vertical tab is not.
		{"padded with form feeds", func(e Env) Env { return e.WithToken("\f" + mockToken + "\f") }, ""},
		{"vertical tab", func(e Env) Env { return e.WithToken("\v" + mockToken) }, protoTokenInvalid},
		{"inner space", func(e Env) Env { return e.WithToken("ry_Test1234 abcdefghijklmnopqrstuvwxyz012345") }, protoTokenInvalid},
		{"inner tab", func(e Env) Env { return e.WithToken("ry_Test1234\tabcdefghijklmnopqrstuvwxyz012345") }, protoTokenInvalid},
		{"control character", func(e Env) Env { return e.WithToken("ry_Test1234_abcdefghijklmnopqrstuvwxyz01234\x7f") }, protoTokenInvalid},
		{"non-ASCII", func(e Env) Env { return e.WithToken("ry_Test1234_ábcdefghijklmnopqrstuvwxyz012345") }, protoTokenInvalid},
		{"not UTF-8", func(e Env) Env { return e.WithToken("ry_Test1234_\xffbcdefghijklmnopqrstuvwxyz012345") }, protoTokenNotUTF8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			env := tc.env(ForMock(m))
			file := []Stanza{protoStanza(protoKeyA, protoFileKey)}

			if tc.message == "" {
				protoWantWrapped(t, wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey))
				protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), map[int][]byte{0: protoFileKey})
				protoWantCount(t, "requests", m.Calls(), 2)
				return
			}

			// Reported against the first recipient or identity to wrap,
			// and against a file that has a matching stanza.
			protoWantFailure(t, wrap(t, env, []string{recipient(protoKeyA), recipient(protoKeyB)}, nil, protoFileKey), "recipient 0", tc.message)
			protoWantFailure(t, wrap(t, env, nil, []string{identity(protoKeyA), identity(protoKeyB)}, protoFileKey), "identity 0", tc.message)
			protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), nil, PluginError{"stanza 0 0", tc.message})
			protoWantCount(t, "requests", m.Calls(), 0)
		})
	}
}

func TestProtocolWrongTokenIsUnauthorized(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m).WithToken("ry_Wrong000_abcdefghijklmnopqrstuvwxyz012345")

	o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
	protoWantFailure(t, o, "recipient 0", "rypt: unauthorized")

	o = unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
	protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", "rypt: unauthorized"})
	protoWantCount(t, "requests", m.Calls(), 2)
}

func TestProtocolReadsTheTokenOnlyWhenAStanzaMatches(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m).WithoutToken()
	stanza := protoStanza(protoKeyA, protoFileKey)

	// Once per file, however many of its stanzas match.
	doubled := []Stanza{stanza, stanza}
	o := unwrap(t, env, []string{identity(protoKeyA)}, doubled, doubled)
	protoWantUnwrap(t, o, nil,
		PluginError{"stanza 0 0", protoTokenNotSet},
		PluginError{"stanza 1 0", protoTokenNotSet},
	)

	// No stanza for a loaded key: nothing to do, so no token needed.
	protoWantNothing(t, unwrap(t, env, []string{identity(protoKeyB)}, []Stanza{stanza, protoX25519()}))
	protoWantCount(t, "requests", m.Calls(), 0)
}

// ---------------------------------------------------------------------------
// The API URL

func TestProtocolChecksTheAPIURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		url     string
		message string
	}{
		// Accepted, but nothing listens on port 1.
		{"http://127.0.0.1:1", protoConnectionFailed},
		{"http://[::1]:1", protoConnectionFailed},
		{"http://127.0.0.1:1/prefix/", protoConnectionFailed},
		{"https://127.0.0.1:1", protoConnectionFailed},

		// Plain http is for the addresses 127.0.0.1 and [::1] only, spelled
		// so. A name, even localhost, is looked up, and where /etc/hosts
		// does not list it, DNS could point it at another machine, which
		// would then get the token and the file key in the clear.
		{"http://localhost:1", protoMustUseHTTPS},
		{"http://LocalHost:1", protoMustUseHTTPS},
		{"http://rypt.example.test", protoMustUseHTTPS},
		{"http://10.0.0.1:8080", protoMustUseHTTPS},
		{"http://127.0.0.2:1", protoMustUseHTTPS},
		{"http://[::ffff:127.0.0.1]:1", protoMustUseHTTPS},
		{"http://[0:0:0:0:0:0:0:1]:1", protoMustUseHTTPS},
		{"http://localhost.example.test:1", protoMustUseHTTPS},

		// Not valid, whatever the scheme and host: a query or a fragment,
		// even a bare "?" or "#", and a port outside 1 to 65535, which is
		// refused before any connection is tried.
		{"http://127.0.0.1:1/#", protoNotAValidURL},
		{"http://localhost:1/#", protoNotAValidURL},
		{"http://example.com/#", protoNotAValidURL},
		{"http://127.0.0.1:1/?", protoNotAValidURL},
		{"http://127.0.0.1:99999", protoNotAValidURL},
		{"http://127.0.0.1:0", protoNotAValidURL},
		{"https://rypt.example.test:65536", protoNotAValidURL},

		{"ftp://rypt.example.test", protoNotAValidURL},
		{"rypt.example.test", protoNotAValidURL},
		{"https://", protoNotAValidURL},
		{"https://user:pass@rypt.example.test", protoNotAValidURL},
		{"https://user@rypt.example.test", protoNotAValidURL},
		{"https://rypt.example.test/?key=1", protoNotAValidURL},
		{"https://rypt.example.test/?", protoNotAValidURL},
		{"https://rypt.example.test/#f", protoNotAValidURL},
		{"https://rypt.example.test/a b", protoNotAValidURL},
		{" https://rypt.example.test", protoNotAValidURL},
		{"https://rypt.example.test/\t", protoNotAValidURL},
		{"https://rypt.example.test/é", protoNotAValidURL},
		{"https://rypt.example.test/\xff", protoNotAValidURL},
	} {
		t.Run(fmt.Sprintf("%q", tc.url), func(t *testing.T) {
			t.Parallel()
			env := Env{}.WithToken(mockToken).WithAPIURL(tc.url)
			o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", tc.message)
		})
	}

	// Decrypting reports it once a stanza needs the API.
	for _, tc := range []struct {
		url     string
		message string
	}{
		{"http://rypt.example.test", protoMustUseHTTPS},
		{"http://localhost:1", protoMustUseHTTPS},
		{"https://rypt.example.test/\xff", protoNotAValidURL},
		{"http://127.0.0.1:99999", protoNotAValidURL},
	} {
		t.Run(fmt.Sprintf("unwrapping %q", tc.url), func(t *testing.T) {
			t.Parallel()
			env := Env{}.WithToken(mockToken).WithAPIURL(tc.url)
			o := unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
			protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", tc.message})
		})
	}
}

func TestProtocolKeepsTheAPIURLPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		prefix string
		suffix string
	}{
		{"root with a slash", "", "/"},
		{"prefix", "/api", ""},
		{"prefix with a slash", "/api", "/"},
		{"two segments", "/rypt/api", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMockWith(t, MockConfig{Prefix: tc.prefix})
			env := ForMock(m).WithAPIURL(m.URL() + tc.suffix)

			file := protoWrapped(t, env, protoKeyA)
			protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), map[int][]byte{0: protoFileKey})
			want := []string{
				tc.prefix + "/v1/keys/" + goldenKeyA + "/encrypt",
				tc.prefix + "/v1/keys/" + goldenKeyA + "/decrypt",
			}
			var paths []string
			for _, r := range m.Requests() {
				paths = append(paths, r.Path)
			}
			if !slices.Equal(paths, want) {
				t.Errorf("request paths %q, want %q", paths, want)
			}
		})
	}
}

// The name localhost is looked up, so plain http to it could reach another
// machine: it is refused before any request, although a mock listens there.
func TestProtocolRefusesPlainHTTPToLocalhost(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"localhost", "LOCALHOST"} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			m := NewMock(t)
			env := ForMock(m).WithAPIURL(fmt.Sprintf("http://%s:%d", host, m.Port()))

			o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", protoMustUseHTTPS)
			o = unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
			protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", protoMustUseHTTPS})
			protoWantCount(t, "requests", m.Calls(), 0)
		})
	}
}

// Over https, the certificate proves who answers, so the name localhost is
// fine.
func TestProtocolReachesTheAPIAtHTTPSLocalhost(t *testing.T) {
	t.Parallel()
	protoSkipUnlessLinux(t)
	m := NewMockWith(t, MockConfig{TLS: true, CertNames: []string{"localhost"}})
	env := ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile).WithAPIURL(fmt.Sprintf("https://localhost:%d", m.Port()))

	file := protoWrapped(t, env, protoKeyA)
	protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), map[int][]byte{0: protoFileKey})
	protoWantCount(t, "requests", m.Calls(), 2)
	for _, r := range m.Requests() {
		if want := fmt.Sprintf("localhost:%d", m.Port()); r.Host != want {
			t.Errorf("%s: Host %q, want %q", r.Operation, r.Host, want)
		}
	}
}

func TestProtocolSendsTheDocumentedRequests(t *testing.T) {
	t.Parallel()
	m := NewMock(t)
	env := ForMock(m)
	file := protoWrapped(t, env, protoKeyA)
	protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), map[int][]byte{0: protoFileKey})

	requests := m.Requests()
	if len(requests) != 2 {
		t.Fatalf("%d requests, want 2", len(requests))
	}
	for i, want := range []struct {
		operation string
		field     string
		value     []byte
	}{
		{"encrypt", "plaintext", protoFileKey},
		{"decrypt", "ciphertext", toySeal(protoKeyA, protoFileKey)},
	} {
		r := requests[i]
		if path := "/v1/keys/" + goldenKeyA + "/" + want.operation; r.Method != http.MethodPost || r.Path != path || r.RawQuery != "" {
			t.Errorf("%s: %s %s?%s, want POST %s", want.operation, r.Method, r.Path, r.RawQuery, path)
		}
		if host := fmt.Sprintf("127.0.0.1:%d", m.Port()); r.Host != host {
			t.Errorf("%s: Host %q, want %q", want.operation, r.Host, host)
		}
		for name, value := range map[string]string{
			"Authorization": "Bearer " + mockToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		} {
			if got := r.Header.Values(name); !slices.Equal(got, []string{value}) {
				t.Errorf("%s: %s %q, want %q", want.operation, name, got, value)
			}
		}
		ua := r.Header.Get("User-Agent")
		sdk, ok := strings.CutPrefix(ua, "age-plugin-rypt/0.2.0 rypt-go/")
		if !ok || sdk == "" || strings.ContainsAny(sdk, " \t") {
			t.Errorf("%s: User-Agent %q, want age-plugin-rypt/0.2.0 rypt-go/<version>", want.operation, ua)
		}
		// Exactly one field, in padded standard base64.
		var body map[string]string
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Errorf("%s: body %q is not a JSON object of strings: %v", want.operation, r.Body, err)
			continue
		}
		if wantBody := map[string]string{want.field: base64.StdEncoding.EncodeToString(want.value)}; !maps.Equal(body, wantBody) {
			t.Errorf("%s: body %q, want %q", want.operation, body, wantBody)
		}
	}
}

// ---------------------------------------------------------------------------
// Network failures and TLS

func TestProtocolReportsAnUnreachableAPI(t *testing.T) {
	t.Parallel()
	// Port 1, as closedAPIURL: a port picked at random could be taken by a
	// parallel test's mock before the plugin dials it.
	env := Env{}.WithToken(mockToken).WithAPIURL(closedAPIURL)

	o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
	protoWantFailure(t, o, "recipient 0", protoConnectionFailed)

	o = unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
	protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", protoConnectionFailed})
}

func TestProtocolSpeaksTLSToAnHTTPSURL(t *testing.T) {
	t.Parallel()
	// The server speaks plain HTTP, so the TLS handshake fails.
	server := protoPlainHTTPServer(t)
	env := Env{}.WithToken(mockToken).WithAPIURL(server.URL("https"))

	o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
	protoWantFailure(t, o, "recipient 0", "rypt: TLS error")
	if server.Conns() == 0 {
		t.Error("the plugin never connected")
	}
}

func TestProtocolChecksTheCertificate(t *testing.T) {
	t.Parallel()
	const rejected = "rypt: TLS certificate rejected"

	t.Run("untrusted", func(t *testing.T) {
		t.Parallel()
		m := NewMockWith(t, MockConfig{TLS: true})
		env := ForMock(m)

		o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
		protoWantFailure(t, o, "recipient 0", rejected)

		o = unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
		protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", rejected})
		protoWantCount(t, "requests", m.Calls(), 0)
	})

	t.Run("trusted", func(t *testing.T) {
		t.Parallel()
		protoSkipUnlessLinux(t)
		m := NewMockWith(t, MockConfig{TLS: true})
		env := ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile)

		file := protoWrapped(t, env, protoKeyA)
		protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), map[int][]byte{0: protoFileKey})
		protoWantCount(t, "requests", m.Calls(), 2)
	})

	t.Run("trusted for another name", func(t *testing.T) {
		t.Parallel()
		protoSkipUnlessLinux(t)
		// httptest's certificate names 127.0.0.1, ::1 and example.com, but
		// not localhost.
		m := NewMockWith(t, MockConfig{TLS: true})
		env := ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile).WithAPIURL(fmt.Sprintf("https://localhost:%d", m.Port()))

		o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
		protoWantFailure(t, o, "recipient 0", rejected)
		protoWantCount(t, "requests", m.Calls(), 0)
	})
}

// A client may hang up as soon as it has answered an error with ok, before
// it reads the done that follows. Writing done then fails, but it must not
// kill the plugin with SIGPIPE, as a Go program dies by default when its
// stdout is a pipe nobody reads: the exit code stays 3.
func TestProtocolExitsWith3WhenTheClientHangsUpAfterAnError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	// A recipient refused as it is read, before any request.
	cmd := pluginBin(t).command(ctx, Env{}, "--age-plugin=recipient-v1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, s := range wrapPhase1([]string{rawRecipient(make([]byte, 15))}, nil, [][]byte{protoFileKey}) {
		writeStanza(stdin, s)
	}
	// The error comes first: age's framework reports a recipient before it
	// sends anything else, grease included.
	s, err := readStanza(bufio.NewReader(stdout))
	if err != nil || s.Type != "error" {
		cmd.Process.Kill()
		t.Fatalf("the plugin sent %+v, %v; want an error", s, err)
	}
	// Nobody reads stdout from now on, so the plugin's next write fails.
	stdout.Close()
	writeStanza(stdin, Stanza{Type: "ok"})
	stdin.Close()
	err = cmd.Wait()

	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("the plugin did not finish within %v; stderr %q", runTimeout, stderr.String())
	case err != nil && !errors.As(err, &exitErr):
		t.Fatalf("running the plugin: %v", err)
	}
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		t.Errorf("the plugin died of %v, want exit code 3", status.Signal())
	} else if code := cmd.ProcessState.ExitCode(); code != 3 {
		t.Errorf("exit code %d, want 3; stderr %q", code, stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Standard error
//
// net/http logs some events through Go's standard logger, which writes to
// standard error. A successful run must still write nothing there.

// protoWantNoStderr checks that the runs wrote nothing to standard error,
// and so not the token either.
func protoWantNoStderr(t *testing.T, outcomes ...*Outcome) {
	t.Helper()
	for _, o := range outcomes {
		if o.Stderr != "" {
			t.Errorf("a successful run wrote %d bytes to stderr: %.300q", len(o.Stderr), o.Stderr)
		}
		if strings.Contains(o.Stderr, mockToken) {
			t.Error("a successful run wrote the token to stderr")
		}
	}
}

// net/http logs the bytes a server sends after a complete answer, on a
// connection that waits for the next request.
func TestProtocolLogsNothingWhenTheAPISendsBytesAfterItsAnswer(t *testing.T) {
	t.Parallel()
	m := NewMockWith(t, MockConfig{Unsolicited: "SERVER-CONTROLLED-TEXT " + mockBodyMarker})
	env := ForMock(m)

	// net/http logs the bytes from a background goroutine, which may not
	// get to it before the plugin exits; each run is another chance. The
	// HTTP/2 test below is the certain check, but runs on Linux only.
	const runs = 3
	for range runs {
		wrapped := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
		protoWantWrapped(t, wrapped)
		unwrapped := unwrap(t, env, []string{identity(protoKeyA)}, wrapped.Stanzas(0))
		protoWantUnwrap(t, unwrapped, map[int][]byte{0: protoFileKey})
		protoWantNoStderr(t, wrapped, unwrapped)
	}
	protoWantCount(t, "requests", m.Calls(), 2*runs)
}

// With GODEBUG=http2debug=2, Go's HTTP/2 client logs every header it sends,
// the token among them, and every frame, file keys among them.
func TestProtocolLogsNothingWithHTTP2Debugging(t *testing.T) {
	t.Parallel()
	protoSkipUnlessLinux(t)
	m := NewMockWith(t, MockConfig{TLS: true, HTTP2: true})
	env := ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile).WithVar("GODEBUG", "http2debug=2")

	wrapped := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
	protoWantWrapped(t, wrapped)
	unwrapped := unwrap(t, env, []string{identity(protoKeyA)}, wrapped.Stanzas(0))
	protoWantUnwrap(t, unwrapped, map[int][]byte{0: protoFileKey})
	protoWantNoStderr(t, wrapped, unwrapped)
	protoWantCount(t, "requests", m.Calls(), 2)
	// Otherwise the debug switch had nothing to log.
	for _, r := range m.Requests() {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("%s spoke %s, want HTTP/2.0", r.Operation, r.Proto)
		}
	}
}

// ---------------------------------------------------------------------------
// Proxies

func TestProtocolReachesARemoteAPIThroughHTTPSProxy(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"HTTPS_PROXY", "https_proxy"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			proxy := protoHTTPProxy(t)
			env := protoRemoteEnv().WithVar(name, proxy.URL("http"))

			// The proxy refuses the tunnel.
			o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", protoConnectionFailed)

			heads := proxy.Seen()
			if len(heads) == 0 || len(heads) > 3 || len(heads) != proxy.Conns() {
				t.Fatalf("the proxy got %d connections and %d requests %q; want 1 to 3 of each", proxy.Conns(), len(heads), heads)
			}
			for _, head := range heads {
				if !strings.HasPrefix(head, "CONNECT "+protoRemoteTarget+" ") {
					t.Errorf("the proxy got %q, want a CONNECT to %s", head, protoRemoteTarget)
				}
				// The token travels only inside the tunnel.
				if strings.Contains(head, mockToken) {
					t.Errorf("the proxy saw the token: %q", head)
				}
			}
		})
	}
}

func TestProtocolNoProxyBypassesTheProxy(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			proxy := protoHTTPProxy(t)
			env := protoRemoteEnv().
				WithVar("HTTPS_PROXY", proxy.URL("http")).
				WithVar(name, "rypt.example.test")

			// Connected directly, so the name does not resolve.
			o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", protoConnectionFailed)
			protoWantCount(t, "connections to the proxy", proxy.Conns(), 0)
		})
	}
}

func TestProtocolIgnoresHTTPProxyAndAllProxy(t *testing.T) {
	t.Parallel()
	httpProxy := protoHTTPProxy(t)
	socksProxy := protoSOCKSProxy(t)
	env := protoRemoteEnv().
		WithVar("HTTP_PROXY", httpProxy.URL("http")).
		WithVar("http_proxy", httpProxy.URL("http")).
		WithVar("ALL_PROXY", socksProxy.URL("socks5")).
		WithVar("all_proxy", httpProxy.URL("http"))

	// Connected directly, so the name does not resolve.
	o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
	protoWantFailure(t, o, "recipient 0", protoConnectionFailed)
	protoWantCount(t, "connections to the HTTP proxy", httpProxy.Conns(), 0)
	protoWantCount(t, "connections to the SOCKS proxy", socksProxy.Conns(), 0)
}

func TestProtocolReachesALoopbackAPIDirectlyWhateverTheProxies(t *testing.T) {
	t.Parallel()
	// Port 1, as closedAPIURL: nothing listens there, so a request sent
	// through one of these proxies fails.
	withDeadProxies := func(env Env) Env {
		for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			env = env.WithVar(name, closedAPIURL)
		}
		return env
	}
	check := func(t *testing.T, m *Mock, env Env) {
		t.Helper()
		file := protoWrapped(t, env, protoKeyA)
		protoWantUnwrap(t, unwrap(t, env, []string{identity(protoKeyA)}, file), map[int][]byte{0: protoFileKey})
		protoWantCount(t, "requests", m.Calls(), 2)
	}

	t.Run("http 127.0.0.1", func(t *testing.T) {
		t.Parallel()
		m := NewMock(t)
		check(t, m, withDeadProxies(ForMock(m)))
	})
	t.Run("https 127.0.0.1", func(t *testing.T) {
		t.Parallel()
		protoSkipUnlessLinux(t)
		m := NewMockWith(t, MockConfig{TLS: true})
		check(t, m, withDeadProxies(ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile)))
	})
	t.Run("https localhost", func(t *testing.T) {
		t.Parallel()
		protoSkipUnlessLinux(t)
		m := NewMockWith(t, MockConfig{TLS: true, CertNames: []string{"localhost"}})
		env := ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile).WithAPIURL(fmt.Sprintf("https://localhost:%d", m.Port()))
		check(t, m, withDeadProxies(env))
	})
	// net/http never proxies lowercase localhost, so the plugin does not
	// check a proxy value it would never use.
	t.Run("https localhost with an unparseable HTTPS_PROXY", func(t *testing.T) {
		t.Parallel()
		protoSkipUnlessLinux(t)
		m := NewMockWith(t, MockConfig{TLS: true, CertNames: []string{"localhost"}})
		env := ForMock(m).WithVar("SSL_CERT_FILE", m.CertFile).WithAPIURL(fmt.Sprintf("https://localhost:%d", m.Port()))
		check(t, m, env.WithVar("HTTPS_PROXY", "%zz"))
	})
}

// net/http bypasses a proxy only for localhost in lowercase, so LOCALHOST
// goes through HTTPS_PROXY, and the plugin checks the value it holds.
func TestProtocolSendsUppercaseLocalhostThroughHTTPSProxy(t *testing.T) {
	t.Parallel()
	const api = "https://LOCALHOST:1"

	t.Run("a proxy", func(t *testing.T) {
		t.Parallel()
		proxy := protoHTTPProxy(t)
		env := Env{}.WithToken(mockToken).WithAPIURL(api).WithVar("HTTPS_PROXY", proxy.URL("http"))

		// The proxy refuses the tunnel.
		o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
		protoWantFailure(t, o, "recipient 0", protoConnectionFailed)
		heads := proxy.Seen()
		if len(heads) == 0 {
			t.Fatal("the proxy got no request")
		}
		for _, head := range heads {
			if !strings.HasPrefix(head, "CONNECT LOCALHOST:1 ") {
				t.Errorf("the proxy got %q, want a CONNECT to LOCALHOST:1", head)
			}
		}
	})
	t.Run("an unparseable proxy", func(t *testing.T) {
		t.Parallel()
		env := Env{}.WithToken(mockToken).WithAPIURL(api).WithVar("HTTPS_PROXY", "%zz")
		o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
		protoWantFailure(t, o, "recipient 0", "HTTPS_PROXY is not a valid proxy URL")
	})
}

func TestProtocolRefusesAnUnparseableHTTPSProxy(t *testing.T) {
	t.Parallel()
	values := []string{
		// Values that Go's proxy parser rejects even with http:// put in
		// front.
		"%zz", "http://127.0.0.1:%zz", "http://127.0.0.1:1\x7f",
		// A proxy scheme without "//" and a host. Go would put http:// in
		// front and use a proxy at a host named after the scheme.
		"http:/127.0.0.1:3128", "socks5:/127.0.0.1:1080", "HTTP:/proxy", "http:",
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy"} {
		for _, value := range values {
			t.Run(fmt.Sprintf("%s=%q", name, value), func(t *testing.T) {
				t.Parallel()
				env := protoRemoteEnv().WithVar(name, value)
				o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
				protoWantFailure(t, o, "recipient 0", name+" is not a valid proxy URL")
			})
		}
	}

	t.Run("unwrapping", func(t *testing.T) {
		t.Parallel()
		env := protoRemoteEnv().WithVar("HTTPS_PROXY", values[0])
		o := unwrap(t, env, []string{identity(protoKeyA)}, []Stanza{protoStanza(protoKeyA, protoFileKey)})
		protoWantUnwrap(t, o, nil, PluginError{"stanza 0 0", "HTTPS_PROXY is not a valid proxy URL"})
	})
}

func TestProtocolReachesARemoteAPIThroughASOCKS5Proxy(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			proxy := protoSOCKSProxy(t)
			env := protoRemoteEnv().WithVar("HTTPS_PROXY", proxy.URL(scheme))

			// The proxy refuses the connection. Go resolves no name
			// itself for either scheme: the proxy gets the name.
			o := wrap(t, env, []string{recipient(protoKeyA)}, nil, protoFileKey)
			protoWantFailure(t, o, "recipient 0", protoConnectionFailed)

			seen := proxy.Seen()
			if len(seen) == 0 || len(seen) > 3 || len(seen) != proxy.Conns() {
				t.Fatalf("the proxy got %d connections and %d requests %q; want 1 to 3 of each", proxy.Conns(), len(seen), seen)
			}
			for _, target := range seen {
				if target != protoRemoteTarget {
					t.Errorf("the proxy was asked for %q, want %q", target, protoRemoteTarget)
				}
			}
		})
	}
}
