// Shared support for black-box tests of the age-plugin-rypt binary: a mock
// rypt API, a minimal age plugin client, a hermetic environment for the
// plugin process, leak checks, and encoders that do not use the plugin's code.
//
// TestMain builds the plugin once. Every helper drives a binary from the
// outside, so the same tests can also run against another implementation
// named by AGE_PLUGIN_RYPT_COMPAT_BINARY, such as the Rust 0.1.0 build.
//
// Naming: types, their constructors, methods and fields are exported (Mock,
// NewMock, Env, ForMock, Outcome.Errors); free helper functions, constants
// and variables are not (statusKey, wrap, recipient, mockToken).
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// ---------------------------------------------------------------------------
// The binaries under test

// compatEnvVar names another implementation of the plugin, such as the Rust
// 0.1.0 build, for compatibility tests.
const compatEnvVar = "AGE_PLUGIN_RYPT_COMPAT_BINARY"

// runTimeout bounds every run of a plugin binary, so that a hung plugin fails
// its test instead of stalling the suite. The plugin's own deadline is 30 s
// per operation.
const runTimeout = 2 * time.Minute

var (
	// builtPlugin is the binary TestMain built, or "" if the build failed.
	builtPlugin Bin
	// compatPlugin is the binary named by AGE_PLUGIN_RYPT_COMPAT_BINARY, or "".
	compatPlugin Bin
	// compatProblem says why that binary cannot be used, or is "".
	compatProblem string
)

// TestMain builds the plugin once, with `go build -o <tmpdir>/age-plugin-rypt
// github.com/x6c-co/age-plugin-rypt` run from the module root, and removes
// the directory when the tests are done. It also reads
// AGE_PLUGIN_RYPT_COMPAT_BINARY.
//
// A failed build does not stop the run. TestMain prints the build output
// once, every test that needs the binary fails, and tests of the harness
// itself (TestMockSelfCheck) still run.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "age-plugin-rypt-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	if bin, err := buildPlugin(dir); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: building the plugin failed: %v\n", err)
	} else {
		builtPlugin = bin
	}
	compatPlugin, compatProblem = findCompatPlugin()
	// When TestMain returns, the testing package exits with m.Run's result.
	m.Run()
}

// buildPlugin builds the plugin into dir.
func buildPlugin(dir string) (Bin, error) {
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "age-plugin-rypt")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/x6c-co/age-plugin-rypt")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, out)
	}
	return Bin(bin), nil
}

// moduleRoot finds the directory holding go.mod, starting from the working
// directory, which go test sets to this package's directory.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod in the working directory or above it")
		}
		dir = parent
	}
}

// findCompatPlugin returns the binary named by AGE_PLUGIN_RYPT_COMPAT_BINARY,
// or why it cannot be used. Both are empty when the variable is unset.
func findCompatPlugin() (Bin, string) {
	path := os.Getenv(compatEnvVar)
	if path == "" {
		return "", ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Sprintf("%s: %v", compatEnvVar, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Sprintf("%s: %v", compatEnvVar, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Sprintf("%s: %s is not an executable file", compatEnvVar, abs)
	}
	return Bin(abs), ""
}

// pluginBin returns the binary TestMain built. It fails the test if the
// build failed.
func pluginBin(t testing.TB) Bin {
	t.Helper()
	if builtPlugin == "" {
		t.Fatal("the plugin was not built; the build output is at the start of the test log")
	}
	return builtPlugin
}

// compatBin returns the binary named by AGE_PLUGIN_RYPT_COMPAT_BINARY. It
// skips the test when the variable is unset, and fails it when the variable
// does not name an executable file.
func compatBin(t testing.TB) Bin {
	t.Helper()
	if compatProblem != "" {
		t.Fatal(compatProblem)
	}
	if compatPlugin == "" {
		t.Skipf("%s is not set", compatEnvVar)
	}
	return compatPlugin
}

// Bin is the path of a plugin binary to run: the one TestMain built
// (pluginBin) or another implementation (compatBin).
type Bin string

// Dir is the directory holding the binary, to put on PATH for an age client
// (Env.WithPath). age finds a plugin by its name, so this works only for a
// binary named age-plugin-rypt.
func (b Bin) Dir() string {
	return filepath.Dir(string(b))
}

// command prepares a run of the binary with exactly env's variables.
func (b Bin) command(ctx context.Context, env Env, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, string(b), args...)
	cmd.Env = env.Environ()
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// ---------------------------------------------------------------------------
// Encoders, independent of the plugin's code

// Golden vectors from the spec. The encodings are frozen: real files depend
// on them.
const (
	goldenKeyA       = "3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47"
	goldenRecipientA = "age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g"
	goldenIdentityA  = "AGE-PLUGIN-RYPT-18U4FC8NMF48Z48CSDJX452C7GU098V2X"

	goldenKeyB       = "670ef9c3-1a6e-4117-ae6e-ffc92329ff7b"
	goldenRecipientB = "age1rypt1vu80nsc6deq30tnwllyjx20l0vah96qf"
	goldenIdentityB  = "AGE-PLUGIN-RYPT-1VU80NSC6DEQ30TNWLLYJX20L0VH9Y308"
)

// UUID is a rypt key id: 16 bytes, whose canonical form is lowercase
// hyphenated hex, as in 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47.
type UUID [16]byte

// ParseUUID parses the canonical form of a UUID and nothing else: no
// uppercase, braces, URN prefix or 32-digit form.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("%q is not a hyphenated UUID", s)
	}
	digits := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if strings.ToLower(digits) != digits {
		return u, fmt.Errorf("%q is not lowercase", s)
	}
	if _, err := hex.Decode(u[:], []byte(digits)); err != nil {
		return u, fmt.Errorf("%q is not a UUID: %v", s, err)
	}
	return u, nil
}

// MustParseUUID is ParseUUID for UUIDs known to be valid. It panics on an
// invalid one.
func MustParseUUID(s string) UUID {
	u, err := ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

// String returns the canonical form: lowercase hyphenated hex.
func (u UUID) String() string {
	h := hex.EncodeToString(u[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Hex returns the 32 hex digits without hyphens, a form the plugin's `new
// --key` accepts but a stanza must not use.
func (u UUID) Hex() string {
	return hex.EncodeToString(u[:])
}

// recipient encodes a key as an age1rypt1… recipient, using age's encoder.
func recipient(key UUID) string {
	return rawRecipient(key[:])
}

// identity encodes a key as an AGE-PLUGIN-RYPT-1… identity, using age's
// encoder.
func identity(key UUID) string {
	return rawIdentity(key[:])
}

// rawRecipient encodes any payload as a rypt recipient, for testing that
// the plugin rejects one that is not 16 bytes.
func rawRecipient(payload []byte) string {
	return plugin.EncodeRecipient("rypt", payload)
}

// rawIdentity encodes any payload as a rypt identity, for testing that the
// plugin rejects one that is not 16 bytes.
func rawIdentity(payload []byte) string {
	return plugin.EncodeIdentity("rypt", payload)
}

// ---------------------------------------------------------------------------
// Mock rypt API

// mockToken is the only token the mock accepts. It is shaped like a rypt
// API key.
const mockToken = "ry_Test1234_abcdefghijklmnopqrstuvwxyz012345"

// mockBodyMarker is in every body the mock sends that is not a successful
// answer, so that tests can check the plugin never repeats response text.
const mockBodyMarker = "mock-body-marker"

// sdkResponseLimit is the most of a response body the rypt Go SDK reads.
const sdkResponseLimit = 8 << 20

// Keys the mock answers specially. The UUIDs are those of the Rust 0.1.0
// tests. Any other key, except statusKey's, gets correct answers.
var (
	// shortKey's decrypt answers one byte less than was encrypted: 15
	// bytes for a file key.
	shortKey = MustParseUUID("5a5a5a5a-0000-4000-8000-000000000015")
	// notJSONKey is answered with 200 and a body that is not JSON.
	notJSONKey = MustParseUUID("5a5a5a5a-0000-4000-8000-0000000000a1")
	// missingFieldKey is answered with 200 and JSON without the expected
	// field.
	missingFieldKey = MustParseUUID("5a5a5a5a-0000-4000-8000-0000000000a2")
	// badBase64Key is answered with 200 and a field that is not valid
	// base64: the correct answer's base64 followed by a stray "!".
	badBase64Key = MustParseUUID("5a5a5a5a-0000-4000-8000-0000000000a3")
	// emptyCiphertextKey's encrypt answers 200 with an empty ciphertext,
	// and its decrypt 200 with an empty plaintext.
	emptyCiphertextKey = MustParseUUID("5a5a5a5a-0000-4000-8000-0000000000a4")
	// oversizedKey is answered with 200 and valid JSON larger than
	// sdkResponseLimit, whose fields are valid base64.
	oversizedKey = MustParseUUID("5a5a5a5a-0000-4000-8000-0000000000a5")
)

// statusKey returns a key the mock answers with status on every request
// that has the right token, with an error body that fits the status: for
// example "unavailable" for 503, and a Location header back at the mock for
// a 3xx. status must be from 200 to 599; the mock treats other numbers as
// ordinary keys. statusKey(404) is 00000000-0000-0000-0000-000000000404.
func statusKey(status int) UUID {
	return MustParseUUID(fmt.Sprintf("00000000-0000-0000-0000-%012d", status))
}

// forcedStatus returns the status a statusKey key forces.
func forcedStatus(key UUID) (int, bool) {
	digits, ok := strings.CutPrefix(key.String(), "00000000-0000-0000-0000-")
	if !ok {
		return 0, false
	}
	status, err := strconv.Atoi(digits)
	if err != nil || status < 200 || status > 599 {
		return 0, false
	}
	return status, true
}

// errorCode returns the rypt error code the mock sends with status.
func errorCode(status int) string {
	switch status {
	case 400:
		return "invalid_ciphertext"
	case 401:
		return "unauthorized"
	case 402:
		return "billing_required"
	case 403:
		return "action_not_allowed"
	case 404:
		return "not_found"
	case 405:
		return "method_not_allowed"
	case 409:
		return "key_pending_deletion"
	case 413:
		return "payload_too_large"
	case 415:
		return "unsupported_media_type"
	case 429:
		return "rate_limited"
	case 500:
		return "internal_error"
	case 502, 503, 504:
		return "unavailable"
	default:
		return "mock_status"
	}
}

// toyMagic starts every toy ciphertext. Its length makes the toy ciphertext
// of a 16-byte file key 41 bytes long, so its base64 needs padding.
const toyMagic = "mock-rypt"

// toySeal returns the mock's ciphertext of plaintext under key: toyMagic,
// the key's 16 bytes, then the plaintext XORed with 0x5a.
func toySeal(key UUID, plaintext []byte) []byte {
	out := append([]byte(toyMagic), key[:]...)
	for _, b := range plaintext {
		out = append(out, b^0x5a)
	}
	return out
}

// toyOpen reverses toySeal. It fails for a ciphertext under another key.
func toyOpen(key UUID, ciphertext []byte) ([]byte, bool) {
	rest, ok := bytes.CutPrefix(ciphertext, []byte(toyMagic))
	if !ok {
		return nil, false
	}
	rest, ok = bytes.CutPrefix(rest, key[:])
	if !ok {
		return nil, false
	}
	plaintext := make([]byte, len(rest))
	for i, b := range rest {
		plaintext[i] = b ^ 0x5a
	}
	return plaintext, true
}

// toyOpenAny opens a toy ciphertext under whatever key it names.
func toyOpenAny(ciphertext []byte) ([]byte, bool) {
	rest, ok := bytes.CutPrefix(ciphertext, []byte(toyMagic))
	if !ok || len(rest) < len(UUID{}) {
		return nil, false
	}
	return toyOpen(UUID(rest[:len(UUID{})]), ciphertext)
}

// oversizedBody is the answer for oversizedKey. Each field is valid padded
// base64, and the two together are larger than sdkResponseLimit.
var oversizedBody = sync.OnceValue(func() []byte {
	field := strings.Repeat("A", sdkResponseLimit/2+4096)
	return []byte(`{"ciphertext":"` + field + `","plaintext":"` + field + `"}`)
})

// Mock is a rypt API on a random 127.0.0.1 port, one per test.
//
// It implements POST /v1/keys/{id}/encrypt and /decrypt with toySeal, a
// reversible toy cipher bound to the key. Like rypt, it checks the bearer
// token (only mockToken is accepted), the content type, and that the binary
// field is padded standard base64. Errors use rypt's envelope, {"error":
// code, "message": "... mockBodyMarker", "request_id": "..."}. It records
// every request.
//
// Checks run in this order, the first failure deciding the answer: the path
// (404), the token (401), the method (405), the content type (415), the
// query (400), the key's form (400), statusKey, the special keys, the body
// (400), and for decrypt the ciphertext's key (400 invalid_ciphertext).
type Mock struct {
	// CertFile is a PEM file of the mock's certificate when it serves
	// https. Set SSL_CERT_FILE to it to make the plugin trust the mock.
	CertFile string

	server      *httptest.Server
	prefix      string
	unsolicited string

	mu       sync.Mutex
	requests []MockRequest
}

// MockConfig sets how NewMockWith serves.
type MockConfig struct {
	// Prefix serves the API under a path, such as "/api", so that
	// RYPT_API_URL=http://127.0.0.1:port/api works. Requests outside it are
	// answered 404 not_found.
	Prefix string
	// TLS serves https, with httptest's certificate, which names 127.0.0.1,
	// ::1 and example.com. Nothing trusts it unless told to (see
	// Mock.CertFile).
	TLS bool
	// HTTP2 makes a TLS mock offer HTTP/2 only, which Go's client then
	// speaks. Without it, a mock speaks HTTP/1.1.
	HTTP2 bool
	// CertNames are the host names and IP addresses that a TLS mock's
	// certificate names instead of httptest's, such as "localhost". The
	// certificate is made for this mock and signs itself.
	CertNames []string
	// Unsolicited is sent after every answer, on the same HTTP/1.1
	// connection, as a server with a bug might: the client has asked for
	// nothing more, so it reads these bytes as an answer to no request.
	Unsolicited string
}

// MockRequest is a request the mock received.
type MockRequest struct {
	Method string
	// Proto is the HTTP version the client spoke, such as "HTTP/1.1" or
	// "HTTP/2.0".
	Proto string
	// Path is the path as sent, still escaped, prefix included.
	Path     string
	RawQuery string
	Host     string
	// Operation is "encrypt" or "decrypt" for a request to
	// {prefix}/v1/keys/{id}/{operation}, and "" for any other path.
	Operation string
	// Key is the {id} path segment of an encrypt or decrypt request.
	Key string
	// Header holds every request header, among them Authorization,
	// Content-Type, Accept and User-Agent.
	Header http.Header
	// Body is the request body, up to 1 MiB.
	Body []byte
}

// NewMock starts a plain-http mock at the root path. The test's cleanup
// stops it.
func NewMock(t testing.TB) *Mock {
	t.Helper()
	return NewMockWith(t, MockConfig{})
}

// NewMockWith starts a mock as config says. The test's cleanup stops it.
func NewMockWith(t testing.TB, config MockConfig) *Mock {
	t.Helper()
	m := &Mock{prefix: strings.TrimRight(config.Prefix, "/"), unsolicited: config.Unsolicited}
	switch {
	case m.prefix != "" && !strings.HasPrefix(m.prefix, "/"):
		t.Fatalf("mock prefix %q does not start with /", config.Prefix)
	case !config.TLS && (config.HTTP2 || len(config.CertNames) > 0):
		t.Fatal("a mock serves HTTP/2 or another certificate only with TLS")
	case config.HTTP2 && config.Unsolicited != "":
		t.Fatal("a mock sends unsolicited bytes only over HTTP/1.1")
	}
	m.server = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	// Handshakes the plugin refuses are expected; keep them out of the log.
	m.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if config.TLS {
		m.server.EnableHTTP2 = config.HTTP2
		if len(config.CertNames) > 0 {
			cert, err := selfSignedCert(config.CertNames)
			if err != nil {
				t.Fatal(err)
			}
			m.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
		m.server.StartTLS()
		m.CertFile = filepath.Join(t.TempDir(), "mock-cert.pem")
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.server.Certificate().Raw})
		if err := os.WriteFile(m.CertFile, cert, 0o600); err != nil {
			m.server.Close()
			t.Fatal(err)
		}
	} else {
		m.server.Start()
	}
	t.Cleanup(m.server.Close)
	return m
}

// selfSignedCert makes a certificate for a TLS server that names each of
// names, read as an IP address where it is one and as a host name
// otherwise. It signs itself, so a client that trusts it as a root accepts
// it for those names.
func selfSignedCert(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "age-plugin-rypt e2e mock"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// URL is the API's base URL, prefix included, to use as RYPT_API_URL.
func (m *Mock) URL() string {
	return m.server.URL + m.prefix
}

// Port is the port the mock listens on, for URLs that name the mock
// another way, such as https://localhost:port.
func (m *Mock) Port() int {
	return m.server.Listener.Addr().(*net.TCPAddr).Port
}

// Requests returns every request received so far, in order.
func (m *Mock) Requests() []MockRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.requests)
}

// Calls counts every request received, whatever its path or outcome.
func (m *Mock) Calls() int {
	return len(m.Requests())
}

// EncryptCalls counts requests to an encrypt path, whatever their outcome.
func (m *Mock) EncryptCalls() int {
	return m.count("encrypt")
}

// DecryptCalls counts requests to a decrypt path, whatever their outcome.
func (m *Mock) DecryptCalls() int {
	return m.count("decrypt")
}

func (m *Mock) count(operation string) int {
	n := 0
	for _, r := range m.Requests() {
		if r.Operation == operation {
			n++
		}
	}
	return n
}

// serve records the request, then sends the answer.
func (m *Mock) serve(w http.ResponseWriter, r *http.Request) {
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	req := MockRequest{
		Method:   r.Method,
		Proto:    r.Proto,
		Path:     r.URL.EscapedPath(),
		RawQuery: r.URL.RawQuery,
		Host:     r.Host,
		Header:   r.Header.Clone(),
		Body:     body,
	}
	req.Key, req.Operation = m.route(req.Path)
	m.mu.Lock()
	m.requests = append(m.requests, req)
	m.mu.Unlock()

	status, answer := m.answer(req, readErr)
	w.Header().Set("Content-Type", "application/json")
	if status >= 300 && status < 400 {
		// A plugin that followed the redirect would get not_found instead.
		w.Header().Set("Location", m.URL()+"/redirected")
	}
	bodyAllowed := status != http.StatusNoContent && status != http.StatusNotModified
	if bodyAllowed {
		w.Header().Set("Content-Length", strconv.Itoa(len(answer)))
	} else {
		answer = nil
	}
	if m.unsolicited != "" {
		m.sendWithUnsolicited(w, status, answer)
		return
	}
	w.WriteHeader(status)
	w.Write(answer)
}

// sendWithUnsolicited sends the answer on the bare connection, as net/http
// would send it, with the unsolicited bytes right after it in the same
// write, so that they have arrived by the time the client has read the
// answer. Then it leaves the connection open, as for another request, until
// the client closes it.
func (m *Mock) sendWithUnsolicited(w http.ResponseWriter, status int, answer []byte) {
	header := w.Header().Clone()
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "the mock cannot send unsolicited bytes: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	header.Write(&b)
	b.WriteString("\r\n")
	b.Write(answer)
	b.WriteString(m.unsolicited)
	if _, err := conn.Write(b.Bytes()); err != nil {
		return
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	io.Copy(io.Discard, buffered.Reader)
}

// route splits a path of the form {prefix}/v1/keys/{id}/{operation}.
func (m *Mock) route(path string) (key, operation string) {
	rest, ok := strings.CutPrefix(path, m.prefix+"/v1/keys/")
	if !ok {
		return "", ""
	}
	key, operation, ok = strings.Cut(rest, "/")
	if !ok || key == "" || (operation != "encrypt" && operation != "decrypt") {
		return "", ""
	}
	return key, operation
}

// answer decides the status and body for a request, as Mock describes.
func (m *Mock) answer(req MockRequest, readErr error) (int, []byte) {
	if req.Operation == "" {
		return failure(http.StatusNotFound)
	}
	if req.Header.Get("Authorization") != "Bearer "+mockToken {
		return failure(http.StatusUnauthorized)
	}
	if req.Method != http.MethodPost {
		return failure(http.StatusMethodNotAllowed)
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return failure(http.StatusUnsupportedMediaType)
	}
	if req.RawQuery != "" {
		return failureCode(http.StatusBadRequest, "invalid_query")
	}
	key, err := ParseUUID(req.Key)
	if err != nil {
		return failureCode(http.StatusBadRequest, "invalid_request")
	}
	if status, ok := forcedStatus(key); ok {
		return failure(status)
	}
	switch key {
	case notJSONKey:
		return http.StatusOK, []byte("not json " + mockBodyMarker)
	case missingFieldKey:
		return success("result", mockBodyMarker)
	case oversizedKey:
		return http.StatusOK, oversizedBody()
	}
	if readErr != nil {
		return failure(http.StatusRequestEntityTooLarge)
	}

	inputField, outputField := "plaintext", "ciphertext"
	if req.Operation == "decrypt" {
		inputField, outputField = "ciphertext", "plaintext"
	}
	input, ok := binaryField(req.Body, inputField)
	if !ok {
		return failureCode(http.StatusBadRequest, "invalid_request")
	}
	var output []byte
	if req.Operation == "encrypt" {
		output = toySeal(key, input)
	} else {
		if output, ok = toyOpen(key, input); !ok {
			return failure(http.StatusBadRequest)
		}
		if key == shortKey && len(output) > 0 {
			output = output[:len(output)-1]
		}
	}
	if key == emptyCiphertextKey {
		output = nil
	}
	encoded := base64.StdEncoding.EncodeToString(output)
	if key == badBase64Key {
		encoded += "!"
	}
	return success(outputField, encoded)
}

// binaryField returns the bytes of a JSON body's string field, which must be
// non-empty, padded standard base64, as rypt requires.
func binaryField(body []byte, name string) ([]byte, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil, false
	}
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return nil, false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil, false
	}
	b, ok := strictBase64(s)
	if !ok || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// strictBase64 decodes padded standard base64, also refusing what Go's
// decoder lets through: line breaks and non-zero trailing bits.
func strictBase64(s string) ([]byte, bool) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return b, err == nil
}

// errorEnvelope is the body of every rypt error.
type errorEnvelope struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// failure is an error answer with the code that fits status.
func failure(status int) (int, []byte) {
	return failureCode(status, errorCode(status))
}

// failureCode is an error answer in rypt's envelope, with the marker.
func failureCode(status int, code string) (int, []byte) {
	body, _ := json.Marshal(errorEnvelope{
		Error:     code,
		Message:   "the mock refused the request: " + mockBodyMarker,
		RequestID: "req_mock",
	})
	return status, body
}

// success is a 200 answer with a single string field.
func success(field, value string) (int, []byte) {
	body, _ := json.Marshal(map[string]string{field: value})
	return http.StatusOK, body
}

// ---------------------------------------------------------------------------
// Environment of the plugin process

// closedAPIURL is every Env's RYPT_API_URL unless a test sets another or
// removes it: a loopback port nothing listens on, so that a test that forgets
// the mock can never reach a real rypt deployment.
const closedAPIURL = "http://127.0.0.1:1"

// Env is the complete environment of a plugin process. Nothing is inherited
// from the test's own environment: not the developer's proxy variables,
// RYPT_TOKEN or RYPT_API_URL, and not PATH unless a test sets it
// (WithPath). The zero Env holds only RYPT_API_URL=closedAPIURL.
//
// Each With method returns a changed copy and leaves its receiver alone, so
// one Env can be the base of many.
type Env struct {
	// changes are applied in order to the zero Env's variables.
	changes []envChange
}

type envChange struct {
	name, value string
	unset       bool
}

// ForMock is an Env whose requests go to m with the token m accepts.
func ForMock(m *Mock) Env {
	return Env{}.WithToken(mockToken).WithAPIURL(m.URL())
}

// WithToken sets RYPT_TOKEN.
func (e Env) WithToken(token string) Env {
	return e.WithVar("RYPT_TOKEN", token)
}

// WithoutToken removes RYPT_TOKEN.
func (e Env) WithoutToken() Env {
	return e.WithoutVar("RYPT_TOKEN")
}

// WithAPIURL sets RYPT_API_URL.
func (e Env) WithAPIURL(url string) Env {
	return e.WithVar("RYPT_API_URL", url)
}

// WithoutAPIURL removes RYPT_API_URL, so that the plugin uses its default,
// https://api.rypt.dev. Tests must never reach it: use this only with a
// proxy (HTTPS_PROXY) that never forwards, or with no token.
func (e Env) WithoutAPIURL() Env {
	return e.WithoutVar("RYPT_API_URL")
}

// WithPath sets PATH to dirs, for example the plugin's directory (Bin.Dir)
// for an age client to find it.
func (e Env) WithPath(dirs ...string) Env {
	return e.WithVar("PATH", strings.Join(dirs, string(os.PathListSeparator)))
}

// WithVar sets a variable. The value may hold any bytes but NUL, such as
// invalid UTF-8.
func (e Env) WithVar(name, value string) Env {
	return e.change(envChange{name: name, value: value})
}

// WithoutVar removes a variable.
func (e Env) WithoutVar(name string) Env {
	return e.change(envChange{name: name, unset: true})
}

func (e Env) change(c envChange) Env {
	// Clipped, so that append copies: Envs built from one base never share
	// their changes.
	e.changes = append(slices.Clip(e.changes), c)
	return e
}

// vars returns the variables as a map.
func (e Env) vars() map[string]string {
	vars := map[string]string{"RYPT_API_URL": closedAPIURL}
	for _, c := range e.changes {
		if c.unset {
			delete(vars, c.name)
		} else {
			vars[c.name] = c.value
		}
	}
	return vars
}

// Lookup returns a variable's value and whether it is set.
func (e Env) Lookup(name string) (string, bool) {
	value, ok := e.vars()[name]
	return value, ok
}

// Environ returns the variables as NAME=value strings sorted by name, for
// exec.Cmd.Env. The slice is never nil, because a nil exec.Cmd.Env would
// make the process inherit the test's environment.
func (e Env) Environ() []string {
	vars := e.vars()
	environ := make([]string, 0, len(vars))
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		environ = append(environ, name+"="+vars[name])
	}
	return environ
}

// envSecrets returns the tokens a run with env must not leak: mockToken, and
// env's RYPT_TOKEN as the plugin sends it, trimmed of the ASCII whitespace
// WHATWG defines, which leaves out the vertical tab.
func envSecrets(env Env) [][]byte {
	secrets := [][]byte{[]byte(mockToken)}
	if token, ok := env.Lookup("RYPT_TOKEN"); ok {
		secrets = append(secrets, []byte(strings.Trim(token, " \t\n\f\r")))
	}
	return secrets
}

// ---------------------------------------------------------------------------
// Stanzas

// Stanza is an age header stanza or a plugin protocol command: a type,
// arguments and a body. readStanza leaves empty Args and Body nil.
type Stanza struct {
	Type string
	Args []string
	Body []byte
}

// Equal reports whether two stanzas have the same type, arguments and body,
// treating nil and empty alike.
func (s Stanza) Equal(other Stanza) bool {
	return s.Type == other.Type && slices.Equal(s.Args, other.Args) && bytes.Equal(s.Body, other.Body)
}

// stanzaColumns is the width of a full stanza body line.
const stanzaColumns = 64

// writeStanza writes s in the age format: "-> type args\n", then the body in
// standard base64 without padding, 64 columns per line, ending with a line
// shorter than 64 columns. That line is empty when the body's length is a
// multiple of 48, including 0. It writes whatever s holds, valid or not.
func writeStanza(w io.Writer, s Stanza) error {
	var b strings.Builder
	b.WriteString("-> ")
	b.WriteString(strings.Join(append([]string{s.Type}, s.Args...), " "))
	b.WriteByte('\n')
	body := base64.RawStdEncoding.EncodeToString(s.Body)
	for len(body) >= stanzaColumns {
		b.WriteString(body[:stanzaColumns])
		b.WriteByte('\n')
		body = body[stanzaColumns:]
	}
	b.WriteString(body)
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}

// readStanza reads one stanza in the age format, strictly: the type and
// every argument are non-empty printable ASCII separated by single spaces,
// body lines are at most 64 columns, the body ends with a shorter line, and
// it is canonical unpadded standard base64. It returns io.EOF only when r
// ends before a stanza starts.
func readStanza(r *bufio.Reader) (Stanza, error) {
	line, err := r.ReadString('\n')
	if err == io.EOF && line == "" {
		return Stanza{}, io.EOF
	}
	if err != nil {
		return Stanza{}, fmt.Errorf("reading a stanza header after %q: %w", line, noEOF(err))
	}
	words, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "-> ")
	if !ok {
		return Stanza{}, fmt.Errorf("malformed stanza header %q", line)
	}
	fields := strings.Split(words, " ")
	for _, f := range fields {
		if !isPrintableASCII(f) {
			return Stanza{}, fmt.Errorf("malformed stanza header %q", line)
		}
	}
	s := Stanza{Type: fields[0]}
	if len(fields) > 1 {
		s.Args = fields[1:]
	}

	var encoded strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return Stanza{}, fmt.Errorf("reading the body of a %q stanza after %q: %w", s.Type, line, noEOF(err))
		}
		chunk := strings.TrimSuffix(line, "\n")
		if len(chunk) > stanzaColumns || strings.Contains(chunk, "\r") {
			return Stanza{}, fmt.Errorf("malformed body line %q in a %q stanza", line, s.Type)
		}
		encoded.WriteString(chunk)
		if len(chunk) < stanzaColumns {
			break
		}
	}
	body, err := base64.RawStdEncoding.Strict().DecodeString(encoded.String())
	if err != nil {
		return Stanza{}, fmt.Errorf("malformed body in a %q stanza: %v", s.Type, err)
	}
	if len(body) > 0 {
		s.Body = body
	}
	return s, nil
}

// noEOF turns io.EOF into io.ErrUnexpectedEOF, for input that ends inside a
// stanza.
func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// isPrintableASCII reports whether s is non-empty and only has characters
// from '!' to '~', as age requires of a stanza's type and arguments.
func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Plugin protocol client

// Commands each state machine's client acknowledges with ok. Anything else,
// such as grease, gets unsupported.
var (
	recipientV1Commands = []string{"labels", "recipient-stanza", "error", "msg"}
	identityV1Commands  = []string{"file-key", "error", "msg"}
)

// Outcome is what a plugin did in one run of a state machine.
type Outcome struct {
	// Commands are the phase 2 commands the client acknowledged with ok,
	// in order.
	Commands []Stanza
	// All is every command the plugin sent before done, including grease
	// and anything else the client answered with unsupported.
	All []Stanza
	// Done says whether the plugin ended phase 2 with done. age's Go
	// framework does not after an error for a recipient or identity: it
	// exits with code 3 instead. age-plugin-rypt then sends done itself,
	// because clients built on the Rust age crate, such as rage, wait for
	// it.
	Done bool
	// Stderr is everything the plugin wrote to standard error.
	Stderr string
	// ExitCode is the plugin's exit code, or -1 if a signal ended it.
	ExitCode int
}

// Stanzas returns the recipient stanzas for one file, as they would appear
// in its header.
func (o *Outcome) Stanzas(file int) []Stanza {
	index := strconv.Itoa(file)
	var stanzas []Stanza
	for _, c := range o.Commands {
		if c.Type != "recipient-stanza" || len(c.Args) < 2 || c.Args[0] != index {
			continue
		}
		s := Stanza{Type: c.Args[1], Body: c.Body}
		if len(c.Args) > 2 {
			s.Args = c.Args[2:]
		}
		stanzas = append(stanzas, s)
	}
	return stanzas
}

// PluginError is an error command. It is comparable with ==, so a test can
// check o.Errors() with slices.Equal.
type PluginError struct {
	// Args are the command's arguments joined by spaces, such as
	// "recipient 0", "identity 1", "stanza 2 0" or "internal".
	Args string
	// Message is the command's body.
	Message string
}

// Errors returns every error command, in order.
func (o *Outcome) Errors() []PluginError {
	var errs []PluginError
	for _, c := range o.Commands {
		if c.Type == "error" {
			errs = append(errs, PluginError{Args: strings.Join(c.Args, " "), Message: string(c.Body)})
		}
	}
	return errs
}

// FileKeys returns each unwrapped file key by its file's index. A file with
// no file-key command is missing from the map.
func (o *Outcome) FileKeys() map[int][]byte {
	keys := map[int][]byte{}
	for _, c := range o.Commands {
		if c.Type != "file-key" || len(c.Args) != 1 {
			continue
		}
		if file, err := strconv.Atoi(c.Args[0]); err == nil {
			keys[file] = c.Body
		}
	}
	return keys
}

// wrapPhase1 is what age sends a recipient-v1 plugin in phase 1.
func wrapPhase1(recipients, identities []string, fileKeys [][]byte) []Stanza {
	var phase1 []Stanza
	for _, r := range recipients {
		phase1 = append(phase1, Stanza{Type: "add-recipient", Args: []string{r}})
	}
	for _, i := range identities {
		phase1 = append(phase1, Stanza{Type: "add-identity", Args: []string{i}})
	}
	for _, k := range fileKeys {
		phase1 = append(phase1, Stanza{Type: "wrap-file-key", Body: k})
	}
	return append(phase1, Stanza{Type: "extension-labels"}, Stanza{Type: "done"})
}

// unwrapPhase1 is what age sends an identity-v1 plugin in phase 1.
func unwrapPhase1(identities []string, files [][]Stanza) []Stanza {
	var phase1 []Stanza
	for _, i := range identities {
		phase1 = append(phase1, Stanza{Type: "add-identity", Args: []string{i}})
	}
	for n, file := range files {
		for _, s := range file {
			args := append([]string{strconv.Itoa(n), s.Type}, s.Args...)
			phase1 = append(phase1, Stanza{Type: "recipient-stanza", Args: args, Body: s.Body})
		}
	}
	return append(phase1, Stanza{Type: "done"})
}

// session plays the age client's side of one protocol run, over a plugin's
// stdin and stdout. It writes phase 1, then serves phase 2: it acknowledges
// the known commands with ok and answers anything else, such as grease, with
// unsupported, until done or the end of the plugin's output. It closes stdin
// when phase 2 ends. An error means the plugin broke the protocol: it wrote
// something that is not a stanza, or anything after done.
func session(stdin io.WriteCloser, stdout io.Reader, phase1 []Stanza, known []string) (*Outcome, error) {
	defer stdin.Close()
	in := &stickyWriter{w: stdin}
	for _, s := range phase1 {
		// A failed write means the plugin stopped reading. What it says
		// before it exits still counts, so serving goes on.
		_ = writeStanza(in, s)
	}

	o := &Outcome{}
	r := bufio.NewReader(stdout)
	for {
		s, err := readStanza(r)
		if err == io.EOF {
			return o, nil
		}
		if err != nil {
			return o, err
		}
		if s.Type == "done" {
			o.Done = true
			break
		}
		o.All = append(o.All, s)
		reply := "unsupported"
		if slices.Contains(known, s.Type) {
			reply = "ok"
			o.Commands = append(o.Commands, s)
		}
		_ = writeStanza(in, Stanza{Type: reply})
	}

	stdin.Close()
	rest, err := io.ReadAll(r)
	if err != nil {
		return o, err
	}
	if len(rest) > 0 {
		return o, fmt.Errorf("the plugin wrote %q after done", rest)
	}
	return o, nil
}

// stickyWriter drops every write after the first one that fails. A plugin
// may exit at any point, and writing to it after that only fails again.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	s.err = err
	return n, err
}

// Run runs the binary as `--age-plugin=<stateMachine>` with env, sends
// phase1 (which should end with done), and serves phase 2, acknowledging the
// known commands. It fails the test if the plugin breaks the protocol or
// does not finish within runTimeout. It checks nothing else: no exit code
// and no leaks (call checkNoLeaks for those).
func (b Bin) Run(t testing.TB, env Env, stateMachine string, phase1 []Stanza, known ...string) *Outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	cmd := b.command(ctx, env, "--age-plugin="+stateMachine)
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
		t.Fatalf("starting %s: %v", b, err)
	}

	o, sessionErr := session(stdin, stdout, phase1, known)
	if sessionErr != nil {
		cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	o.Stderr = stderr.String()
	o.ExitCode = cmd.ProcessState.ExitCode()

	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("%s %s did not finish within %v; stderr: %q", b, stateMachine, runTimeout, o.Stderr)
	case sessionErr != nil:
		t.Fatalf("%s %s broke the protocol: %v; stderr: %q", b, stateMachine, sessionErr, o.Stderr)
	case waitErr != nil && !errors.As(waitErr, &exitErr):
		t.Fatalf("running %s %s: %v", b, stateMachine, waitErr)
	}
	return o
}

// Wrap runs recipient-v1 as age does: it adds the recipients, then the
// identities, asks for each file key to be wrapped, offers the labels
// extension, and serves phase 2. Then it checks the run leaked nothing
// (checkNoLeaks), with the env's tokens and the file keys as secrets and the
// returned stanza bodies as ciphertexts.
func (b Bin) Wrap(t testing.TB, env Env, recipients, identities []string, fileKeys ...[]byte) *Outcome {
	t.Helper()
	o := b.Run(t, env, "recipient-v1", wrapPhase1(recipients, identities, fileKeys), recipientV1Commands...)
	var ciphertexts [][]byte
	for _, c := range o.Commands {
		if c.Type == "recipient-stanza" {
			ciphertexts = append(ciphertexts, c.Body)
		}
	}
	checkNoLeaks(t, o, append(envSecrets(env), fileKeys...), ciphertexts)
	return o
}

// Unwrap runs identity-v1 as age does: it adds the identities, sends each
// file's stanzas, and serves phase 2. Every file needs at least one stanza,
// because the protocol cannot express an empty file. Then it checks the run
// leaked nothing (checkNoLeaks), with the env's tokens and the file keys
// inside toy ciphertexts as secrets, and the stanza bodies as ciphertexts.
func (b Bin) Unwrap(t testing.TB, env Env, identities []string, files ...[]Stanza) *Outcome {
	t.Helper()
	o := b.Run(t, env, "identity-v1", unwrapPhase1(identities, files), identityV1Commands...)
	secrets := envSecrets(env)
	var ciphertexts [][]byte
	for _, file := range files {
		for _, s := range file {
			ciphertexts = append(ciphertexts, s.Body)
			if fileKey, ok := toyOpenAny(s.Body); ok {
				secrets = append(secrets, fileKey)
			}
		}
	}
	checkNoLeaks(t, o, secrets, ciphertexts)
	return o
}

// CLIResult is how a run of the binary's command line ended.
type CLIResult struct {
	// ExitCode is the exit code, or -1 if a signal ended the process.
	ExitCode int
	Stdout   string
	Stderr   string
}

// RunCLI runs the binary with args and env, feeding it stdin (nil for empty
// input). The binary may stop reading stdin early, as it does past its size
// limit. It fails the test only if the binary cannot run or does not finish
// within runTimeout.
func (b Bin) RunCLI(t testing.TB, env Env, stdin []byte, args ...string) CLIResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	cmd := b.command(ctx, env, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("%s %q did not finish within %v; stderr: %q", b, args, runTimeout, stderr.String())
	case err != nil && !errors.As(err, &exitErr):
		t.Fatalf("running %s %q: %v", b, args, err)
	}
	return CLIResult{ExitCode: cmd.ProcessState.ExitCode(), Stdout: stdout.String(), Stderr: stderr.String()}
}

// wrap is Bin.Wrap with the binary TestMain built.
func wrap(t testing.TB, env Env, recipients, identities []string, fileKeys ...[]byte) *Outcome {
	t.Helper()
	return pluginBin(t).Wrap(t, env, recipients, identities, fileKeys...)
}

// unwrap is Bin.Unwrap with the binary TestMain built.
func unwrap(t testing.TB, env Env, identities []string, files ...[]Stanza) *Outcome {
	t.Helper()
	return pluginBin(t).Unwrap(t, env, identities, files...)
}

// runCLI is Bin.RunCLI with the binary TestMain built.
func runCLI(t testing.TB, env Env, stdin []byte, args ...string) CLIResult {
	t.Helper()
	return pluginBin(t).RunCLI(t, env, stdin, args...)
}

// ---------------------------------------------------------------------------
// Leak checks

// minLeakLen is the length of the shortest secret or ciphertext the leak
// checks look for. Shorter ones could match by chance.
const minLeakLen = 8

// userVisible lists the commands whose text an age client shows the user.
var userVisible = []string{"error", "msg", "confirm", "request-public", "request-secret"}

// leakForms returns the forms in which a secret could leak: raw, hex in
// either case, standard and URL-safe base64 without padding (padded base64
// contains them), and a byte slice as Go's %v and Rust's {:?} print it.
func leakForms(secret []byte) [][]byte {
	decimal := make([]string, len(secret))
	for i, b := range secret {
		decimal[i] = strconv.Itoa(int(b))
	}
	lowerHex := hex.EncodeToString(secret)
	return [][]byte{
		secret,
		[]byte(lowerHex),
		[]byte(strings.ToUpper(lowerHex)),
		[]byte(base64.RawStdEncoding.EncodeToString(secret)),
		[]byte(base64.RawURLEncoding.EncodeToString(secret)),
		[]byte("[" + strings.Join(decimal, " ") + "]"),
		[]byte("[" + strings.Join(decimal, ", ") + "]"),
	}
}

// containsLeak reports whether text holds secret in any of its leakForms.
func containsLeak(text, secret []byte) bool {
	if len(secret) < minLeakLen {
		return false
	}
	for _, form := range leakForms(secret) {
		if bytes.Contains(text, form) {
			return true
		}
	}
	return false
}

// leaks lists what a plugin run gave away:
//   - any output on stderr;
//   - a secret (a token or a file key) in any command's arguments or body,
//     except the body of a file-key command, which is meant to carry one;
//   - a ciphertext or mockBodyMarker in a command the user sees.
func leaks(o *Outcome, secrets, ciphertexts [][]byte) []string {
	var found []string
	if o.Stderr != "" {
		found = append(found, fmt.Sprintf("the plugin wrote to stderr: %q", o.Stderr))
	}
	for _, c := range o.All {
		text := []byte(strings.Join(c.Args, " "))
		if c.Type != "file-key" {
			text = append(append(text, '\n'), c.Body...)
		}
		what := fmt.Sprintf("the %s command %q", c.Type, c.Args)
		found = append(found, textLeaks(what, text, secrets, ciphertexts, slices.Contains(userVisible, c.Type))...)
	}
	return found
}

// textLeaks lists the secrets in text and, if the user sees text, the
// ciphertexts and mock response bodies in it.
func textLeaks(what string, text []byte, secrets, ciphertexts [][]byte, shown bool) []string {
	var found []string
	for _, s := range secrets {
		if containsLeak(text, s) {
			found = append(found, what+" leaks a secret")
		}
	}
	if !shown {
		return found
	}
	for _, c := range ciphertexts {
		if containsLeak(text, c) {
			found = append(found, what+" leaks a ciphertext")
		}
	}
	if bytes.Contains(text, []byte(mockBodyMarker)) {
		found = append(found, what+" repeats a mock response body")
	}
	return found
}

// checkNoLeaks reports every leak in o (see leaks) as a test error, without
// stopping the test. Bin.Wrap and Bin.Unwrap call it on every outcome; call
// it on an outcome of Bin.Run that should leak nothing.
func checkNoLeaks(t testing.TB, o *Outcome, secrets, ciphertexts [][]byte) {
	t.Helper()
	for _, leak := range leaks(o, secrets, ciphertexts) {
		t.Error(leak)
	}
}

// checkTextNoLeaks is checkNoLeaks for text an age client shows the user,
// such as its stderr: it must hold no secret, ciphertext or mock response
// body. what names the text in failure messages.
func checkTextNoLeaks(t testing.TB, what string, text []byte, secrets, ciphertexts [][]byte) {
	t.Helper()
	for _, leak := range textLeaks(what, text, secrets, ciphertexts, true) {
		t.Error(leak)
	}
}

// ---------------------------------------------------------------------------
// Self-check of the harness

// TestMockSelfCheck checks the harness alone, without the plugin binary: the
// encoders against the spec's golden vectors, the stanza codec, the toy
// cipher, the mock API, the Env builder, the leak checks, the protocol
// client against age's own plugin framework run in this process, and running
// processes with fake plugins written in sh.
func TestMockSelfCheck(t *testing.T) {
	t.Run("golden vectors", testGoldenVectors)
	t.Run("stanza codec", testStanzaCodec)
	t.Run("toy cipher", testToyCipher)
	t.Run("mock API", testMockAPI)
	t.Run("mock under a prefix", testMockPrefix)
	t.Run("mock over TLS", testMockTLS)
	t.Run("mock sending unsolicited bytes", testMockUnsolicited)
	t.Run("env", testEnv)
	t.Run("leak checks", testLeakChecks)
	t.Run("client and age's plugin framework", testClientWithFramework)
	t.Run("running binaries", testRunningBinaries)
}

// fakePlugin writes an sh script to a file and returns it as a Bin. The
// script runs with an empty environment, so it can use shell builtins only.
func fakePlugin(t *testing.T, script string) Bin {
	t.Helper()
	path := filepath.Join(t.TempDir(), "age-plugin-rypt")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return Bin(path)
}

// skipPhase1 is sh that reads phase 1 up to and including done's body line.
const skipPhase1 = `while read -r line; do [ "$line" = "-> done" ] && break; done
read -r _
`

func testRunningBinaries(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	// Nothing reaches the process from the test's own environment.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("RYPT_TOKEN", "from-the-shell")

	// Prints how many lines it read, then its exported variables.
	show := fakePlugin(t, `n=0
while read -r line; do n=$((n+1)); done
printf '%s|%s|%s\n' "$n" "${RYPT_TOKEN-unset}" "${RYPT_API_URL-unset}"
export -p
printf '%s\n' "$*" >&2
exit 7
`)
	// exported returns the first line and the names show exported, except
	// those the shell itself makes.
	exported := func(stdout string) (string, []string) {
		first, rest, _ := strings.Cut(stdout, "\n")
		var names []string
		for _, line := range strings.Split(strings.TrimSpace(rest), "\n") {
			name, _, _ := strings.Cut(strings.TrimPrefix(line, "export "), "=")
			if !slices.Contains([]string{"PWD", "OLDPWD", "SHLVL", "_"}, name) {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		return first, names
	}

	got := show.RunCLI(t, Env{}, []byte("a\nb\n"), "new", "--key", goldenKeyA)
	first, names := exported(got.Stdout)
	if got.ExitCode != 7 || got.Stderr != "new --key "+goldenKeyA+"\n" || first != "2|unset|"+closedAPIURL || !slices.Equal(names, []string{"RYPT_API_URL"}) {
		t.Errorf("RunCLI = %+v; exported %q", got, names)
	}
	got = show.RunCLI(t, Env{}.WithToken("tok").WithPath("/nowhere"), nil)
	first, names = exported(got.Stdout)
	// dash quotes values with ' and bash with ", so the quotes are dropped.
	unquoted := strings.NewReplacer("'", "", `"`, "").Replace(got.Stdout)
	if first != "0|tok|"+closedAPIURL || !slices.Equal(names, []string{"PATH", "RYPT_API_URL", "RYPT_TOKEN"}) || !strings.Contains(unquoted, "PATH=/nowhere\n") {
		t.Errorf("RunCLI printed %q", got.Stdout)
	}

	// A plugin that sends grease and a msg, and reports the replies.
	chatty := fakePlugin(t, skipPhase1+`printf '%s\n' '-> grease-x 1' ''
read -r first; read -r _
printf '%s\n' '-> msg' 'aGk'
read -r second; read -r _
printf '%s\n' '-> done' ''
printf '%s %s %s\n' "$1" "$first" "$second" >&2
`)
	o := chatty.Run(t, Env{}, "recipient-v1", wrapPhase1([]string{goldenRecipientA}, nil, [][]byte{[]byte("0123456789abcdef")}), recipientV1Commands...)
	if !o.Done || o.ExitCode != 0 || o.Stderr != "--age-plugin=recipient-v1 -> unsupported -> ok\n" {
		t.Errorf("chatty plugin: done %v, exit %d, stderr %q", o.Done, o.ExitCode, o.Stderr)
	}
	if want := []Stanza{{Type: "msg", Body: []byte("hi")}}; !slices.EqualFunc(o.Commands, want, Stanza.Equal) || len(o.All) != 2 {
		t.Errorf("chatty plugin: commands %+v, all %+v", o.Commands, o.All)
	}

	// A plugin that exits with 3 after an error, as age's framework does.
	failing := fakePlugin(t, skipPhase1+`printf '%s\n' '-> error recipient 0' 'cnlwdDogNDA0'
read -r _; read -r _
exit 3
`)
	o = failing.Run(t, Env{}, "recipient-v1", wrapPhase1([]string{goldenRecipientA}, nil, [][]byte{[]byte("0123456789abcdef")}), recipientV1Commands...)
	if want := []PluginError{{"recipient 0", "rypt: 404"}}; !slices.Equal(o.Errors(), want) || o.Done || o.ExitCode != 3 || o.Stderr != "" {
		t.Errorf("failing plugin: errors %q, done %v, exit %d, stderr %q", o.Errors(), o.Done, o.ExitCode, o.Stderr)
	}

	// The same, then done, as age-plugin-rypt does.
	failingDone := fakePlugin(t, skipPhase1+`printf '%s\n' '-> error recipient 0' 'cnlwdDogNDA0'
read -r _; read -r _
printf '%s\n' '-> done' ''
exit 3
`)
	o = failingDone.Run(t, Env{}, "recipient-v1", wrapPhase1([]string{goldenRecipientA}, nil, [][]byte{[]byte("0123456789abcdef")}), recipientV1Commands...)
	if want := []PluginError{{"recipient 0", "rypt: 404"}}; !slices.Equal(o.Errors(), want) || !o.Done || o.ExitCode != 3 || o.Stderr != "" {
		t.Errorf("failing plugin that sends done: errors %q, done %v, exit %d, stderr %q", o.Errors(), o.Done, o.ExitCode, o.Stderr)
	}

	// A plugin that exits at once, without reading: writes to it fail
	// quietly, and the outcome is empty.
	o = fakePlugin(t, "exit 1\n").Run(t, Env{}, "identity-v1", unwrapPhase1([]string{goldenIdentityA}, [][]Stanza{{{Type: "x", Body: make([]byte, 1<<17)}}}), identityV1Commands...)
	if o.Done || o.ExitCode != 1 || len(o.All) != 0 {
		t.Errorf("silent plugin: done %v, exit %d, all %+v", o.Done, o.ExitCode, o.All)
	}
}

func testGoldenVectors(t *testing.T) {
	for _, v := range []struct{ key, recipient, identity string }{
		{goldenKeyA, goldenRecipientA, goldenIdentityA},
		{goldenKeyB, goldenRecipientB, goldenIdentityB},
	} {
		key, err := ParseUUID(v.key)
		if err != nil {
			t.Fatal(err)
		}
		if got := key.String(); got != v.key {
			t.Errorf("ParseUUID(%q).String() = %q", v.key, got)
		}
		if got := recipient(key); got != v.recipient {
			t.Errorf("recipient(%s) = %q, want %q", key, got, v.recipient)
		}
		if got := rawRecipient(key[:]); got != v.recipient {
			t.Errorf("rawRecipient(%s) = %q, want %q", key, got, v.recipient)
		}
		if got := identity(key); got != v.identity {
			t.Errorf("identity(%s) = %q, want %q", key, got, v.identity)
		}
		if got := rawIdentity(key[:]); got != v.identity {
			t.Errorf("rawIdentity(%s) = %q, want %q", key, got, v.identity)
		}
		if name, data, err := plugin.ParseRecipient(v.recipient); err != nil || name != "rypt" || !bytes.Equal(data, key[:]) {
			t.Errorf("age parses %q as %q, %x, %v", v.recipient, name, data, err)
		}
		if name, data, err := plugin.ParseIdentity(v.identity); err != nil || name != "rypt" || !bytes.Equal(data, key[:]) {
			t.Errorf("age parses %q as %q, %x, %v", v.identity, name, data, err)
		}
	}

	key := MustParseUUID(goldenKeyA)
	if got := key.Hex(); got != strings.ReplaceAll(goldenKeyA, "-", "") {
		t.Errorf("Hex() = %q", got)
	}
	for _, s := range []string{
		strings.ToUpper(goldenKeyA),
		key.Hex(),
		"{" + goldenKeyA + "}",
		"urn:uuid:" + goldenKeyA,
		goldenKeyA[:35],
		goldenKeyA + "0",
		"3f2a9c1e+7b4d-4e2a-9f10-6c8d5a2b1e47",
		"3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e4g",
		"",
	} {
		if _, err := ParseUUID(s); err == nil {
			t.Errorf("ParseUUID(%q) succeeded", s)
		}
	}

	if got := statusKey(404).String(); got != "00000000-0000-0000-0000-000000000404" {
		t.Errorf("statusKey(404) = %s", got)
	}
	for _, status := range []int{200, 302, 503, 599} {
		if got, ok := forcedStatus(statusKey(status)); !ok || got != status {
			t.Errorf("forcedStatus(statusKey(%d)) = %d, %v", status, got, ok)
		}
	}
	for _, k := range []UUID{{}, statusKey(199), statusKey(600), shortKey, key} {
		if got, ok := forcedStatus(k); ok {
			t.Errorf("forcedStatus(%s) = %d, want none", k, got)
		}
	}
}

func testStanzaCodec(t *testing.T) {
	for _, n := range []int{0, 1, 2, 47, 48, 49, 95, 96, 100} {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i*7 + n)
		}
		in := Stanza{Type: "t", Args: []string{"a", "b"}, Body: body}
		var buf bytes.Buffer
		if err := writeStanza(&buf, in); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		if lines[0] != "-> t a b" {
			t.Errorf("%d bytes: header %q", n, lines[0])
		}
		bodyLines := lines[1:]
		if want := n/48 + 1; len(bodyLines) != want {
			t.Errorf("%d bytes: %d body lines, want %d", n, len(bodyLines), want)
		}
		for _, l := range bodyLines[:len(bodyLines)-1] {
			if len(l) != stanzaColumns {
				t.Errorf("%d bytes: full line of %d columns", n, len(l))
			}
		}
		if last := bodyLines[len(bodyLines)-1]; len(last) >= stanzaColumns || (n%48 == 0) != (last == "") {
			t.Errorf("%d bytes: last line %q", n, last)
		}
		if strings.Contains(buf.String(), "=") {
			t.Errorf("%d bytes: padded: %q", n, buf.String())
		}

		r := bufio.NewReader(&buf)
		out, err := readStanza(r)
		if err != nil || !out.Equal(in) {
			t.Errorf("%d bytes: read back %+v, %v", n, out, err)
		}
		if _, err := readStanza(r); err != io.EOF {
			t.Errorf("%d bytes: after the stanza: %v, want io.EOF", n, err)
		}
	}

	// age's own encoding of 48 zero bytes: a full line, then an empty one.
	var buf bytes.Buffer
	writeStanza(&buf, Stanza{Type: "x", Body: make([]byte, 48)})
	if want := "-> x\n" + strings.Repeat("A", 64) + "\n\n"; buf.String() != want {
		t.Errorf("48 zero bytes encode as %q, want %q", buf.String(), want)
	}

	// Empty arguments and body read back as nil.
	buf.Reset()
	writeStanza(&buf, Stanza{Type: "ok"})
	writeStanza(&buf, Stanza{Type: "recipient-stanza", Args: []string{"0", "rypt", goldenKeyA}, Body: []byte("abc")})
	r := bufio.NewReader(&buf)
	if s, err := readStanza(r); err != nil || s.Type != "ok" || s.Args != nil || s.Body != nil {
		t.Errorf("read %#v, %v", s, err)
	}
	if s, err := readStanza(r); err != nil || len(s.Args) != 3 || string(s.Body) != "abc" {
		t.Errorf("read %#v, %v", s, err)
	}

	for _, bad := range []string{
		"x\n\n",
		"->x\n\n",
		"-> \n\n",
		"-> a  b\n\n",
		"-> a b \n\n",
		"-> a\tb\n\n",
		"-> a\xffb\n\n",
		"-> a",
		"-> a\n",
		"-> a\nAAAA",
		"-> a\n" + strings.Repeat("A", 65) + "\n",
		"-> a\n" + strings.Repeat("A", 64) + "\n",
		"-> a\nAAA=\n",
		"-> a\nAB\n",
		"-> a\nA\n",
		"-> a\nAA\r\n",
		"-> a\nA-_A\n",
	} {
		if s, err := readStanza(bufio.NewReader(strings.NewReader(bad))); err == nil || err == io.EOF {
			t.Errorf("readStanza(%q) = %#v, %v; want an error", bad, s, err)
		}
	}
}

func testToyCipher(t *testing.T) {
	key := MustParseUUID(goldenKeyA)
	fileKey := []byte("0123456789abcdef")
	ciphertext := toySeal(key, fileKey)
	if len(ciphertext) != 41 {
		t.Errorf("a toy ciphertext of a file key is %d bytes, want 41", len(ciphertext))
	}
	if encoded := base64.StdEncoding.EncodeToString(ciphertext); !strings.HasSuffix(encoded, "=") {
		t.Errorf("the base64 of a toy ciphertext needs no padding: %s", encoded)
	}
	if got, ok := toyOpen(key, ciphertext); !ok || !bytes.Equal(got, fileKey) {
		t.Errorf("toyOpen = %q, %v", got, ok)
	}
	if got, ok := toyOpenAny(ciphertext); !ok || !bytes.Equal(got, fileKey) {
		t.Errorf("toyOpenAny = %q, %v", got, ok)
	}
	if _, ok := toyOpen(MustParseUUID(goldenKeyB), ciphertext); ok {
		t.Error("toyOpen opened a ciphertext under another key")
	}
	for _, bad := range [][]byte{nil, []byte("mock-ryp"), []byte(toyMagic + "short"), bytes.Repeat([]byte{1}, 41)} {
		if _, ok := toyOpenAny(bad); ok {
			t.Errorf("toyOpenAny(%q) succeeded", bad)
		}
	}
	// Otherwise the leak checks would see a file key in every stanza.
	if containsLeak(ciphertext, fileKey) {
		t.Error("a toy ciphertext shows its file key")
	}
}

// selfCheckClient returns a client for m that never follows redirects.
func selfCheckClient(m *Mock) *http.Client {
	c := *m.server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// mockReply is the mock's answer to a self-check request.
type mockReply struct {
	status int
	header http.Header
	body   []byte
}

// mockCall sends a request to url, with token and contentType unless empty,
// and the Accept and User-Agent headers a client would send.
func mockCall(t *testing.T, c *http.Client, method, url, token, contentType, body string) mockReply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "e2e-self-check")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return mockReply{resp.StatusCode, resp.Header, answer}
}

// mockOperation calls an operation of key at base with field set to value
// in padded standard base64.
func mockOperation(t *testing.T, c *http.Client, base, operation string, key UUID, field string, value []byte) mockReply {
	t.Helper()
	body, err := json.Marshal(map[string]string{field: base64.StdEncoding.EncodeToString(value)})
	if err != nil {
		t.Fatal(err)
	}
	return mockCall(t, c, http.MethodPost, base+"/v1/keys/"+key.String()+"/"+operation, mockToken, "application/json", string(body))
}

// jsonField returns a field of a JSON object of strings.
func jsonField(t *testing.T, body []byte, name string) (string, bool) {
	t.Helper()
	var fields map[string]string
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("%.200q is not a JSON object of strings: %v", body, err)
	}
	value, ok := fields[name]
	return value, ok
}

// wantAnswer checks a 200 answer and returns its field, decoded.
func wantAnswer(t *testing.T, what string, reply mockReply, field string) []byte {
	t.Helper()
	if reply.status != http.StatusOK {
		t.Fatalf("%s: status %d, body %q", what, reply.status, reply.body)
	}
	if got := reply.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("%s: Content-Type %q", what, got)
	}
	encoded, ok := jsonField(t, reply.body, field)
	if !ok {
		t.Fatalf("%s: no %q in %q", what, field, reply.body)
	}
	value, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("%s: %q is not base64: %v", what, encoded, err)
	}
	return value
}

// wantRefusal checks an error answer in rypt's envelope, with the marker.
func wantRefusal(t *testing.T, what string, reply mockReply, status int, code string) {
	t.Helper()
	if reply.status != status {
		t.Errorf("%s: status %d, want %d", what, reply.status, status)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(reply.body, &envelope); err != nil {
		t.Errorf("%s: %q is not rypt's error envelope: %v", what, reply.body, err)
		return
	}
	if envelope.Error != code || !strings.Contains(envelope.Message, mockBodyMarker) || envelope.RequestID == "" {
		t.Errorf("%s: %+v, want code %q and the marker", what, envelope, code)
	}
}

func testMockAPI(t *testing.T) {
	m := NewMock(t)
	c := selfCheckClient(m)
	key := MustParseUUID(goldenKeyA)
	other := MustParseUUID(goldenKeyB)
	fileKey := []byte("0123456789abcdef")
	if !strings.HasPrefix(m.URL(), "http://127.0.0.1:") || !strings.HasSuffix(m.URL(), ":"+strconv.Itoa(m.Port())) {
		t.Errorf("URL %q, port %d", m.URL(), m.Port())
	}

	// A round trip, then a request to an unknown path, all recorded.
	ciphertext := wantAnswer(t, "encrypt", mockOperation(t, c, m.URL(), "encrypt", key, "plaintext", fileKey), "ciphertext")
	if !bytes.Equal(ciphertext, toySeal(key, fileKey)) {
		t.Errorf("encrypt answered %q", ciphertext)
	}
	plaintext := wantAnswer(t, "decrypt", mockOperation(t, c, m.URL(), "decrypt", key, "ciphertext", ciphertext), "plaintext")
	if !bytes.Equal(plaintext, fileKey) {
		t.Errorf("decrypt answered %q", plaintext)
	}
	wantRefusal(t, "unknown path", mockCall(t, c, http.MethodPost, m.URL()+"/v1/keys/"+key.String()+"/rewrap", mockToken, "application/json", "{}"), 404, "not_found")
	if m.EncryptCalls() != 1 || m.DecryptCalls() != 1 || m.Calls() != 3 {
		t.Errorf("counted %d encrypt, %d decrypt, %d in all", m.EncryptCalls(), m.DecryptCalls(), m.Calls())
	}
	requests := m.Requests()
	first := requests[0]
	if first.Method != http.MethodPost || first.Path != "/v1/keys/"+key.String()+"/encrypt" ||
		first.Operation != "encrypt" || first.Key != key.String() || !json.Valid(first.Body) {
		t.Errorf("recorded %+v", first)
	}
	for name, want := range map[string]string{
		"Authorization": "Bearer " + mockToken,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"User-Agent":    "e2e-self-check",
	} {
		if got := first.Header.Get(name); got != want {
			t.Errorf("recorded %s %q, want %q", name, got, want)
		}
	}
	if requests[2].Operation != "" || requests[2].Key != "" {
		t.Errorf("recorded %+v for an unknown path", requests[2])
	}

	// A ciphertext under another key is refused, like rypt does.
	wantRefusal(t, "decrypt under another key", mockOperation(t, c, m.URL(), "decrypt", other, "ciphertext", ciphertext), 400, "invalid_ciphertext")

	// Requests the mock refuses before looking at the key.
	encryptURL := m.URL() + "/v1/keys/" + key.String() + "/encrypt"
	good := `{"plaintext":"` + base64.StdEncoding.EncodeToString(fileKey) + `"}`
	for _, tc := range []struct {
		what, method, url, token, contentType, body string
		status                                      int
		code                                        string
	}{
		{"wrong token", "POST", encryptURL, "ry_Wrong000_abcdefghijklmnopqrstuvwxyz012345", "application/json", good, 401, "unauthorized"},
		{"no token", "POST", encryptURL, "", "application/json", good, 401, "unauthorized"},
		{"GET", "GET", encryptURL, mockToken, "application/json", "", 405, "method_not_allowed"},
		{"no content type", "POST", encryptURL, mockToken, "", good, 415, "unsupported_media_type"},
		{"text content type", "POST", encryptURL, mockToken, "text/plain", good, 415, "unsupported_media_type"},
		{"a query", "POST", encryptURL + "?x=1", mockToken, "application/json", good, 400, "invalid_query"},
		{"uppercase key", "POST", m.URL() + "/v1/keys/" + strings.ToUpper(key.String()) + "/encrypt", mockToken, "application/json", good, 400, "invalid_request"},
		{"32-digit key", "POST", m.URL() + "/v1/keys/" + key.Hex() + "/encrypt", mockToken, "application/json", good, 400, "invalid_request"},
		{"other version", "POST", m.URL() + "/v2/keys/" + key.String() + "/encrypt", mockToken, "application/json", good, 404, "not_found"},
		{"unpadded base64", "POST", encryptURL, mockToken, "application/json", `{"plaintext":"MDEyMzQ1Njc4OWFiY2RlZg"}`, 400, "invalid_request"},
		{"base64 with a newline", "POST", encryptURL, mockToken, "application/json", `{"plaintext":"MDEyMzQ1Njc4\nOWFiY2RlZg=="}`, 400, "invalid_request"},
		{"url-safe base64", "POST", encryptURL, mockToken, "application/json", `{"plaintext":"-_-_"}`, 400, "invalid_request"},
		{"non-zero trailing bits", "POST", encryptURL, mockToken, "application/json", `{"plaintext":"AB=="}`, 400, "invalid_request"},
		{"empty field", "POST", encryptURL, mockToken, "application/json", `{"plaintext":""}`, 400, "invalid_request"},
		{"null field", "POST", encryptURL, mockToken, "application/json", `{"plaintext":null}`, 400, "invalid_request"},
		{"number field", "POST", encryptURL, mockToken, "application/json", `{"plaintext":1}`, 400, "invalid_request"},
		{"wrong field", "POST", encryptURL, mockToken, "application/json", `{"ciphertext":"AAAA"}`, 400, "invalid_request"},
		{"not JSON", "POST", encryptURL, mockToken, "application/json", `plaintext=AAAA`, 400, "invalid_request"},
	} {
		wantRefusal(t, tc.what, mockCall(t, c, tc.method, tc.url, tc.token, tc.contentType, tc.body), tc.status, tc.code)
	}
	// A charset parameter is fine.
	wantAnswer(t, "charset", mockCall(t, c, "POST", encryptURL, mockToken, "application/json; charset=utf-8", good), "ciphertext")

	// statusKey forces a status with a fitting code, on both operations.
	for status, code := range map[int]string{
		400: "invalid_ciphertext",
		401: "unauthorized",
		402: "billing_required",
		403: "action_not_allowed",
		404: "not_found",
		409: "key_pending_deletion",
		429: "rate_limited",
		500: "internal_error",
		502: "unavailable",
		503: "unavailable",
		418: "mock_status",
		201: "mock_status",
	} {
		for _, operation := range []string{"encrypt", "decrypt"} {
			reply := mockOperation(t, c, m.URL(), operation, statusKey(status), "plaintext", fileKey)
			wantRefusal(t, fmt.Sprintf("%s with statusKey(%d)", operation, status), reply, status, code)
		}
	}
	redirect := mockOperation(t, c, m.URL(), "encrypt", statusKey(302), "plaintext", fileKey)
	if redirect.status != 302 || redirect.header.Get("Location") != m.URL()+"/redirected" {
		t.Errorf("statusKey(302): status %d, Location %q", redirect.status, redirect.header.Get("Location"))
	}
	if reply := mockOperation(t, c, m.URL(), "encrypt", statusKey(204), "plaintext", fileKey); reply.status != 204 || len(reply.body) != 0 {
		t.Errorf("statusKey(204): status %d, body %q", reply.status, reply.body)
	}
	wantRefusal(t, "statusKey(503) with a wrong token",
		mockCall(t, c, "POST", m.URL()+"/v1/keys/"+statusKey(503).String()+"/encrypt", "ry_wrong", "application/json", good), 401, "unauthorized")

	// The special keys.
	short := wantAnswer(t, "shortKey encrypt", mockOperation(t, c, m.URL(), "encrypt", shortKey, "plaintext", fileKey), "ciphertext")
	if got := wantAnswer(t, "shortKey decrypt", mockOperation(t, c, m.URL(), "decrypt", shortKey, "ciphertext", short), "plaintext"); !bytes.Equal(got, fileKey[:15]) {
		t.Errorf("shortKey decrypt answered %q", got)
	}
	for _, operation := range []string{"encrypt", "decrypt"} {
		field := map[string]string{"encrypt": "ciphertext", "decrypt": "plaintext"}[operation]

		// These keys are answered before the body is read.
		reply := mockOperation(t, c, m.URL(), operation, notJSONKey, "plaintext", fileKey)
		if reply.status != 200 || json.Valid(reply.body) || !bytes.Contains(reply.body, []byte(mockBodyMarker)) {
			t.Errorf("notJSONKey %s: status %d, body %q", operation, reply.status, reply.body)
		}

		reply = mockOperation(t, c, m.URL(), operation, missingFieldKey, "plaintext", fileKey)
		if _, ok := jsonField(t, reply.body, field); reply.status != 200 || ok || !bytes.Contains(reply.body, []byte(mockBodyMarker)) {
			t.Errorf("missingFieldKey %s: status %d, body %q", operation, reply.status, reply.body)
		}

		reply = mockOperation(t, c, m.URL(), operation, oversizedKey, "plaintext", fileKey)
		if reply.status != 200 || len(reply.body) <= sdkResponseLimit || !json.Valid(reply.body) {
			t.Errorf("oversizedKey %s: status %d, %d bytes", operation, reply.status, len(reply.body))
		}
		if encoded, _ := jsonField(t, reply.body, field); !strings.HasPrefix(encoded, "AAAA") {
			t.Errorf("oversizedKey %s: no %s", operation, field)
		}

		inputs := map[string]struct {
			field string
			value []byte
		}{
			"encrypt": {"plaintext", fileKey},
			"decrypt": {"ciphertext", toySeal(badBase64Key, fileKey)},
		}
		in := inputs[operation]
		reply = mockOperation(t, c, m.URL(), operation, badBase64Key, in.field, in.value)
		encoded, _ := jsonField(t, reply.body, field)
		valid, cut := strings.CutSuffix(encoded, "!")
		if _, err := base64.StdEncoding.DecodeString(encoded); reply.status != 200 || !cut || err == nil {
			t.Errorf("badBase64Key %s: status %d, %s %q", operation, reply.status, field, encoded)
		}
		want := map[string][]byte{"encrypt": toySeal(badBase64Key, fileKey), "decrypt": fileKey}[operation]
		if got, err := base64.StdEncoding.DecodeString(valid); err != nil || !bytes.Equal(got, want) {
			t.Errorf("badBase64Key %s: %q without the stray character is %q, %v", operation, encoded, got, err)
		}
	}
	if reply := mockOperation(t, c, m.URL(), "encrypt", emptyCiphertextKey, "plaintext", fileKey); reply.status != 200 || string(reply.body) != `{"ciphertext":""}` {
		t.Errorf("emptyCiphertextKey encrypt: status %d, body %q", reply.status, reply.body)
	}
	if reply := mockOperation(t, c, m.URL(), "decrypt", emptyCiphertextKey, "ciphertext", toySeal(emptyCiphertextKey, fileKey)); reply.status != 200 || string(reply.body) != `{"plaintext":""}` {
		t.Errorf("emptyCiphertextKey decrypt: status %d, body %q", reply.status, reply.body)
	}
}

func testMockPrefix(t *testing.T) {
	m := NewMockWith(t, MockConfig{Prefix: "/api/"})
	c := selfCheckClient(m)
	key := MustParseUUID(goldenKeyA)
	fileKey := []byte("0123456789abcdef")
	if !strings.HasSuffix(m.URL(), "/api") {
		t.Errorf("URL %q", m.URL())
	}
	wantAnswer(t, "under the prefix", mockOperation(t, c, m.URL(), "encrypt", key, "plaintext", fileKey), "ciphertext")
	wantRefusal(t, "outside the prefix", mockOperation(t, c, m.server.URL, "encrypt", key, "plaintext", fileKey), 404, "not_found")
	wantRefusal(t, "a doubled slash", mockOperation(t, c, m.URL()+"/", "encrypt", key, "plaintext", fileKey), 404, "not_found")
	if got := m.Requests()[0].Path; got != "/api/v1/keys/"+key.String()+"/encrypt" {
		t.Errorf("recorded path %q", got)
	}
	if m.EncryptCalls() != 1 || m.Calls() != 3 {
		t.Errorf("counted %d encrypt, %d in all", m.EncryptCalls(), m.Calls())
	}
}

func testMockTLS(t *testing.T) {
	m := NewMockWith(t, MockConfig{TLS: true})
	key := MustParseUUID(goldenKeyA)
	fileKey := []byte("0123456789abcdef")
	if !strings.HasPrefix(m.URL(), "https://127.0.0.1:") {
		t.Errorf("URL %q", m.URL())
	}

	// A client that trusts only CertFile gets through.
	pemBytes, err := os.ReadFile(m.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("%s holds no certificate", m.CertFile)
	}
	trusting := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	wantAnswer(t, "over TLS", mockOperation(t, trusting, m.URL(), "encrypt", key, "plaintext", fileKey), "ciphertext")

	// One with the system's roots does not.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, m.URL()+"/v1/keys/"+key.String()+"/encrypt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req); err == nil {
		resp.Body.Close()
		t.Error("a client with the system's roots trusts the mock")
	}
	if m.Calls() != 1 {
		t.Errorf("counted %d requests", m.Calls())
	}
	if got := m.Requests()[0].Proto; got != "HTTP/1.1" {
		t.Errorf("recorded the version %q, want HTTP/1.1", got)
	}

	// With HTTP2, a client that would speak either speaks HTTP/2.
	m = NewMockWith(t, MockConfig{TLS: true, HTTP2: true})
	roots = x509.NewCertPool()
	roots.AddCert(m.server.Certificate())
	h2 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true}}
	wantAnswer(t, "over HTTP/2", mockOperation(t, h2, m.URL(), "encrypt", key, "plaintext", fileKey), "ciphertext")
	if got := m.Requests()[0].Proto; got != "HTTP/2.0" {
		t.Errorf("recorded the version %q, want HTTP/2.0", got)
	}

	// With CertNames, the certificate names localhost, and the mock's
	// CertFile holds it.
	m = NewMockWith(t, MockConfig{TLS: true, CertNames: []string{"localhost", "127.0.0.1"}})
	pemBytes, err = os.ReadFile(m.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("%s holds no certificate", m.CertFile)
	}
	trusting = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	for _, base := range []string{fmt.Sprintf("https://localhost:%d", m.Port()), m.URL()} {
		wantAnswer(t, "at "+base, mockOperation(t, trusting, base, "encrypt", key, "plaintext", fileKey), "ciphertext")
	}
	if got := m.Requests()[0].Host; got != fmt.Sprintf("localhost:%d", m.Port()) {
		t.Errorf("recorded the host %q", got)
	}
	if err := m.server.Certificate().VerifyHostname("example.com"); err == nil {
		t.Error("the certificate made for localhost and 127.0.0.1 also names example.com")
	}
}

func testMockUnsolicited(t *testing.T) {
	const extra = "UNSOLICITED-BYTES"
	m := NewMockWith(t, MockConfig{Unsolicited: extra})
	key := MustParseUUID(goldenKeyA)
	fileKey := []byte("0123456789abcdef")

	conn, err := net.Dial("tcp", m.server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	body := `{"plaintext":"` + base64.StdEncoding.EncodeToString(fileKey) + `"}`
	req, err := http.NewRequest(http.MethodPost, m.URL()+"/v1/keys/"+key.String()+"/encrypt", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+mockToken)
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}

	// A complete answer that keeps the connection open, then the bytes.
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Close || resp.ContentLength != int64(len(answer)) {
		t.Errorf("status %d, close %v, length %d for a %d-byte body", resp.StatusCode, resp.Close, resp.ContentLength, len(answer))
	}
	reply := mockReply{resp.StatusCode, resp.Header, answer}
	if got := wantAnswer(t, "the answer", reply, "ciphertext"); !bytes.Equal(got, toySeal(key, fileKey)) {
		t.Errorf("encrypt answered %q", got)
	}
	rest := make([]byte, len(extra))
	if _, err := io.ReadFull(r, rest); err != nil || string(rest) != extra {
		t.Errorf("after the answer came %q, %v; want %q", rest, err, extra)
	}
	if m.EncryptCalls() != 1 {
		t.Errorf("counted %d encrypt requests", m.EncryptCalls())
	}
}

func testEnv(t *testing.T) {
	// Nothing comes from the test's own environment.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("RYPT_TOKEN", "from-the-shell")
	var zero Env
	if got, want := zero.Environ(), []string{"RYPT_API_URL=" + closedAPIURL}; !slices.Equal(got, want) {
		t.Errorf("Env{}.Environ() = %q, want %q", got, want)
	}
	if got := zero.WithoutAPIURL().Environ(); got == nil || len(got) != 0 {
		t.Errorf("Env{}.WithoutAPIURL().Environ() = %#v, want an empty non-nil slice", got)
	}

	m := NewMock(t)
	env := ForMock(m)
	if got, want := env.Environ(), []string{"RYPT_API_URL=" + m.URL(), "RYPT_TOKEN=" + mockToken}; !slices.Equal(got, want) {
		t.Errorf("ForMock(m).Environ() = %q, want %q", got, want)
	}

	// Changes to one base do not reach each other.
	base := env.WithVar("A", "1")
	x := base.WithVar("X", "x")
	y := base.WithVar("Y", "y").WithoutToken()
	if _, ok := x.Lookup("Y"); ok {
		t.Error("x sees y's change")
	}
	if _, ok := y.Lookup("X"); ok {
		t.Error("y sees x's change")
	}
	if v, ok := x.Lookup("RYPT_TOKEN"); !ok || v != mockToken {
		t.Errorf("x has RYPT_TOKEN %q, %v", v, ok)
	}
	if _, ok := y.Lookup("RYPT_TOKEN"); ok {
		t.Error("y still has RYPT_TOKEN")
	}
	if _, ok := base.Lookup("X"); ok {
		t.Error("base sees x's change")
	}

	// The last change wins.
	if v, _ := y.WithToken("a").WithToken("b").Lookup("RYPT_TOKEN"); v != "b" {
		t.Errorf("RYPT_TOKEN %q, want b", v)
	}
	if v, _ := env.WithAPIURL("https://h/").Lookup("RYPT_API_URL"); v != "https://h/" {
		t.Errorf("RYPT_API_URL %q", v)
	}
	if got := zero.WithPath("/a", "/b").Environ(); !slices.Contains(got, "PATH=/a"+string(os.PathListSeparator)+"/b") {
		t.Errorf("WithPath: %q", got)
	}
	if got := zero.WithVar("RYPT_TOKEN", "ry_\xff_abc").Environ(); !slices.Contains(got, "RYPT_TOKEN=ry_\xff_abc") {
		t.Errorf("WithVar with invalid UTF-8: %q", got)
	}

	secrets := envSecrets(zero.WithToken(" \t\fother-token\r\n"))
	if len(secrets) != 2 || string(secrets[0]) != mockToken || string(secrets[1]) != "other-token" {
		t.Errorf("envSecrets = %q", secrets)
	}
	// The plugin does not trim a vertical tab, so neither does envSecrets.
	if secrets := envSecrets(zero.WithToken("\vother-token")); len(secrets) != 2 || string(secrets[1]) != "\vother-token" {
		t.Errorf("envSecrets = %q", secrets)
	}
}

func testLeakChecks(t *testing.T) {
	key := MustParseUUID(goldenKeyA)
	fileKey := []byte("0123456789abcdef")
	ciphertext := toySeal(key, fileKey)
	secrets := append(envSecrets(ForMock(NewMock(t))), fileKey)
	ciphertexts := [][]byte{ciphertext}

	clean := &Outcome{All: []Stanza{
		{Type: "labels"},
		{Type: "recipient-stanza", Args: []string{"0", "rypt", key.String()}, Body: ciphertext},
		{Type: "file-key", Args: []string{"0"}, Body: fileKey},
		{Type: "error", Args: []string{"stanza", "0", "0"}, Body: []byte("rypt: 400; rypt: key not found")},
		{Type: "grease-1f", Args: []string{"12"}, Body: []byte{1, 2, 3}},
	}}
	if found := leaks(clean, secrets, ciphertexts); len(found) != 0 {
		t.Errorf("a clean outcome leaks: %q", found)
	}

	errorSaying := func(text string) *Outcome {
		return &Outcome{All: []Stanza{{Type: "error", Args: []string{"recipient", "0"}, Body: []byte(text)}}}
	}
	for what, o := range map[string]*Outcome{
		"stderr":                       {Stderr: "oops"},
		"the token in an error":        errorSaying("bad token " + mockToken),
		"the token in arguments":       {All: []Stanza{{Type: "error", Args: []string{mockToken}}}},
		"the file key in an error":     errorSaying("key 0123456789abcdef"),
		"the file key in hex":          errorSaying(hex.EncodeToString(fileKey)),
		"the file key in uppercase":    errorSaying(strings.ToUpper(hex.EncodeToString(fileKey))),
		"the file key in base64":       errorSaying(base64.StdEncoding.EncodeToString(fileKey)),
		"the file key in url base64":   errorSaying(base64.RawURLEncoding.EncodeToString(fileKey)),
		"the file key as Go prints it": errorSaying(fmt.Sprint(fileKey)),
		"the file key as Rust does":    errorSaying("[48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]"),
		"the file key in grease":       {All: []Stanza{{Type: "grease-2", Body: fileKey}}},
		"the file key in a stanza":     {All: []Stanza{{Type: "recipient-stanza", Args: []string{"0", "rypt", key.String()}, Body: fileKey}}},
		"the file key in a msg":        {All: []Stanza{{Type: "msg", Body: []byte(hex.EncodeToString(fileKey))}}},
		"a ciphertext in an error":     errorSaying("got " + base64.StdEncoding.EncodeToString(ciphertext)),
		"a ciphertext in a msg":        {All: []Stanza{{Type: "msg", Body: []byte(hex.EncodeToString(ciphertext))}}},
		"a response body in an error":  errorSaying("rypt: the mock refused the request: " + mockBodyMarker),
	} {
		if found := leaks(o, secrets, ciphertexts); len(found) == 0 {
			t.Errorf("%s is not caught", what)
		}
	}

	// A secret too short to look for is not caught by chance.
	if found := leaks(errorSaying("rypt: 400"), [][]byte{[]byte("400")}, nil); len(found) != 0 {
		t.Errorf("a short secret is caught: %q", found)
	}

	shown := []byte("age: error: rypt plugin: rypt: key not found\n")
	if found := textLeaks("stderr", shown, secrets, ciphertexts, true); len(found) != 0 {
		t.Errorf("clean text leaks: %q", found)
	}
	if found := textLeaks("stderr", []byte("age: "+mockBodyMarker), secrets, ciphertexts, true); len(found) == 0 {
		t.Error("a response body in text is not caught")
	}
}

// fakeRecipient wraps a file key into a "fake" stanza naming its key in
// hex, or fails.
type fakeRecipient struct {
	key  []byte
	fail bool
}

func (r fakeRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	if r.fail {
		return nil, errors.New("fake wrap failure")
	}
	return []*age.Stanza{{Type: "fake", Args: []string{hex.EncodeToString(r.key)}, Body: slices.Clone(fileKey)}}, nil
}

// fakeIdentity unwraps the "fake" stanzas for its key, and fails on a
// "fake-fail" stanza.
type fakeIdentity struct {
	key []byte
}

func (i fakeIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		switch {
		case s.Type == "fake-fail":
			return nil, errors.New("fake unwrap failure")
		case s.Type == "fake" && len(s.Args) == 1 && s.Args[0] == hex.EncodeToString(i.key):
			return s.Body, nil
		}
	}
	return nil, age.ErrIncorrectIdentity
}

// failingKey is the key whose fakeRecipient fails.
var failingKey = statusKey(500)

// runFramework serves one session with age's own plugin framework, as a
// plugin named rypt with fake recipients and identities, run in this process
// and connected by pipes.
func runFramework(t *testing.T, stateMachine string, phase1 []Stanza, known []string) *Outcome {
	t.Helper()
	p, err := plugin.New("rypt")
	if err != nil {
		t.Fatal(err)
	}
	asRecipient := func(data []byte) (age.Recipient, error) {
		if len(data) != 16 {
			return nil, fmt.Errorf("key id must be 16 bytes, got %d", len(data))
		}
		return fakeRecipient{key: data, fail: bytes.Equal(data, failingKey[:])}, nil
	}
	p.HandleRecipient(asRecipient)
	p.HandleIdentityAsRecipient(asRecipient)
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return fakeIdentity{key: data}, nil
	})

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	var stderr bytes.Buffer
	p.SetIO(stdinReader, stdoutWriter, &stderr)
	exit := make(chan int, 1)
	go func() {
		var code int
		if stateMachine == "recipient-v1" {
			code = p.RecipientV1()
		} else {
			code = p.IdentityV1()
		}
		stdoutWriter.Close()
		// Later writes by the client fail instead of blocking.
		stdinReader.Close()
		exit <- code
	}()

	o, err := session(stdinWriter, stdoutReader, phase1, known)
	o.ExitCode = <-exit
	o.Stderr = stderr.String()
	if err != nil {
		t.Fatalf("%s: %v; stderr %q", stateMachine, err, o.Stderr)
	}
	return o
}

// checkGrease checks that grease, which age's framework sends at random,
// went unacknowledged, and that every acknowledged command is a known one.
func checkGrease(t *testing.T, o *Outcome, known []string) {
	t.Helper()
	for _, c := range o.Commands {
		if !slices.Contains(known, c.Type) {
			t.Errorf("acknowledged a %q command", c.Type)
		}
	}
	for _, c := range o.All {
		if !slices.Contains(known, c.Type) && !strings.HasPrefix(c.Type, "grease-") {
			t.Errorf("unexpected %q command", c.Type)
		}
	}
}

func testClientWithFramework(t *testing.T) {
	keyA, keyB := MustParseUUID(goldenKeyA), MustParseUUID(goldenKeyB)
	// Bodies of one short line, exactly one full line, and several lines.
	fileKeys := [][]byte{[]byte("0123456789abcdef"), bytes.Repeat([]byte{7}, 48), bytes.Repeat([]byte{9}, 100)}

	// Grease is random, so each run is repeated.
	for range 20 {
		o := runFramework(t, "recipient-v1", wrapPhase1([]string{recipient(keyA)}, []string{identity(keyB)}, fileKeys), recipientV1Commands)
		if !o.Done || o.ExitCode != 0 || o.Stderr != "" || len(o.Errors()) != 0 {
			t.Fatalf("wrap: done %v, exit %d, stderr %q, errors %q", o.Done, o.ExitCode, o.Stderr, o.Errors())
		}
		if len(o.Commands) == 0 || !o.Commands[0].Equal(Stanza{Type: "labels"}) {
			t.Errorf("wrap: no empty labels command first: %+v", o.Commands)
		}
		for i, fileKey := range fileKeys {
			want := []Stanza{
				{Type: "fake", Args: []string{keyA.Hex()}, Body: fileKey},
				{Type: "fake", Args: []string{keyB.Hex()}, Body: fileKey},
			}
			if got := o.Stanzas(i); !slices.EqualFunc(got, want, Stanza.Equal) {
				t.Errorf("wrap: file %d has stanzas %+v, want %+v", i, got, want)
			}
		}
		checkGrease(t, o, recipientV1Commands)
	}

	// The framework exits with 3 right after an error for a recipient,
	// without done.
	for range 5 {
		o := runFramework(t, "recipient-v1", wrapPhase1([]string{recipient(keyA), recipient(failingKey)}, nil, fileKeys[:1]), recipientV1Commands)
		if want := []PluginError{{"recipient 1", "fake wrap failure"}}; !slices.Equal(o.Errors(), want) {
			t.Errorf("failing wrap: errors %q, want %q", o.Errors(), want)
		}
		if o.Done || o.ExitCode != 3 || len(o.Stanzas(0)) != 0 {
			t.Errorf("failing wrap: done %v, exit %d, stanzas %+v", o.Done, o.ExitCode, o.Stanzas(0))
		}
		checkGrease(t, o, recipientV1Commands)
	}
	o := runFramework(t, "recipient-v1", wrapPhase1(nil, []string{identity(keyA), rawIdentity(make([]byte, 15))}, fileKeys[:1]), recipientV1Commands)
	if want := []PluginError{{"identity 1", "key id must be 16 bytes, got 15"}}; !slices.Equal(o.Errors(), want) || o.ExitCode != 3 {
		t.Errorf("bad identity: errors %q, exit %d", o.Errors(), o.ExitCode)
	}

	files := [][]Stanza{
		{
			{Type: "X25519", Args: []string{"abc"}, Body: bytes.Repeat([]byte{1}, 32)},
			{Type: "fake", Args: []string{keyA.Hex()}, Body: fileKeys[0]},
		},
		{{Type: "fake-fail"}},
		{{Type: "fake", Args: []string{keyB.Hex()}, Body: fileKeys[0]}},
		{{Type: "fake", Args: []string{keyA.Hex()}, Body: fileKeys[2]}},
	}
	for range 20 {
		o := runFramework(t, "identity-v1", unwrapPhase1([]string{identity(keyA)}, files), identityV1Commands)
		if !o.Done || o.ExitCode != 0 || o.Stderr != "" {
			t.Fatalf("unwrap: done %v, exit %d, stderr %q", o.Done, o.ExitCode, o.Stderr)
		}
		if want := []PluginError{{"stanza 1 0", "fake unwrap failure"}}; !slices.Equal(o.Errors(), want) {
			t.Errorf("unwrap: errors %q, want %q", o.Errors(), want)
		}
		want := map[int][]byte{0: fileKeys[0], 3: fileKeys[2]}
		if got := o.FileKeys(); !maps.EqualFunc(got, want, bytes.Equal) {
			t.Errorf("unwrap: file keys %x, want %x", got, want)
		}
		checkGrease(t, o, identityV1Commands)
	}

	// What breaks the protocol is an error, but an early end is not.
	for _, tc := range []struct {
		output string
		done   bool
		bad    bool
	}{
		{"", false, false},
		{"-> done\n\n", true, false},
		{"-> error recipient 0\ncnlwdDogNDA0\n", false, false},
		{"garbage\n", false, true},
		{"-> error recipient 0\n", false, true},
		{"-> done\n\nmore", true, true},
	} {
		o, err := session(nopWriteCloser{io.Discard}, strings.NewReader(tc.output), nil, recipientV1Commands)
		if o.Done != tc.done || (err != nil) != tc.bad {
			t.Errorf("session on %q: done %v, error %v", tc.output, o.Done, err)
		}
	}
}

// nopWriteCloser is an io.WriteCloser whose Close does nothing.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
