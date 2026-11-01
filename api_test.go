package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// env returns a getenv function for clientFromEnv that sees only vars.
func env(vars ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(vars); i += 2 {
		m[vars[i]] = vars[i+1]
	}
	return func(name string) string { return m[name] }
}

const testToken = "ry_Test1234_abcdefghijklmnopqrstuvwxyz012345"

// newTestClient returns a client for the API at url with a short timeout.
func newTestClient(t *testing.T, url string, timeout time.Duration) *apiClient {
	t.Helper()
	c, err := clientFromEnv(env("RYPT_TOKEN", testToken, "RYPT_API_URL", url))
	if err != nil {
		t.Fatalf("clientFromEnv(%q): %v", url, err)
	}
	c.timeout = timeout
	return c
}

func TestStatusMessages(t *testing.T) {
	for status, want := range map[int]string{
		401: "rypt: unauthorized",
		403: "rypt: unauthorized",
		404: "rypt: key not found",
		429: "rypt: rate limit or op cap reached",
	} {
		if got := statusMessage(status); got != want {
			t.Errorf("statusMessage(%d) = %q, want %q", status, got, want)
		}
	}
	for _, status := range []int{301, 302, 307, 308, 400, 402, 409, 500, 502, 503} {
		if got, want := statusMessage(status), "rypt: "+strconv.Itoa(status); got != want {
			t.Errorf("statusMessage(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestTokenFrom(t *testing.T) {
	for _, tt := range []struct{ in, want, err string }{
		{"ry_a_b", "ry_a_b", ""},
		{" \try_a_b\r\n", "ry_a_b", ""},
		{"", "", "RYPT_TOKEN is not set"},
		{" \n", "", "RYPT_TOKEN is not set"},
		{"ry_a b", "", "RYPT_TOKEN contains invalid characters"},
		{"ry_a\nb", "", "RYPT_TOKEN contains invalid characters"},
		{"ry_a\x7fb", "", "RYPT_TOKEN contains invalid characters"},
		{"ry_\u00e9", "", "RYPT_TOKEN contains invalid characters"},
		{"ry_\xff_", "", "RYPT_TOKEN is not valid UTF-8"},
		// Only the ASCII whitespace 0.1.0 trimmed: not a vertical tab, and
		// not a Unicode space.
		{"\fry_x\f", "ry_x", ""},
		{"\vry_x", "", "RYPT_TOKEN contains invalid characters"},
		{"\u00a0ry_x\u00a0", "", "RYPT_TOKEN contains invalid characters"},
		{"\u0085ry_x", "", "RYPT_TOKEN contains invalid characters"},
	} {
		got, err := tokenFrom(tt.in)
		if got != tt.want || errText(err) != tt.err {
			t.Errorf("tokenFrom(%q) = %q, %q; want %q, %q", tt.in, got, errText(err), tt.want, tt.err)
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestClientFromEnvRequiresAToken(t *testing.T) {
	for _, vars := range [][]string{nil, {"RYPT_TOKEN", ""}, {"RYPT_TOKEN", "  "}} {
		if _, err := clientFromEnv(env(vars...)); errText(err) != "RYPT_TOKEN is not set" {
			t.Errorf("%q: err = %v", vars, err)
		}
	}
}

func TestAPIURLs(t *testing.T) {
	for _, tt := range []struct{ url, err string }{
		{"", ""},
		{"https://api.rypt.dev", ""},
		{"https://rypt.example.com/", ""},
		{"https://rypt.example.com:8443/api//", ""},
		{"HTTPS://rypt.example.com", ""},
		{"https://127.0.0.1:8443", ""},
		{"http://127.0.0.1:8080", ""},
		{"http://[::1]:8080/", ""},
		{"https://localhost:8443", ""},
		{"https://rypt.example.com:65535", ""},
		{"https://rypt.example.com:", ""},
		{"http://127.0.0.1:", ""},

		{"http://api.rypt.dev", "RYPT_API_URL must use https"},
		{"http://10.0.0.1", "RYPT_API_URL must use https"},
		{"http://127.0.0.2", "RYPT_API_URL must use https"},
		{"http://127.1", "RYPT_API_URL must use https"},
		{"http://[::2]", "RYPT_API_URL must use https"},
		{"http://[::ffff:127.0.0.1]", "RYPT_API_URL must use https"},
		{"http://localhost.example.com", "RYPT_API_URL must use https"},
		// A name is looked up, and could lead to another machine.
		{"http://localhost:8080", "RYPT_API_URL must use https"},
		{"http://LOCALHOST", "RYPT_API_URL must use https"},
		{"http://[0:0:0:0:0:0:0:1]", "RYPT_API_URL must use https"},
		{"HTTP://rypt.example.com/api", "RYPT_API_URL must use https"},

		{"api.rypt.dev", "RYPT_API_URL is not a valid URL"},
		{"ftp://api.rypt.dev", "RYPT_API_URL is not a valid URL"},
		{"https://", "RYPT_API_URL is not a valid URL"},
		{"http://", "RYPT_API_URL is not a valid URL"},
		{"https://api.rypt.dev/?x=1", "RYPT_API_URL is not a valid URL"},
		{"https://api.rypt.dev/?", "RYPT_API_URL is not a valid URL"},
		{"http://localhost/?", "RYPT_API_URL is not a valid URL"},
		{"http://127.0.0.1/?", "RYPT_API_URL is not a valid URL"},
		{"http://example.com/?", "RYPT_API_URL is not a valid URL"},
		{"http://example.com/#", "RYPT_API_URL is not a valid URL"},
		{"http://127.0.0.1:1/#", "RYPT_API_URL is not a valid URL"},
		{"http://localhost:1/#", "RYPT_API_URL is not a valid URL"},
		{"https://rypt.example.com:0", "RYPT_API_URL is not a valid URL"},
		{"https://rypt.example.com:65536", "RYPT_API_URL is not a valid URL"},
		{"http://127.0.0.1:99999", "RYPT_API_URL is not a valid URL"},
		{"https://api.rypt.dev/#v1", "RYPT_API_URL is not a valid URL"},
		{"http://10.0.0.1/#v1", "RYPT_API_URL is not a valid URL"},
		{"https://user:pass@api.rypt.dev", "RYPT_API_URL is not a valid URL"},
		{"https://user@api.rypt.dev:443", "RYPT_API_URL is not a valid URL"},
		{"http://user:pass@127.0.0.1:8080", "RYPT_API_URL is not a valid URL"},
		{"http://user@10.0.0.1", "RYPT_API_URL is not a valid URL"},
		{"https://api.rypt.dev ", "RYPT_API_URL is not a valid URL"},
		{" https://api.rypt.dev", "RYPT_API_URL is not a valid URL"},
		{"https://api.rypt.dev/\u00e9", "RYPT_API_URL is not a valid URL"},
		{"https://[127.0.0.1]", "RYPT_API_URL is not a valid URL"},
		{"mailto:rypt@example.com", "RYPT_API_URL is not a valid URL"},
	} {
		_, err := clientFromEnv(env("RYPT_TOKEN", testToken, "RYPT_API_URL", tt.url))
		if errText(err) != tt.err {
			t.Errorf("RYPT_API_URL=%q: err = %q, want %q", tt.url, errText(err), tt.err)
		}
	}
}

func TestDefaultAPIURL(t *testing.T) {
	// Spelled out rather than taken from the SDK, so that a change there
	// shows up here.
	for _, value := range []string{"", "https://api.rypt.dev"} {
		raw, u, err := apiURLFrom(value)
		if err != nil || raw != "https://api.rypt.dev" || u.Scheme != "https" || u.Host != "api.rypt.dev" || u.Path != "" {
			t.Errorf("apiURLFrom(%q) = %q, %v, %v", value, raw, u, err)
		}
	}
}

func TestOperationTimeout(t *testing.T) {
	c, err := clientFromEnv(env("RYPT_TOKEN", testToken))
	if err != nil {
		t.Fatal(err)
	}
	if c.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", c.timeout)
	}
}

func TestValidProxy(t *testing.T) {
	for _, v := range []string{
		"http://proxy.example.com:3128",
		"https://proxy.example.com",
		"socks5://127.0.0.1:1080",
		"socks5h://proxy:1080",
		"http://user:pass@proxy:3128",
		"proxy.example.com:3128",
		"127.0.0.1:3128",
		"[::1]:3128",
		"proxy",
		"HTTP://PROXY:3128",
	} {
		if !validProxy(v) {
			t.Errorf("validProxy(%q) = false", v)
		}
	}
	for _, v := range []string{
		"http://[::1",
		"://proxy",
		"http://",
		"ftp://proxy.example.com",
		"socks4://proxy:1080",
		"not a proxy",
		"%zz",
		// A scheme without "//" would make a proxy at a host named
		// after the scheme.
		"http:/proxy:3128",
		"socks5:/proxy:1080",
		"HTTP:/proxy",
		"http:",
	} {
		if validProxy(v) {
			t.Errorf("validProxy(%q) = true", v)
		}
	}
}

func TestCheckProxyNamesTheVariable(t *testing.T) {
	remote := "https://rypt.example.com"
	for _, tt := range []struct {
		vars []string
		err  string
	}{
		{[]string{"HTTPS_PROXY", "http://[::1"}, "HTTPS_PROXY is not a valid proxy URL"},
		{[]string{"https_proxy", "http://[::1"}, "https_proxy is not a valid proxy URL"},
		{[]string{"HTTPS_PROXY", "http://proxy:3128", "https_proxy", "http://[::1"}, ""},
		{[]string{"HTTPS_PROXY", "socks5://proxy:1080"}, ""},
		{[]string{"HTTP_PROXY", "http://[::1", "ALL_PROXY", "http://[::1"}, ""},
	} {
		vars := append([]string{"RYPT_TOKEN", testToken, "RYPT_API_URL", remote}, tt.vars...)
		if _, err := clientFromEnv(env(vars...)); errText(err) != tt.err {
			t.Errorf("%q: err = %q, want %q", tt.vars, errText(err), tt.err)
		}
	}
	// net/http bypasses the proxy for the name localhost only when it is
	// written in lowercase, so any other spelling needs a valid proxy.
	for _, upper := range []string{"https://LOCALHOST:1", "https://LocalHost:1"} {
		_, err := clientFromEnv(env("RYPT_TOKEN", testToken, "RYPT_API_URL", upper, "HTTPS_PROXY", "http://[::1"))
		if errText(err) != "HTTPS_PROXY is not a valid proxy URL" {
			t.Errorf("%s: err = %q", upper, errText(err))
		}
	}
	// This machine is never reached through a proxy, so its setting
	// doesn't matter.
	for _, local := range []string{"http://127.0.0.1:1", "https://127.0.0.1:1", "https://localhost:1", "http://[::1]:1", "https://[::1%25lo]:1", "https://[::ffff:127.0.0.1]:1"} {
		if _, err := clientFromEnv(env("RYPT_TOKEN", testToken, "RYPT_API_URL", local, "HTTPS_PROXY", "http://[::1")); err != nil {
			t.Errorf("%s: %v", local, err)
		}
	}
}

// fakeRypt is a rypt API that echoes the plaintext back as the ciphertext,
// unless the key's last group of digits is an HTTP status to answer with.
type fakeRypt struct {
	*httptest.Server
	requests  atomic.Int64
	userAgent atomic.Value
}

func newFakeRypt(t *testing.T, plaintext func([]byte) []byte) *fakeRypt {
	f := &fakeRypt{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		f.userAgent.Store(r.Header.Get("User-Agent"))
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 5 || parts[1] != "v1" || parts[2] != "keys" {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		key, op := parts[3], parts[4]
		if status, err := strconv.Atoi(strings.TrimLeft(key[24:], "0")); strings.HasPrefix(key, "00000000-") && err == nil {
			http.Error(w, `{"error":"forced","message":"secret-marker"}`, status)
			return
		}
		var body map[string][]byte
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch op {
		case "encrypt":
			json.NewEncoder(w).Encode(map[string][]byte{"ciphertext": append([]byte("ct:"), body["plaintext"]...)})
		case "decrypt":
			pt, ok := bytes.CutPrefix(body["ciphertext"], []byte("ct:"))
			if !ok {
				http.Error(w, `{"error":"invalid_ciphertext"}`, http.StatusBadRequest)
				return
			}
			if plaintext != nil {
				pt = plaintext(pt)
			}
			json.NewEncoder(w).Encode(map[string][]byte{"plaintext": pt})
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// statusKey is a key the fake rypt answers with HTTP status.
func statusKey(status int) keyID {
	return mustParseUUID(fmt.Sprintf("00000000-0000-0000-0000-%012d", status))
}

func TestEncryptAndDecrypt(t *testing.T) {
	f := newFakeRypt(t, nil)
	c := newTestClient(t, f.URL, 5*time.Second)
	fileKey := bytes.Repeat([]byte{7}, 16)
	ciphertext, err := c.encrypt(testKey, fileKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.decrypt(testKey, ciphertext)
	if err != nil || !bytes.Equal(got, fileKey) {
		t.Fatalf("decrypt = %x, %v", got, err)
	}
	if ua, _ := f.userAgent.Load().(string); !strings.HasPrefix(ua, "age-plugin-rypt/"+version+" rypt-go/") {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestStatusErrors(t *testing.T) {
	f := newFakeRypt(t, nil)
	c := newTestClient(t, f.URL, 5*time.Second)
	for status, want := range map[int]string{
		400: "rypt: 400",
		401: "rypt: unauthorized",
		402: "rypt: 402",
		403: "rypt: unauthorized",
		404: "rypt: key not found",
		409: "rypt: 409",
		429: "rypt: rate limit or op cap reached",
		500: "rypt: 500",
		502: "rypt: 502",
		302: "rypt: 302",
	} {
		_, err := c.encrypt(statusKey(status), make([]byte, 16))
		if errText(err) != want {
			t.Errorf("status %d: encrypt err = %q, want %q", status, errText(err), want)
		}
		_, err = c.decrypt(statusKey(status), []byte("ct:xxxxxxxxxxxxxxxx"))
		if errText(err) != want {
			t.Errorf("status %d: decrypt err = %q, want %q", status, errText(err), want)
		}
	}
}

func TestDecryptedFileKeyMustBe16Bytes(t *testing.T) {
	for _, n := range []int{1, 15, 17, 32} {
		f := newFakeRypt(t, func(pt []byte) []byte { return bytes.Repeat([]byte{1}, n) })
		c := newTestClient(t, f.URL, 5*time.Second)
		_, err := c.decrypt(testKey, []byte("ct:xxxxxxxxxxxxxxxx"))
		if errText(err) != "rypt: decrypted file key is not 16 bytes" {
			t.Errorf("%d bytes: err = %q", n, errText(err))
		}
	}
	// The SDK refuses an empty plaintext itself.
	f := newFakeRypt(t, func(pt []byte) []byte { return nil })
	c := newTestClient(t, f.URL, 5*time.Second)
	if _, err := c.decrypt(testKey, []byte("ct:x")); errText(err) != "rypt: invalid response" {
		t.Errorf("empty plaintext: err = %q", errText(err))
	}
}

func TestInvalidResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":        "not json",
		"missing field":   `{"other":"AAAA"}`,
		"bad base64":      `{"ciphertext":"AAA$"}`,
		"empty":           `{"ciphertext":""}`,
		"wrong JSON type": `{"ciphertext":7}`,
		"no body":         ``,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}))
		c := newTestClient(t, srv.URL, 5*time.Second)
		_, err := c.encrypt(testKey, make([]byte, 16))
		if errText(err) != "rypt: invalid response" {
			t.Errorf("%s: err = %q", name, errText(err))
		}
		srv.Close()
	}
}

// listen returns a loopback listener that serve handles every connection
// of, until the test ends.
func listen(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return l.Addr().String()
}

func assertTimesOut(t *testing.T, url string) {
	t.Helper()
	timeout := 500 * time.Millisecond
	c := newTestClient(t, url, timeout)
	for _, op := range []struct {
		name string
		call func() error
	}{
		{"encrypt", func() error { _, err := c.encrypt(testKey, make([]byte, 16)); return err }},
		{"decrypt", func() error { _, err := c.decrypt(testKey, []byte("ct:xxxxxxxxxxxxxxxx")); return err }},
	} {
		start := time.Now()
		err := op.call()
		elapsed := time.Since(start)
		if errText(err) != "rypt: request timed out" {
			t.Errorf("%s: err = %q", op.name, errText(err))
		}
		// Without the deadline, the SDK's own timeout would apply to each
		// of its attempts.
		if elapsed < timeout || elapsed > 5*time.Second {
			t.Errorf("%s took %v", op.name, elapsed)
		}
	}
}

func TestASilentServerTimesOut(t *testing.T) {
	addr := listen(t, func(conn net.Conn) { time.Sleep(10 * time.Second) })
	assertTimesOut(t, "http://"+addr)
}

func TestATricklingTLSHandshakeTimesOut(t *testing.T) {
	// A TLS record header, then one byte at a time: each read succeeds, so
	// only a deadline over the whole request stops it.
	addr := listen(t, func(conn net.Conn) {
		if _, err := conn.Write([]byte{0x16, 0x03, 0x03, 0x40, 0x00}); err != nil {
			return
		}
		for range 200 {
			time.Sleep(50 * time.Millisecond)
			if _, err := conn.Write([]byte{0}); err != nil {
				return
			}
		}
	})
	assertTimesOut(t, "https://"+addr)
}

func TestAnUntrustedCertificateIsRejected(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// The server would log the handshake the client aborts.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	c := newTestClient(t, srv.URL, 5*time.Second)
	if _, err := c.encrypt(testKey, make([]byte, 16)); errText(err) != "rypt: TLS certificate rejected" {
		t.Errorf("err = %q", errText(err))
	}
}

func TestAPlainHTTPServerAtAnHTTPSURLIsATLSError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := newTestClient(t, "https://"+srv.Listener.Addr().String(), 5*time.Second)
	if _, err := c.encrypt(testKey, make([]byte, 16)); errText(err) != "rypt: TLS error" {
		t.Errorf("err = %q", errText(err))
	}
}

func TestAClosedPortIsAConnectionFailure(t *testing.T) {
	// Port 1, as in the e2e tests: a port just freed could be taken by a
	// mock that another test package starts meanwhile.
	c := newTestClient(t, "http://127.0.0.1:1", 5*time.Second)
	if _, err := c.encrypt(testKey, make([]byte, 16)); errText(err) != "rypt: connection failed" {
		t.Errorf("err = %q", errText(err))
	}
}

func TestAnUnsupportedTLSVersionIsATLSError(t *testing.T) {
	// A ServerHello for TLS 1.0, which crypto/tls refuses with an error
	// of no particular type.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x01}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00, 0x00, 0x2f, 0x00)
	addr := listen(t, func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 4096)); err != nil {
			return
		}
		conn.Write(hello)
	})
	c := newTestClient(t, "https://"+addr, 5*time.Second)
	if _, err := c.encrypt(testKey, make([]byte, 16)); errText(err) != "rypt: TLS error" {
		t.Errorf("err = %q", errText(err))
	}
}

func TestADroppedConnectionIsAConnectionFailure(t *testing.T) {
	var attempts atomic.Int64
	addr := listen(t, func(conn net.Conn) {
		attempts.Add(1)
		// Read the request, then hang up without an answer.
		conn.Read(make([]byte, 4096))
	})
	c := newTestClient(t, "http://"+addr, 10*time.Second)
	if _, err := c.decrypt(testKey, []byte("ct:xxxxxxxxxxxxxxxx")); errText(err) != "rypt: connection failed" {
		t.Errorf("err = %q", errText(err))
	}
	// decrypt is safe to repeat, so the SDK tried three times.
	if n := attempts.Load(); n != 3 {
		t.Errorf("%d attempts, want 3", n)
	}
}

func TestErrorsNeverQuoteTheServer(t *testing.T) {
	f := newFakeRypt(t, nil)
	c := newTestClient(t, f.URL, 5*time.Second)
	for _, status := range []int{400, 401, 404, 409, 429, 500} {
		_, err := c.decrypt(statusKey(status), []byte("ct:xxxxxxxxxxxxxxxx"))
		if err == nil || strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), testToken) {
			t.Errorf("status %d: err = %v", status, err)
		}
	}
	if got := describe(base64.CorruptInputError(3)); got != "rypt: request failed" {
		t.Errorf("describe(non-SDK error) = %q", got)
	}
}
