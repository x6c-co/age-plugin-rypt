package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/x6c-co/rypt"
)

// operationTimeout bounds each encrypt or decrypt, retries included.
const operationTimeout = 30 * time.Second

// The messages for each way the plugin's configuration or a request can
// fail. Every error this file returns is one of these fixed messages: none
// carries the token, the file key, the ciphertext or any text the server
// sent.
const (
	msgTokenNotSet     = "RYPT_TOKEN is not set"
	msgTokenNotUnicode = "RYPT_TOKEN is not valid UTF-8"
	msgTokenInvalid    = "RYPT_TOKEN contains invalid characters"
	msgURLInvalid      = "RYPT_API_URL is not a valid URL"
	msgURLNotHTTPS     = "RYPT_API_URL must use https"

	msgUnauthorized     = "rypt: unauthorized"
	msgKeyNotFound      = "rypt: key not found"
	msgRateLimited      = "rypt: rate limit or op cap reached"
	msgInvalidResponse  = "rypt: invalid response"
	msgFileKeyLength    = "rypt: decrypted file key is not 16 bytes"
	msgConnectionFailed = "rypt: connection failed"
	msgCertRejected     = "rypt: TLS certificate rejected"
	msgTLSError         = "rypt: TLS error"
	msgTimedOut         = "rypt: request timed out"
	msgRequestFailed    = "rypt: request failed"
)

// fileKeySize is the size of an age file key.
const fileKeySize = 16

// apiClient calls rypt's direct encrypt and decrypt operations.
type apiClient struct {
	client  *rypt.Client
	timeout time.Duration
}

// clientFromEnv builds a client from RYPT_TOKEN, RYPT_API_URL and the proxy
// variables, looked up with getenv.
func clientFromEnv(getenv func(string) string) (*apiClient, error) {
	token, err := tokenFrom(getenv("RYPT_TOKEN"))
	if err != nil {
		return nil, err
	}
	rawURL, base, err := apiURLFrom(getenv("RYPT_API_URL"))
	if err != nil {
		return nil, err
	}
	client, err := rypt.NewClient(token,
		rypt.WithBaseURL(rawURL),
		rypt.WithUserAgent("age-plugin-rypt/"+version))
	if err != nil {
		// The token, the user agent and the URL were checked already, and
		// the SDK's rules for the URL are no looser than apiURLFrom's.
		return nil, errors.New(msgURLInvalid)
	}
	if err := checkProxy(base, getenv); err != nil {
		return nil, err
	}
	return &apiClient{client: client, timeout: operationTimeout}, nil
}

// tokenFrom reads the API token from the value of RYPT_TOKEN.
func tokenFrom(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New(msgTokenNotUnicode)
	}
	// rypt trims the token too, so a newline read from a file is harmless.
	// These are the ASCII whitespace characters as WHATWG defines them, the
	// set 0.1.0 trimmed: a vertical tab is not among them.
	token := strings.Trim(value, " \t\n\f\r")
	if token == "" {
		return "", errors.New(msgTokenNotSet)
	}
	// Anything else could not be sent in a header.
	if !isPrintableASCII(token) {
		return "", errors.New(msgTokenInvalid)
	}
	return token, nil
}

// apiURLFrom reads the API base URL from the value of RYPT_API_URL,
// defaulting to production, and returns it both as given and parsed.
//
// Plain http is allowed only to the loopback addresses 127.0.0.1 and ::1,
// as in 0.1.0, and never to the name localhost. A name is looked up, and the
// lookup can reach DNS, whose answer could send the token and the file key
// in the clear to another machine. The SDK checks the URL by the same rule
// since v0.2.0; this function checks first so that each problem gets the
// plugin's own message.
func apiURLFrom(value string) (string, *url.URL, error) {
	if value == "" {
		value = rypt.DefaultBaseURL
	}
	if !isPrintableASCII(value) {
		return "", nil, errors.New(msgURLInvalid)
	}
	u, err := url.Parse(value)
	switch {
	case err != nil, u.Opaque != "", u.User != nil, u.Hostname() == "",
		// Checked on the string, as the SDK does, so that a bare "?" or
		// "#" is refused too.
		strings.ContainsAny(value, "?#"),
		// url.Parse checks only that a port is made of digits.
		!validPort(u.Port()):
		return "", nil, errors.New(msgURLInvalid)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if host := u.Hostname(); host != "127.0.0.1" && host != "::1" {
			return "", nil, errors.New(msgURLNotHTTPS)
		}
	default:
		return "", nil, errors.New(msgURLInvalid)
	}
	return value, u, nil
}

// validPort reports whether port, from url.URL.Port, is empty, which means
// the scheme's default, or a number from 1 to 65535.
func validPort(port string) bool {
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// checkProxy refuses a proxy setting that Go would silently ignore.
//
// For an https URL, net/http takes the proxy from HTTPS_PROXY, or
// https_proxy when that is empty. A value it cannot parse is skipped as if
// it were not set, so the request would quietly go around the proxy the
// user meant. A loopback host is never proxied, and plain http is only
// ever allowed to one, so neither needs the check.
func checkProxy(base *url.URL, getenv func(string) string) error {
	if base.Scheme != "https" || isLoopbackHost(base.Hostname()) {
		return nil
	}
	name := "HTTPS_PROXY"
	value := getenv(name)
	if value == "" {
		name = "https_proxy"
		value = getenv(name)
	}
	if value == "" {
		return nil
	}
	if !validProxy(value) {
		return fmt.Errorf("%s is not a valid proxy URL", name)
	}
	return nil
}

// validProxy reports whether a proxy variable's value names a proxy that
// net/http would use as meant.
//
// Like golang.org/x/net/http/httpproxy, it reads a value without a scheme,
// such as "127.0.0.1:3128", as an http proxy. Unlike it, it refuses a value
// with a scheme that does not parse into a host: httpproxy would put
// "http://" in front of that too, and so connect to a host named after the
// scheme, or ignore the value altogether.
func validProxy(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if strings.Contains(value, "://") {
			return false
		}
		// Such as "http:/proxy:3128", which httpproxy would read as
		// "http://http:/proxy:3128", a proxy at the host "http".
		if err == nil && isProxyScheme(u.Scheme) {
			return false
		}
		if u, err = url.Parse("http://" + value); err != nil {
			return false
		}
	}
	return u.Hostname() != "" && isProxyScheme(u.Scheme)
}

// isProxyScheme reports whether net/http can use a proxy URL with scheme.
func isProxyScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "socks5", "socks5h":
		return true
	}
	return false
}

// isLoopbackHost reports whether net/http's proxy logic treats host as this
// machine and so never sends it through a proxy: the name localhost, in
// lowercase only, or a loopback IP address.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	// As httpproxy does: netip accepts an IPv6 zone, such as ::1%lo, which
	// net.ParseIP refuses, and net.IP counts ::ffff:127.0.0.1 as loopback,
	// which netip.Addr.IsLoopback does not.
	a, err := netip.ParseAddr(host)
	return err == nil && net.IP(a.AsSlice()).IsLoopback()
}

// isPrintableASCII reports whether s is made only of the bytes 0x21 to
// 0x7e: printable ASCII without the space.
func isPrintableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// encrypt encrypts a file key under key and returns the raw ciphertext.
func (c *apiClient) encrypt(key keyID, fileKey []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	ciphertext, err := c.client.Encrypt(ctx, key.String(), fileKey, nil)
	if err != nil {
		return nil, errors.New(describe(err))
	}
	return ciphertext, nil
}

// decrypt decrypts a ciphertext key made and returns the file key.
func (c *apiClient) decrypt(key keyID, ciphertext []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	plaintext, err := c.client.Decrypt(ctx, key.String(), ciphertext, nil)
	if err != nil {
		return nil, errors.New(describe(err))
	}
	if len(plaintext) != fileKeySize {
		clear(plaintext)
		return nil, errors.New(msgFileKeyLength)
	}
	return plaintext, nil
}

// describe returns the fixed message for an error from the SDK.
func describe(err error) string {
	var e *rypt.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return msgTimedOut
	case !errors.As(err, &e):
		return msgRequestFailed
	case e.Kind == rypt.KindAPI:
		return statusMessage(e.StatusCode)
	case e.Kind == rypt.KindResponse:
		return msgInvalidResponse
	case e.Kind == rypt.KindTransport:
		return transportMessage(e.Err)
	}
	return msgRequestFailed
}

// statusMessage returns the message for an HTTP status other than 2xx.
func statusMessage(status int) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return msgUnauthorized
	case http.StatusNotFound:
		return msgKeyNotFound
	case http.StatusTooManyRequests:
		return msgRateLimited
	}
	return fmt.Sprintf("rypt: %d", status)
}

// transportMessage returns the message for a request that got no complete
// answer.
func transportMessage(err error) string {
	var (
		verifyErr  *tls.CertificateVerificationError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
		recordErr  tls.RecordHeaderError
		alertErr   tls.AlertError
		opErr      *net.OpError
		netErr     net.Error
	)
	switch {
	case err == nil:
		return msgRequestFailed
	case errors.As(err, &verifyErr), errors.As(err, &unknownCA),
		errors.As(err, &hostErr), errors.As(err, &invalidErr):
		return msgCertRejected
	case errors.Is(err, http.ErrSchemeMismatch), errors.As(err, &recordErr),
		errors.As(err, &alertErr),
		// A TLS alert from the other side, or one this side sent.
		errors.As(err, &opErr) && (opErr.Op == "remote error" || opErr.Op == "local error"),
		// crypto/tls reports most handshake failures as plain errors.
		strings.Contains(err.Error(), "tls: "):
		return msgTLSError
	case errors.As(err, &netErr) && netErr.Timeout():
		return msgTimedOut
	}
	// Anything else on the way: the name lookup, the connection, the proxy,
	// or a connection that broke before the whole answer arrived.
	return msgConnectionFailed
}
