//! A blocking client for rypt's direct `encrypt` and `decrypt` operations.
//!
//! Every error this module returns is a short fixed message. None of them
//! carries the token, the file key, the ciphertext or a response body.

use std::env::VarError;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use base64::{Engine, prelude::BASE64_STANDARD};
use serde::Deserialize;
use ureq::http::Uri;
use ureq::{Proxy, ProxyProtocol};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Where the API is when `RYPT_API_URL` is not set.
pub const DEFAULT_API_URL: &str = "https://api.rypt.dev";

/// The error when there is no token to send.
pub const TOKEN_NOT_SET: &str = "RYPT_TOKEN is not set";
const TOKEN_NOT_UNICODE: &str = "RYPT_TOKEN is not valid UTF-8";
const TOKEN_INVALID: &str = "RYPT_TOKEN contains invalid characters";
const URL_INVALID: &str = "RYPT_API_URL is not a valid URL";
const URL_NOT_HTTPS: &str = "RYPT_API_URL must use https";
const SOCKS_UNSUPPORTED: &str = "SOCKS proxies are not supported";

/// The variables ureq takes a proxy from, in its order of precedence.
const PROXY_VARIABLES: [&str; 6] = [
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// How long one request may take, start to finish.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The largest response accepted, in bytes. rypt's answers about a 16-byte
/// file key are around a hundred bytes.
const MAX_RESPONSE: usize = 64 * 1024;

const USER_AGENT: &str = concat!("age-plugin-rypt/", env!("CARGO_PKG_VERSION"));

/// A rypt API client for one token.
pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Zeroizing<String>,
    timeout: Duration,
}

/// A validated `RYPT_API_URL`.
#[derive(Debug)]
struct ApiUrl {
    /// The URL without trailing slashes, ready for a path to be appended.
    base: String,
    uri: Uri,
    loopback: bool,
}

#[derive(Deserialize)]
struct CiphertextResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct PlaintextResponse {
    plaintext: String,
}

impl Client {
    /// Builds a client from `RYPT_TOKEN`, `RYPT_API_URL` and the proxy
    /// environment variables.
    pub fn from_env() -> Result<Self, String> {
        let token = token_from(std::env::var("RYPT_TOKEN"))?;
        let api = api_url_from(std::env::var("RYPT_API_URL"))?;
        // A server on this machine needs no proxy, and a proxy would see an
        // http request in the clear.
        let proxy = if api.loopback {
            None
        } else {
            env_proxy(&api.uri)?
        };
        Ok(Self::new(token, api, proxy, TIMEOUT))
    }

    fn new(token: Zeroizing<String>, api: ApiUrl, proxy: Option<Proxy>, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .user_agent(USER_AGENT)
            .proxy(proxy)
            .https_only(!api.loopback)
            // rypt never redirects. Following one would hand the request to a
            // server the user did not name.
            .max_redirects(0)
            // Every status but 200 is an error, mapped in `send`.
            .http_status_as_error(false)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            base: api.base,
            token,
            timeout,
        }
    }

    /// Encrypts `plaintext` under `key` and returns the raw ciphertext.
    pub fn encrypt(&self, key: Uuid, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let encoded = Zeroizing::new(BASE64_STANDARD.encode(plaintext));
        // Standard base64 needs no JSON escaping.
        let body = Zeroizing::new(format!(r#"{{"plaintext":"{}"}}"#, encoded.as_str()));
        let response = self.post(key, "encrypt", body)?;
        let parsed: CiphertextResponse =
            serde_json::from_slice(&response).map_err(|_| invalid_response())?;
        match BASE64_STANDARD.decode(parsed.ciphertext) {
            // An empty ciphertext could never be decrypted.
            Ok(ciphertext) if !ciphertext.is_empty() => Ok(ciphertext),
            _ => Err(invalid_response()),
        }
    }

    /// Decrypts a ciphertext `key` produced and returns the plaintext.
    pub fn decrypt(&self, key: Uuid, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let body = Zeroizing::new(format!(
            r#"{{"ciphertext":"{}"}}"#,
            BASE64_STANDARD.encode(ciphertext)
        ));
        let response = self.post(key, "decrypt", body)?;
        let encoded = Zeroizing::new(
            serde_json::from_slice::<PlaintextResponse>(&response)
                .map_err(|_| invalid_response())?
                .plaintext,
        );
        // Reserve up front so decoding never reallocates and leaves a copy behind.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(base64::decoded_len_estimate(
            encoded.len(),
        )));
        BASE64_STANDARD
            .decode_vec(encoded.as_bytes(), &mut plaintext)
            .map_err(|_| invalid_response())?;
        Ok(plaintext)
    }

    /// Sends one request on a worker thread and waits for it at most
    /// `timeout`.
    ///
    /// ureq's own timeout is not enough: a server that trickles bytes during
    /// the TLS handshake can outlast it indefinitely.
    fn post(
        &self,
        key: Uuid,
        operation: &str,
        body: Zeroizing<String>,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let agent = self.agent.clone();
        let url = format!("{}/v1/keys/{}/{}", self.base, key.hyphenated(), operation);
        let authorization = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .spawn(move || {
                // Fails only once the deadline has passed. The result is then
                // dropped, which wipes it.
                let _ = sender.send(send(&agent, &url, &authorization, &body));
            })
            .map_err(|_| request_failed())?;
        match receiver.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(timed_out()),
            Err(RecvTimeoutError::Disconnected) => Err(request_failed()),
        }
    }
}

fn send(
    agent: &ureq::Agent,
    url: &str,
    authorization: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut response = agent
        .post(url)
        .header("Authorization", authorization)
        .content_type("application/json")
        .send(body)
        .map_err(|e| transport_message(&e))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(status_message(status));
    }
    read_body(response.body_mut().as_reader())
}

/// Reads a response body of at most `MAX_RESPONSE` bytes.
///
/// The buffer has room for one byte more, so reading never reallocates and
/// leaves an unwiped copy behind, and that byte, if it arrives, shows the body
/// is too large.
fn read_body(body: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE + 1));
    body.take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|_| invalid_response())?;
    if buffer.len() > MAX_RESPONSE {
        return Err(invalid_response());
    }
    Ok(buffer)
}

/// The message for an HTTP status other than 200 from rypt.
pub fn status_message(status: u16) -> String {
    match status {
        401 | 403 => "rypt: unauthorized".to_owned(),
        404 => "rypt: key not found".to_owned(),
        429 => "rypt: rate limit or op cap reached".to_owned(),
        _ => format!("rypt: {status}"),
    }
}

fn transport_message(error: &ureq::Error) -> String {
    let message = match error {
        ureq::Error::StatusCode(status) => return status_message(*status),
        ureq::Error::Timeout(_) => return timed_out(),
        ureq::Error::Rustls(e) => tls_message(e),
        ureq::Error::Tls(_) => "rypt: TLS error",
        // rustls reports handshake failures, certificates included, as
        // io::Error wrapping a rustls::Error.
        ureq::Error::Io(e) => match e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(e) => tls_message(e),
            None => "rypt: connection failed",
        },
        // A proxy refusing the tunnel is a failure to connect, too.
        ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed
        | ureq::Error::ConnectProxyFailed(_) => "rypt: connection failed",
        _ => return request_failed(),
    };
    message.to_owned()
}

fn tls_message(error: &rustls::Error) -> &'static str {
    match error {
        rustls::Error::InvalidCertificate(_) => "rypt: TLS certificate rejected",
        _ => "rypt: TLS error",
    }
}

fn invalid_response() -> String {
    "rypt: invalid response".to_owned()
}

fn request_failed() -> String {
    "rypt: request failed".to_owned()
}

fn timed_out() -> String {
    "rypt: request timed out".to_owned()
}

/// Reads the token from the value of `RYPT_TOKEN`.
fn token_from(value: Result<String, VarError>) -> Result<Zeroizing<String>, String> {
    let value = match value {
        Ok(value) => Zeroizing::new(value),
        Err(VarError::NotPresent) => return Err(TOKEN_NOT_SET.to_owned()),
        Err(VarError::NotUnicode(raw)) => {
            drop(Zeroizing::new(raw.into_encoded_bytes()));
            return Err(TOKEN_NOT_UNICODE.to_owned());
        }
    };
    // rypt trims the token too, so a newline read from a file is harmless.
    let token = value.trim_ascii();
    if token.is_empty() {
        return Err(TOKEN_NOT_SET.to_owned());
    }
    // Anything else could not be sent in a header.
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(TOKEN_INVALID.to_owned());
    }
    Ok(Zeroizing::new(token.to_owned()))
}

/// Reads and checks the value of `RYPT_API_URL`, defaulting to production.
///
/// The URL must be https, except for a loopback address, so the token and
/// file key are never sent in the clear over a network.
fn api_url_from(value: Result<String, VarError>) -> Result<ApiUrl, String> {
    let url = match value {
        Ok(url) if !url.is_empty() => url,
        Ok(_) | Err(VarError::NotPresent) => DEFAULT_API_URL.to_owned(),
        Err(VarError::NotUnicode(_)) => return Err(URL_INVALID.to_owned()),
    };
    let invalid = || URL_INVALID.to_owned();
    // A query would end up in front of the path appended to the URL, and
    // http::Uri silently drops a fragment, so both are refused up front.
    if url.contains(['?', '#']) || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid());
    }
    let uri: Uri = url.parse().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    // rypt authenticates with the token, never with credentials in the URL.
    if authority.as_str().contains('@') {
        return Err(invalid());
    }
    // http::Uri accepts a port it cannot represent, such as 99999, and then
    // reports no port at all.
    if authority.as_str().len() > authority.host().len() && authority.port_u16().is_none() {
        return Err(invalid());
    }
    let host = authority.host();
    let bracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    // http::Uri accepts anything in brackets, but only an IPv6 address may be
    // there. ureq would look anything else up by name, brackets and all.
    if bracketed.is_some_and(|inner| inner.parse::<Ipv6Addr>().is_err()) {
        return Err(invalid());
    }
    let loopback = match bracketed {
        Some(inner) => inner.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback()),
        None => host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback()),
    };
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if loopback => {}
        Some("http") => return Err(URL_NOT_HTTPS.to_owned()),
        _ => return Err(invalid()),
    }
    Ok(ApiUrl {
        base: url.trim_end_matches('/').to_owned(),
        uri,
        loopback,
    })
}

/// The proxy ureq would take from the environment for `uri`.
///
/// ureq skips a proxy variable it cannot parse, and then uses the next one or
/// no proxy at all: either way it would quietly go around the proxy the user
/// meant. So the variable ureq would look at first, the first one set to a
/// non-empty value, must parse.
fn env_proxy(uri: &Uri) -> Result<Option<Proxy>, String> {
    for name in PROXY_VARIABLES {
        let Some(value) = std::env::var_os(name).filter(|v| !v.is_empty()) else {
            continue;
        };
        if !value.to_str().is_some_and(|v| Proxy::new(v).is_ok()) {
            return Err(format!("{name} is not a valid proxy URL"));
        }
        break;
    }
    // The proxy itself comes from ureq, which also reads NO_PROXY.
    checked_proxy(Proxy::try_from_env(), uri)
}

/// Refuses a SOCKS proxy that would be used for `uri`. ureq is built without
/// SOCKS support and would silently connect directly instead.
fn checked_proxy(proxy: Option<Proxy>, uri: &Uri) -> Result<Option<Proxy>, String> {
    match proxy {
        Some(proxy)
            if matches!(
                proxy.protocol(),
                ProxyProtocol::Socks4
                    | ProxyProtocol::Socks4A
                    | ProxyProtocol::Socks5
                    | ProxyProtocol::Socks5h
            ) && !proxy.is_no_proxy(uri) =>
        {
            Err(SOCKS_UNSUPPORTED.to_owned())
        }
        proxy => Ok(proxy),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{self, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    use super::*;

    const KEY: Uuid = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);

    fn token(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    fn url(s: &str) -> Result<ApiUrl, String> {
        api_url_from(Ok(s.to_owned()))
    }

    #[cfg(unix)]
    fn not_unicode() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'r', b'y', 0xff, b'_'])
    }

    #[test]
    fn status_messages() {
        assert_eq!(status_message(401), "rypt: unauthorized");
        assert_eq!(status_message(403), "rypt: unauthorized");
        assert_eq!(status_message(404), "rypt: key not found");
        assert_eq!(status_message(429), "rypt: rate limit or op cap reached");
        for status in [204, 301, 302, 307, 308, 400, 402, 409, 500, 503] {
            assert_eq!(status_message(status), format!("rypt: {status}"));
        }
    }

    #[test]
    fn token_is_trimmed() {
        assert_eq!(token_from(Ok("ry_a_b".into())).unwrap().as_str(), "ry_a_b");
        assert_eq!(
            token_from(Ok(" \try_a_b\r\n".into())).unwrap().as_str(),
            "ry_a_b"
        );
    }

    #[test]
    fn missing_empty_or_blank_token_is_not_set() {
        for value in [
            Err(VarError::NotPresent),
            Ok(String::new()),
            Ok(" \n".into()),
        ] {
            assert_eq!(token_from(value).unwrap_err(), "RYPT_TOKEN is not set");
        }
    }

    #[test]
    fn token_with_unsendable_characters_is_refused() {
        for value in ["ry_a b", "ry_a\nb", "ry_\u{e9}"] {
            assert_eq!(
                token_from(Ok(value.into())).unwrap_err(),
                "RYPT_TOKEN contains invalid characters"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn token_that_is_not_unicode_is_refused() {
        assert_eq!(
            token_from(Err(VarError::NotUnicode(not_unicode()))).unwrap_err(),
            "RYPT_TOKEN is not valid UTF-8"
        );
    }

    #[test]
    fn api_url_defaults_to_production() {
        for value in [Err(VarError::NotPresent), Ok(String::new())] {
            let api = api_url_from(value).unwrap();
            assert_eq!(api.base, "https://api.rypt.dev");
            assert!(!api.loopback);
        }
    }

    #[test]
    fn api_url_accepts_https_anywhere() {
        let api = url("https://rypt.example.com/").unwrap();
        assert_eq!(api.base, "https://rypt.example.com");
        assert!(!api.loopback);
        assert_eq!(
            url("https://rypt.example.com:8443/api//").unwrap().base,
            "https://rypt.example.com:8443/api"
        );
        assert!(url("HTTPS://rypt.example.com").is_ok());
    }

    #[test]
    fn api_url_accepts_http_only_for_a_loopback_address() {
        for local in [
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://[::1]:8080/",
            "http://[0:0:0:0:0:0:0:1]",
        ] {
            let api = url(local).unwrap();
            assert!(api.loopback, "{local}");
            assert!(!api.base.ends_with('/'), "{local}");
        }
        // Names are looked up, and could resolve anywhere.
        for remote in [
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://api.rypt.dev",
            "http://10.0.0.1",
            "http://[::2]",
            "http://[::ffff:127.0.0.1]",
            "http://127.1",
            "http://localhost.example.com",
        ] {
            assert_eq!(
                url(remote).unwrap_err(),
                "RYPT_API_URL must use https",
                "{remote}"
            );
        }
    }

    #[test]
    fn api_url_refuses_anything_else() {
        for bad in [
            "api.rypt.dev",
            "ftp://api.rypt.dev",
            "https://",
            "https://api.rypt.dev/?x=1",
            "https://api.rypt.dev/#v1",
            "https://user:pass@api.rypt.dev",
            "https://user:pass@api.rypt.dev:443",
            "https://user@api.rypt.dev:443",
            "http://user:pass@127.0.0.1:8080",
            "https://api.rypt.dev ",
            " https://api.rypt.dev",
            "https://api.rypt.dev:99999",
            // Only an IPv6 address may be in brackets.
            "http://[127.0.0.1]:8080",
            "https://[127.0.0.1]",
            "http://[localhost]",
            "https://[api.rypt.dev]",
        ] {
            assert_eq!(
                url(bad).unwrap_err(),
                "RYPT_API_URL is not a valid URL",
                "{bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn api_url_that_is_not_unicode_is_refused() {
        assert_eq!(
            api_url_from(Err(VarError::NotUnicode(not_unicode()))).unwrap_err(),
            "RYPT_API_URL is not a valid URL"
        );
    }

    fn socks_proxy(no_proxy: &str) -> Proxy {
        Proxy::builder(ProxyProtocol::Socks5)
            .host("127.0.0.1")
            .port(9)
            .no_proxy(no_proxy)
            .build()
            .unwrap()
    }

    #[test]
    fn a_socks_proxy_is_refused_unless_no_proxy_exempts_the_host() {
        let rypt = url("https://rypt.example.com").unwrap().uri;
        assert_eq!(
            checked_proxy(Some(socks_proxy("other.example.com")), &rypt).unwrap_err(),
            "SOCKS proxies are not supported"
        );
        assert!(
            checked_proxy(Some(socks_proxy("rypt.example.com")), &rypt)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn an_http_proxy_or_none_is_kept() {
        let rypt = url("https://rypt.example.com").unwrap().uri;
        let http = Proxy::new("http://127.0.0.1:3128").unwrap();
        assert!(checked_proxy(Some(http), &rypt).unwrap().is_some());
        assert!(checked_proxy(None, &rypt).unwrap().is_none());
    }

    #[test]
    fn reads_a_body_of_up_to_64_kib_without_reallocating() {
        for size in [0, 1, 100, MAX_RESPONSE - 1, MAX_RESPONSE] {
            let body = read_body(io::repeat(b' ').take(size as u64)).unwrap();
            assert_eq!(body.len(), size);
            assert_eq!(body.capacity(), MAX_RESPONSE + 1, "{size}");
        }
    }

    #[test]
    fn refuses_a_body_over_64_kib() {
        for size in [MAX_RESPONSE + 1, MAX_RESPONSE + 2, 10 * MAX_RESPONSE] {
            assert_eq!(
                read_body(io::repeat(b' ').take(size as u64)).unwrap_err(),
                "rypt: invalid response",
                "{size}"
            );
        }
        // Even an endless body.
        assert!(read_body(io::repeat(b' ')).is_err());
    }

    #[test]
    fn agent_never_redirects_and_times_out_after_30_seconds() {
        let client = Client::new(
            token("t"),
            url("https://rypt.example.com").unwrap(),
            None,
            TIMEOUT,
        );
        let config = client.agent.config();
        assert_eq!(client.timeout, Duration::from_secs(30));
        assert_eq!(config.timeouts().global, Some(Duration::from_secs(30)));
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.http_status_as_error());
        assert!(config.https_only());
        assert!(config.proxy().is_none());
    }

    #[test]
    fn agent_allows_http_only_for_loopback() {
        let client = Client::new(
            token("t"),
            url("http://127.0.0.1:1").unwrap(),
            None,
            TIMEOUT,
        );
        assert!(!client.agent.config().https_only());
    }

    /// A local server that accepts connections and then runs `serve` on each.
    fn serve_with(serve: fn(std::net::TcpStream)) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || serve(stream));
            }
        });
        port
    }

    fn assert_times_out(base: String) {
        let timeout = Duration::from_millis(500);
        let client = Client::new(token("t"), url(&base).unwrap(), None, timeout);
        let start = Instant::now();
        assert_eq!(
            client.encrypt(KEY, &[7; 16]).unwrap_err(),
            "rypt: request timed out"
        );
        let elapsed = start.elapsed();
        assert!(elapsed >= timeout, "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn a_silent_server_times_out() {
        let port = serve_with(|stream| {
            thread::sleep(Duration::from_secs(60));
            drop(stream);
        });
        assert_times_out(format!("http://127.0.0.1:{port}"));
    }

    #[test]
    fn a_trickling_tls_handshake_times_out() {
        // A TLS record header, then one byte at a time: each read succeeds, so
        // only a deadline over the whole request stops it.
        let port = serve_with(|mut stream| {
            if stream.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).is_err() {
                return;
            }
            for _ in 0..1200 {
                thread::sleep(Duration::from_millis(50));
                if stream.write_all(&[0]).is_err() {
                    return;
                }
            }
        });
        assert_times_out(format!("https://127.0.0.1:{port}"));
    }
}
