# age-plugin-rypt

An [age](https://age-encryption.org) plugin that protects files with a
[rypt.dev](https://rypt.dev) key. age encrypts the file as usual. The plugin
then sends age's 16-byte file key to rypt to be encrypted under one of your
rypt keys, and stores the result in the file's header. Decrypting sends that
ciphertext back to rypt, which returns the file key only to a caller holding a
valid API token for the key's tenant.

It works with the Go `age` CLI (1.1 or later) and with `rage`, and should work
with any other client that implements the age plugin protocol.

## Installation

age finds plugins on your `PATH` by the name `age-plugin-rypt`. Install it in
one of these ways.

### Homebrew (macOS and Linux)

```sh
brew install x6c-co/tap/age-plugin-rypt
```

This also installs the `age` CLI. Use the full name as shown: Homebrew only
loads formulae from a third-party tap once you trust them, and installing by
full name trusts this one formula.

Like any formula without a prebuilt Homebrew bottle, it needs current Xcode
Command Line Tools on macOS (`xcode-select --install`), or a C compiler on
Linux. On Intel Macs, Homebrew also builds `age` and Go from source, which
takes a while. The tarballs below need none of this.

### Prebuilt binaries

Each [release](https://github.com/x6c-co/age-plugin-rypt/releases) has a
tarball for macOS (Apple silicon and Intel) and Linux (x86_64 and arm64,
statically linked), and a `SHA256SUMS` file. The macOS binaries are signed
with a Developer ID and notarized by Apple.

```sh
curl -LO https://github.com/x6c-co/age-plugin-rypt/releases/download/v0.1.0/age-plugin-rypt-v0.1.0-aarch64-apple-darwin.tar.gz
tar -xzf age-plugin-rypt-v0.1.0-aarch64-apple-darwin.tar.gz
sudo mkdir -p /usr/local/bin
sudo install age-plugin-rypt-v0.1.0-aarch64-apple-darwin/age-plugin-rypt /usr/local/bin/
```

When a macOS binary was downloaded in a browser, macOS checks its notarization
with Apple the first time it runs, which needs an internet connection.

To check that a tarball was built by this repository's release workflow from
that release's tag:

```sh
gh attestation verify age-plugin-rypt-v0.1.0-aarch64-apple-darwin.tar.gz \
  --repo x6c-co/age-plugin-rypt \
  --signer-workflow x6c-co/age-plugin-rypt/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 \
  --deny-self-hosted-runners
```

Each tarball also holds `LICENSE-THIRD-PARTY`, the licenses of the crates built
into the binary.

### From source

```sh
cargo install --locked --git https://github.com/x6c-co/age-plugin-rypt
```

`--locked` builds with the dependency versions in `Cargo.lock`. It needs Rust
1.85 or later.

Check it is found:

```sh
age-plugin-rypt --version
```

## Configuration

The plugin reads its settings from environment variables, never from disk.

| variable | meaning |
|---|---|
| `RYPT_TOKEN` | **Required** for encrypting and decrypting. A rypt API key, `ry_<prefix>_<secret>`, sent as `Authorization: Bearer …`. Surrounding whitespace is ignored. |
| `RYPT_API_URL` | Optional. The API base URL, without `/v1`. Defaults to `https://api.rypt.dev`. It must use `https`, except for a loopback address written as an IP address (`127.0.0.1`, anything in `127.0.0.0/8`, or `[::1]`), which may use `http`. A name such as `localhost` needs `https`, since it is looked up and could resolve to another machine. |

```sh
export RYPT_TOKEN=ry_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

If `RYPT_TOKEN` is unset or empty, age reports `RYPT_TOKEN is not set`.

**Proxies.** For a remote API URL the plugin uses the first of `ALL_PROXY`,
`HTTPS_PROXY` and `HTTP_PROXY`, each in either case, that is set to a
non-empty value. That value must be a valid proxy URL, or the plugin refuses
to run with, for example, `HTTPS_PROXY is not a valid proxy URL`, rather than
go around the proxy. `NO_PROXY` (or `no_proxy`, if `NO_PROXY` is unset) lists
hosts to reach directly, comma-separated without spaces: `example.com` matches
only that host, `.example.com` or `*.example.com` its subdomains, and `*`
everything. SOCKS proxies are not supported: the plugin refuses to run with
`SOCKS proxies are not supported` unless `NO_PROXY` exempts the API host. With
`https`, a proxy only learns the host it connects to. A loopback address is
always reached directly.

**TLS.** Certificates are checked against Mozilla's root certificates, built
into the binary. The operating system's trust store and `SSL_CERT_FILE` are not
used, so a proxy that intercepts TLS with its own certificate authority fails
with `rypt: TLS certificate rejected`.

## Making an identity and a recipient

You need the id (a UUID) of a rypt key you already have. Create one in the
rypt console or with `POST /v1/keys`.

`new` writes an identity file for that key. It does not call the rypt API.

```console
$ age-plugin-rypt new --key 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47 > rypt-identity.txt
$ cat rypt-identity.txt
# created: 2026-09-29T20:52:51-05:00
# key: 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47
AGE-PLUGIN-RYPT-18U4FC8NMF48Z48CSDJX452C7GU098V2X
```

`recipient` prints the matching recipient. It reads an identity file from a
path, or from standard input when you give no path or `-`. It prints one line
for each rypt identity in the file, and skips identities of other types. The
file must be UTF-8 and at most 1 MiB. `recipient` refuses a rypt identity that
age itself would refuse: one in lowercase, or with spaces around it. It does
not check the file's other lines.

```console
$ age-plugin-rypt recipient rypt-identity.txt
age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g
$ age-plugin-rypt recipient < rypt-identity.txt
age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g
```

The identity file contains no secret: both strings just encode the key id. The
secret is `RYPT_TOKEN`. Anyone with a valid token for the key's tenant and a
copy of the file can decrypt it, whether or not they have the identity file.

## Encrypting and decrypting

```sh
# Encrypt to the recipient...
age -e -r age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g -o secrets.tar.age secrets.tar

# ...or to the identity file, which encrypts to the same key.
age -e -i rypt-identity.txt -o secrets.tar.age secrets.tar

# Decrypt.
age -d -i rypt-identity.txt -o secrets.tar secrets.tar.age
```

`rage` takes the same flags. The plugin has no default identity, so `-j rypt`
does not work: always pass `-i` with an identity file.

rypt recipients can be combined with X25519, SSH and other classic recipients.
For example, add an offline X25519 key as a break-glass copy:

```sh
age-keygen -o backup.key    # keep this file offline
age -e -r age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g -r "$(age-keygen -y backup.key)" \
    -o secrets.tar.age secrets.tar

# If rypt is unavailable:
age -d -i backup.key -o secrets.tar secrets.tar.age
```

age and rage refuse to combine post-quantum recipients (`age1pq1…`,
`age1tagpq1…`) with classic ones, rypt included, and a passphrase with any
other recipient.

**Identity order.** age clients run the plugin once per identity, and stop at
the first identity that reports an error. If one identity file or list of `-i`
flags holds a rypt identity and another key, a rypt failure (no token, the API
unreachable, the key deleted) can stop decryption before the other key is
tried. `rage` and age before 1.3 try identities in the order given, so list the
key you expect to work first. age 1.3 and later try X25519 and post-quantum
keys before plugin identities, but not SSH keys or passphrase-protected
identity files, so list those first on every client. Decrypting with the
break-glass key on its own always works.

## How it works

Each rypt recipient adds one stanza to the age header:

```
-> rypt 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47
<rypt ciphertext of the file key>
```

The argument is the key id in lowercase hyphenated form. The body is the raw
ciphertext rypt's `POST /v1/keys/{id}/encrypt` returned. The plugin uses
rypt's direct `encrypt`/`decrypt` operations on the file key, not envelope
mode.

- **Encrypting** costs one rypt operation per rypt recipient or identity, per
  file.
- **Decrypting** tries the file's `rypt` stanzas whose key id matches one of
  your identities, in header order, and stops at the first that decrypts.
  Stanzas for other keys are skipped without a request. If an attempt fails,
  the plugin moves on to the next stanza, and reports the failure only if no
  stanza decrypts. rypt counts only the operations it completes, so a refused
  attempt costs nothing. A refusal that comes after rypt finds the key (a
  `400`, a `409`, or the free-tier cap) is recorded in the key's audit log;
  one that comes before (a `401`, `403`, `404`, or the rate limit) is not.
- A `rypt` stanza that does not follow the format above makes the header
  invalid. The plugin reports `rypt: invalid stanza` and decrypts nothing from
  that file, as the age plugin protocol requires.

Each request is limited to 30 seconds in total. The plugin never follows a
redirect: any answer other than `200` is an error.

### Key lifecycle

- **Rotation.** rypt ciphertext names the key version it was made under, so
  files keep decrypting after a rotation for as long as that version is
  retained. `software` keys retain 3 versions and `hsm` keys 2. **`free` and
  `wrapped` keys retain only one**: rotating one makes every file encrypted
  under the previous version undecryptable at once (`rypt: 400`). Before
  rotating such a key, re-encrypt its files to another recipient, or decrypt
  them and encrypt them again once the rotation is done.
- **Deletion.** A deleted key refuses every operation (`rypt: 409`) for seven
  days. Within those days it can be restored, in the console or with
  `POST /v1/keys/{id}/restore` using the same token, and its files decrypt
  again. Once the seven days are up it can no longer be restored, even while it
  still answers `rypt: 409`. It is then destroyed, or at once with "delete now"
  in the console: the error becomes `rypt: key not found`, and files encrypted
  only to it are lost. Add a second recipient if that is not acceptable.
- **Billing.** On a paid key whose billing has lapsed, encrypting fails with
  `rypt: 402`. Decrypting keeps working.
- **Free-tier cap.** A `free` key that has used its 10,000 operations for the
  month refuses decrypting as well as encrypting, with
  `rypt: rate limit or op cap reached`, until 00:00 UTC on the 1st. For files
  that must stay readable, use a paid tier or add a second recipient (and mind
  the identity order above).

## Errors

| message | cause |
|---|---|
| `RYPT_TOKEN is not set` | The variable is unset, empty, or only whitespace. |
| `RYPT_TOKEN is not valid UTF-8`, `RYPT_TOKEN contains invalid characters` | The value can't be a token: it has spaces, control characters or non-ASCII characters inside it. |
| `RYPT_API_URL is not a valid URL` | Not an absolute `http` or `https` URL, or it has a query, a fragment, credentials, or something other than an IPv6 address in brackets. |
| `RYPT_API_URL must use https` | An `http` URL whose host is not a loopback IP address. |
| `SOCKS proxies are not supported` | The proxy the plugin would use is a SOCKS proxy (see Proxies above). |
| `ALL_PROXY is not a valid proxy URL`, and the same for the other proxy variables | The proxy variable the plugin would use cannot be parsed. |
| `rypt: unauthorized` | 401 or 403: the token is wrong, malformed or revoked, or is a console token rather than an API key. |
| `rypt: key not found` | 404: the token's tenant has no key with this id. It may be mistyped, belong to another tenant, or have been destroyed. A `RYPT_API_URL` with the wrong path, such as one ending in `/v1`, also gives a 404. |
| `rypt: rate limit or op cap reached` | 429: over 100 requests a second for this API key, or a `free` key at its monthly cap. |
| `rypt: 400` | rypt refused the ciphertext: the stanza was made under another key, under a key version rotation has retired, or is corrupt. |
| `rypt: 402` | Encrypting with a paid key whose billing has lapsed. |
| `rypt: 409` | The key is pending deletion. |
| `rypt: <status>` | Any other HTTP status, including a redirect. |
| `rypt: connection failed` | The DNS lookup or the connection failed, or the proxy refused the connection. |
| `rypt: TLS certificate rejected` | The server's certificate is not trusted (see TLS above). |
| `rypt: TLS error` | Another TLS failure, for example an `https` URL for a server that doesn't speak TLS. |
| `rypt: request timed out` | No complete answer within 30 seconds. |
| `rypt: request failed` | The request could not be sent. |
| `rypt: invalid response` | rypt answered 200 with something that is not a valid answer. |
| `rypt: invalid stanza` | The file has a malformed `rypt` stanza, so its header is invalid. |
| `rypt: decrypted file key is not 16 bytes` | rypt returned something that is not an age file key. |
| `rypt has no default identity: …` | `-j rypt` was used; pass `-i` with an identity file. |
| `key id must be 16 bytes, got N` | The recipient or identity is not a valid rypt key. |

The `recipient` subcommand prints its own errors, prefixed with
`age-plugin-rypt:`: `no rypt identity found`; `line N:` followed by
`identity must be uppercase`, `identity has surrounding whitespace, which age
does not accept`, `invalid Bech32 encoding` or `key id must be 16 bytes, got N`;
and, naming the file or `standard input`, `larger than 1 MiB`, `not valid UTF-8`
or the system's reason the file could not be read.

## Security notes

- The plugin never prints or logs the token, the file key, the ciphertext, or
  a response body. Errors are the fixed messages above.
- rypt sees each file key in the clear while it encrypts or decrypts it. That
  is what direct mode means, and why rypt holds the key.
- The plugin wipes the buffers it controls that held the token, a file key or
  a response, once it is done with them. Copies inside the HTTP and TLS
  libraries' own buffers cannot be wiped from the plugin.

## Development

```sh
cargo test
```

The tests run the plugin against a mock rypt API on 127.0.0.1:

- `tests/protocol.rs` drives the plugin protocol directly. Every run also
  checks that nothing secret reached stderr or any message.
- `tests/age_library.rs` encrypts and decrypts whole files with the `age`
  crate.
- `tests/age_cli.rs` does the same with the `age` or `rage` CLI. It is skipped
  when neither is on `PATH`, unless `AGE_PLUGIN_RYPT_REQUIRE_CLI` is set, as it
  is in CI.
- `tests/cli.rs` covers the `new` and `recipient` subcommands.

GitHub Actions runs `.github/workflows/ci.yml` on pushes to `main`, on pull
requests, and weekly: the tests on Linux and macOS with the `age` CLI
installed, a build with the minimum supported Rust version, and `cargo audit`
for security advisories. [RELEASING.md](RELEASING.md) covers releases.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
