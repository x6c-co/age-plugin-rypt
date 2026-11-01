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

This downloads the prebuilt binary, which is signed and notarized on macOS,
and also installs the `age` CLI.
On a Mac, the formula needs macOS 13 Ventura or later (see Prebuilt binaries).
Use the full name as shown: Homebrew only loads formulae from a third-party tap
once you trust them, and installing by full name trusts this one formula.

If Homebrew says the Command Line Tools are missing or out of date, run
`xcode-select --install` and try again. On Intel Macs, Homebrew has no prebuilt
`age`, so Homebrew compiles `age` from source, which takes a while.

### Prebuilt binaries

Each [release](https://github.com/x6c-co/age-plugin-rypt/releases) has a
tarball for macOS (Apple silicon and Intel) and Linux (x86_64 and arm64,
statically linked), and a `SHA256SUMS` file. The tarballs are named
`age-plugin-rypt-vX.Y.Z-<os>-<arch>.tar.gz`, where `<os>-<arch>` is
`darwin-arm64` (Apple silicon), `darwin-amd64` (Intel), `linux-amd64` (x86_64)
or `linux-arm64`. The macOS binaries are signed with a Developer ID and
notarized by Apple.

The macOS binaries need macOS 13 Ventura or later, the oldest macOS that Go
1.27 supports. Version 0.1.0 ran on macOS 11 on Apple silicon and on macOS
10.12 on Intel. A Mac that cannot run Ventura should stay on 0.1.0, whose
tarballs are on its release page. Homebrew refuses to install 0.2.0 on such a
Mac.

```sh
curl -LO https://github.com/x6c-co/age-plugin-rypt/releases/download/v0.2.0/age-plugin-rypt-v0.2.0-darwin-arm64.tar.gz
tar -xzf age-plugin-rypt-v0.2.0-darwin-arm64.tar.gz
sudo mkdir -p /usr/local/bin
sudo install age-plugin-rypt-v0.2.0-darwin-arm64/age-plugin-rypt /usr/local/bin/
```

When a macOS binary was downloaded in a browser, macOS checks its notarization
with Apple the first time it runs, which needs an internet connection.

To check that a tarball was built by this repository's release workflow from
that release's tag:

```sh
gh attestation verify age-plugin-rypt-v0.2.0-darwin-arm64.tar.gz \
  --repo x6c-co/age-plugin-rypt \
  --signer-workflow x6c-co/age-plugin-rypt/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.0 \
  --deny-self-hosted-runners
```

Each tarball also holds `LICENSE-THIRD-PARTY`, the licenses of the Go modules
built into the binary and of Go itself, whose runtime and standard library are
part of every Go binary.

### From source

```sh
go install github.com/x6c-co/age-plugin-rypt@latest
```

This needs Go 1.27 or later, and builds with the dependency versions in the
module's `go.mod`. On a Mac, Go 1.27 needs macOS 13 Ventura or later, and so
does the binary it builds. `go install` puts the binary in
`$(go env GOPATH)/bin` (`~/go/bin` by default), or in `GOBIN` if that is set.
age only finds the plugin if that directory is on your `PATH`.

Check it is found:

```console
$ age-plugin-rypt --version
age-plugin-rypt 0.2.0
```

## Configuration

The plugin reads its settings from environment variables. It has no
configuration file.

| variable | meaning |
|---|---|
| `RYPT_TOKEN` | **Required** for encrypting and decrypting. A rypt API key, `ry_<prefix>_<secret>`, sent as `Authorization: Bearer …`. Spaces, tabs, newlines, form feeds and carriage returns around it are ignored. |
| `RYPT_API_URL` | Optional. The API base URL, without `/v1`. Defaults to `https://api.rypt.dev`, also when it is set but empty. It must use `https`, except for the hosts `127.0.0.1` and `[::1]`, which may also use `http`. Every other host needs `https`: other loopback addresses such as `127.0.0.2`, other ways of writing `::1`, and the name `localhost`, since a name is looked up and could resolve to another machine. A path is kept: with `https://example.com/api`, requests go to `https://example.com/api/v1/keys/…`. |

```sh
export RYPT_TOKEN=ry_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

If `RYPT_TOKEN` is unset or empty, age reports `RYPT_TOKEN is not set`.

**Proxies.** The plugin follows Go's standard proxy rules.

- The API uses `https`, so the plugin uses the proxy in `HTTPS_PROXY`, or in
  `https_proxy` if `HTTPS_PROXY` is unset or empty. `HTTP_PROXY` and
  `ALL_PROXY` are not used.
- The value is a URL with the scheme `http`, `https`, `socks5` or `socks5h`,
  or just `host:port`, which means an `http` proxy.
- If the value is anything else, or cannot be parsed, the plugin sends no
  request. It reports `HTTPS_PROXY is not a valid proxy URL` (or the same for
  `https_proxy`), rather than go around the proxy or use the wrong one. This
  includes a value such as `http:/proxy:3128`. That value has one of those
  schemes but no `//` after it, and Go would read it as a proxy at a host
  named `http`.
- `NO_PROXY` (or `no_proxy`, if `NO_PROXY` is unset or empty) lists hosts to
  reach directly, separated by commas. `example.com` matches that host and its
  subdomains. `.example.com` and `*.example.com` match only its subdomains. An
  IP address, or a CIDR range such as `10.0.0.0/8`, matches the addresses it
  covers. `*` matches everything. An entry that ends in a port, such as
  `example.com:8443`, matches only that port.
- Go's HTTP library always reaches a loopback IP address, such as `127.0.0.1`
  or `[::1]`, directly. It reaches the name `localhost` directly only when the
  name is written in lowercase. Another spelling, such as `https://LOCALHOST`,
  goes through the proxy.
- The plugin does not check the proxy value for a loopback IP address or for
  lowercase `localhost`. It checks the value for every other `https` host,
  even one that `NO_PROXY` lists.
- With `https`, a proxy only learns the host it connects to.

**TLS.** Certificates are checked against the operating system's trust store.
On Linux, `SSL_CERT_FILE` and `SSL_CERT_DIR`, when set, are used in place of
the system's certificate file and directories. Only when the system has no root
certificates at all does the plugin fall back to Mozilla's root certificates,
which are built into the binary. A proxy that intercepts TLS with its own
certificate authority therefore works once the operating system trusts that
authority. A certificate the system does not trust fails with
`rypt: TLS certificate rejected`.

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

age 1.3 and later refuses to combine post-quantum recipients (`age1pq1…`,
`age1tagpq1…`) with classic ones, rypt included. rage needs `age-plugin-pq` on
`PATH` to use post-quantum recipients at all, and that plugin then refuses the
same combinations. Both refuse a passphrase with any other recipient.

**Identity order.** age and rage run the plugin once per identity, and stop at
the first identity that reports an error. If one identity file or list of `-i`
flags holds a rypt identity and another key, a rypt failure (no token, the API
unreachable, the key deleted) can stop decryption before the other key is
tried. `rage` and age before 1.3 try identities in the order given, so list the
key you expect to work first. age 1.3 and later try X25519 and post-quantum
keys before plugin identities, but not SSH keys or passphrase-protected
identity files, so list those first on every client. Two rypt identities
behave like any other pair: age and rage stop at the first rypt identity whose
stanza fails, even if a later rypt identity would decrypt the file. List the
rypt identity you expect to work first, or decrypt with that identity alone.
Decrypting with the break-glass key on its own always works.

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

Version 0.2.0 uses the same stanza, recipient and identity formats as 0.1.0.
Files encrypted with 0.1.0 decrypt with 0.2.0, files encrypted with 0.2.0
decrypt with 0.1.0, and identity files made by either version work with both.

- **Encrypting** costs one rypt operation per rypt recipient or identity, per
  file.
- **Decrypting** tries the file's `rypt` stanzas whose key id matches an
  identity given to that run of the plugin, in header order, and stops at the
  first that decrypts. Stanzas for other keys are skipped without a request,
  so a file with no stanza for your keys needs no `RYPT_TOKEN`. If an attempt
  fails, the plugin moves on to the next matching stanza. If none decrypts,
  the plugin reports one error for the file: the different failure messages
  in header order, joined with `; `. age, rage and SOPS run the plugin once
  for each identity, so in practice the stanzas tried are those of one key. A
  file has more than one stanza for a key only when that key was given more
  than once when the file was encrypted. (For several rypt identities, see
  Identity order above.) rypt counts only the operations it completes, so a
  refused attempt costs nothing. A refusal that comes after rypt finds the key
  (a `400`, a `409`, or the free-tier cap) is recorded in the key's audit log;
  one that comes before (a `401`, `403`, `404`, or the rate limit) is not.
- A `rypt` stanza that does not follow the format above makes the header
  invalid. The plugin then reports `rypt: invalid stanza` and sends no request
  for that file. It recovers no file key from the file, not even from a
  well-formed `rypt` stanza in it. This is what the age plugin protocol
  requires.

If the connection to rypt cannot be made, the connection drops before the
answer is complete, or rypt answers `502`, `503` or `504`, the plugin sends the
same request again, at most twice more. It waits up to a quarter of a second
before the first retry and up to half a second before the second. It does not
retry a `429`, a `500` or any other `4xx` answer. Each encrypt or decrypt
request, retries included, must finish within 30 seconds in total. A retried
request can be counted once for each attempt, so up to three times: after a
dropped connection or a `502`, `503` or `504`, rypt may have completed an
earlier attempt.

The plugin never follows a redirect: a `3xx` answer is an error, like any
other answer outside `2xx`. A `2xx` answer is accepted only if its body is the
answer rypt documents.

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
  only to it are lost. Add a second recipient if that is not acceptable. If
  the second recipient is another rypt key, age and rage still stop at the
  first rypt identity whose stanza fails, so decrypt with the second key's
  identity alone, or list it first (see Identity order above).
- **Billing.** On a paid key whose billing has lapsed, encrypting fails with
  `rypt: 402`. Decrypting keeps working.
- **Free-tier cap.** A `free` key that has used its 10,000 operations for the
  month refuses decrypting as well as encrypting, with
  `rypt: rate limit or op cap reached`, until 00:00 UTC on the 1st. For files
  that must stay readable, use a paid tier or add a second recipient (and mind
  the identity order above).

## Errors

age prints these messages after `rypt plugin: `. rage prints the same
messages, with its own text before them. When several stanzas of a file fail
to decrypt in one run of the plugin, their different messages are joined with
`; `. With age, rage and SOPS, those are stanzas of one key (see Decrypting
above).

| message | cause |
|---|---|
| `RYPT_TOKEN is not set` | The variable is unset or empty, or holds only spaces, tabs, newlines, form feeds and carriage returns. |
| `RYPT_TOKEN is not valid UTF-8`, `RYPT_TOKEN contains invalid characters` | The value can't be a token. Either it is not valid UTF-8, or, after the ignored characters around it (see Configuration) are removed, it still contains a space, a control character such as a vertical tab, or a character outside ASCII. |
| `RYPT_API_URL is not a valid URL` | Not an absolute `http` or `https` URL with a host, or it has a query or a fragment (any `?` or `#`, even with nothing after it), credentials, a port outside 1–65535, spaces, control characters or non-ASCII characters. |
| `RYPT_API_URL must use https` | An `http` URL, valid otherwise, whose host is not `127.0.0.1` or `[::1]`, such as `http://localhost`. |
| `HTTPS_PROXY is not a valid proxy URL`, or the same for `https_proxy` | The proxy variable the plugin would use is not a proxy URL the plugin accepts, or cannot be parsed (see Proxies above). |
| `rypt: unauthorized` | 401 or 403: the token is wrong, malformed or revoked, or is a console token rather than an API key. |
| `rypt: key not found` | 404: the token's tenant has no key with this id. It may be mistyped, belong to another tenant, or have been destroyed. A `RYPT_API_URL` with the wrong path, such as one ending in `/v1`, also gives a 404. |
| `rypt: rate limit or op cap reached` | 429: over 100 requests a second for this API key, or a `free` key at its monthly cap. |
| `rypt: 400` | rypt refused the ciphertext: the stanza was made under another key, under a key version rotation has retired, or is corrupt. |
| `rypt: 402` | Encrypting with a paid key whose billing has lapsed. |
| `rypt: 409` | The key is pending deletion. |
| `rypt: <status>` | Any other HTTP status outside `2xx`, including a redirect. A `502`, `503` or `504` is reported only after the retries failed as well. |
| `rypt: connection failed` | The DNS lookup or the connection failed, the proxy refused or failed the connection, or the connection dropped before the answer was complete, on every attempt. |
| `rypt: TLS certificate rejected` | The server's certificate is not trusted, or is not for the host in the URL (see TLS above). |
| `rypt: TLS error` | Another TLS failure, for example an `https` URL for a server that doesn't speak TLS. |
| `rypt: request timed out` | No complete answer within 30 seconds, retries included, or the network timed out. |
| `rypt: request failed` | The request failed for another reason. |
| `rypt: invalid response` | rypt answered with a `2xx` status but not with a valid answer: the body is not the JSON rypt documents, is larger than 8 MiB, or holds an empty or non-base64 value. |
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
  a response body. Errors are the fixed messages above, and nothing is written
  to standard error when a run succeeds. To keep standard error clean, the
  plugin discards everything written to Go's standard logger. Go's HTTP
  library writes there every request header sent over HTTP/2, the token among
  them, when `GODEBUG=http2debug` is set, and any bytes a server sends after
  its answer.
- rypt sees each file key in the clear while it encrypts or decrypts it. That
  is what direct mode means, and why rypt holds the key.
- The plugin does not wipe file keys from memory. age's Go plugin framework,
  which runs the plugin protocol, holds every file key in ordinary memory and
  never clears it, and the plugin only passes the keys on. The rypt client
  library clears its own copies of the request and response bodies.
  `recipient` clears its copy of the identity file it read. A decrypted value
  that is not 16 bytes is rejected and cleared. The token is held as a Go
  string, which cannot be cleared at all. Copies inside the HTTP and TLS
  libraries' own buffers cannot be wiped from the plugin either. Go cannot
  guarantee that clearing a buffer removes every copy from memory, so the
  clearing reduces exposure rather than preventing it. Version 0.1.0 wiped
  file keys and the token too. Version 0.2.0 cannot, for the reasons above.

## Development

```sh
go test ./...
```

This runs two sets of tests:

- The unit tests, in the `_test.go` files next to the code at the root of the
  repository.
- The end-to-end tests in `e2e/`. They build the binary and run it against a
  mock rypt API on 127.0.0.1, through the age plugin protocol and through the
  `new` and `recipient` subcommands. The tests that use an age CLI run
  `age`, or `rage` when `age` is not on `PATH`. They are skipped when neither
  is found. When `AGE_PLUGIN_RYPT_REQUIRE_CLI` is set, as it is in CI, they
  fail instead. To use only one of the two programs, set
  `AGE_PLUGIN_RYPT_CLI` to `age` or `rage`. The tests then fail if that
  program is not on `PATH`.

To check that this version and another build can decrypt each other's files,
for example a 0.1.0 binary, set `AGE_PLUGIN_RYPT_COMPAT_BINARY` to the path of
the other build's `age-plugin-rypt` binary. The compatibility test runs against
that binary.

GitHub Actions runs `.github/workflows/ci.yml` on pushes to `main`, on pull
requests, and weekly. It checks the formatting with `gofmt`, runs `go vet`,
and runs the tests with the race detector on Linux and macOS with the `age`
CLI installed. On macOS it then runs the age CLI tests again with `rage`,
which is built on the Rust age library rather than the Go one. It also builds
and vets the plugin with the oldest Go that `go.mod` allows, and runs
`govulncheck`, which reports security advisories for code the plugin can
reach, in its dependencies and in the standard library.
[RELEASING.md](RELEASING.md) covers releases, and
[CHANGELOG.md](CHANGELOG.md) lists the changes in each version.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
