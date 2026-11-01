# Changelog

All notable changes to age-plugin-rypt are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [semantic versioning](https://semver.org).

## Unreleased

## 0.2.0

age-plugin-rypt is now written in Go. The stanza, recipient and identity
formats have not changed, so files encrypted with 0.1.0 decrypt with 0.2.0 and
the other way round, and identity files made by `new` keep working.

- `RYPT_API_URL` may use `http` only for the hosts `127.0.0.1` and `[::1]`,
  written exactly so. 0.1.0 also allowed the rest of `127.0.0.0/8`, and other
  ways of writing `::1`, such as `[0:0:0:0:0:0:0:1]`. `localhost` still needs
  `https`, as in 0.1.0, because a name is looked up and could resolve to
  another machine.
- Proxies follow Go's standard rules. The plugin uses `HTTPS_PROXY` or
  `https_proxy`, and `NO_PROXY` or `no_proxy`. `ALL_PROXY` and `HTTP_PROXY`
  are no longer used. SOCKS5 proxies (`socks5://` and `socks5h://`) now work.
- In `NO_PROXY`, an entry such as `example.com` now matches that host and its
  subdomains. Entries may be CIDR ranges, such as `10.0.0.0/8`, and may end in
  a port. Spaces around entries are now ignored. Prefix entries, such as
  `192.168.` or `10.*`, no longer work.
- Certificates are checked against the operating system's trust store, and on
  Linux against `SSL_CERT_FILE` and `SSL_CERT_DIR`. Mozilla's root
  certificates, built into the binary, are used only when the system has none.
  A proxy that intercepts TLS now works when the operating system trusts its
  certificate authority.
- A request is retried, at most twice, when the connection cannot be made,
  when it drops part-way, or after a `502`, `503` or `504`. Each encrypt or
  decrypt request, retries included, still has 30 seconds in total. rypt may
  count a retried request once for each attempt, up to three times.
- When decrypting a file fails, the plugin reports one error for the file. If
  several stanzas failed in one run of the plugin, their different messages
  are joined with `; `. age, rage and SOPS run the plugin once for each
  identity, so with them this happens only for a file with several stanzas
  for the same key.
- A configuration error, such as a missing `RYPT_TOKEN`, an invalid
  `RYPT_API_URL` or an invalid proxy variable, is reported against the
  recipient, identity or file that needed a request, rather than as an
  internal error. age still prints the same text, such as
  `rypt plugin: RYPT_TOKEN is not set`. When encrypting, rage now names the
  recipient or identity, where 0.1.0 printed `(internal)` before the message,
  as in `(internal) RYPT_TOKEN is not set`.
- After an error about a recipient or an identity, the plugin exits with
  status 3, where 0.1.0 exited with 0. It still ends its reply with `done`, as
  0.1.0 did. rage waits for `done`, so it still shows the plugin's message.
  age shows the message without it. Clients ignore the exit status.
- A recipient or identity whose Bech32 encoding is not canonical, such as one
  with non-zero padding bits, is now refused, as age itself refuses it. 0.1.0
  accepted such strings, so a hand-edited identity file that worked with rage
  and 0.1.0 can now fail. `new` never writes such strings.
- `new --key` accepts the `urn:uuid:` prefix in any case, such as `URN:UUID:`.
  0.1.0 accepted only lowercase.
- Responses of up to 8 MiB are read. 0.1.0 stopped at 64 KiB.
- A `2xx` answer other than `200` is accepted if its body is a valid answer.
  0.1.0 treated every status other than `200` as an error.
- `--age-plugin` with an unknown state machine exits with status 4 and age's
  own message.
- Release tarballs are named `age-plugin-rypt-vX.Y.Z-<os>-<arch>.tar.gz`, with
  `darwin-arm64`, `darwin-amd64`, `linux-arm64` or `linux-amd64`, instead of
  Rust target triples. The Linux binaries are still statically linked.
  `LICENSE-THIRD-PARTY` now lists Go modules and Go's own license.
- The macOS binaries need macOS 13 Ventura or later, the oldest macOS that Go
  1.27 supports. 0.1.0 ran on macOS 11 on Apple silicon and on macOS 10.12 on
  Intel. Macs that cannot run Ventura should stay on 0.1.0. The Homebrew
  formula now refuses to install on an older macOS.
- File keys and the token are no longer wiped from memory. 0.1.0 wiped file
  keys, the request and response bodies, and the token. 0.2.0 is built on
  age's Go plugin framework, which holds file keys in ordinary memory and
  never clears them, and the token is a Go string, which cannot be cleared.
  The rypt client library still clears the request and response bodies.
- To install from source, run
  `go install github.com/x6c-co/age-plugin-rypt@latest`, which needs Go 1.27
  or later.

## 0.1.0

The first release, written in Rust, released on 2026-10-08.

- The `age1rypt1…` recipient, the `AGE-PLUGIN-RYPT-1…` identity and the
  `rypt` stanza, which wraps age's file key with rypt's direct `encrypt` and
  `decrypt` operations.
- The `new` and `recipient` subcommands.
- Configuration through `RYPT_TOKEN` and `RYPT_API_URL`.
- Prebuilt binaries for macOS and Linux, with the macOS binaries signed and
  notarized, and a Homebrew formula in `x6c-co/tap`.
