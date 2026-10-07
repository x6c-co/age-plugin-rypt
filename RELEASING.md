# Releasing

Pushing a tag such as `v0.1.0` runs `.github/workflows/release.yml`. It:

1. runs the tests (`.github/workflows/ci.yml`);
2. builds static Linux binaries for x86_64 and arm64, and macOS binaries for
   Apple silicon and Intel;
3. signs the macOS binaries with the Developer ID certificate, notarizes them
   with Apple, and runs them;
4. publishes a GitHub release with one tarball per platform, `SHA256SUMS` and
   build provenance attestations;
5. commits the updated formula to the Homebrew tap, `x6c-co/homebrew-tap`.

Each tarball holds the binary, the README, this project's licenses, and
`LICENSE-THIRD-PARTY`: the licenses of the crates built into the binary,
written by [cargo-about](https://github.com/EmbarkStudios/cargo-about) from
`about.toml` and `about.hbs`. If a new dependency brings a license that
`about.toml` doesn't accept, the release stops; add the license there if it is
acceptable.

## One-time setup

### Repository settings

- **Release tags:** add a tag ruleset (Settings > Rules > Rulesets) for `v*`
  with Restrict creations, Restrict updates, Restrict deletions and Block force
  pushes, and only the Repository admin role on the bypass list. Whoever
  creates a release tag chooses the workflow code that receives the signing
  keys.
- **Immutable releases:** turn on release immutability (Settings > General >
  Releases) before the first release. A published release's tag and files then
  can't be changed or replaced. The workflow publishes as its very last step,
  so a failure earlier in a run can be fixed by re-running it.

### The environments

In Settings > Environments, create two environments. For each, limit
Deployment branches and tags to the tag pattern `v*` and the branch `main`
(for dry runs).

- **`release`** holds the Apple secrets below. Add yourself, or whoever
  approves releases, as a required reviewer, and turn off administrator
  bypass, so every release waits for that approval.
- **`homebrew-tap`** holds the tap token below.

### The Homebrew tap

1. Create the public repository `x6c-co/homebrew-tap` with a README. It must
   have a commit before the workflow can push to it. The release workflow
   writes `Formula/age-plugin-rypt.rb`.
2. Create a fine-grained personal access token:
   - Resource owner: **x6c-co**.
   - Repository access: **Only select repositories**, `x6c-co/homebrew-tap`.
   - Permissions: **Contents: Read and write**.
   - Expiration: the organization's default policy allows at most 366 days.
     Set a date, and note it.

   If you aren't an owner of x6c-co, an owner must approve the token
   (Organization settings > Personal access tokens > Pending requests) before
   it can push.
3. Save it as the secret `HOMEBREW_TAP_TOKEN` in the `homebrew-tap`
   environment.

Without the token, releases still publish, and the workflow skips the formula
update with a warning. A deploy key with write access to the tap is an
alternative that never expires, but the workflow would need changes to push
over SSH.

### Signing and notarization

You need membership of the Apple Developer Program. Only the team's Account
Holder can create the certificate.

These steps use OpenSSL, so they work without a Mac. Run them in a private
directory outside the repository.

1. Make a private key and a certificate signing request:

   ```sh
   umask 077
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
   openssl req -new -key key.pem -out DeveloperID.certSigningRequest \
     -subj "/emailAddress=you@example.com/CN=Your Name"
   ```

2. In Certificates, Identifiers & Profiles, create a **Developer ID
   Application** certificate. Choose the **G2 Sub-CA**: the original authority
   stops signing on 1 February 2027. Upload the request and download
   `developerID_application.cer`.
3. Bundle the key, the certificate and Apple's G2 intermediate certificate
   into one `.p12` file. The runner's keychain may not have the intermediate,
   and `codesign` fails without it. The 3DES and SHA-1 options are there
   because macOS's `security import` can reject OpenSSL 3's default `.p12`
   encryption.

   ```sh
   curl -fsSLO https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
   openssl x509 -inform DER -in developerID_application.cer -out cert.pem
   openssl x509 -inform DER -in DeveloperIDG2CA.cer -out ca.pem
   openssl rand -hex 24 | tr -d '\n' > p12-password
   openssl pkcs12 -export -inkey key.pem -in cert.pem -certfile ca.pem \
     -name "Developer ID Application" -passout file:p12-password \
     -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 \
     -out certificate.p12
   ```

   Keep `certificate.p12` and `p12-password` in a password manager. The
   `.p12` holds the key, so you can delete `key.pem`.
4. In App Store Connect, under Users and Access > Integrations, create a
   **Team** API key with the Developer role. Download the `.p8` file (it can
   only be downloaded once) and note the key ID and the issuer ID.
5. Save these secrets in the `release` environment. `gh secret set` reads the
   value from standard input, so it never appears in a command line:

   | secret | value |
   |---|---|
   | `MACOS_CERTIFICATE_P12_BASE64` | `base64 -w0 certificate.p12` |
   | `MACOS_CERTIFICATE_PASSWORD` | the contents of `p12-password` |
   | `APPLE_API_KEY_P8_BASE64` | `base64 -w0 AuthKey_XXXXXXXXXX.p8` |
   | `APPLE_API_KEY_ID` | the key ID |
   | `APPLE_API_ISSUER_ID` | the issuer ID |

   ```sh
   base64 -w0 certificate.p12 | gh secret set MACOS_CERTIFICATE_P12_BASE64 --env release
   gh secret set MACOS_CERTIFICATE_PASSWORD --env release < p12-password
   ```

   (On macOS, use `base64 -i FILE` instead of `base64 -w0 FILE`.)

The workflow stops if only some of the five secrets are set.

Until the secrets exist, a tag push fails at the signing job rather than
publish binaries that Gatekeeper blocks when downloaded in a browser. To
release unsigned anyway (Homebrew installs work either way), set the repository
variable `ALLOW_UNSIGNED_MACOS` to `true`; the release notes then say the macOS
binaries aren't signed. Delete the variable once the secrets are set.

## Before the first release

Run the workflow by hand (Actions > Release > Run workflow, on `main`). This is
a dry run. It builds every platform, signs, notarizes and runs the macOS
binaries, packages the tarballs, generates the formula, and checks that the tap
token can push. It publishes and commits nothing; the tarballs are left as the
run's `release-files` artifact. Like a release, it waits for approval of the
`release` environment before signing.

Until the Apple secrets are set, a dry run builds the macOS binaries unsigned,
with a warning, so everything but signing can be tested before the certificate
arrives. Run it again once the secrets are in place.

Apple can hold a new team's first notarizations for review for a day or more.
Do the dry run early. If the notarization step gives up, the run's summary
shows the submission ID; re-run the workflow once `xcrun notarytool info <ID>`
says Accepted.

## Each release

1. Update `version` in `Cargo.toml`, and run `cargo build` to update
   `Cargo.lock`.
2. Commit and push to `main`, then tag and push the tag:

   ```sh
   git push origin main
   git tag v0.1.0
   git push origin v0.1.0
   ```

The tag must match the version in `Cargo.toml`. A tag with a hyphen, such as
`v0.2.0-rc.1`, publishes a prerelease and leaves the formula alone. The
formula is never moved back to an older version.

If the formula update fails, for example because the token expired, replace
`HOMEBREW_TAP_TOKEN` and re-run the failed `homebrew` job.

## Upkeep

- **Every year:** the tap token expires after at most 366 days. Replace it and
  its secret.
- **Developer ID certificate:** the current one expires on 17 September 2031,
  when Apple's G2 intermediate certificate does. Make a new one before then and
  replace the two certificate secrets. Binaries already released keep working.
- **Actions:** the workflows pin each action to a commit. Dependabot
  (`.github/dependabot.yml`) opens a pull request when one has a new release.
- **Weekly audit:** GitHub disables scheduled workflows in a public repository
  after 60 days without activity. If the weekly `cargo audit` stops, re-enable
  the CI workflow in the Actions tab.

## Checking a release

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify age-plugin-rypt-v0.1.0-aarch64-apple-darwin.tar.gz \
  --repo x6c-co/age-plugin-rypt \
  --signer-workflow x6c-co/age-plugin-rypt/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 \
  --deny-self-hosted-runners
```

On a Mac, `codesign --display --verbose=2 age-plugin-rypt` should show
`Authority=Developer ID Application: …` and a `Timestamp`.
