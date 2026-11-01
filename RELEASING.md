# Releasing

Pushing a tag such as `v0.2.0` runs `.github/workflows/release.yml`. It:

1. runs the tests (`.github/workflows/ci.yml`);
2. cross-compiles all four binaries on one Linux runner with Go
   (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`): macOS for Apple silicon
   and Intel, and statically linked Linux for x86_64 and arm64. It runs the
   x86_64 Linux binary there, and the arm64 one on an arm64 runner;
3. signs the macOS binaries with the Developer ID certificate, notarizes them
   with Apple, and runs them;
4. publishes a GitHub release with one tarball per platform, `SHA256SUMS` and
   build provenance attestations;
5. asks the Go module proxy for the new version, so that
   `go install github.com/x6c-co/age-plugin-rypt@latest` finds it at once;
6. commits the updated formula to the Homebrew tap, `x6c-co/homebrew-tap`.

The tarballs are named `age-plugin-rypt-vX.Y.Z-<os>-<arch>.tar.gz`, where
`<os>-<arch>` is `darwin-arm64`, `darwin-amd64`, `linux-arm64` or
`linux-amd64`. Each holds the binary, the README, this project's licenses, and
`LICENSE-THIRD-PARTY`, which `scripts/third-party-licenses.sh` writes. That
file lists every Go module the binary is built from on any of the four
platforms, with its version and the text of its license files from the module
cache, and Go's own license, since the Go runtime and standard library are
built into the binary. If a module has no license file, the release stops.
The script does not judge whether a license is acceptable, so check the
license of a new dependency before adding it. To see the file, run
`scripts/third-party-licenses.sh` at the root of the repository; it is not
committed.

## One-time setup

### Repository settings

- **Release tags:** add a tag ruleset (Settings > Rules > Rulesets) for `v*`
  with Restrict creations, Restrict updates, Restrict deletions and Block force
  pushes, and only the Repository admin role on the bypass list. Whoever
  creates a release tag chooses the workflow code that receives the signing
  keys.
- **Immutable releases:** turn on release immutability (Settings > General >
  Releases) before the first release. A published release's tag and files then
  can't be changed or replaced. The release job publishes as its last step,
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

## Dry runs

Run the workflow by hand (Actions > Release > Run workflow, on `main`). This is
a dry run. Do one before the first release, and after changing the workflow.
It builds every platform, signs, notarizes and runs the macOS binaries,
packages the tarballs, generates the formula, and checks that the tap token
can push. It publishes and commits nothing; the tarballs are left as the
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

1. Update `const version` in `main.go`. `go run . --version` should then print
   `age-plugin-rypt` and the new version.
2. Commit and push to `main`, then tag and push the tag:

   ```sh
   git push origin main
   git tag v0.2.0
   git push origin v0.2.0
   ```

The tag must be `v` followed by the version that `go run . --version` prints;
the release stops otherwise. A tag with a hyphen, such as `v0.3.0-rc.1`,
publishes a prerelease and leaves the formula alone. The formula is never
moved back to an older version.

If the formula update fails, for example because the token expired, replace
`HOMEBREW_TAP_TOKEN` and re-run the failed `homebrew` job.

## Upkeep

- **Every year:** the tap token expires after at most 366 days. Replace it and
  its secret.
- **Developer ID certificate:** the current one expires on 17 September 2031,
  when Apple's G2 intermediate certificate does. Make a new one before then and
  replace the two certificate secrets. Binaries already released keep working.
- **Dependencies:** the workflows pin each action to a commit. Dependabot
  (`.github/dependabot.yml`) opens a pull request when an action or a Go
  module in `go.mod` has a new release; for a Go module, it waits a week after
  the release.
- **Go:** CI and the release build with the latest Go release. The `go` line
  in `go.mod` is the oldest Go the module supports, and the CI job "Minimum Go
  version" builds and vets with exactly that Go.
- **Oldest macOS:** the release builds with `go-version: stable`, so a new Go
  release can raise the oldest macOS that the binaries run on. Go's linker
  stamps that version into each macOS binary as `minos`. Go 1.27 stamps 13.0,
  which is macOS 13 Ventura. Before each release, check the version. With the
  latest Go release installed, this command shows it in Go's linker source:
  `grep -n 'macOS *= *macVersionFlag' "$(go env GOROOT)/src/cmd/link/internal/ld/macho.go"`.
  On a Mac, `otool -l age-plugin-rypt | grep -A4 LC_BUILD_VERSION` shows the
  `minos` line of a built macOS binary, such as one from a dry run's
  `release-files` artifact. If the version changed, update `MACOS_MINIMUM` in
  `scripts/homebrew_formula.py` to Homebrew's name for that macOS (such as
  `sonoma` for macOS 14), and the macOS versions in the README's Installation
  section and in the CHANGELOG.
- **Weekly audit:** the CI workflow runs
  [govulncheck](https://go.dev/doc/tutorial/govulncheck) every week, on
  pushes to `main`, on pull requests, and before each release (the release
  workflow runs CI first). It reports the advisories, in the dependencies
  and in the Go standard library, whose vulnerable code the plugin can reach;
  update the module, or build the release with the fixed Go. GitHub disables
  scheduled workflows in a public repository after 60 days without activity.
  If the weekly run stops, re-enable the CI workflow in the Actions tab.

## Checking a release

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify age-plugin-rypt-v0.2.0-darwin-arm64.tar.gz \
  --repo x6c-co/age-plugin-rypt \
  --signer-workflow x6c-co/age-plugin-rypt/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.0 \
  --deny-self-hosted-runners
```

On a Mac, `codesign --display --verbose=2 age-plugin-rypt` should show
`Authority=Developer ID Application: …` and a `Timestamp`.
