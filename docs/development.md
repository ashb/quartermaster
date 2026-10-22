# Development

## Build and check

The current target is an Apple Silicon Mac running macOS 26, with Xcode
Command Line Tools selected. Install Rust with rustfmt and Clippy, just, and uv with Python 3.12
or later.
The GitHub examples also need `gh`; integration tests need `jq`.

Run these from the repository root:

```sh
just build
just test
just check
```

The build prints the app bundle path. Protected-key flows require a signed
build; see below. Rust dependencies are authored in Cargo manifests and
`Cargo.lock`. `just fetch` downloads them for subsequent offline builds.

## Sign and run

Use an Apple development certificate with its private key available in Keychain.
Create `signing.local.toml` at the repository root with your ten-character Team ID
and the certificate's SHA-256 fingerprint, without spaces or colons:

```toml
[development]
team = "YOURTEAMID"
certificate_sha256 = "<64 hexadecimal characters>"
```

This file is ignored by Git. Obtain development provisioning profiles for the
UI and backend through Xcode, matching their
[UI](../macos/Quartermaster/Info.plist) and
[backend](../macos/Quartermaster/Backend-Info.plist) bundle IDs and the groups in
their [UI](../macos/Quartermaster/Quartermaster.entitlements) and
[backend](../macos/Quartermaster/Backend.entitlements) entitlements. The signing helper
searches Xcode's profile directories and the previous signed build. To select
profiles explicitly:

```sh
QM_FRONTEND_PROFILE=/path/to/frontend.provisionprofile \
QM_BACKEND_PROFILE=/path/to/backend.provisionprofile \
  just build-signed
```

Once signing is configured:

```sh
just run
open target/macos/signed/Quartermaster.app
```

`just run` builds, signs and starts the backend. Opening the app shows the
`QM [DEBUG]` menu. Starting it creates no read grant and requests no fingerprint;
enrolment and credential use can require authentication. This is a development
build, identified by the `[DEBUG BUILD. Insecure]` banner.

Quit the UI through its menu, then use `just stop` to stop the backend. It is
started for the logged-in user; login startup is not configured.

To use a vault and make real requests, follow [GitHub setup](github.md).

## Integration tests

```sh
just test-integration
```

This tests Swift/Rust IPC without a fingerprint. It requires a logged-in macOS
GUI session and Swift command-line tools.

The hardware cases use disposable keys and the normal approval dialog. Run them
when ready to authenticate, after preparing a signed app as above:

```sh
just test-integration hardware
just test-integration frontend-exit
```

The first checks cache unwrap and request signing with one fingerprint. The
second checks cleanup when the authenticated frontend exits. Logs and artefacts
are saved under `target/integration/`.

To finish building and signing before an attended test:

```sh
just test-integration hardware --build-only
just test-integration --run-prepared /path/printed/by/the/build
```

Hardware cases are separate from `just test`, whose Swift key tests use an
in-memory keychain. Passing those tests does not exercise Touch ID hardware.

## Troubleshooting

Development state lives under
`~/Library/Application Support/Quartermaster/Development/`:

| Path | Contents |
|---|---|
| `backend.log` | Backend output; check this first for startup or request failures. |
| `gh/` | Isolated GitHub CLI configuration. |
| `github.json` | Simulation/real-GitHub selection and repository configuration. |
| `vault/` | Encrypted vault cache and enrolment metadata. |

If the UI reports a disconnected or unavailable backend, quit it, run `just run`,
then reopen the signed app. Restart both after rebuilding so they come from the
same signed build.

Use **Vault status** to inspect enrolment. For an incompatible or damaged cache,
use **Discard offline cache…**, then **Enrol dedicated vault…** to rebuild it
from the vault. Discarding the local cache does not modify the source vault.

To inspect the approval key without creating one:

```sh
target/macos/signed/Quartermaster.app/Contents/MacOS/Quartermaster --approval-key-status
```

For intentional approval-key recovery, quit the UI and stop the backend before
running the same command with `--approval-key-reset`. It deletes the development
approval key and its public enrolment. Restart and enrol again afterwards.

If signing reports no valid identity or profile, check that the pinned certificate
is valid, its private key is available, and both profiles include it and allow
the required keychain groups. A signing-key permission prompt concerns build
signing, separately from the application's runtime fingerprint approvals.
