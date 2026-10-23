# Development

## Build and check

The current target is an Apple Silicon Mac running macOS 26, with full Xcode
selected. Install Bazelisk, just, uv with Python 3.12 or later, and prek. The
GitHub examples also need `gh`; integration tests need `jq`.

Select Xcode and restart Bazel after installing or switching Xcode:

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
bazelisk shutdown
```

Command Line Tools alone are insufficient. If Swift tests cannot find Xcode's
testing frameworks, select Xcode this way rather than setting only `DEVELOPER_DIR`.

Run these from the repository root:

```sh
just build
just test
just check
```

The unsigned app is `bazel-bin/macos/Quartermaster.app`. Running the protected-key
flows requires a signed build; see below. `just fmt` applies Rust formatting,
and `just check` checks Rust formatting, Clippy, Swift formatting and BUILD files.
To run only Rust tests, use `just test //crates/... //bins/...`.

Bazel is the build and test system. Edit Cargo manifests for Rust dependencies,
update `Cargo.lock`, then run `bazelisk run //:gazelle` after dependency or source
changes. Review the generated BUILD changes before committing. `just fetch`
downloads dependencies and toolchains ahead of a build.

## Sign and run

Use an Apple development certificate with its private key available in Keychain.
Create `signing.local.toml` at the repository root with your ten-character Team ID
and the certificate's SHA-256 fingerprint, without spaces or colons:

```toml
[development]
team = "YOURTEAMID"
certificate_sha256 = "<64 hexadecimal characters>"
```

This file is ignored by Git. Add your Apple account in Xcode's Settings → Accounts,
then prepare profiles for the configured certificate:

```sh
just provision
just build-signed
```

`just provision` generates a disposable Xcode project from the app's bundle IDs
and entitlement files, then builds two stub apps to let Xcode issue the profiles.
Xcode manages signing for these disposable stubs and may create a development
certificate or request account or signing-key authorization. Provisioning succeeds
only if both resulting profiles authorize the certificate pinned in
`signing.local.toml`; the real app always uses that exact certificate. The project
and stub apps stay under `target/macos/provisioning/`; Bazel continues to build the
real app. No Xcode project needs maintaining.

Free Personal Team profiles expire after seven days. Rerun `just provision` after
expiry, or after changing the certificate, team, bundle IDs or entitlements, then
rebuild the signed app. Renewing profiles does not require deleting retained
Keychain keys. The signing helper searches Xcode's profile directories, the stub
apps and the previous signed build. To select profiles explicitly:

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
GUI session and full Xcode.

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

If signing reports no valid identity, check that the pinned certificate is valid
and its private key is available. For missing or expired profiles, run
`just provision` and rebuild; update or unset any explicit profile overrides.
A signing-key permission prompt concerns build signing, separately from the
application's runtime fingerprint approvals.
