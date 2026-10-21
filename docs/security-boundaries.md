# Architectural security principles

This document defines Quartermaster's required security boundaries.
Changes to these boundaries require an explicit decision recorded here, with
the reason and security consequences, before implementation weakens them.

## Component ownership

| Component | Owns | Boundary |
|---|---|---|
| Rust broker | Verified principals and sessions, request parsing and canonicalization, hard constraints, approval verification and dispatch | Constructs authority from verified facts; never accepts a caller's identity, classification or approval as authoritative |
| Swift approval UI and native security module | Faithful request presentation, OS authentication and the biometric-protected approval key | Signs the frozen request it presents; cannot grant authority beyond the broker's constraints |
| Policy engine | Declarative rules over broker-verified principal, session, action, resource and context | May restrict authority; cannot bypass Rust checks or mint approval capabilities |
| Credential providers | Provider authentication, retrieval and encrypted cache handling behind private interfaces | An unlocked provider or valid credential is not permission to use it |
| Trusted dispatch adapters | Credential use for the exact approved operation and destination | Require a bound capability; never expose a general secret-retrieval interface to clients |
| Client and guest transports | Carry bounded requests and responses | Cannot select trusted identities, providers, host sessions or enforcement routes |
| Host bridge | Host-selected VM/session binding and bounded transport | No vault-wide access or credential-provider authority |
| Separate Docker worker | Docker transport and approved path translation | No credential-provider access; never bypasses Sockguard |
| Sockguard | Final Docker-specific authorization | Every admitted Docker operation must pass its enforcement; no raw-daemon fallback |

## Make accidental bypass difficult

The application credential owner is the private `qm-broker` service. Its public
facade accepts service locations and returns status metadata; snapshots, key
holders, enrolment verifiers, persistence and credential-bearing transports
remain inside the owner. The executable handles process orchestration without
direct access to provider or cryptographic APIs. `qm-providers` is a trusted
low-level dependency, not an authorization boundary for application callers.

Rust types and module boundaries must make the safe path the ordinary path.
Private constructors distinguish parsed data, verified identity, valid ciphertext
and verified authorization. Credential-use and release APIs must require the
appropriate authorization capability, rather than relying on callers to remember a
separate check. Keep raw provider types and plaintext access behind those APIs.

Use consuming capabilities for single-use authority; do not expose unchecked
constructors, cloning or deserialization that can recreate it. Runtime checks
remain necessary for expiry, policy changes and revocation. A well-typed value
is not proof that its permission is still current. These boundaries prevent
accidental misuse; they cannot protect against deliberately malicious broker code.

## Authenticate facts before assigning authority

Authenticate both IPC peers before enrolment or sensitive operations. Verify
the running process through OS identity, including process generation where
available; a PID, executable name or client-supplied field is insufficient.
Process ancestry and command arguments are advisory context and must be labelled
accordingly. They cannot establish permission.

The broker parses, bounds and freezes the canonical request. Its binding must
cover the principal, session, operation, resource, destination, credential and
effective policy version as applicable. Transports cannot replace these facts
with an assertion that a request was already checked.

## Approve what the user can understand

The UI must present the security-relevant meaning of the immutable request it
signs. It independently checks the request digest, challenge binding and supported
presentation format. If it cannot explain the operation or a field that affects
its authority, it must refuse approval. Operation classification and policy
decisions remain in Rust; the UI does not maintain a second authorization policy.

Only one approval may be armed for user presence at a time. The UI owns the
biometric-protected approval key; the broker receives its enrolled public key and
request-bound proof. Enrolment must authenticate the key-holding component and
establish the required key protection; a supplied public key alone proves neither.
When approval is required, a UI success message, policy result or authentication
boolean is never a substitute for that proof. Conversely, a valid signature
proves key use, not faithful presentation: the UI remains trusted code.

The UI may transfer its fresh OS-authenticated `LAContext` over mutually
authenticated NSXPC so the Rust owner can open its own protected cache. Native
context handles remain confined to their owning queue and connection generation;
they never contain application-level write authority. The owner must still verify
a separate request-bound, single-use approval signature before a required write.
Cache keys, vault keys and decrypted credential material do not cross into the UI.

Freeze the full provider selection and operation before authentication, then
compare the authenticated cache to that selection after opening it. Bind the
actual credential digest, original nonce and original authentication event to
the final challenge. The UI must compare the entire challenge with its frozen
presentation before signing with further authentication UI forbidden. Context
transfer and cache work cannot restart either approval deadline. Release and
invalidate the backend context after required signing/unwrap work, rejection,
cancellation or connection loss; never reuse it for another write.

## Keep authority narrow and short-lived

Approvals are request-bound, expiring and single-use. Mediated request approvals
have a 30-second dispatch window from the original successful fresh OS
authentication event. Their dispatch lifetime
starts at successful fresh OS authentication, with a separate deadline for
waiting for the user. IPC delay, credential retrieval, reconnects and retries
must never restart or extend that lifetime. Recheck authority at dispatch.

Policy returns structured `Allow`, `Deny` or `RequireApproval` decisions, with
machine-readable reasons and any user-presence requirements. `RequireApproval`
is not authorization. Policy errors, invalid decisions and unknown operations
fail closed. Grants bind to the effective policy version; relevant policy or
session changes invalidate outstanding authority, even if settings later revert.

The credential owner can authorize an eligible operation from a validated
`Allow` decision without user approval. It may issue a reusable grant scoped to
the verified principal, session, actions, resources, credential role, policy
generation, absolute expiry and budget. Each operation must satisfy those limits;
reconnect and activity never extend them. Mandatory approval requirements still
apply. Policy authorization and verified user approval are distinct sources of
authority, and both require current authorization at final dispatch admission.

Reusable read grants live only in the Rust owner's memory. Establishing a grant
requires a fresh, signed approval of its verified caller, repository, credential
binding, scope, absolute expiry and budget. A one-use issuance challenge belongs
to the current backend and approval session; consuming it cannot replenish an
existing grant. Proof acceptance retains pending evidence. Final admission of the
initiating read installs the grant and debits its first use atomically; cancellation
or UI loss before admission prevents issuance. After admission, eligible reads
survive UI exit. The grant covers all instances of the verified executable running
as that OS user, sharing its budget; the dialog must state this scope.
Backend restart requires fresh authorization on next use, without prompting merely
because the application launched. Configuration changes may revoke grants but
cannot create them. Expiry and exhaustion require fresh approval, without silently
renewing authority. This avoids persistent revocation and budget rollback state.

A mediated-read rule selects its credential role on the host. It may select a
credential with broader upstream permissions because the broker still enforces
the exact read operation. The role does not attest upstream read-only permissions
and never grants direct credential delivery or waives mutation approval.

Keep each operation record through final admission. Accepting a proof does not
end cancellation. Cancellation and admission serialize on that record, together
with any shared grant-budget debit. A cancellation that wins prevents handoff;
after admission the result is `AlreadyAdmitted`. Unknown IDs and the wrong
principal cannot receive a successful cancellation acknowledgement. An uncertain
handoff consumes its budget and authority without an automatic retry.

An authenticated UI connection can cancel only interactive operations bound to
its enrolment session. Losing that connection cancels those operations without
revoking unrelated read grants. Cache state and legitimately authorized standalone
unlock work have their own lifecycle.

Provider operations freeze the enrolment, device-key pin and cache revision
before native or network work. Completion must recheck the provider generation
and frozen revision before installing plaintext or publishing encrypted state.
Explicit lock, discard or account replacement invalidates older completions;
cancelling a write or closing its UI does not invalidate an independent unlock.
Refresh cannot change the selected binding or move its sync checkpoint backward.

Cancellation, disconnect, expiry and session termination must discard affected
pending work. Host policy determines which scoped grants survive screen lock,
sleep or session deactivation, independently of required write approval. The
development policy retains the already-unlocked cache and preserves authorized
reads only until their original expiry, while cancelling pending approvals and provider work and
invalidating native authentication contexts. Waking or unlocking cannot restore
an old approval or replenish a grant. Logout and backend restart clear cached
secrets and transient authority. Lifecycle policy belongs to the host; clients
cannot select a more permissive lifetime. Configuration for choosing different
lifetimes by operation or risk remains future work.
When those choices become configurable, they must participate in the effective
policy binding and invalidate affected authority on change, including change
followed by reversion.
Read-grant and network deadlines count time asleep using a continuous monotonic
clock, so sleep combined with wall-clock rollback cannot extend authority.
Unchanged policy reloads may shorten active deadlines to the remaining absolute
UTC expiry, but never extend them or replenish their budgets.
No failure may fall back to broader credentials, simulated presence or an
unenforced route. An uncertain dispatch cannot retry with a consumed grant;
revocation cannot retract an operation already sent.

Use typed UTC timestamps for persisted sync state and monotonic deadlines for
authority. Cross-process clock samples are distinct from wire integers and valid
only within the current boot and authenticated connection; they cannot recover
authority after restart.

## Contain credentials and key lifecycle

Credential validity and permission to use it are separate capabilities. Every
credential path, including reads, must pass through the appropriate constrained
authority. Plaintext is limited to the trusted bound sink, kept out of logs,
errors and client-visible metadata, and zeroized when its holder is dropped.

Approval keys persist across normal launches and rebuilds. Missing or substituted
enrolled keys require explicit recovery; lookup errors must not silently create
a replacement. Encrypted provider caches are disposable: confirmed key loss or
invalid authenticated cache data requires discarding the cache and resyncing,
with reauthentication when needed. User cancellation is not evidence of cache
corruption and must not discard it.

The configured Vaultwarden server controls its redirect routing. Follow its
redirects using `rbw`'s normal HTTP behaviour, including 307 method/body
preservation, with ordinary TLS validation and sensitive-header handling.
The user explicitly accepted this trust in the
[Vaultwarden redirect decision](decisions/0002-vaultwarden-redirects.md).
Validate the resulting account and selected item before accepting a snapshot.

## Development changes distribution trust, not authorization

Development builds may use locally trusted or ad-hoc signing instead of an
identity trusted for production distribution. OS requirements for protected-key
operations still apply. The visible debug warning means that this is not a
production-signed build; it does not permit disabled security checks.

Debug and production peers must reject each other in both directions, using
verified identities and separate service and storage namespaces. A peer's
self-declared build mode is insufficient. Development builds using real
credentials must preserve biometric protection, request binding, credential
isolation, expiry and fail-closed behaviour. Simulated authentication belongs only
in isolated tests with dummy data, never as a runtime fallback for real secrets.

Development code is still trusted with any plaintext it is authorized to use.
Local pairing cannot protect against replacing the entire development bundle,
and unattended signing does not make arbitrary development code trustworthy.

## Mediated host services

Strict guest profiles keep reusable credentials and broad signing authority on
the host. Guest files, environments, mounts, headers and responses must contain
no real PAT, vault key, master password, refresh token or provider session.
Providers expose only selected, authorized bindings; no unmediated vault agent,
generic decrypt service or arbitrary secret-retrieval endpoint is available.

Verify local IPC peers through OS identity and process generation. Same-user
ownership and socket permissions are not enough. A verified interpreter binary
does not authenticate the script or package it runs; interpreted workloads need
independently established narrow authority.

Git HTTP, GitHub API and SSH signing are separate authorization surfaces. A
strict no-write profile cannot expose a general push-capable SSH key or agent.
An SSH signature proves key use, not repository confinement or fetch-versus-push.
Filtered guest agents enumerate and sign only host-allowlisted public-key
fingerprints. Reject add, remove and load operations and unsupported extensions;
do not expose the unrestricted host agent socket.

The host fixes the Docker upstream and Sockguard profile. Every admitted Engine
operation passes Sockguard; there is no raw-daemon fallback, alternate endpoint,
guest-selected owner/profile or unrestricted engine command. Session termination
revokes new work and streams without claiming to undo completed operations or
established SSH connections, or deleting unrelated engine resources.

Bound stream admission before opening multiplexed streams. Disconnect, partial
EOF, cancellation or a stalled consumer must not block unrelated work or retain
revoked authority. API/SSH and Docker carriers have separate worker processes,
queues, budgets and revocation.

Mount translation accepts only recognized bind-source fields and verified
guest/host/engine mappings. Initially allow only stable export roots. Arbitrary
child paths require race-safe engine-side resolution and leased staging; a
one-time path check is insufficient. Preserve read-only restrictions and reject
child-symlink escapes. Enforce per-project Compose ownership and visibility.

Strict Docker profiles deny port publication at creation and start until the
combined adapter/Sockguard path enforces it. Do not remove environment or mount
redaction as a compatibility fix, or redact required owner-scoped network fields
in a way that breaks the approved CLI/Compose protocol.

## Cache and diagnostic protection

The cache uses authenticated encryption and a persistent, device-bound Secure
Enclave key with OS-enforced presence. Bind the configured account, selected
item/field/role, device key and freshness state to authenticated cache contents;
unverified header metadata cannot supply identity. Check resource limits before
KDF or decryption work. Refresh cannot change the selection or regress its sync
checkpoint. Use private, symlink-safe storage and complete atomic replacement.

Apply and verify Time Machine exclusion after every replacement. That exclusion
does not protect against APFS snapshots; confidentiality depends on encryption.
Consider rollback explicitly: a local checkpoint cannot detect simultaneous
rollback of all local state without an independent authority.

Broker-managed credentials and vault keys must never appear in arguments,
client-visible metadata or guest-shared files. Keep secrets, Authorization headers
and signed download URLs out of logs, diagnostics, error strings and, where
controllable, crash dumps. Observed caller arguments may appear in the local
approval UI as escaped context; never log or persist them. Audit denial, dispatch,
confirmed and uncertain outcomes as sanitized metadata. Reusable credential
material is not stored in ordinary Keychain items for the primary Vaultwarden
setup.

## Evidence and compatibility

Security tests must exercise the boundary being claimed. Mock authentication,
dummy upstreams and skipped hardware tests do not qualify biometric hardware,
live-provider dispatch or release behaviour. Installed-client, guest-carrier and
Docker/Compose claims need tests through their complete enforcement paths and
recorded versions. Carrier admission, provider-session expiry, policy failures
and every accepted permission need executable negative coverage; a useful local
probe does not establish release compatibility.

Resource-scoped API authority requires verified mappings for numeric repository
IDs, absolute response URLs and GraphQL node/global IDs. A method or query label
alone does not prove an operation's effects or resource ownership.
