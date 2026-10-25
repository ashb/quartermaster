# Architectural security principles

This document defines Quartermaster's required security boundaries.
Changes to these boundaries require an explicit decision recorded here, with
the reason and security consequences, before implementation weakens them.

## Component ownership

| Component | Owns | Boundary |
|---|---|---|
| Rust broker | Verified principals and sessions, request validation and preservation, hard constraints, approval verification and dispatch | Constructs authority from verified facts; never accepts a caller's identity, classification or approval as authoritative |
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

The broker validates, bounds and freezes the complete request. Its binding must
cover the principal, session, request, destination, credential, effective policy
version and any claimed resource scope. Transports cannot replace these facts
with an assertion that a request was already checked.

## Approve what the user can understand

The UI must faithfully present the immutable request it signs. It independently
checks the request digest, challenge binding and supported presentation format.
Keep the process tree, exact permitted command and labelled repository visible
without expanding Details. Distinguish verified scope from advisory context.
For GitHub, the proposed contract below permits either a verified explanation or
complete request inspection with its effects explicitly unverified. If the UI
cannot present the complete request within its supported bounds, it must refuse
approval. Operation classification and policy decisions remain in Rust; the UI
does not maintain a second authorization policy.

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

## GitHub requests: matching and approval (proposed)

The development broker implements the request-preserving, one-use approval path
below when the host enables unverified requests. Live-provider and hardware
acceptance remain. Repository grants follow the requested name; Quartermaster
never rewrites a named URL into a numeric-ID URL. The
[repository contract](github.md#repository-identity) describes metadata checks
and name reuse between verification and dispatch. This contract replaces
rejection based solely on an unfamiliar
GitHub API shape with fresh approval for that request. GitHub can add APIs
without requiring Quartermaster to understand their effects before a user can
authorize their use.

### When a request needs a fingerprint

Quartermaster checks host restrictions and matches the request against
host-controlled patterns. A pattern may describe a read operation, a repository,
particular inputs or another explicitly supported condition. The fallback uses
the host-selected GitHub HTTPS origin and the profile's explicitly selected
credential for per-request approvals. That binding is independent of read-grant
bindings and is frozen before authentication. Neither the client nor an upstream
permission error can silently select a different credential or destination.

| Result | Behaviour |
|---|---|
| An applicable denial or failed mandatory restriction | Reject; an approval cannot override it. |
| A complete match authorizes use without approval | Proceed within the rule's principal, credential, resource, grant and lifetime limits. |
| A match requires approval | Request a fresh fingerprint for this request. |
| No complete match, including unfamiliar fields or API shapes | Request a fresh fingerprint for this request. |
| Invalid policy or policy evaluation failure | Reject; a failure is not an unmatched request. |

Every condition of an automatic allow rule must be verified. Matching a path prefix,
HTTP method or part of a GraphQL operation is insufficient when other inputs
could change its effect or scope. Rules must account for all forwarded inputs;
an unfamiliar field cannot be silently ignored to obtain an automatic match.
A supported denial predicate established from the request rejects the whole
request, even when companion inputs are unfamiliar. For GraphQL, that includes
any forbidden effect established in the selected operation: adding an unknown
sibling field cannot turn it into an approvable request. Mandatory approval
predicates likewise survive unfamiliar companion input. These restrictions
take precedence over an allow rule.

Host restrictions distinguish predicates over verified request facts from
properties that require positive proof. A configured requirement to prove
repository confinement denies when that proof is unavailable; ordinary lack of
API knowledge alone requires approval. A missing schema is not a policy-engine
failure and cannot create permission.

For example, a grant might permit a client's issue reads in one repository.
A request that satisfies that pattern uses the existing grant. A new endpoint,
or an additional parameter whose effect the rule does not cover, instead gets
the normal fingerprint dialog. Its extra input is preserved for review and
dispatch. Approving it does not extend the read grant or teach a new allow rule.

### What the user approves

For an unfamiliar request, the dialog identifies the verified caller, GitHub
destination and selected provider/account/item/field. It states that the effects
are unverified and makes the complete method, target, query, application headers
and body available for inspection. Request content is untrusted data, rendered
as inert text or an explicit byte view; formatting must not hide control
characters, duplicate fields or omitted content. A digest or truncated summary
cannot stand in for inspection of the complete request.

Repository scope is stated only when verified. An unfamiliar request cannot
borrow a repository-limited grant merely because its URL mentions that
repository. If scope is unverified, the dialog must say that this is one use of
the selected credential without a verified repository restriction. It cannot
claim confinement to the repository from an existing read grant. Explicit host
restrictions still apply, including any requirement to prove resource scope.

Approval covers only the captured request, verified caller/session, destination,
selected credential and effective policy. It requires the existing request-bound
signature, fresh authentication, original dispatch deadline and atomic single
use. It creates no reusable grant. The UI receives credential identity, never
the injected token or decrypted vault material. Authentication and cancellation
retain the boundaries above; unlocking the cache supplies no approval.

### Forward the request the client supplied

Quartermaster preserves the method, target path and query, body bytes and
application header names, values and order, including repeated fields.
It must not rebuild a GitHub request from a classified operation, reserialize
JSON, discard unfamiliar input, substitute a different API version or add API
defaults. Parsed facts and friendly descriptions are views of the captured
request; they do not become a replacement payload.

For the proposed HTTP/1.1 transport, the permitted changes are limited to:

- Replacing a single caller `Authorization` field, or inserting it when absent,
  with authentication from the frozen host-selected credential. Duplicate
  `Authorization` fields are rejected; a second field is never appended.
- Converting an absolute-form request target to origin-form after checking its
  scheme and authority against the selected HTTPS origin and the sole `Host`
  field. The path and query octets are unchanged. Mismatched or duplicate
  authorities deny.
- Emitting `Content-Length` from the complete frozen body when framing requires
  it, and replacing connection management with `Connection: close`. Incoming
  `Connection` and `Keep-Alive` fields are consumed locally. Only `close` and
  `keep-alive` connection options are accepted.

Conflicting or duplicate lengths, transfer encodings, trailers, proxy
authorization, `Expect` handshakes, CONNECT tunnels and protocol upgrades are outside this transport's supported framing
and are rejected before approval. In particular, a `Connection` option cannot
cause an application header to disappear. No other request fields may be added,
removed, reordered or re-encoded. These limits concern HTTP transport, not
recognition of GitHub APIs; see [HTTP forwarding](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1)
and [HTTP/1.1 framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

The approval binds a versioned description of these changes, the effective
application request and the selected credential identity and digest. The secret
authentication value stays in Rust. The final dispatch checks this binding;
it cannot choose new transformations or substitute a later body, target,
application header or credential.

An unfamiliar request is treated as potentially mutating even if it uses GET.
One approval permits one dispatch, without automatic retry after uncertain
delivery. A redirect is a different request and needs its own authorization;
the original approval does not cover it. Existing grants can cover recognized
redirected reads only after checking the new request. Vaultwarden routing is
governed separately by the redirect decision below.

### GraphQL and changes to GitHub

GraphQL uses the same decision model. Parsing identifies the selected operation,
its variables, fragments, aliases and directives. Automatic rules must cover
the complete effective operation and every resource relationship on which their
scope depends. A query label or repository root alone proves neither a permitted
operation nor repository confinement. Node IDs need verified ownership when a
rule relies on that ownership.

If the operation does not match, the user can approve the complete original
document, variables, operation selection and other forwarded input once. Missing
schema knowledge prevents automatic matching, not request inspection. None of
those inputs is rewritten for dispatch.

API schemas describe request structure; they do not grant authority. The
effective policy binds pattern definitions, matching semantics and any schema
version used to determine permission. Changing any of them invalidates affected
authority, including change followed by reversion; a descriptive-only schema
update cannot broaden a match. An ordinary caller cannot install patterns by
approving a request.

The guarantee is authorization of the exact request, not proof of all its
upstream consequences. Unknown requests default to approval, but an incorrect
automatic rule can still authorize too much. Rules and their matchers remain
trusted security code. A genuinely read-only upstream credential offers a
separate barrier against writes where used; a credential role label alone
does not attest those upstream permissions.

A denial covers the request facts and effects its predicate can establish.
It cannot promise to recognize the same effect through every future API.
An absolute ban on an effect requires independent enforcement, such as upstream
credential permissions that exclude it. Otherwise an unfamiliar request's
effects remain explicitly unverified, even after the user approves its bytes.
Approval also cannot freeze GitHub's state, mutable resource names or changes
to the credential's upstream permissions.

## Keep authority narrow and short-lived

Approvals are request-bound, expiring and single-use. Mediated request approvals
have a 30-second dispatch window from the original successful fresh OS
authentication event. Their dispatch lifetime
starts at successful fresh OS authentication, with a separate deadline for
waiting for the user. IPC delay, credential retrieval, reconnects and retries
must never restart or extend that lifetime. Recheck authority at dispatch.

Policy returns structured `Allow`, `Deny` or `RequireApproval` decisions, with
machine-readable reasons and any user-presence requirements. `RequireApproval`
is not authorization. Policy errors and invalid decisions deny. Under the proposed
GitHub contract above, a valid policy with no complete request match requires
fresh approval; it cannot silently authorize the request. Other unsupported
services remain denied. Grants bind to the effective policy version; relevant
policy or session changes invalidate outstanding authority, even if settings
later revert.

The credential owner can authorize an eligible operation from a validated
`Allow` decision without user approval. It may issue a reusable grant scoped to
the verified principal, session, actions, resources, credential role, policy
generation and absolute expiry. Each operation must satisfy those limits;
reconnect and activity never extend them. Mandatory approval requirements still
apply. Policy authorization and verified user approval are distinct sources of
authority, and both require current authorization at final dispatch admission.

Reusable read grants live only in the Rust owner's memory. Establishing a grant
requires a fresh, signed approval of its verified caller, repository, credential
binding, scope and absolute expiry. A one-use issuance challenge belongs
to the current backend and approval session; consuming it cannot extend an
existing grant. Proof acceptance retains pending evidence. Final admission of the
initiating read installs the grant atomically; cancellation
or UI loss before admission prevents issuance. After admission, eligible reads
survive UI exit. The grant covers all instances of the verified executable running
as that OS user.
Backend restart requires fresh authorization on next use, without prompting merely
because the application launched. Configuration changes may revoke grants but
cannot create them. Expiry requires fresh approval, without silently renewing
authority. This avoids persistent revocation and grant rollback state.

A mediated-read rule selects its credential role on the host. It may select a
credential with broader upstream permissions because the broker still enforces
the exact read operation. The role does not attest upstream read-only permissions
and never grants direct credential delivery or waives mutation approval.

Keep each operation record through final admission. Accepting a proof does not
end cancellation. Cancellation and admission serialize on that record.
A cancellation that wins prevents handoff;
after admission the result is `AlreadyAdmitted`. Unknown IDs and the wrong
principal cannot receive a successful cancellation acknowledgement. An uncertain
handoff consumes its single-use authority without an automatic retry.

An authenticated UI connection can cancel only interactive operations bound to
its enrolment session. Losing that connection cancels those operations without
revoking unrelated read grants. Cache state and legitimately authorized standalone
unlock work have their own lifecycle.

Before publication, recheck the original operation generation and cache revision.
Revocation before publication admission preserves the previous files. An admitted
encrypted write may finish, but a later generation change forbids installing its
plaintext. Failed completions must release their reservations.

Provider operations freeze the enrolment, device-key pin and cache revision
before native or network work. Completion must recheck the provider generation
and frozen revision before installing plaintext or publishing encrypted state.
Explicit lock, discard or account replacement invalidates older completions;
cancelling a write or closing its UI does not invalidate an independent unlock.

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

Admission must detect intervening console/session and sleep/wake changes even
when callbacks are delayed or the console is interactive again. Missing, malformed
or regressed lifecycle evidence ends the session. Record revocation before
waiting for authority serialization; later callbacks cannot restore it.

Use typed UTC timestamps for persisted sync state and monotonic deadlines for
authority. Cross-process clock samples are distinct from wire integers and valid
only within the current boot and authenticated connection; they cannot recover
authority after restart.

Read-grant and network deadlines count time asleep using a continuous monotonic
clock, so sleep combined with wall-clock rollback cannot extend authority.
Unchanged policy reloads may shorten active deadlines to the remaining absolute
UTC expiry, but never extend them.
No failure may fall back to broader credentials, simulated presence or an
unenforced route. An uncertain dispatch cannot retry with a consumed grant;
revocation cannot retract an operation already sent.

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

## Credential handoff (planned)

Tools without a mediated transport may receive a selected credential in their
environment after a separate credential-release authorization. This mode trades
request-level enforcement for compatibility. It is a host-configured mode, never
an automatic response to a failed or unfamiliar mediated request.

Authorize the verified recipient, selected provider/account/item/field and
effective policy before release. Policy may allow it, require a fingerprint or
deny it. A required approval must bind that release; a mediated read grant or
cache unlock cannot be reused as credential-release authority. The UI presents
the recipient and credential identity, never vault keys or secret values.

Once released, the tool can copy the credential or pass it to descendants.
Quartermaster cannot enforce per-request restrictions or retract those copies.
Expiration of a release grant or process exit does not expire the credential;
further limits require upstream scope, expiry or revocation. Strict profiles
that prohibit credential export continue to deny handoff.
