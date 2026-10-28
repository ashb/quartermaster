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

The private Rust credential owner contains provider, cryptographic, persistence
and credential-bearing transport access. Executable orchestration uses its public
service facade; raw provider types are not an application authorization boundary.
Private constructors distinguish parsed data, verified identity, valid ciphertext
and verified authorization. Credential-use and release APIs require the appropriate
capability and keep raw providers and plaintext behind that boundary.

Single-use capabilities must be consumed, without unchecked constructors, cloning
or deserialization that recreate them. Recheck expiry, policy and revocation at
use. Types prevent accidental misuse, not deliberately malicious broker code.

## Settings authority

Rust owns the approved settings revision, vault selection and UI approval-key pin
as one record in its exact Data Protection Keychain group, without file-backed
authority. Editable cache metadata selects neither policy nor enrolment.
The record uses `AfterFirstUnlockThisDeviceOnly` without a biometric ACL: the OS
enforces group access, while the backend enforces signed settings approval.

Only an authenticated UI may register a key into an unconfigured record. Settings
changes require a fresh, settings-domain signature binding the complete previous
and proposed records, revision, session, nonce and authentication timestamp. Swift
independently validates those bindings and presents the change as inert escaped
bytes. Settings publication creates no runtime grants or general API authority.

Every configured settings record must retain its signature. Verify it against the
enrolled frontend approval key before trusting the record, including after restart.
The key requires Touch ID for signing; verification needs only its public key and
does not prompt. The signature must cover the complete effective settings,
including backend-resolved values. Rust may prepare drafts but must not publish
or trust unsigned changes. An unsigned bootstrap record may pin the approval key
but grants no settings or provider authority.

Recognised older settings formats produce an inactive migration candidate, never
an empty configured state. Preserve the source and its revision until the user
reviews and signs either the complete import or a disabled replacement with no
selected provider. Bind the source format and digest into either review, and
reject publication if the source changes. Discarding settings retains encrypted
cache files and keys and must work without opening the old cache. Until either
choice is published, ordinary settings edits remain blocked. Later, Cancel,
expiry and restart preserve the pending migration; a signed resolution loads
normally without another migration. Unknown or damaged formats fail explicitly rather
than falling back to defaults or discovering authority from cache files.

Saving reviewed repository names may perform fixed GitHub metadata GETs using
the selected credential, after an authenticated protected-key operation. This
internal-read policy permits each frozen name once, under the save's original
deadline and cancellation, session, provider and cache checks. Redirects and
mismatched names fail. Swift must verify the resolved proposal preserves the
reviewed draft except for those identities before signing the complete record;
partial lookup results never become active settings.

Enrolment verification seals an inactive cache slot and retains its verified
snapshot only in Rust. Approval selects its exact binding, device-key identity
and cache revision. Cancellation, expiry, connection loss or a conflicting
provider generation prevents selection and releases pending plaintext. Importing
a previous selection freezes its slot, binding and key identity, rejects cache
substitution and requires authenticated unwrap. Orphan cache files cannot select
an enrolment or initiate a settings import.
Opening settings or reviewing drafts never arms authentication; the user chooses
Save Changes before Touch ID authorizes publication.

Publication consumes a single-use admission. Authority is suspended before the
protected record is replaced outside the authority mutex. Uncertain persistence
fails closed; recovery reloads protected state rather than replaying the proof.
The user can cancel before admission; cancellation cannot undo an already admitted
publication. Locking and revoking access remain unprompted reductions.

## Authenticate facts before assigning authority

Authenticate both IPC peers before enrolment or sensitive operations. Verify
the running process through OS identity, including process generation where
available; a PID, executable name, same-user socket ownership or client-supplied
field is insufficient. A verified interpreter does not authenticate its script
or package; interpreted workloads need independently established narrow authority.
Displayed ancestry and command arguments provide context and never grant permission.

An explicitly approved process root may scope reusable reads to verified
descendants of that execution. Retain the caller's verified executable restriction;
root membership cannot approve writes or authenticate an interpreter's script.
Bind the root to its uid, kernel process unique identity and exec generation in
the current backend session. Same-image exec ends that root lifetime. PID, start
time, executable hash, terminal name and working directory cannot substitute.

Use bounded native parent verification independently of the displayed tree. Each
edge must match the current parent PID, process unique identity and parent exec
generation recorded at fork. Stop at the approved root; unreadable ancestors
above it need not be inspected. Reparenting, missing evidence or a changed edge
prevents reuse. A socket peer's retained audit identity must remain current after
request capture and at admission; never adopt a replacement as the old caller.

Bracket native watch registration and admission with matching process queries.
Exec/exit notifications invalidate permanently; synchronous generation checks
detect replacement before delayed notifications arrive. A failed or lost monitor
cannot be recreated to revive authority. Unsupported native queries, malformed
results and late validation fail closed to per-use approval, subject to policy.
The private macOS process ABI is a capability requirement, not a fallback to PID
matching on other systems.

Native admission is the common observation point of two matching bounded
leaf-to-root collections, conditional on completing validation and consuming the
bound authority under broker serialization. Process facts are not locked until
network delivery: a transition after that admission may race with an admitted
send and prevents later reuse. Do not cache successful membership as permission
for a later dispatch or let provider/UI waits separate validation from consumption.

Deliberate descriptor sharing and request relaying are outside this local scope.
A Unix stream peer token identifies a sampled socket owner, not the writer of
each byte. Reject observed peer changes without claiming to prevent cooperation
by an authorised process. Shared-daemon conversation attribution requires separate
verified provenance; process ancestry alone cannot supply it.

The broker validates, bounds and freezes the complete request. Its binding must
cover the principal, session, request, destination, credential, effective policy
version and any claimed resource scope. Transports cannot replace these facts
with an assertion that a request was already checked.

## Approve what the user can understand

The UI faithfully presents the immutable request and independently checks its
digest, challenge binding and supported format. Keep the process tree, exact
observed command and clearly labelled repository name visible without expanding
Details when the request has one understood named target. A displayed name is
request context, not proof of confinement or authority. GitHub approval uses a
verified explanation or complete request inspection with effects explicitly
unverified.
If the complete request cannot be presented within supported bounds, refuse
approval. Classification and policy remain in Rust, without a second UI policy.

Only one approval may be armed for user presence at a time. The UI owns the
biometric-protected approval key; the broker receives its enrolled public key and
request-bound proof. Enrolment must authenticate the key-holding component and
establish the required key protection; a supplied public key alone proves neither.
UI success, a policy result or an authentication boolean cannot replace required
proof. A signature proves key use, not faithful presentation: the UI remains trusted.

The UI may transfer its fresh OS-authenticated `LAContext` over mutually
authenticated NSXPC so the Rust owner can open its own protected cache. Native
context handles remain confined to their owning queue and connection generation.
The context grants neither Keychain-group access nor application write authority;
a required write still needs a separate request-bound, single-use signature.

An explicit vault unlock binds the approved settings revision, complete provider
selection and authenticated UI session before Touch ID. Cancellation, expiry,
disconnect, host lock or a changed selection prevents later installation of the
decrypted snapshot. Unlocking creates no API grant or settings authority. Sync
uses ordinary provider access after the authentication context has been released.

An authenticated context can remain reusable until invalidated; its reuse-duration
property controls recent device-unlock reuse, not its lifetime. Create a fresh
context for each approval, enforce the original authentication deadline at use,
and invalidate both holders when the operation ends. The context does not attest
the fingerprint's time or the user's intent; freshness and faithful presentation
remain responsibilities of the trusted UI. See
[Apple's context reuse model](https://developer.apple.com/videos/play/wwdc2022/10108/?time=361).

Freeze the full provider selection and operation before authentication, then
compare the authenticated cache to that selection after opening it. Bind the
actual credential digest, original nonce and original authentication event to
the final challenge. The UI must compare the entire challenge with its frozen
presentation before signing with further authentication UI forbidden. Context
transfer and cache work cannot restart either approval deadline. Release and
invalidate the backend context after required signing/unwrap work, rejection,
cancellation or connection loss; never reuse it for another write.

## GitHub requests: matching and approval (proposed)

When the host enables unfamiliar requests, an unknown GitHub API shape requires
fresh approval of that request. Repository grants follow the requested name;
Quartermaster never rewrites a named URL into a numeric-ID URL. The
[repository contract](github.md#repository-identity) describes metadata checks
and name reuse between verification and dispatch.

### When a request needs a fingerprint

Match host-controlled patterns against verified request facts after mandatory
restrictions. Per-request approval freezes the host-selected GitHub HTTPS origin
and profile credential independently of read-grant bindings. Neither the client
nor an upstream permission error can substitute a credential or destination.

| Result | Behaviour |
|---|---|
| An applicable denial or failed mandatory restriction | Reject; an approval cannot override it. |
| A complete match authorizes use without approval | Proceed within the rule's principal, credential, resource, grant and lifetime limits. |
| A match requires approval | Request a fresh fingerprint for this request. |
| No complete match, including unfamiliar fields or API shapes | Request a fresh fingerprint for this request. |
| Invalid policy or policy evaluation failure | Reject; a failure is not an unmatched request. |

Automatic allow rules must verify every condition and cover all forwarded inputs;
a path prefix, HTTP method or recognized GraphQL field cannot hide other effects
or scope. A supported denial rejects the whole request even with unfamiliar
companion inputs, including unknown GraphQL siblings. Mandatory approval
predicates also survive unfamiliar input. Both take precedence over allow rules.

Host restrictions distinguish predicates over verified request facts from
properties that require positive proof. A configured requirement to prove
repository confinement denies when that proof is unavailable; ordinary lack of
API knowledge alone requires approval. A missing schema is not a policy-engine
failure and cannot create permission.

### What the user approves

For unfamiliar requests, keep the verified caller, GitHub request summary and a
clear warning that the request is not fully understood visible. Details contains
the destination, selected provider/account/item/field and complete method,
target, query, application headers and body. Render untrusted content as inert
text or explicit bytes without hiding control characters, duplicates or omissions.
The summary may be shortened;
the complete request must remain inspectable before approval.

Display repository names independently of numeric identity pins; a missing pin
alone is not a user-facing warning. Show the action once, avoid repeating it as
an effect, and retain any additional known actions. Only claim repository
confinement when verified: a displayed name cannot borrow a read grant or satisfy
a mandatory scope restriction. Unknown or multiple repository targets must not
be presented as one understood repository. Reusable grants show their extent and
expiry; per-request approval creates none.

Approval follows the request binding above and [authority lifecycle](#keep-authority-narrow-and-short-lived).
It creates no reusable grant, extends none and installs no rule. The UI receives
credential identity only.

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
authorization, `Expect` handshakes, CONNECT tunnels and protocol upgrades are
rejected before approval. In particular, a `Connection` option cannot
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

GraphQL rules cover the complete selected operation, including variables,
fragments, aliases, directives and every resource relationship supporting scope.
A query label or repository root proves neither permission nor confinement;
node IDs need verified ownership when a rule relies on it. Unmatched requests
retain the complete original document, variables, operation selection and other
forwarded input for one-use approval. Missing schemas prevent automatic matching,
not inspection.

API schemas describe request structure; they do not grant authority. The
effective policy binds pattern definitions, matching semantics and any schema
version used to determine permission. Changing any of them invalidates affected
authority, including change followed by reversion; a descriptive-only schema
update cannot broaden a match. An ordinary caller cannot install patterns by
approving a request.

Exact-request approval does not prove upstream consequences. Rules and matchers
remain trusted security code; denials cover only effects their predicates can
establish. An absolute ban needs independent enforcement, such as genuinely
read-only upstream permissions, which a credential role label cannot attest.
Approval cannot freeze upstream state, mutable names or credential permissions,
and unfamiliar effects remain unverified after approval.

## Keep authority narrow and short-lived

Approvals are request-bound, expiring and single-use. Mediated request approvals
have a 30-second dispatch window from the original successful fresh OS
authentication event, separate from the deadline for waiting for the user.
IPC delay, credential retrieval, reconnects and retries never restart or extend
that lifetime. Recheck authority at dispatch.

Policy returns structured `Allow`, `Deny` or `RequireApproval` decisions, with
machine-readable reasons and any user-presence requirements. `RequireApproval`
is not authorization. Policy errors and invalid decisions deny; unfamiliar GitHub
requests follow the contract above, while other unsupported services deny.
Grants bind the effective policy version; relevant policy or session changes
invalidate outstanding authority even if settings later revert.

The owner may authorize eligible operations or issue reusable grants from a valid
`Allow`, scoped to verified principal, session, actions, resources, credential role,
policy generation and absolute expiry. Each use must satisfy those limits;
reconnection or activity cannot extend them or waive mandatory approval. Policy
authorization and user approval are distinct; both must remain current at admission.

Reusable read grants live only in Rust memory and require fresh, signed approval
of their verified caller, repository, credential binding, scope and absolute expiry.
A one-use issuance challenge belongs to the current backend and approval session;
consuming it cannot extend an existing grant. Proof acceptance remains pending
until the initiating read's final admission atomically installs the grant.
Cancellation or UI loss before admission prevents issuance; eligible reads then
survive UI exit. Within the bound session, the grant covers all instances of the
verified executable running as that OS user. Configuration can revoke grants,
never create them. Expiry or backend restart requires fresh approval on next use,
without silent renewal or prompting merely because the application launched.

A mediated-read rule selects its credential role on the host. It may select a
credential with broader upstream permissions because the broker still enforces
the exact read operation. The role does not attest upstream read-only permissions
and never grants direct credential delivery or waives mutation approval.

Keep each operation record through final admission: accepting proof does not end
cancellation. Cancellation and admission serialize on that record; cancellation
that wins prevents handoff, while cancellation after admission returns
`AlreadyAdmitted`. Unknown IDs and the wrong principal cannot receive a successful
acknowledgement. An uncertain handoff consumes its single-use authority without
an automatic retry.

An authenticated UI may cancel only interactive operations bound to its enrolment
session. UI loss cancels those operations, not unrelated read grants or independently
authorized cache unlocks.

Provider operations freeze enrolment, device-key pin and cache revision before
native or network work. Recheck the original operation/provider generation and
revision before publication or plaintext installation. Lock, discard or account
replacement invalidates older completions; cancelling a write or closing its UI
does not invalidate an independent unlock. Revocation before publication admission
preserves previous files. An admitted encrypted write may finish, but a later
generation change forbids plaintext installation. Failures release reservations.

Cancellation, disconnect, expiry and session termination must discard affected
pending work. Host policy determines which scoped grants survive screen lock,
sleep or session deactivation, independently of required write approval. The
development policy retains the already-unlocked cache and preserves reads only
until their original expiry, but cancels pending approvals and provider work and
invalidates native contexts. Waking or unlocking cannot restore an approval or
extend a grant. Logout and backend restart clear cached secrets and transient
authority. Clients cannot select more permissive lifetimes; lifecycle choices
must bind the effective policy and invalidate affected authority on change,
including change followed by reversion.

Admission must detect intervening console/session and sleep/wake changes even
when callbacks are delayed or the console is interactive again. Missing, malformed
or regressed lifecycle evidence ends the session. Record revocation before
waiting for authority serialization; later callbacks cannot restore it.

Use typed UTC timestamps for persisted sync state and monotonic deadlines for
authority. Cross-process clock samples are distinct from wire integers and valid
only within the current boot and authenticated connection; they cannot recover
authority after restart.

Read-grant and network deadlines use a continuous monotonic clock, including sleep;
wall-clock rollback cannot extend authority. Unchanged policy reloads may shorten
deadlines to remaining absolute UTC expiry, never extend them. Failures cannot fall
back to broader credentials, simulated presence or an unenforced route. Uncertain
dispatch cannot retry with consumed authority; revocation cannot retract sent work.

## Contain credentials and key lifecycle

Every credential path, including reads, requires constrained authority; validity
or cache unlock alone grants none. Plaintext stays in the trusted bound sink and
is zeroized when its holder drops.

The frontend must never decrypt the cache or receive its symmetric key, derived
vault keys or decrypted credentials, even with an authenticated `LAContext`. Rust
owns unwrap and credential use; IPC exports neither keys nor plaintext. Transient
UI handling of the user-entered enrolment password grants no backend-secret access.

OS-enforced Data Protection Keychain groups separate the roles. Signed development
UI has only `TEAM.dev.quartermaster.phase0`; backend has only
`TEAM.dev.quartermaster.cache.debug`. Its persistent, device-bound, non-exportable
Secure Enclave key wraps the cache key. Private-key unwrap requires
`privateKeyUsage`, `biometryCurrentSet` and `WhenUnlockedThisDeviceOnly`.
Authentication cannot confer the other entitlement.
The UI holds its separate approval key and public enrolment marker.

Both processes are unsandboxed under one OS user: the UI can read, alter or delete
cache ciphertext and metadata. Confidentiality depends on protected keys and
authenticated encryption, not file permissions.

Approval keys persist across launches and rebuilds. Missing or substituted keys
need explicit recovery; lookup errors cannot silently create replacements.
Confirmed cache-key loss or invalid authenticated data requires discarding and
resyncing the disposable cache, with reauthentication when needed. Cancellation
is not corruption and must not discard it.

The configured Vaultwarden server controls redirect routing under the accepted
[redirect decision](decisions/0002-vaultwarden-redirects.md): normal `rbw` behaviour,
including 307 method/body preservation, TLS validation and sensitive-header
handling. Validate the resulting account and selected item before accepting a snapshot.

## Development changes distribution trust, not authorization

Local or ad-hoc signing does not waive OS protected-key requirements or authorize
disabled checks. A debug warning discloses distribution trust, not weaker security.

Debug and production peers must reject each other in both directions, using
verified identities and separate service and storage namespaces. A peer's
self-declared build mode is insufficient. Development builds using real
credentials must preserve biometric protection, request binding, credential
isolation, expiry and fail-closed behaviour. Simulated authentication belongs only
in isolated tests with dummy data, never as a runtime fallback for real secrets.

The signed development artefacts use hardened runtime without `get-task-allow`,
DYLD injection or library-validation exceptions; plain build and test outputs are
not thereby qualified. Only the development service currently starts; rejection
of production startup does not qualify production peer isolation.

Each role's entitlement template must contain only its own Keychain group, with
no additional permissions. Unit tests enforce this contract; signing must also
verify each finished app claims exactly its expected group before publishing it.

Signing authority is part of the trusted build and distribution boundary. An
authority permitted to sign backend-entitled code can create another executable
with backend access. These checks prevent accidental permission changes; they do
not restrict an actor able to bypass the build and sign code directly. This
limitation applies to development and production signing.

## Mediated host services

Strict guest profiles keep reusable credentials and broad signing authority on
the host. Guest files, environments, mounts, headers and responses must contain
no real PAT, vault key, master password, refresh token or provider session.
Providers expose only selected, authorized bindings; no unmediated vault agent,
generic decrypt service or arbitrary secret-retrieval endpoint is available.

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
queues, resource bounds and revocation.

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

Authenticate cache contents and metadata together: configured account, selected
item/field/role, device key and freshness. Unverified headers cannot supply identity.
Check resource limits before KDF or decryption. Refresh cannot change selection or
regress its sync checkpoint. Use private, symlink-safe storage and atomic replacement.

Apply and verify Time Machine exclusion after every replacement; it cannot prevent APFS
snapshots, so encryption protects confidentiality. A local checkpoint cannot detect
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

Security claims require tests through the claimed boundary. Mock authentication,
dummy upstreams and skipped hardware tests do not qualify hardware, live providers
or releases. Installed-client, guest-carrier and Docker/Compose claims require
complete-path tests and recorded versions. Carrier admission, provider-session
expiry, policy failures and every accepted permission need executable negative
coverage; local probes do not establish release compatibility.
Keychain isolation requires attended OS checks that each signed role receives
`errSecMissingEntitlement` for the other's group. Unit tests establish neither
that OS boundary nor signing-key isolation.

## Credential handoff (planned)

Host-configured credential handoff may authorize an unmediated tool to receive
a selected credential in its environment, trading request enforcement for
compatibility. A failed or unfamiliar mediated request never triggers it automatically.

Authorize the verified recipient, selected provider/account/item/field and
effective policy before release. Policy may allow it, require a fingerprint or
deny it. A required approval must bind that release; a mediated read grant or
cache unlock cannot be reused as credential-release authority. The UI presents
the recipient and credential identity, never vault keys or secret values.

Recipients can copy credentials or pass them to descendants. Quartermaster cannot
restrict subsequent requests or retract copies; release-grant expiry and process
exit do not expire credentials. Further limits need upstream scope, expiry or
revocation. Strict profiles prohibiting export deny handoff.
