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
| Sockguard | Final Docker-specific authorization | Every admitted Docker operation must pass its enforcement; no raw-daemon fallback |

## Make accidental bypass difficult

Rust types and module boundaries must make the safe path the ordinary path.
Private constructors distinguish parsed data, verified identity, valid ciphertext
and approved authority. Credential-use and release APIs must require the
appropriate approved capability, rather than relying on callers to remember a
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
A UI success message, policy result or authentication
boolean is never a substitute for that proof. Conversely, a valid signature
proves key use, not faithful presentation: the UI remains trusted code.

## Keep authority narrow and short-lived

Approvals are request-bound, expiring and single-use. Their dispatch lifetime
starts at successful fresh OS authentication, with a separate deadline for
waiting for the user. IPC delay, credential retrieval, reconnects and retries
must never restart or extend that lifetime. Recheck authority at dispatch.

Policy returns structured `Allow`, `Deny` or `RequireApproval` decisions, with
machine-readable reasons and any user-presence requirements. `RequireApproval`
is not authorization. Policy errors, invalid decisions and unknown operations
fail closed. Grants bind to the effective policy version; relevant policy or
session changes invalidate outstanding authority, even if settings later revert.

Cancellation, disconnect, expiry and session termination must discard pending
work. Sleep, lock, logout and restart must revoke the affected session authority.
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
