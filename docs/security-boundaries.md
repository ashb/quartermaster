# Rust credential boundaries

`KdfParameters::validate` produces opaque `ValidatedKdfParameters` under
broker-owned resource ceilings. Only that type can derive a `VaultIdentity`,
which hides rbw's identity and keys. `EncryptedCredential` validates ciphertext
structure and requires a MAC; it is not evidence of successful authentication.
`VaultKeys` hides the raw rbw keys and binds its handle to the owning approval
authority. A grant from a separately constructed session cannot use that handle,
even with the same public key and IDs.

The plaintext path is:

```text
broker-verified frozen request + exact ciphertext digest
    → PendingApproval
    → trusted host authentication event + enrolled-key signature
    → ApprovedRequest
    → VaultKeys::decrypt
    → ApprovedCredentialData
    → consuming dispatch to the bound request's trusted sink
```

Approval and plaintext types have private fields and no public unchecked
constructors, `Clone`, serialization, dereference or secret formatting APIs.
`VaultKeys::decrypt` consumes approval, checks ciphertext binding and verifies its
MAC before returning an opaque plaintext holder. `dispatch` consumes that holder,
rechecks validity and exposes a temporary byte slice with the immutable binding.
Plaintext is zeroized when the holder leaves scope, including on error or unwind.
The sink is trusted code: it must obey the request/recipient binding and can copy
bytes once supplied them. Rust types cannot protect against malicious broker code.

An `ApprovalSession` pins a broker-enrolled P-256 public key and owns session and
policy state. Pending approvals use random nonces and domain-separated signatures
binding session, policy, exact request digest, ciphertext digest and authentication
offset. Consuming pending state prevents reuse; a replacement request or restarted
session has a fresh nonce. Policy generations invalidate old grants even if the
policy later changes back. Session revocation or dropping its owner invalidates
outstanding work.

Waiting has a 120-second deadline. A trusted host callback records successful
fresh OS authentication using `Instant`; the 30-second dispatch window starts
there. Proof delivery and decryption never refresh it. Dispatch checks expiry
again after decryption. Its final check admits the operation; revocation after
that point cannot retract a request already being sent. An uncertain dispatch
must not be retried using the consumed capability.

## Integration contract

This is a reusable approval verifier, not an operational broker or a policy
engine. Public host APIs assume trusted callers. In particular:

- Enrolment must verify the actual presence-protected hardware key and its peer;
  never accept an incoming public key as the trust root.
- `begin` receives the broker's frozen canonical request digest. It must cover
  principal, action, resource, recipient/session and provider identity. A guest's
  digest or authorization decision is not trusted input.
- `record_authentication` must run at the trusted OS-success event. It cannot be
  an IPC method for a UI/guest boolean or a timestamp received later. Calling it
  alone supplies no signature and cannot mint approval.
- Hard constraints and policy must admit the exact operation before `begin`.
  Unknown operations and policy errors must fail closed. This crate does not yet
  parse operations, verify processes or evaluate policy.
- The broker must own each pending request and remove it when handed to approval,
  cancelled, disconnected or expired. Shutdown/sleep/lock/logout must revoke the
  relevant session. No incoming wire representation constructs an approved type.
- Credential use and any permitted release must go through a sink accepting the
  approved capability. A future read grant needs its own constrained capability;
  an unlocked provider is never blanket authority.
