# Vault account snapshot and credential selection

Status: accepted.

Use `rbw`'s public protocol and crypto APIs behind Quartermaster-owned types.
Quartermaster does not edit the source vault or use `rbw` database persistence.
Verify and pin the authenticated account UUID and email without selecting an item.
An empty vault can be enrolled. Signed tool settings select each personal Login
item by UUID and field independently; missing or ambiguous selections fail only
the operation using that item.

Login passwords and named hidden fields are supported by the provider; the
development UI selects passwords. Organization items, master-password reprompt
and MFA challenges require explicit unsupported/required results.

Quartermaster owns prelogin, profile verification and refresh HTTP calls because
the pinned `rbw` APIs omit HTTP-status checks, authenticated profile identity or
rotated refresh tokens needed at those boundaries. Redirects and TLS follow the
[provider redirect decision](0002-vaultwarden-redirects.md).

Keep the master password and access token transient. The encrypted snapshot
retains the refresh token, account key material and encrypted item catalogue so
offline unlock can support later synchronization without retaining the master
password. Ordinary Keychain items contain no vault token or key bytes. Cache
unlock remains separate from authority to use the credential.

Use AES-256-GCM with a fresh random nonce to authenticate the snapshot and its
account identity, catalogue, device-key and freshness metadata together. Credential
selection checks the pinned account and authenticates the selected item's key,
name and field. A remembered
minimum sync time detects rollback within that observation. Rolling back all
local state together cannot be detected
without an independent monotonic authority. Time Machine exclusion reduces
backup exposure; encryption protects confidentiality, including against local
APFS snapshots.

A refused refresh requires reauthentication; an unavailable server preserves
the existing offline snapshot. Rotation followed by failed sync may require
reauthentication because no replacement snapshot was committed.

Compile out dependency logging because `rbw` can emit raw error bodies and SSO
session data before returning an error. Broker diagnostics use sanitized
metadata. Storage replacement and cancellation obey the
[publication contract](../security-boundaries.md#keep-authority-narrow-and-short-lived).
