# Rust cache-key ownership

Status: accepted.

Rust owns cache unwrap so vault keys and decrypted credentials stay out of the
approval UI. The nested backend app has its own keychain access group; the UI's
separate group protects approval signing. Unlocking the cache does not authorize
an application operation.

The P-256 Secure Enclave key is non-exportable, bound to this device and the
current biometric enrolment. Its public-key pin detects substitution. Metadata
lookup cannot prompt for authentication; protected unwrap requires explicit user presence.
Missing or invalidated keys require recovery from the authoritative vault.

Development signing uses local identity and provisioning settings. Reboot,
profile renewal and biometric changes need lifecycle support before release.
See [security boundaries](../security-boundaries.md#contain-credentials-and-key-lifecycle).
