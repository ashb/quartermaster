# Public test vectors

These inputs are dummy material, retained so the credential regression tests run
from a fresh checkout. They contain no user secrets or machine-specific results.

`dummy.type2` was generated using LibreSSL 3.3.6: AES-256-CBC with PKCS7 padding,
then HMAC-SHA256 over `IV || ciphertext`. Key bytes are `00` through `3f`; IV bytes
are `00` through `0f`; plaintext is `quartermaster-dummy-canary`.

The KDF test's independent Python `hashlib`/`hmac` vector uses password
`quartermaster-dummy-master-password`, email `dummy@example.invalid` and one
PBKDF2-HMAC-SHA256 iteration, producing a 32-byte master key. Encryption and MAC
keys are respectively `HMAC-SHA256(master, b"enc\x01")` and
`HMAC-SHA256(master, b"mac\x01")`. These costs are deliberately test-only.
