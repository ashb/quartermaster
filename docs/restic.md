# Restic

`qm run restic -- …` releases a vault login item's password to the configured
Restic process after Touch ID approval. Restic receives the password; QM cannot
restrict its subsequent operations or retract copies.

Open **Settings → Tools → Restic**. Choose the password
item by name and the absolute path to the native executable. For Nix, use
`bin/.restic-wrapped`. Save the settings. This version requires an online vault
and a local repository.

For a disposable repository:

```sh
qm run restic -- --repo /tmp/qm-restic-demo init
qm run restic -- --repo /tmp/qm-restic-demo backup /path/to/test-data
qm run restic -- --repo /tmp/qm-restic-demo restore latest --target /tmp/qm-restic-restored
```

Each invocation requires a new password-release approval, which also unlocks
the vault when needed. Password overrides,
stdin input and remote repositories are unsupported. GitHub's selected item and
read grants are independent of Restic.
