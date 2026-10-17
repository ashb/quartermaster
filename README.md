# Quartermaster: a developer-tooling focused credential provider.

Quartermaster is tool for macOS that manages access to credentials, focused on developer workflows, and giving tools scoped access to do what they need.

It is not a password manager and it does not store credentials itself; instead it delegates that responsibility to a purpose built tool, initially BitWarden or VaultWarden.

## Why this project exists

I had been using 1Password and `op`, particularly the plugin to integrate with GitHub's `gh` cli tool, meaning that access to the cli would require fingerprint auth once every 5-10 minutes, and no credentials were stored unencrypted on disk, which I generally liked.

However a few things mean I'm not happy with that approach anymore

Most importantly, 1Password has given money to the Omarchy project, and I cannot in good conscience use 1Password anymore now they fund Hate and right-wing views. If this is not an issue for you, this project is not for you.

Secondly the `op` tool was "all or nothing". Either you had credentials (or the 5 min cache was still valid) or you don't. I would like something that allows tools to read GH Issues of public repos without repeated prompts, but ask before closing one, or before reading issues on a private repo.

Thirdly, you don't get much context about what process is asking for credentials: "Ghostty wants to access the CLI"? Great, I've got 12 tabs, so which one am I actually allowing access? What else might get access once it's unlocked.

## Current status

Quartermaster provides authenticated credential parsing, bounded key derivation
and consuming approval capabilities for a credential-owning broker.

Use `just test` for the Rust suite and `just check` for tests, formatting and
Clippy. Dependencies are locked; `just fetch` prepares the local offline cache.
