set positional-arguments

default:
    @just --list

# Download locked dependencies for subsequent offline builds.
fetch:
    cargo fetch --locked

test:
    cargo test --locked --offline --workspace --all-features
    swift test --package-path macos/Security --scratch-path target/swift-security

fmt:
    cargo fmt --all

check: test
    cargo fmt --all --check
    cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
