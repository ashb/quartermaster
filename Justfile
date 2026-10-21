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
    prek run --all-files

# Build the normal app and bundled backend without launching them.
build: (_mac "unsigned")

# Build with the certificate selected in signing.local.toml.
build-signed: (_mac "signed")

# Start the bundled development backend; no login startup or fingerprint request.
run: build-signed
    target/xcode/Build/Products/Debug/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd restart

stop:
    target/xcode/Build/Products/Debug/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd stop

[private]
_mac signing:
    #!/bin/sh
    set -eu
    signing=$1
    case "$signing" in unsigned|signed) ;; *) echo 'Unknown signing mode' >&2; exit 2 ;; esac
    repository=$PWD
    if [ "$signing" = signed ]; then
        selection=$(uv run --no-project python scripts/signing_identity.py select)
        read -r team certificate_sha1 certificate_sha256 <<EOF
    $selection
    EOF
    fi
    if ! xcodebuild=$(/usr/bin/xcrun --find xcodebuild); then
        echo 'Full Xcode is required; select its developer directory.' >&2
        exit 1
    fi
    cargo build --locked --offline -p quartermasterd --target aarch64-apple-darwin --target-dir "$repository/target"
    output=xcode
    if [ "$signing" = unsigned ]; then output="$output-unsigned"; fi
    derived="$repository/target/$output"
    set -- "$xcodebuild" -project "$repository/macos/Quartermaster.xcodeproj" -scheme Quartermaster -configuration Debug -derivedDataPath "$derived"
    if [ "$signing" = signed ]; then
        set -- "$@" -allowProvisioningUpdates -allowProvisioningDeviceRegistration "DEVELOPMENT_TEAM=$team" "QM_EXPECTED_SIGNING_IDENTITY=$certificate_sha1"
    else
        set -- "$@" CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=
    fi
    "$@" build
    bundle="$derived/Build/Products/Debug/Quartermaster.app"
    if [ "$signing" = signed ]; then
        uv run --no-project python scripts/signing_identity.py verify "$certificate_sha256" "$bundle" "$bundle/Contents/Helpers/QuartermasterBackend.app"
    fi
    printf '%s\n' "$bundle"
