set positional-arguments

default:
    @just --list

# Download locked dependencies for subsequent offline builds.
fetch:
    cargo fetch --locked

test:
    cargo test --locked --offline --workspace --all-features
    swift test --package-path macos/Security --scratch-path target/swift-security -Xswiftc -plugin-path -Xswiftc "$(dirname "$(xcrun --find swiftc)")/../lib/swift/host/plugins/testing"

# Integration tests; hardware cases require an attended fingerprint.
test-integration *args:
    #!/bin/sh
    set -eu
    umask 077
    test_case=transport
    build_only=false
    prepared=
    while [ "$#" -gt 0 ]; do
        case "$1" in
            transport|hardware|frontend-exit) test_case=$1 ;;
            --build-only) build_only=true ;;
            --run-prepared) shift; prepared=$1 ;;
            *) echo "Usage: just test-integration [transport|hardware|frontend-exit] [--build-only | --run-prepared DIRECTORY]" >&2; exit 2 ;;
        esac
        shift
    done
    repository=$PWD
    fixture=platform::macos::ipc::context::tests::swift_client_fixture
    cleanup_fixture=platform::macos::ipc::context::tests::cleanup_swift_client_fixture
    code_requirement() {
        /usr/bin/codesign --display --verbose=4 "$1" 2> "$output/signature.txt"
        hash=$(awk -F= '/^CDHash=/ {print $2}' "$output/signature.txt")
        [ -n "$hash" ] || return 1
        printf 'cdhash H"%s"' "$hash"
    }
    if [ -z "$prepared" ]; then
        if [ "$build_only" = false ]; then
            cargo test --locked --offline --workspace --test '*'
        fi
        scope=$(/usr/bin/uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')
        output="$repository/target/integration/$scope"
        mkdir -p "$output"
        cargo test --locked --offline -p qm-broker --lib --no-run --message-format=json > "$output/rust-build.json"
        executable=$(jq -sr '[.[] | select(.executable != null and .profile.test) | .executable] | if length == 1 then .[0] else error("Expected one Rust test executable") end' "$output/rust-build.json")
        install -m 755 "$executable" "$output/server"
        swift build --package-path macos --scratch-path target/swift-app --product QuartermasterIntegrationTests
        binaries=$(swift build --package-path macos --scratch-path target/swift-app --show-bin-path)
        install -m 755 "$binaries/QuartermasterIntegrationTests" "$output/client"
        client="$output/client"
        server="$output/server"
        approval_group=
        cache_group=
        if [ "$test_case" != transport ]; then
            selection=$(uv run --offline --no-project python scripts/signing_identity.py select)
            read -r team certificate_sha1 certificate_sha256 <<EOF
    $selection
    EOF
            normal="$repository/target/macos/signed/Quartermaster.app"
            for role in client server; do
                if [ "$role" = client ]; then
                    profile="$normal/Contents/embedded.provisionprofile"
                    group="$team.dev.quartermaster.phase0"
                    title='Quartermaster Security Test'
                    approval_group=$group
                else
                    profile="$normal/Contents/Helpers/QuartermasterBackend.app/Contents/embedded.provisionprofile"
                    group="$team.dev.quartermaster.cache.debug"
                    title='Quartermaster Security Test Backend'
                    cache_group=$group
                fi
                [ -f "$profile" ] || { echo 'Run just build-signed to supply the selected provisioning profiles.' >&2; exit 1; }
                /usr/bin/security cms -D -i "$profile" > "$output/profile.plist"
                identifier=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$output/profile.plist")
                case "$identifier" in "$team".*) ;; *) echo 'Provisioning profile has a different team.' >&2; exit 1 ;; esac
                identifier=${identifier#"$team".}
                app="$output/$role.app"
                mkdir -p "$app/Contents/MacOS"
                mv "$output/$role" "$app/Contents/MacOS/$role"
                cp "$profile" "$app/Contents/embedded.provisionprofile"
                jq -n --arg identifier "$identifier" --arg role "$role" --arg title "$title" \
                    '{CFBundleIdentifier:$identifier, CFBundleExecutable:$role, CFBundleName:$title, CFBundleDisplayName:$title, CFBundlePackageType:"APPL", CFBundleVersion:"1", NSLocalAuthenticationUsageDescription:"Test disposable Quartermaster keys."}' \
                    | /usr/bin/plutil -convert xml1 -o "$app/Contents/Info.plist" -
                jq -n --arg identifier "$team.$identifier" --arg team "$team" --arg group "$group" \
                    '{"com.apple.application-identifier":$identifier, "com.apple.developer.team-identifier":$team, "keychain-access-groups":[$group]}' \
                    | /usr/bin/plutil -convert xml1 -o "$output/$role-entitlements.plist" -
                /usr/bin/codesign --force --options runtime --timestamp=none --sign "$certificate_sha1" \
                    --entitlements "$output/$role-entitlements.plist" "$app"
                uv run --offline --no-project python scripts/signing_identity.py verify "$certificate_sha256" "$app"
                if [ "$role" = client ]; then client="$app/Contents/MacOS/client"; else server="$app/Contents/MacOS/server"; fi
            done
        fi
        jq -n --arg scope "$scope" --arg test_case "$test_case" --arg client "$client" --arg server "$server" \
            --arg approval "$approval_group" --arg cache "$cache_group" --arg result "$output/passed" \
            --arg client_requirement "$(code_requirement "$client")" --arg server_requirement "$(code_requirement "$server")" \
            '{scope:$scope, case:$test_case, service:("dev.quartermaster.test.ipc."+$scope), client:$client, server:$server, approvalGroup:$approval, cacheGroup:$cache, resultPath:$result, clientRequirement:$client_requirement, serverRequirement:$server_requirement}' \
            > "$output/config.json"
    else
        output=$(realpath "$prepared")
    fi
    if [ "$build_only" = true ]; then
        printf 'Prepared without authentication. Run: just test-integration --run-prepared %s\n' "$output"
        exit 0
    fi
    config="$output/config.json"
    scope=$(jq -er '.scope | select(test("^[a-f0-9]{32}$"))' "$config")
    [ "$output" = "$repository/target/integration/$scope" ]
    service=$(jq -er --arg scope "$scope" '.service | select(. == "dev.quartermaster.test.ipc."+$scope)' "$config")
    test_case=$(jq -er '.case | select(. == "transport" or . == "hardware" or . == "frontend-exit")' "$config")
    client=$(jq -er '.client' "$config")
    server=$(jq -er '.server' "$config")
    [ "$(code_requirement "$client")" = "$(jq -r '.clientRequirement' "$config")" ]
    [ "$(code_requirement "$server")" = "$(jq -r '.serverRequirement' "$config")" ]
    [ "$(jq -r '.resultPath' "$config")" = "$output/passed" ]
    domain="gui/$(id -u)"
    destination="$domain/$service"
    registered=false
    cleanup() {
        status=$?
        trap - EXIT HUP INT TERM
        set +e
        if [ "$registered" = true ]; then
            /bin/launchctl bootout "$destination" || status=1
            if /bin/launchctl print "$destination" > /dev/null 2>&1; then
                echo 'Test service remains registered.' >&2
                status=1
            fi
        fi
        if [ "$test_case" != transport ]; then
            "$client" "$config" --cleanup > "$output/client-cleanup.log" 2>&1 || status=1
            QM_NATIVE_IPC_TEST_CONFIG="$config" "$server" --ignored --exact "$cleanup_fixture" --nocapture > "$output/server-cleanup.log" 2>&1 || status=1
            rm -f "$HOME/Library/Application Support/Quartermaster/Development/cache-key.$scope.lock"
        fi
        printf 'Integration logs: %s\n' "$output"
        exit "$status"
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' HUP TERM
    rm -f "$output/passed"
    jq -n --arg service "$service" --arg server "$server" --arg fixture "$fixture" --arg config "$config" --arg log "$output/server.log" \
        '{Label:$service, ProgramArguments:[$server,"--ignored","--exact",$fixture,"--nocapture"], EnvironmentVariables:{QM_NATIVE_IPC_TEST_CONFIG:$config}, MachServices:{($service):true}, RunAtLoad:true, ProcessType:"Interactive", StandardOutPath:$log, StandardErrorPath:$log}' \
        | /usr/bin/plutil -convert xml1 -o "$output/agent.plist" -
    /bin/launchctl bootstrap "$domain" "$output/agent.plist"
    registered=true
    if ! "$client" "$config" > "$output/client.log" 2>&1; then
        cat "$output/client.log" "$output/server.log" >&2
        exit 1
    fi
    attempt=0
    until [ -f "$output/passed" ]; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 200 ]; then cat "$output/server.log" >&2; exit 1; fi
        sleep 0.05
    done
    printf 'Passed %s: Swift client and Rust adapter assertions\n' "$test_case"

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
    target/macos/signed/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd restart

stop:
    target/macos/signed/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd stop

[private]
_mac signing:
    #!/bin/sh
    set -eu
    signing=$1
    case "$signing" in unsigned|signed) ;; *) exit 2 ;; esac
    repository=$PWD
    if [ "$signing" = signed ]; then
        selection=$(uv run --offline --no-project python scripts/signing_identity.py select)
        read -r team certificate_sha1 certificate_sha256 <<EOF
    $selection
    EOF
    fi
    cargo build --locked --offline -p quartermasterd --target aarch64-apple-darwin --target-dir "$repository/target"
    swift build --package-path macos --scratch-path target/swift-app --product Quartermaster
    binaries=$(swift build --package-path macos --scratch-path target/swift-app --show-bin-path)
    destination="$repository/target/macos/$signing"
    mkdir -p "$destination"
    temporary=$(mktemp -d "$destination/build.XXXXXX")
    trap 'rm -rf "$temporary"' EXIT
    bundle="$temporary/Quartermaster.app"
    backend="$bundle/Contents/Helpers/QuartermasterBackend.app"
    mkdir -p "$bundle/Contents/MacOS" "$backend/Contents/MacOS"
    install -m 755 "$binaries/Quartermaster" "$bundle/Contents/MacOS/Quartermaster"
    install -m 755 target/aarch64-apple-darwin/debug/quartermasterd "$backend/Contents/MacOS/quartermasterd"
    install -m 644 macos/Quartermaster/Info.plist "$bundle/Contents/Info.plist"
    install -m 644 macos/Quartermaster/Backend-Info.plist "$backend/Contents/Info.plist"
    if [ "$signing" = signed ]; then
        copy_profile() {
            profile_identifier=$1
            profile_group=$2
            profile_override=$3
            profile_destination=$4
            if [ -n "$profile_override" ]; then
                set -- "$profile_override"
            else
                set -- "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/"*.provisionprofile \
                    "$HOME/Library/MobileDevice/Provisioning Profiles/"*.provisionprofile \
                    "$repository/target/macos/signed/Quartermaster.app/Contents/embedded.provisionprofile" \
                    "$repository/target/macos/signed/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/embedded.provisionprofile" \
                    "$repository/target/xcode/Build/Products/Debug/Quartermaster.app/Contents/embedded.provisionprofile" \
                    "$repository/target/xcode/Build/Products/Debug/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/embedded.provisionprofile"
            fi
            for profile in "$@"; do
                [ -f "$profile" ] || continue
                /usr/bin/security cms -D -i "$profile" > "$temporary/profile.plist" 2>/dev/null || continue
                actual=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$temporary/profile.plist")
                [ "$actual" = "$team.$profile_identifier" ] || continue
                expiration=$(/usr/bin/plutil -extract ExpirationDate raw -o - "$temporary/profile.plist")
                expiry=$(/bin/date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$expiration" '+%s')
                [ "$expiry" -gt "$(date '+%s')" ] || continue
                certificate_matches=false
                profile_index=0
                while /usr/bin/plutil -extract "DeveloperCertificates.$profile_index" raw -o "$temporary/certificate.b64" "$temporary/profile.plist" 2>/dev/null; do
                    /usr/bin/base64 --decode -i "$temporary/certificate.b64" -o "$temporary/certificate.der"
                    fingerprint=$(/usr/bin/shasum -a 256 "$temporary/certificate.der")
                    fingerprint=$(printf '%s' "${fingerprint%% *}" | /usr/bin/tr '[:lower:]' '[:upper:]')
                    if [ "$fingerprint" = "$certificate_sha256" ]; then certificate_matches=true; break; fi
                    profile_index=$((profile_index + 1))
                done
                [ "$certificate_matches" = true ] || continue
                profile_index=0
                while allowed=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:keychain-access-groups:$profile_index" "$temporary/profile.plist" 2>/dev/null); do
                    case "$profile_group" in $allowed) install -m 644 "$profile" "$profile_destination"; return ;; esac
                    profile_index=$((profile_index + 1))
                done
            done
            echo "No valid provisioning profile for $profile_identifier and the configured certificate." >&2
            return 1
        }
        for role in frontend backend; do
            if [ "$role" = frontend ]; then
                app=$bundle
                group="$team.dev.quartermaster.phase0"
                profile_override=${QM_FRONTEND_PROFILE:-}
                template=macos/Quartermaster/Quartermaster.entitlements
            else
                app=$backend
                group="$team.dev.quartermaster.cache.debug"
                profile_override=${QM_BACKEND_PROFILE:-}
                template=macos/Quartermaster/Backend.entitlements
            fi
            identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
            copy_profile "$identifier" "$group" "$profile_override" "$app/Contents/embedded.provisionprofile"
            entitlements="$temporary/$role.entitlements"
            cp "$template" "$entitlements"
            /usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 $group" "$entitlements"
            /usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string $team.$identifier" "$entitlements"
            /usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string $team" "$entitlements"
        done
        /usr/bin/codesign --force --options runtime --timestamp=none --sign "$certificate_sha1" --entitlements "$temporary/backend.entitlements" "$backend"
        /usr/bin/codesign --force --options runtime --timestamp=none --sign "$certificate_sha1" --entitlements "$temporary/frontend.entitlements" "$bundle"
        uv run --offline --no-project python scripts/signing_identity.py verify "$certificate_sha256" "$backend" "$bundle"
    fi
    rm -rf "$destination/Quartermaster.app"
    mv "$bundle" "$destination/Quartermaster.app"
    printf '%s\n' "$destination/Quartermaster.app"
