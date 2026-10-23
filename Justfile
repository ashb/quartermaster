set positional-arguments

default:
    @just --list

# Download dependencies and toolchains for all targets.
fetch:
    bazelisk fetch //...

test *targets="//...":
    bazelisk test "$@"

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
            bazelisk test //crates/qm-broker:public_boundary
        fi
        scope=$(/usr/bin/uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')
        output="$repository/target/integration/$scope"
        mkdir -p "$output"
        bazelisk build //crates/qm-broker:qm_broker_test //macos/Tests:QuartermasterIntegrationTests
        execution_root=$(bazelisk info execution_root)
        executable=$(bazelisk cquery //crates/qm-broker:qm_broker_test --output=starlark --starlark:expr='providers(target)["DefaultInfo"].files_to_run.executable.path')
        install -m 755 "$execution_root/$executable" "$output/server"
        executable=$(bazelisk cquery //macos/Tests:QuartermasterIntegrationTests --output=starlark --starlark:expr='providers(target)["DefaultInfo"].files_to_run.executable.path')
        install -m 755 "$execution_root/$executable" "$output/client"
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
    bazelisk run @rules_rust//:rustfmt -- //crates/... //bins/...

check:
    prek run --all-files

# Build the normal app and bundled backend without launching them.
build:
    bazelisk build //macos:Quartermaster

# Build with the certificate selected in signing.local.toml.
build-signed:
    bazelisk run //macos:sign_development

# Issue or renew development profiles through the account configured in Xcode.
provision:
    bazelisk run //scripts:provision_development

# Start the bundled development backend; no login startup or fingerprint request.
run: build-signed
    target/macos/signed/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd restart

stop:
    target/macos/signed/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd stop
