#!/bin/sh
set -eu

check_profiles=false
if [ "${1:-}" = --check-profiles ]; then
    check_profiles=true
    shift
fi
if [ "$#" -ne 1 ]; then
    echo 'Usage: sign_macos.sh [--check-profiles] STAGING_APP' >&2
    exit 2
fi
input_bundle=$1
if [ ! -d "$input_bundle/Contents/Helpers/QuartermasterBackend.app" ]; then
    echo 'The staging app must contain QuartermasterBackend.app.' >&2
    exit 1
fi
if [ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]; then
    repository=$BUILD_WORKSPACE_DIRECTORY
else
    repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fi
selection=$(uv run --offline --no-project python "$repository/scripts/signing_identity.py" select)
read -r team certificate_sha1 certificate_sha256 <<EOF
$selection
EOF
destination="$repository/target/macos/signed"
mkdir -p "$destination"
temporary=$(mktemp -d "$destination/sign.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
bundle="$temporary/Quartermaster.app"
/usr/bin/ditto "$input_bundle" "$bundle"
chmod -R u+w "$bundle"
backend="$bundle/Contents/Helpers/QuartermasterBackend.app"

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
            "$repository/target/macos/provisioning/apps/Quartermaster.app/Contents/embedded.provisionprofile" \
            "$repository/target/macos/provisioning/apps/QuartermasterBackend.app/Contents/embedded.provisionprofile" \
            "$repository/target/macos/signed/Quartermaster.app/Contents/embedded.provisionprofile" \
            "$repository/target/macos/signed/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app/Contents/embedded.provisionprofile"
    fi
    expired=false
    for profile in "$@"; do
        [ -f "$profile" ] || continue
        /usr/bin/security cms -D -i "$profile" > "$temporary/profile.plist" 2>/dev/null || continue
        actual=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$temporary/profile.plist")
        [ "$actual" = "$team.$profile_identifier" ] || continue
        expiration=$(/usr/bin/plutil -extract ExpirationDate raw -o - "$temporary/profile.plist")
        expiry=$(/bin/date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$expiration" '+%s')
        if [ "$expiry" -le "$(date '+%s')" ]; then expired=true; continue; fi
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
    if [ "$expired" = true ]; then
        echo "Provisioning profiles for $profile_identifier have expired. Run just provision, then just build-signed." >&2
    else
        echo "No valid provisioning profile for $profile_identifier and the configured certificate. Run just provision, then just build-signed." >&2
    fi
    if [ -n "$profile_override" ]; then
        echo 'Update or unset the explicit QM_FRONTEND_PROFILE / QM_BACKEND_PROFILE override after provisioning.' >&2
    fi
    return 1
}
for role in frontend backend; do
    if [ "$role" = frontend ]; then
        app=$bundle
        group="$team.dev.quartermaster.phase0"
        profile_override=${QM_FRONTEND_PROFILE:-}
        template="$repository"/macos/Quartermaster/Quartermaster.entitlements
    else
        app=$backend
        group="$team.dev.quartermaster.cache.debug"
        profile_override=${QM_BACKEND_PROFILE:-}
        template="$repository"/macos/Quartermaster/Backend.entitlements
    fi
    identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
    copy_profile "$identifier" "$group" "$profile_override" "$app/Contents/embedded.provisionprofile"
    entitlements="$temporary/$role.entitlements"
    cp "$template" "$entitlements"
    /usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 $group" "$entitlements"
    /usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string $team.$identifier" "$entitlements"
    /usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string $team" "$entitlements"
done
if [ "$check_profiles" = true ]; then exit 0; fi
/usr/bin/codesign --force --options runtime --timestamp=none --sign "$certificate_sha1" --entitlements "$temporary/backend.entitlements" "$backend"
/usr/bin/codesign --force --options runtime --timestamp=none --sign "$certificate_sha1" --entitlements "$temporary/frontend.entitlements" "$bundle"
uv run --offline --no-project python "$repository/scripts/signing_identity.py" verify "$certificate_sha256" "$backend" "$bundle"
for role in frontend backend; do
    if [ "$role" = frontend ]; then
        app=$bundle
        group="$team.dev.quartermaster.phase0"
    else
        app=$backend
        group="$team.dev.quartermaster.cache.debug"
    fi
    /usr/bin/codesign --display --entitlements - --xml "$app" > "$temporary/signed-entitlements.plist" 2>/dev/null
    groups=$(/usr/bin/plutil -extract keychain-access-groups json -o - "$temporary/signed-entitlements.plist")
    if [ "$groups" != "[\"$group\"]" ]; then
        echo "Signed $role must have exactly the Keychain access group $group." >&2
        exit 1
    fi
done
rm -rf "$destination/Quartermaster.app"
mv "$bundle" "$destination/Quartermaster.app"
printf '%s\n' "$destination/Quartermaster.app"
