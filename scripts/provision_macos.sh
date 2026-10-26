#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo 'Usage: provision_macos.sh GENERATED_PROJECT_DIRECTORY' >&2
    exit 2
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
destination="$repository/target/macos/provisioning"
mkdir -p "$destination"
rm -rf "$destination/project"
/usr/bin/ditto "$1" "$destination/project"
chmod -R u+w "$destination/project"
# Xcode device registration needs a concrete run destination selected through a scheme.
for app in Quartermaster QuartermasterBackend; do
    if ! /usr/bin/xcodebuild -project "$destination/project/QuartermasterProvisioning.xcodeproj" \
        -scheme "$app" -destination "platform=macOS,arch=$(/usr/bin/uname -m)" \
        -configuration Debug -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
        "DEVELOPMENT_TEAM=$team" \
        "SYMROOT=$destination/build" "OBJROOT=$destination/intermediates" \
        "CONFIGURATION_BUILD_DIR=$destination/apps" build; then
        echo "Provisioning failed for $app. Review Xcode's error above; check the account and team in Xcode Settings > Accounts." >&2
        exit 1
    fi
    if [ ! -f "$destination/apps/$app.app/Contents/embedded.provisionprofile" ]; then
        echo "Xcode did not embed a provisioning profile for $app." >&2
        exit 1
    fi
done
temporary=$(mktemp -d "$destination/check.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
/usr/bin/ditto "$destination/apps/Quartermaster.app" "$temporary/Quartermaster.app"
mkdir -p "$temporary/Quartermaster.app/Contents/Helpers"
/usr/bin/ditto "$destination/apps/QuartermasterBackend.app" "$temporary/Quartermaster.app/Contents/Helpers/QuartermasterBackend.app"
if ! QM_FRONTEND_PROFILE="$destination/apps/Quartermaster.app/Contents/embedded.provisionprofile" \
QM_BACKEND_PROFILE="$destination/apps/QuartermasterBackend.app/Contents/embedded.provisionprofile" \
    "$repository/scripts/sign_macos.sh" --check-profiles "$temporary/Quartermaster.app"; then
    echo 'Xcode profiles must authorize the certificate pinned in signing.local.toml. Check that certificate in Xcode before retrying.' >&2
    exit 1
fi
printf 'Provisioning profiles prepared. Run just build-signed.\n'
