#!/bin/sh
set -eu

if [ "${CODE_SIGNING_ALLOWED:-NO}" != YES ]; then
    /usr/bin/touch "$SCRIPT_OUTPUT_FILE_0"
    exit 0
fi

expected=${QM_EXPECTED_SIGNING_IDENTITY:-}
case "$expected" in
    *[!0-9A-Fa-f]*|'')
        echo 'error: Signed builds require a locally selected certificate; use just build-signed.' >&2
        exit 1
        ;;
esac
if [ "${#expected}" -ne 40 ]; then
    echo 'error: The local signing identity must be a certificate fingerprint.' >&2
    exit 1
fi

expected=$(printf '%s' "$expected" | /usr/bin/tr '[:lower:]' '[:upper:]')
actual=$(printf '%s' "${EXPANDED_CODE_SIGN_IDENTITY:-}" | /usr/bin/tr '[:lower:]' '[:upper:]')
if [ "$actual" != "$expected" ]; then
    echo 'error: Xcode selected a different signing certificate; refusing to use its private key.' >&2
    exit 1
fi

/usr/bin/touch "$SCRIPT_OUTPUT_FILE_0"
