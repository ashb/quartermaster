#!/bin/sh
set -eu

revision=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
modified=false
if ! git diff --quiet HEAD --; then modified=true; fi
printf 'STABLE_QM_REVISION %s\nSTABLE_QM_MODIFIED %s\n' "$revision" "$modified"
printf 'QM_BUILD_TIMESTAMP %s\n' "$(date -u +%s)"
