# Try the GitHub integration

The development build lists and reads issues from configured GitHub repositories.
An explicit opt-in also permits one-use approval of other REST and GraphQL
requests, preserving their application bytes. Automated tests exercise that path
against local TLS peers; live-provider and hardware acceptance remain.
Credential delivery through environment variables is not implemented yet.

## Enrol a credential

First [build and start the signed app](development.md#sign-and-run). Use a
dedicated development vault account.

1. Create a fine-grained GitHub token limited to your test repository, with
   **Issues: read-only** and **Metadata: read-only**. These cover the
   [issue reads](https://docs.github.com/en/rest/issues/issues#list-repository-issues)
   and [repository identity check](https://docs.github.com/en/rest/repos/repos#get-a-repository).
2. Put the token in a vault Login item's **password** field. The development UI
   selects this field; custom-field selection is not available in it yet.
3. Choose **Enrol dedicated vault…** from the `QM [DEBUG]` menu. Enter the server
   URL, account email, Login item UUID and master password. The item UUID can be
   omitted only when the vault contains exactly one entry, which must be a
   supported personal Login.
4. Complete enrolment and check **Vault status**. On later runs, use the existing
   enrolment; **Sync vault** refreshes it after changes in the source vault.

The development enrolment uses the role label `github-write`. It can hold the
read-only token above; the label does not give that token write permissions.

## Select a repository

Set the repository name and obtain its numeric ID. With an existing authenticated
`gh` configuration, before using Quartermaster's isolated configuration:

```sh
QM_REPOSITORY=owner/repository
QM_REPOSITORY_ID=$(gh api --hostname github.com "repos/$QM_REPOSITORY" --jq '.id')
QM_DATA="$HOME/Library/Application Support/Quartermaster/Development"
QM_GH_CONFIG="$QM_DATA/gh"
```

Replace `owner/repository`. For a public repository, you can instead read `id`
from `https://api.github.com/repos/OWNER/REPO` in a browser and assign that value
to `QM_REPOSITORY_ID`.

Starting the backend creates the data directory and isolated `gh` configuration.
Save the repository configuration with private permissions:

```sh
QM_GITHUB_CONFIG=$(mktemp "$QM_DATA/github.json.XXXXXX")
cat > "$QM_GITHUB_CONFIG" <<EOF
{
  "version": 1,
  "mode": "github",
  "repositories": [{
    "id": $QM_REPOSITORY_ID,
    "owner": "${QM_REPOSITORY%%/*}",
    "name": "${QM_REPOSITORY#*/}",
    "writes": false
  }]
}
EOF
mv "$QM_GITHUB_CONFIG" "$QM_DATA/github.json"
```

The file must belong to your user and have mode `0600`, which `mktemp` supplies.
Quartermaster verifies the repository's ID and name before reading issues.
Changing configuration does not create a grant.

### Repository identity

Repository grants follow the requested `owner/name`. Quartermaster preserves the
client URL rather than replacing the name with a numeric repository ID.
Metadata must match the configured name and ID when checked; this is a
point-in-time consistency check. If the name is reused after that check, the
request reaches whichever repository GitHub serves under that name at dispatch.

## Make a request

Using the variables above, list issues:

```sh
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET -H 'Accept: application/vnd.github+json' \
  "repos/$QM_REPOSITORY/issues?state=all&per_page=30" --paginate
```

The token in this command is a dummy value for `gh`'s local authentication check.
Quartermaster adds the actual vault token upstream. The isolated configuration
routes requests through its socket and leaves your usual `gh` configuration alone.

The first request opens the read-access dialog. Review the caller, repository,
credential and expiry, then approve with Touch ID. Unlocking the
cache and establishing the grant can use the same fingerprint.

Read an individual issue by setting its number:

```sh
QM_ISSUE=1
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET -H 'Accept: application/vnd.github+json' \
  "repos/$QM_REPOSITORY/issues/$QM_ISSUE" --jq '.number, .title, .state'
```

## What the grant permits

A grant covers the selected repository and credential for all instances of the
verified caller executable running as your OS user, for at most one hour.
Pagination and redirects require the same scope checks. Further reads work
without another fingerprint or the UI remaining open.

Choose **Revoke read access** to end existing grants. Backend restart or logout
also clears them. Currently, established reads remain allowed through screen lock
and wake until expiry; time asleep counts against that expiry. Lock, sleep and
session deactivation cancel pending approvals. These settings are not configurable
in the development UI yet.

Supported list parameters are `state` (`open`, `closed`, `all`), `per_page` (1–100),
`page` (1–10000), and one bounded `before` or `after` cursor. At most three redirects
within the configured repository are permitted. The legacy per-repository
`writes` field has no effect. Automatic matching currently requires a supported
JSON Accept header; `gh`'s wildcard default is unfamiliar input.

## Approve another API request once

Set `"approveUnverifiedRequests": true` at the top level of `github.json` to
enable the general approval path. Without it, requests lacking a complete
configured issue-read match are rejected. Enabling it does not create a read
grant or authorize a request by itself.

The dialog shows the complete effective request as inert escaped bytes, the
selected credential and any recognized effects. Its repository scope remains
unverified: approval permits one request using the credential's upstream
permissions. Only authentication and HTTP framing are replaced; application
headers, query and body are preserved. Redirects need authorization again, and
uncertain delivery is never retried automatically.

For example, with this opt-in and the isolated configuration above:

```sh
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET rate_limit
```

This request uses fresh one-use approval even if an issue-read grant exists.

## Try the approval UI without a GitHub action

Without `github.json`, the backend uses simulation mode. To explicitly select it,
save this configuration using the same private-file procedure above:

```json
{"version": 1, "mode": "simulation", "repositories": []}
```

With a dedicated vault enrolled, run:

```sh
GH_CONFIG_DIR="$HOME/Library/Application Support/Quartermaster/Development/gh" \
GH_ENTERPRISE_TOKEN=quartermaster-dummy-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.example.invalid --method PATCH \
  repos/quartermaster/demo/issues/42 --raw-field state=closed
```

This opens the approval dialog and returns a synthetic response marked
`quartermaster_local_simulation`. No request reaches GitHub. A failed real request
does not switch to simulation.
