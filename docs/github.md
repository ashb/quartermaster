# Try the GitHub integration

The current development build lists and reads issues from configured GitHub
repositories. Other API requests, including real writes and GraphQL, are rejected.
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
Renamed or replaced repositories fail validation; update the configuration before
trying again. Changing configuration does not create a grant.

## Make a request

Using the variables above, list issues:

```sh
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET "repos/$QM_REPOSITORY/issues?state=all&per_page=30" --paginate
```

The token in this command is a dummy value for `gh`'s local authentication check.
Quartermaster adds the actual vault token upstream. The isolated configuration
routes requests through its socket and leaves your usual `gh` configuration alone.

The first request opens the read-access dialog. Review the caller, repository,
credential, expiry and request budget, then approve with Touch ID. Unlocking the
cache and establishing the grant can use the same fingerprint.

Read an individual issue by setting its number:

```sh
QM_ISSUE=1
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET "repos/$QM_REPOSITORY/issues/$QM_ISSUE" --jq '.number, .title, .state'
```

## What the grant permits

A grant covers the selected repository and credential for all instances of the
verified caller executable running as your OS user. It permits up to 100 requests,
for at most one hour. Pagination and redirects consume uses. Further reads work
without another fingerprint or the UI remaining open.

Choose **Revoke read access** to end existing grants. Backend restart or logout
also clears them. Currently, established reads remain allowed through screen lock
and wake until expiry; time asleep counts against that expiry. Lock, sleep and
session deactivation cancel pending approvals. These settings are not configurable
in the development UI yet.

Supported list parameters are `state` (`open`, `closed`, `all`), `per_page` (1–100),
`page` (1–10000), and one bounded `before` or `after` cursor. At most three redirects
within the configured repository are permitted. Setting `writes` to `true` does
not enable real writes.

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
