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
3. Open **Settings → GitHub** and enter the Login item UUID under **Token source**.
   The UUID can be omitted only when the vault contains exactly one entry, which
   must be a supported personal Login.
4. Open **Vault**, enter the server URL, account email and master password, then
   choose **Verify Vault…** and **Review Changes…**. Check the account,
   item and proposed rules, then choose **Save Changes** and approve with Touch ID. Verification alone
   does not replace the active enrolment.

Editing the server, email or Login item after verification invalidates it. Verify
the edited selection before reviewing changes; Discard Changes restores the
approved selection.

If previous settings need migration, Settings explains the change and offers
**Review Import…**. Inspect the previous vault selection and access rules, then
choose **Import and Trust** with Touch ID. Closing the review preserves the
original data. **Sync Vault** refreshes the selected cache from Vaultwarden.

The development enrolment uses the role label `github-write`. It can hold the
read-only token above; the label does not give that token write permissions.

## Select a repository

Choose the repository by name:

```sh
QM_REPOSITORY=owner/repository
QM_DATA="$HOME/Library/Application Support/Quartermaster/Development"
QM_GH_CONFIG="$QM_DATA/gh"
```

Open **Settings → GitHub**, enable GitHub mediation, and add the repository's
`owner/repository` name. Choose **Review Changes…**, inspect the proposal, then
**Save Changes** with Touch ID. Quartermaster uses the selected vault token to
verify the repository's identity before saving; no numeric ID is needed.
Failed verification leaves approved settings unchanged. Adding a repository
does not create a read grant.

Approved settings live in the backend's Data Protection Keychain group. The
backend ignores the old `github.json`; editing or replaying it cannot change
access. Runtime read grants remain in memory.

### Repository identity

Repository grants follow the requested `owner/name`. Quartermaster preserves the
client URL rather than replacing the name with a numeric repository ID.
Metadata must match the configured name and ID when checked; this is a
point-in-time consistency check. A different ID cannot use the old grant: remove
and add the name again, then save with Touch ID to select a replacement.
If the name is reused after the metadata check, the
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

The first request opens the read-access dialog. Under **Authorize for**, choose
**This shell** or **This request**. Review the caller, repository, credential and absolute
expiry, then approve with Touch ID. Unlocking the cache and establishing the grant
can use the same fingerprint. If no shell root can be verified, only one-request
approval is available.

Read an individual issue by setting its number:

```sh
QM_ISSUE=1
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET -H 'Accept: application/vnd.github+json' \
  "repos/$QM_REPOSITORY/issues/$QM_ISSUE" --jq '.number, .title, .state'
```

## What the grant permits

A grant covers issue listing and issue reads in the selected repository, using
the selected credential, for at most one hour. Only the verified caller
executable and its instances beneath the approved shell execution can reuse it.
Pagination and redirects require the same scope checks. Eligible reads work
without another fingerprint or the UI remaining open. Shell exit or exec ends
reuse; unrelated shells do not inherit the grant. A shell grant cannot identify
an individual conversation inside a shared daemon.

Access preferences list active roots, repositories and expiry. Choose **Revoke**
for one grant or **Revoke Read Access** for all grants. Backend restart or logout
also clears them. Currently, established reads remain allowed through screen lock
and wake until expiry; time asleep counts against that expiry. Lock, sleep and
session deactivation cancel pending approvals. These settings are not configurable
in the development UI yet.

Supported list parameters are `state` (`open`, `closed`, `all`), `per_page` (1–100),
`page` (1–10000), and one bounded `before` or `after` cursor. At most three redirects
within the configured repository are permitted. Automatic matching currently requires a supported
JSON Accept header; `gh`'s wildcard default is unfamiliar input.

## Approve another API request once

In **Settings → GitHub**, enable **Allow unfamiliar requests**, then review and approve the change. Without it, requests lacking a complete
configured issue-read match are rejected. Enabling it does not create a read
grant or authorize a request by itself.

The dialog shows the action, repository name when understood, command and process
tree. Additional known actions and unfamiliar inputs remain visible. Details
contains the selected credential and complete effective HTTP request as inert
escaped bytes. JSON bodies offer **Readable** and **Raw** views. Readable expands
query strings and formats the remaining fields; ambiguous or malformed bodies
stay in Raw. The displayed name does not create a repository grant: approval
covers this request only. Only authentication and HTTP framing are replaced;
application headers, query and body are preserved. Redirects need authorization
again, and uncertain delivery is never retried automatically.

For example, with this opt-in and the isolated configuration above:

```sh
GH_CONFIG_DIR="$QM_GH_CONFIG" GH_TOKEN=quartermaster-local-only GH_PROMPT_DISABLED=1 \
  gh api --hostname github.com --method GET rate_limit
```

This request uses fresh one-use approval even if an issue-read grant exists.
