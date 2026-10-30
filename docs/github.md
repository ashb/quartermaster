# Try the GitHub integration

The development build mediates repository, issue, pull request and Actions reads,
including logs, for configured GitHub repositories. Other REST and GraphQL
requests require an explicit opt-in and one-use approval. Quartermaster keeps
the vault token in the backend and preserves application requests.

## Enrol a credential

First [build and start the signed app](development.md#sign-and-run). Use a
dedicated development vault account.

1. Create a fine-grained GitHub token limited to your test repository, with
   **Metadata**, [**Contents**](https://docs.github.com/en/rest/repos/contents#get-a-repository-readme),
   **Issues**, **Pull requests**, **Commit statuses** and
   [**Actions**](https://docs.github.com/en/rest/actions/workflow-runs#download-workflow-run-logs)
   set to **read-only**. Grant **Issues: read and write** only if you need issue
   close/reopen. Related project summaries may need additional upstream access;
   a Quartermaster grant does not supply missing GitHub permissions.
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

Fine-grained PATs [cannot access the Checks API](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#fine-grained-personal-access-tokens-limitations).
With this token, default `gh pr view` can fail when a PR has Actions checks,
and `gh run view` cannot display check annotations; log downloads still work.
Checks require a GitHub App token with **Checks: read** or a classic PAT with
`repo` scope for private repositories. **Workflows** permission does not enable
check reads.

## Select a repository

Choose the repository by name:

```sh
QM_REPOSITORY=owner/repository
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

The app bundles a `qm` command. From the repository root, put the signed build's
commands on your shell's path:

```sh
export PATH="$PWD/target/macos/signed/Quartermaster.app/Contents/MacOS:$PATH"
```

Using the repository variable above, list issues:

```sh
qm run gh -- api --hostname github.com --method GET -H 'Accept: application/vnd.github+json' \
  "repos/$QM_REPOSITORY/issues?state=all&per_page=30" --paginate
```

`qm run gh --` starts the bundled backend if needed and passes the remaining
arguments directly to `gh` on your path. It creates a private temporary
configuration pointing at Quartermaster's socket and supplies a dummy token for
`gh`'s local authentication check. Quartermaster adds the real vault token upstream.
Your normal `gh` configuration, shell environment and `GH_HOST` remain unchanged.

The wrapper preserves standard input, output and error, and returns `gh`'s exit
status. It removes its temporary configuration after exit, failed launch or
handled interruption; SIGKILL cannot run cleanup. It leaves the shared backend
running. This configures `gh`'s HTTP client, not Git subprocesses or arbitrary
extensions with their own network clients.

The first request opens the read-access dialog with **This process** selected.
Choose **This shell** for broader reuse. Review the caller, repository, credential
and expiry, then approve with Touch ID. Unlocking the cache and establishing the
grant can use the same fingerprint. If the process lifetime cannot be verified,
only one-request approval is available.

Read an individual issue by setting its number:

```sh
QM_ISSUE=1
qm run gh -- api --hostname github.com --method GET -H 'Accept: application/vnd.github+json' \
  "repos/$QM_REPOSITORY/issues/$QM_ISSUE" --jq '.number, .title, .state'
```

## What the grant permits

Read approvals default to all recognised reads for the selected repository:
metadata/README, issues and pull requests, Actions metadata, logs and check
annotations. The review also describes related summaries, which can refer to
other repositories. Logs may contain sensitive workflow output. Writes and
unfamiliar requests still need separate approval.

**This process** covers subsequent requests from the same running execution,
including new connections; children and later invocations cannot reuse it.
**This shell** permits descendants using the same verified caller executable.
Both scopes bind the selected credential and repository for at most one hour,
ending earlier when the selected process exits or replaces its executable.
Eligible reads work without another fingerprint or the UI remaining open.
A shell grant cannot identify an individual conversation inside a shared daemon.

Access preferences list active roots, repositories and expiry. Choose **Revoke**
for one grant or **Revoke Read Access** for all grants. Backend restart or logout
also clears them. Currently, established reads remain allowed through screen lock
and wake until expiry; time asleep counts against that expiry. Lock, sleep and
session deactivation cancel pending approvals. These settings are not configurable
in the development UI yet.

Covered REST and GraphQL requests must have complete semantic analysis; an
unknown field, argument or companion prevents reuse. Default `gh` request headers
are supported. Workflow changes, PR reviews and arbitrary artifact downloads are
outside the read grant.

For logs, Quartermaster returns GitHub's presigned download URL unchanged and
relays storage requests without API credentials. `gh` follows redirects, extracts
archives and may fall back to individual job logs. Each relay allows 64 MiB of
response bytes and 120 seconds. Issued URLs remain
usable until GitHub expires them, even after a Quartermaster grant is revoked.
Client decompression and cache use are outside these limits.

## Approve another API request once

In **Settings → GitHub**, enable **Allow unfamiliar requests**, then review and approve the change. Without it, requests lacking a complete
configured read match are rejected. Enabling it does not create a read
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

For example, with this opt-in:

```sh
qm run gh -- api --hostname github.com --method GET rate_limit
```

This request uses fresh one-use approval even if an issue-read grant exists.
