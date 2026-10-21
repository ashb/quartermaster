# Vaultwarden redirects

Status: accepted.

Use `rbw` 1.15.0's normal HTTP redirect behaviour for Vaultwarden authentication
and synchronization. Follow a configured server's 307 response, including the
method and body preservation required by that status. The configured server's
redirect destinations are trusted routing decisions. Keep the HTTP client's
normal TLS verification and sensitive-header handling.

A separate cross-origin redirect prohibition would reject routing chosen by the
configured server. No provider fork or custom redirect restriction is needed.

Account and item identity checks still apply to the resulting vault data.
This decision covers the Vaultwarden provider; GitHub archive handling has its
own destination and authorization requirements.
