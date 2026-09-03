# LINE channel diagnostics: real API responses and what to tell the user

Every response below was recorded live against `api.line.me` on 2026-09-03
with production LINE Login channels in known permission states. Use this as
the source of truth when building setup-verification UI around this gem:
each state maps to a concrete, actionable message for the person configuring
the channel.

Response bodies are quoted verbatim, except that access tokens are truncated
and channel IDs are elided as `"..."` — the `error`/`error_description`/
`scope`/`message` values are the exact strings LINE returns.

## Reading a channel's permissions without any user login

A LINE Login channel's console permissions can be read server-side with only
the Channel ID + Channel Secret, before any member ever logs in:

```
POST https://api.line.me/v2/oauth/accessToken     # client_credentials
POST https://api.line.me/v2/oauth/verify          # read scope codes
POST https://api.line.me/v2/oauth/revoke          # clean up (idempotent)
```

The `scope` field of the verify response carries undocumented
channel-permission codes, mapped empirically across 30+ production channels:

| Code | Meaning | Consequence when absent |
|---|---|---|
| `P` | PROFILE | (always present on LINE Login channels) |
| `OC` | OPENID_CONNECT | No ID token; `openid` scope inert; email impossible |
| `OCE` | Email permission (approved via console application) | Login succeeds but the email claim is silently missing |
| `CM` | Observed on 2 channels; meaning unconfirmed | Treat unknown codes gracefully — parse the scope as a set |

Scope ordering is not stable (`"OC P OCE"` and `"P OC OCE"` both occur) —
always split and compare as a set, never string-match.

## Response matrix

### A. Token issuance — `POST /v2/oauth/accessToken` (client_credentials)

| State | Status | Body |
|---|---|---|
| Valid credentials | 200 | `{"access_token":"...","expires_in":2592000,"token_type":"Bearer"}` |
| Wrong secret | 400 | `{"error":"invalid_client","error_description":"invalid client_secret"}` |
| Unknown numeric channel ID | 400 | `{"error":"invalid_request","error_description":"some parameters in the wrong format"}` |
| Non-numeric channel ID | 400 | `{"error":"invalid_request","error_description":"some parameters in the wrong format"}` |

Wrong-ID and wrong-secret are distinguishable: `invalid_client` means the ID
exists and the secret is wrong; `invalid_request` means the ID itself is bad.
Issued tokens live 30 days — always revoke after probing.

### B. Permission read — `POST /v2/oauth/verify`

| State | Status | Body |
|---|---|---|
| Email permission approved | 200 | `{"client_id":"...","expires_in":2591998,"scope":"OC P OCE"}` |
| Email permission NOT applied | 200 | `{"client_id":"...","expires_in":2591998,"scope":"OC P"}` |
| PROFILE only (no OIDC; pre-OIDC-era channels) | 200 | `{"client_id":"...","expires_in":2591999,"scope":"P"}` |
| Invalid token | 400 | `{"error":"invalid_request","error_description":"access_token in invalid format"}` |
| Revoked/expired token | 400 | `{"error":"invalid_request","error_description":"access_token invalid"}` |

The returned `client_id` also confirms which channel the credentials belong
to — compare it against the configured Channel ID to catch copy-paste mixups.

### C. Endpoint version traps

| Call | Status | Body |
|---|---|---|
| Channel token on `GET /oauth2/v2.1/verify` | 400 | `{"error":"invalid_request","error_description":"The access token not JWS"}` |
| Channel token on `GET /v2/profile` | 403 | `{"message":"Access Denied"}` |
| Garbage id_token on `POST /oauth2/v2.1/verify` | 400 | `{"error":"invalid_request","error_description":"JWS format error"}` |

Channel access tokens only work on the v2.0 verify endpoint; the v2.1
endpoints expect JWT-based or user tokens.

### D. Token exchange errors — `POST /oauth2/v2.1/token` (authorization_code)

| State | Status | Body |
|---|---|---|
| Valid client, bogus/expired code | 400 | `{"error":"invalid_grant","error_description":"invalid authorization code"}` |
| Wrong secret AND bogus code | 400 | `{"error":"invalid_grant","error_description":"invalid authorization code"}` |

LINE validates the code before the client secret, so a broken secret hides
behind `invalid_grant` until a real login supplies a valid code — which is
why credential validation must use client_credentials (A), not the login
flow.

### E. Revoke — `POST /v2/oauth/revoke`

200 with an empty body, idempotent (revoking an already-revoked token is
also 200). Send the token URL-encoded (`--data-urlencode` / form encoding);
raw interpolation 400s on tokens containing `+` or `/`.

## Suggested UI guidance per detected state

| Detected state | What to tell the person configuring the channel |
|---|---|
| A: `invalid_client` | "Channel Secret is wrong — re-copy it from the LINE Developers console (Basic settings)." |
| A: `invalid_request` | "Channel ID not found — it should be the numeric ID from the LINE Developers console, not the channel name." |
| B: scope lacks `OCE` | "Email permission has not been applied for. Members can log in, but their email will not be imported. Apply under LINE Developers console → Basic settings → OpenID Connect → Email address permission." |
| B: scope is `P` only | "This channel predates OpenID Connect support and cannot issue ID tokens. Create a new LINE Login channel **under the same provider** and update the credentials here." |
| B: `client_id` ≠ configured ID | "These credentials belong to a different channel than the Channel ID entered." |
| D during a real login: `invalid_grant` recurring | Callback URL is likely not registered — it cannot be read or verified via any API; the authorize page shows the error on LINE's side and never redirects back. Show the exact callback URL to register, with a copy button. |

## What can never be verified via API

- **Registered Callback URLs** — no read API exists; a mismatch surfaces
  only as an error page on LINE's own authorize screen.
- **Provider membership** — user IDs are scoped per provider, and nothing in
  any token or response identifies the provider. If the owner recreates the
  channel under a different provider, every existing member's LINE user ID
  changes and account links silently break. (Channel rotation is real: one
  production school swapped channels within a single day of observation.)
- **Redirect URI mismatch as a machine-readable error** — it never reaches
  the token endpoint.
