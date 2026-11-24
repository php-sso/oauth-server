---
title: What it supports
weight: 2
lead: Grants, OpenID Connect, logout, tokens, and what is not there yet.
---

| Grant | Notes |
| --- | --- |
| `authorization_code` | PKCE is **required**, S256 only (no `plain`). Codes are single use; replaying one revokes what was issued from it. |
| `refresh_token` | Rotation on every use. Reusing an old token revokes the whole chain. A refresh checks access again, and carries only the scopes the server still offers and the client may still ask for. |
| `client_credentials` | Confidential clients only. The token's subject is the client; no refresh token, no ID token. |
| `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628: device authorization endpoint, polling with `slow_down`, and a verifier your approval page uses. |

Deliberately **not** supported: the `password` grant and the implicit flow (both removed by the OAuth 2.0
Security BCP and OAuth 2.1), and `plain` PKCE.

OpenID Connect: ID tokens (`nonce`, `sid`, `at_hash`, `auth_time`, `amr`), UserInfo, discovery (also as RFC 8414), JWKS with
key rotation, RFC 9207 `iss` on authorization responses, `prompt=none`, `prompt=login` and `max_age`.

Dynamic client registration (RFC 7591) and its management protocol (RFC 7592), see [Client registration](../registration/).

Resource indicators (RFC 8707), see [Resource indicators](../resource-indicators/): tokens that only one API accepts. Not for the device
authorization request, only for the token requests of the device grant.

Logout and revocation: RP-initiated logout (end-session endpoint), back-channel logout, token revocation
(RFC 7009) and introspection (RFC 7662).

Tokens: access tokens are RS256 JWTs of type `at+jwt` (RFC 9068) with a `jti`, a family id and the login
session. Refresh tokens and codes are random 256-bit values and only their SHA-256 hash is stored.

Not there yet: `prompt=consent` / `select_account` (refused as `invalid_request`), front-channel logout,
DPoP / mTLS.
