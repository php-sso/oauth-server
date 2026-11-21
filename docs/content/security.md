---
title: Security behaviour
weight: 6
lead: Behaviour worth knowing before you go live.
---

- Redirect URIs match exactly. Errors about the client or redirect URI are never redirected.
- A wrong PKCE verifier or redirect URI spends the code: a guess gets one try.
- Client authentication failures are indistinguishable, whether the client exists or not.
- Whatever a `UserClaimsProvider` returns under `iss`, `sub`, `aud`, `exp`, `nonce`, `sid` and the other
  reserved names is dropped.
- The bearer middleware rejects ID tokens (only `at+jwt` counts), expired or foreign tokens, and tokens whose
  family was revoked, and never says which check failed.
- JWT verification accepts only `RS256`, a known `kid`, and refuses `jku`, `jwk`, `x5u`, `x5c`, `x5t` and `crit`.
- User codes for the device flow are short: rate-limit attempts on your verification page.
- The end-session endpoint ends a session only with a valid ID token hint (any age) or after the person
  confirmed. Your confirmation form needs its own CSRF protection.
- Back-channel logout is one attempt per client with whatever timeout your PSR-18 client has, and never
  throws; the outcomes come back as `LogoutDelivery` objects for you to log or retry. If clients can register
  their own logout URIs, keep your HTTP client from reaching internal addresses.
- `RefreshTokenStore::revokeSession()` must revoke every token family created during the session, including
  families of clients that never got a refresh token, or their access tokens survive the logout.
