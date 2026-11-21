# php-sso/oauth-server

An OAuth 2.0 and OpenID Connect authorization server for PSR-7 / PSR-15 applications.

- PSR-7 messages in and out, PSR-15 request handlers and middleware: it fits any framework.
- No third-party runtime dependencies: only the PSR interface packages and PHP's own `openssl` and `json`.
- Storage, people, clients and keys are interfaces you implement; nothing here knows about your database.
- Small on purpose, and strict by default.

## Install

```
composer require php-sso/oauth-server
```

PHP 8.2 or newer, with `ext-json` and `ext-openssl`.

## What it supports

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

Logout and revocation: RP-initiated logout (end-session endpoint), back-channel logout, token revocation
(RFC 7009) and introspection (RFC 7662).

Tokens: access tokens are RS256 JWTs of type `at+jwt` (RFC 9068) with a `jti`, a family id and the login
session. Refresh tokens and codes are random 256-bit values and only their SHA-256 hash is stored.

Not there yet: `prompt=consent` / `select_account` (refused as `invalid_request`), front-channel logout,
DPoP / mTLS, dynamic client registration.

## Using it

```php
$server = new AuthorizationServer(
    config: new ServerConfig('https://sso.example.com', ['openid', 'profile', 'email']),
    endpoints: new Endpoints(),              // /authorize, /token, /userinfo, /jwks, /end-session, /revoke, /introspect, ...
    clients: $yourClientRepository,          // ClientRepository (your Client class also implements SupportsLogout)
    claims: $yourClaimsProvider,             // UserClaimsProvider
    policy: $yourAccessPolicy,               // AccessPolicy: may this person use this client?
    ui: $yourAuthorizationUi,                // AuthorizationUi: login redirect, "no access" page
    keys: new StaticKeyProvider(new SigningKey('key-1', $privatePem)),
    codes: $codeStore, refreshTokens: $refreshStore, devices: $deviceStore,   // your storage
    revokedAccessTokens: $revokedStore,
    logout: new LogoutSupport($sessionRegistry, $sessionTerminator, $logoutUi, $psr18Client, $psr17RequestFactory),
    responseFactory: $psr17, streamFactory: $psr17,
    claimNames: ['sub', 'name', 'email'],    // for the discovery document
);
```

Every collaborator is required: a missing one is an error when the server is built, not a feature that
quietly switches off.


Whenever your application ends a login session itself (the person signed out, an administrator ended it, a
password was reset), call `$server->logoutService()->sessionEnded($sessionId, $userId)`: it revokes what the
session issued and tells the clients that support back-channel logout.

The signed-in person reaches the authorization handler through the request attributes
`AuthorizationHandler::USER_ID` and `SESSION_ID`, which your own login middleware sets, plus `AUTH_TIME` (when they
last actually authenticated) for `max_age` and `auth_time`, and `AMR` (how they authenticated: a list of RFC 8176 names such
as `pwd`, `otp`, `mfa`) for the ID token's `amr`. Like `auth_time`, `amr` is kept with the code and every refresh token of the
chain; names that are not strings without spaces are dropped, and a claims provider cannot set `amr` itself. For `prompt=login` and an exceeded `max_age`, your
`AuthorizationUi::loginRequired()` receives the request with `FORCE_LOGIN` set and `RESUME_PARAMS` (the request
without `prompt` and `max_age`): authenticate again even if a session exists, then send the browser back to the
authorization endpoint with exactly those parameters. On your device
verification page, `$server->deviceVerifier()` looks up the code a person typed and approves or denies it.

## Roles, and APIs behind the server

Access tokens name two audiences: the server itself (`ServerConfig::audience()`, which its own userinfo,
introspection and revocation endpoints check) and the client they were issued to, as `"aud": [<server>, <client id>]`.
An API that serves one application protects its routes with
`$server->bearerTokenMiddleware(['invoices:read'], audience: 'that-client-id')`: tokens issued to other
applications are refused. An API in another process does the same check on `aud` itself, and must accept an array.

Claims that depend on the client, such as the roles a person has in that application, come from an optional
second interface on your `UserClaimsProvider`: implement `ClientSpecificClaims::clientClaimsFor($clientId, $userId, $scopes)`.
Its claims go into the access token (so an API can use them), the ID token and the userinfo response, are read
again on every refresh, and cannot override the reserved claims. A provider that does not implement it behaves
as before.

## Verifying tokens this server did not sign

The same checks are available to a relying party or an API that only has someone's public keys, such as another
provider's JWKS. `JwtDecoder` takes any `VerificationKeys` (`KeyProvider` is one, with a signing key too), and
`VerificationKeySet::fromJwks($document)` builds one from a published key set, leaving out keys it cannot use (other key
types, encryption keys, other algorithms, RSA keys below 2048 bits) instead of failing. `decode()` checks the signature
(RS256 only, a known `kid`, no `jku`, `jwk`, `x5u`, `x5c` or `crit` headers); `ClaimsValidator` then checks the issuer,
the audience and the time window.

```php
$claims = (new JwtDecoder(VerificationKeySet::fromJwks($jwks)))->decode($idToken)['claims'];
(new ClaimsValidator(new SystemClock(), 'https://idp.example.com', leeway: 60))->validate($claims, audience: 'my-client-id');
```

## Security behaviour worth knowing

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

## Develop

```bash
composer install
composer check      # PHPStan (level max, strict rules, no baseline) and PHPUnit
```

Tests follow Arrange, Act, Assert, one file per method:
`tests/unit/PhpSso/OAuthServer/{Namespace}/{Class}/{Method}Test.php`.

## License

MIT. See [LICENSE](LICENSE).
