# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project follows [Semantic Versioning](https://semver.org/).

## Unreleased

- Resource indicators (RFC 8707), off unless you pass a `ResourcePolicy` (`resourcePolicy:` on `AuthorizationServer`). The `resource` parameter
  (repeatable) is accepted at the authorization endpoint and at the token endpoint for every grant. An access token issued for resources has them as
  its audience, next to this server's own, and no longer names the client; a refresh may narrow the resources but never widen them, and the
  grant keeps them through every rotation. Errors use `invalid_target`. `AuthorizationCodeRecord` and `RefreshTokenRecord` have a new `resources`
  list that your stores must keep, and `Params::repeated()` reads a parameter that appears more than once.
- `RegistrarPolicy` (optional, `registrarPolicy:` on `AuthorizationServer`): decides per registrar whether it may register apps right now
  (checked on every registration, so taking the right away works for tokens already issued) and which scopes the apps it registers may
  get, also when those apps update themselves. Discovery advertises `registration_endpoint` only while some client may register.

## 1.1.1 - 2026-11-24

- Fix: the registration endpoints read the raw JSON body when the framework left the parsed body empty, which is what PHP's own request factory does for JSON requests.

## 1.1.0 - 2026-11-24

- Dynamic client registration (RFC 7591) and client configuration management (RFC 7592), off unless you pass a
  `ClientRegistrations` store to `AuthorizationServer`. Registering needs an access token with the `client:register` scope
  (`registrationMiddleware()`); each client gets a registration access token to read, replace or delete only its own registration.
  Adds `registrationHandler()`, `clientConfigurationHandler()`, `ClientsWithRegistrations`, `InMemoryClientRegistrations`,
  and `registration_endpoint` in the discovery document.

## 1.0.0 - 2026-11-21

First release.

- OAuth 2.0 and OpenID Connect authorization server for PSR-7 and PSR-15 applications, with no third-party runtime dependencies.
- Grants: authorization code with required PKCE, refresh tokens with rotation and reuse detection (a refresh carries only the
  scopes the server still offers and the client may still ask for), client credentials, and device authorization (RFC 8628).
- OpenID Connect: ID tokens, UserInfo, discovery, JWKS with key rotation, `prompt` and `max_age`, RP-initiated and back-channel
  logout, token revocation and introspection.
- Verifying tokens this server did not sign: `JwtDecoder` (RS256 only) with `VerificationKeySet::fromJwks()`, and `ClaimsValidator`.
