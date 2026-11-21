---
title: Using it
weight: 3
lead: Build the server, and what your application has to provide.
---

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
