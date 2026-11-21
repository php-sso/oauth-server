---
title: Roles, and APIs behind the server
weight: 4
lead: Audiences, and claims that depend on the client.
---

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
