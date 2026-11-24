---
title: Resource indicators
weight: 6
lead: Tokens that only one API accepts (RFC 8707).
---

Without resource indicators, an access token is for this server and for the client it was issued to. With them, a client says which API a
token is for, by sending the API's address as `resource`, and the token is only good there. That is what you want when one login server
protects several APIs, and what MCP servers ask of their clients.

It is off unless you give the server a `ResourcePolicy`: the `resource` parameter is ignored without one.

```php
final class MyResources implements ResourcePolicy
{
    public function allows(Client $client, string $resource): bool
    {
        return in_array($resource, $this->allowedFor($client->id()), true);   // exact match, from your database
    }
}

$server = new AuthorizationServer(/* ... */, resourcePolicy: new MyResources());
```

## How it behaves

- `resource` goes on the authorization request and, for any grant, on the token request. It may appear several times
  (`resource=https://a.example&resource=https://b.example`). Each is an absolute URI without a fragment.
- The authorization request names what the person is signing in for. The token request may name some or all of those, never more.
  When the authorization named none, the token request may name any resource the client is allowed.
- The access token's `aud` is the resources followed by this server's own audience (so `/userinfo` keeps working). It does **not**
  name the client id any more. An API protects itself with `bearerTokenMiddleware([...], audience: 'https://a.example')` and refuses
  tokens meant for another API.
- A refresh token keeps the resources of the whole grant through every rotation. A refresh may narrow them for one access token; the
  next refresh can still ask for any of the originals. The policy is asked again on every refresh, so taking a resource away works at once.
- An unknown, malformed or not allowed resource is an `invalid_target` error (redirected to the client at the authorization endpoint).
- ID tokens are unchanged: they are for the client.

## Your stores

`AuthorizationCodeRecord` and `RefreshTokenRecord` have a `resources` list. Store it and give it back, or tokens lose their audience
restriction when refreshed. A refresh token stored before you added the column simply has none.
