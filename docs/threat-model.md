# Threat model

What the library defends against, how, and what it leaves to you.

## Assets

Authorization codes, refresh tokens, access and ID tokens, client secrets, the signing key, the person's session.

## Attacks and defences

| Threat | Defence |
| --- | --- |
| Stolen authorization code | Single use, short TTL, bound to the client and redirect URI. PKCE (S256) is required for public clients, and for confidential ones unless the server is configured otherwise. |
| Code replay | A second redemption is refused and revokes everything issued from the first (RFC 9700). Two simultaneous redemptions: exactly one wins, because `markUsed()` is atomic. |
| Stolen refresh token | Rotation on every use. An old token coming back revokes the whole chain. A refresh cannot widen the scope. Expiry and session end revoke it. |
| Open redirect | Exact string match of `redirect_uri` against the registered list. Until it matches, errors are never redirected. |
| Authorization request tampering | `request` and `request_uri` are refused rather than ignored. |
| Mix-up between servers | `iss` is returned in every authorization response (RFC 9207). |
| Token forgery | RS256 only, key from the server's own key set. `alg`, `typ` and `kid` are checked. The signature must be in canonical base64url. `alg: none` and key-confusion are covered by a test that alters every character of a valid token. |
| Token misuse across APIs | `aud` holds the server and the client. APIs can require their own audience. Access tokens are `at+jwt`, ID tokens `JWT`, so one cannot pass for the other, also not as `id_token_hint`. |
| Client secret guessing | Secrets are compared by your repository (use `password_verify`). Every authentication failure gives the same answer. |
| Finding out which client ids exist | An unknown id gets the same answer as a wrong secret. If your repository implements `EqualisesVerificationTime`, it also takes about as long. |
| Key leakage through logs | `SigningKey` hides the key from stack traces and dumps. |
| Device flow abuse | Polling faster than the interval gets `slow_down` and a longer interval. A device code is consumed once. |
| Logout CSRF | A bare logout link asks for confirmation. Only a valid `id_token_hint` skips it. |

## Not defended, on purpose

- **Rate limiting.** The library has no limiter, because it does not know the caller's address or where to keep counts. Without one, anyone can try client secrets and codes as fast as the network allows. Secrets and codes are long and random, so guessing is not realistic, but limit the endpoints anyway. The php-sso server does this for failed client authentication: count failures per client and address together (so nobody can lock an app out by naming its client id) and per address alone, answer 429 past the limits.
- **A compromised resource server or client.** A stolen valid access token works until it expires (default short). Revocation is checked at introspection and by `BearerTokenMiddleware`.
- **Token binding.** No DPoP or mTLS. A bearer token works for whoever holds it.
- **A malicious administrator.** The admin can read what the application stores and add themselves to any client.

## Not supported

Implicit and password grants (removed in OAuth 2.1), request objects, `claims` parameter, dynamic client registration,
`acr` values, address and phone scopes, bearer tokens in a POST body, front-channel logout.

## Your side of the bargain

See "What you are responsible for" in [SECURITY.md](../SECURITY.md).
