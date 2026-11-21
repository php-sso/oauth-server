---
title: Verifying tokens this server did not sign
weight: 5
lead: The same checks, for a relying party or an API.
---

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
