# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through
GitHub's "Report a vulnerability" button on the Security tab of this repository
(private vulnerability reporting). Include what you found, how to reproduce it, and which version.

What to expect:

- An acknowledgement within 3 working days.
- A first assessment within 10 working days.
- A fix and a coordinated disclosure date agreed with you. The default is 90 days at most.
- Credit in the release notes, unless you prefer to stay anonymous.

## Supported versions

Only the latest minor release of the latest major version receives security fixes.

## Scope

In scope: the code in `src/` (token issuing and validation, the endpoints, PKCE, JWT handling, logout).
Out of scope: the storage, login screens and admin UI of the application that uses this library,
and the in-memory stores in `src/InMemory/`, which exist for tests and examples only.

## What you are responsible for

The library enforces the protocol. These parts are yours, and the
[threat model](https://php-sso.github.io/oauth-server/threat-model/) lists what happens if they are wrong:

- Storage implementations must make `markUsed()` and `markConsumed()` atomic.
- Serve the issuer over HTTPS only.
- Keep the private signing key readable by the server only.
- Rate-limit the token endpoint and your login form. Count failed client authentications (`invalid_client`) per client and address together, so an attacker cannot lock a real app out.
- Implement `EqualisesVerificationTime` on your client repository if checking a secret is slow on purpose (a password hash), so unknown client ids cannot be told apart by response time.
