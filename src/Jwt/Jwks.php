<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

/** The JSON Web Key Set (RFC 7517) that lets clients and APIs verify our tokens. */
final class Jwks
{
    /** @return array{keys: list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>} */
    public static function toArray(KeyProvider $provider): array
    {
        return ['keys' => array_map(static fn (VerificationKey $key): array => $key->toJwk(), $provider->verificationKeys())];
    }
}
