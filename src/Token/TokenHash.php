<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

/**
 * What gets stored instead of a secret. The values are 256 random bits, so a plain SHA-256 is enough:
 * there is nothing to brute-force, and a leaked database does not reveal usable tokens.
 */
final class TokenHash
{
    public static function of(string $token): string
    {
        return hash('sha256', $token);
    }
}
