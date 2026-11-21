<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Pkce;

use PhpSso\OAuthServer\Encoding\Base64Url;

/** Proof Key for Code Exchange (RFC 7636). Only the S256 method exists here; `plain` is not supported. */
final class Pkce
{
    public const METHOD = 'S256';

    /**
     * Stored as the challenge of a code that was requested without PKCE. Only confidential clients can do that, and
     * only when {@see \PhpSso\OAuthServer\Config\ServerConfig::$requirePkceForConfidentialClients} is off.
     */
    public const NONE = '';

    /** A challenge is the unpadded base64url of a SHA-256 digest: exactly 43 characters. */
    public static function isValidChallenge(string $challenge): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) === 1;
    }

    /** A verifier is 43 to 128 characters from the unreserved set. */
    public static function isValidVerifier(string $verifier): bool
    {
        return preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $verifier) === 1;
    }

    public static function challengeFor(string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }

    public static function verify(string $challenge, string $verifier): bool
    {
        return self::isValidVerifier($verifier) && hash_equals($challenge, self::challengeFor($verifier));
    }
}
