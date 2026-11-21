<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Encoding;

/** Base64url without padding (RFC 4648 section 5), as used by JWTs and PKCE. */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Returns null for anything that is not valid unpadded base64url, instead of guessing. */
    public static function decode(string $text): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/', $text) !== 1 || strlen($text) % 4 === 1) {
            return null;
        }

        $decoded = base64_decode(strtr($text, '-_', '+/'), true);

        // Only the canonical spelling: leftover bits in the last character must be zero, so one byte string has one text.
        return $decoded === false || self::encode($decoded) !== $text ? null : $decoded;
    }
}
