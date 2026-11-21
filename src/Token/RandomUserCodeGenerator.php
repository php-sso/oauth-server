<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

/**
 * Eight characters from the 20-letter consonant alphabet RFC 8628 recommends: no vowels (no words), no
 * characters that look alike, and easy to read off a TV. About 2.5 * 10^10 combinations.
 */
final class RandomUserCodeGenerator implements UserCodeGenerator
{
    public const ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    public function generate(): string
    {
        $code = '';
        for ($i = 0; $i < 8; ++$i) {
            $code .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
        }

        return $code;
    }

    /** Normalizes what a person typed: case, spaces and dashes do not matter. */
    public static function normalize(string $typed): string
    {
        return strtoupper((string) preg_replace('/[\s-]+/', '', $typed));
    }

    /** The code as shown to people: WDJB-MJHT. */
    public static function format(string $code): string
    {
        return substr($code, 0, 4) . '-' . substr($code, 4);
    }
}
