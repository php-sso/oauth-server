<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Encoding\Base64Url;
use RuntimeException;

/** Builds tokens a well-behaved encoder never would, to check that the decoder refuses them. */
final class JwtForge
{
    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function rs256(array $header, array $claims, string $privatePem): string
    {
        $input = self::part($header) . '.' . self::part($claims);
        $key = openssl_pkey_get_private($privatePem);
        $signature = null;
        if ($key === false || !openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256) || !is_string($signature)) {
            throw new RuntimeException('Could not sign.');
        }

        return $input . '.' . Base64Url::encode($signature);
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function hs256(array $header, array $claims, string $secret): string
    {
        $input = self::part($header) . '.' . self::part($claims);

        return $input . '.' . Base64Url::encode(hash_hmac('sha256', $input, $secret, true));
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function unsigned(array $header, array $claims, string $signature = ''): string
    {
        return self::part($header) . '.' . self::part($claims) . '.' . $signature;
    }

    /** @param array<string, mixed> $data */
    private static function part(array $data): string
    {
        return Base64Url::encode(json_encode($data, JSON_THROW_ON_ERROR));
    }
}
