<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Jwt\SigningKey;
use RuntimeException;

/** RSA keys for tests. Generating one takes a moment, so each is made once per run. */
final class TestKeys
{
    /** @var array<string, string> */
    private static array $pems = [];

    public static function privatePem(string $name = 'a'): string
    {
        if (!isset(self::$pems[$name])) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            if ($key === false || !openssl_pkey_export($key, $pem) || !is_string($pem)) {
                throw new RuntimeException('Could not generate a test key.');
            }
            self::$pems[$name] = $pem;
        }

        return self::$pems[$name];
    }

    public static function signingKey(string $kid = 'key-a', string $name = 'a'): SigningKey
    {
        return new SigningKey($kid, self::privatePem($name));
    }
}
