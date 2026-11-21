<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;

/** What OpenSSL says about an RSA key, checked and typed. Internal to the JWT classes. */
final readonly class RsaKeyDetails
{
    private function __construct(
        public int $bits,
        public string $modulus,
        public string $exponent,
        public string $publicKeyPem,
    ) {
    }

    /** @throws InvalidArgumentException when the key is not an RSA key of at least 2048 bits */
    public static function of(OpenSSLAsymmetricKey $key): self
    {
        $details = openssl_pkey_get_details($key);
        $rsa = $details['rsa'] ?? null;
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || !is_array($rsa)) {
            throw new InvalidArgumentException('The key must be an RSA key.');
        }

        $bits = $details['bits'] ?? null;
        $modulus = $rsa['n'] ?? null;
        $exponent = $rsa['e'] ?? null;
        $pem = $details['key'] ?? null;
        if (!is_int($bits) || !is_string($modulus) || !is_string($exponent) || !is_string($pem)) {
            throw new InvalidArgumentException('OpenSSL could not describe the key.');
        }
        if ($bits < 2048) {
            throw new InvalidArgumentException('The key must have at least 2048 bits.');
        }

        return new self($bits, $modulus, $exponent, $pem);
    }
}
