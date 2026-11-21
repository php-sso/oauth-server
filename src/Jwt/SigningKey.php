<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;

/** The private RSA key tokens are signed with, identified by `kid`. At least 2048 bits. */
final readonly class SigningKey
{
    /** @var non-empty-string */
    public string $privateKeyPem;

    /** The private key must not end up in stack traces or log lines: the parameter is marked sensitive and dumps show only the kid. */
    public function __construct(public string $kid, #[\SensitiveParameter] string $privateKeyPem)
    {
        if ($kid === '') {
            throw new InvalidArgumentException('A signing key needs a kid.');
        }
        if ($privateKeyPem === '') {
            throw new InvalidArgumentException('The signing key is empty.');
        }
        $this->privateKeyPem = $privateKeyPem;
        $key = openssl_pkey_get_private($privateKeyPem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException('The signing key is not a readable PEM private key (without a passphrase).');
        }
        RsaKeyDetails::of($key); // throws unless it is an RSA key of at least 2048 bits
    }

    /** @return array{kid: string} what var_dump() and print_r() show: never the key itself */
    public function __debugInfo(): array
    {
        return ['kid' => $this->kid];
    }

    /** The matching public key, to verify what this key signs and to publish in the JWKS. */
    public function verificationKey(): VerificationKey
    {
        $key = openssl_pkey_get_private($this->privateKeyPem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException('The signing key cannot be read.');
        }

        return new VerificationKey($this->kid, RsaKeyDetails::of($key)->publicKeyPem);
    }
}
