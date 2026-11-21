<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use InvalidArgumentException;

/** One signing key, plus optionally the public keys of retired ones. Enough for most applications. */
final readonly class StaticKeyProvider implements KeyProvider
{
    /** @var list<VerificationKey> */
    private array $verificationKeys;

    /** @param list<VerificationKey> $retiredKeys */
    public function __construct(private SigningKey $signingKey, array $retiredKeys = [])
    {
        $keys = [$signingKey->verificationKey(), ...$retiredKeys];
        $kids = array_map(static fn (VerificationKey $key): string => $key->kid, $keys);
        if (count(array_unique($kids)) !== count($kids)) {
            throw new InvalidArgumentException('Every key needs its own kid.');
        }
        $this->verificationKeys = $keys;
    }

    public function signingKey(): SigningKey
    {
        return $this->signingKey;
    }

    public function verificationKeys(): array
    {
        return $this->verificationKeys;
    }
}
