<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use InvalidArgumentException;

/**
 * A fixed set of public keys, typically the JSON Web Key Set (RFC 7517) another provider publishes, for checking tokens that
 * provider signed.
 */
final readonly class VerificationKeySet implements VerificationKeys
{
    /** @param list<VerificationKey> $keys */
    public function __construct(private array $keys)
    {
    }

    /**
     * Reads a JWKS document. Keys this library cannot use are left out rather than failing the whole set, because providers
     * publish keys for other purposes and algorithms next to the ones they sign with: anything that is not an RSA key, a key
     * meant for encryption or for another algorithm than RS256, a key smaller than 2048 bits, and one that is malformed.
     *
     * @param array<mixed> $document the decoded JWKS
     */
    public static function fromJwks(array $document): self
    {
        $keys = [];
        $jwks = $document['keys'] ?? [];
        foreach (is_array($jwks) ? $jwks : [] as $jwk) {
            if (!is_array($jwk) || array_is_list($jwk) || ($jwk['kty'] ?? null) !== 'RSA') {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }
            if (isset($jwk['alg']) && $jwk['alg'] !== 'RS256') {
                continue;
            }
            try {
                /** @var array<string, mixed> $jwk */
                $keys[] = VerificationKey::fromJwk($jwk);
            } catch (InvalidArgumentException) {
                continue;
            }
        }

        return new self($keys);
    }

    public function verificationKeys(): array
    {
        return $this->keys;
    }
}
