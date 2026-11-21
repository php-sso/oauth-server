<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use JsonException;
use PhpSso\OAuthServer\Encoding\Base64Url;
use RuntimeException;

/** Creates signed JWTs (RFC 7515 compact serialization), RS256 only. */
final readonly class JwtEncoder
{
    public function __construct(private KeyProvider $keys)
    {
    }

    /**
     * @param array<string, mixed> $claims
     * @param string               $type   The `typ` header: `JWT`, `at+jwt` for access tokens, `logout+jwt` for logout tokens.
     *
     * @return non-empty-string
     */
    public function encode(array $claims, string $type = 'JWT'): string
    {
        $key = $this->keys->signingKey();

        try {
            $header = json_encode(['alg' => 'RS256', 'typ' => $type, 'kid' => $key->kid], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $payload = json_encode($claims === [] ? new \stdClass() : $claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new RuntimeException('The claims cannot be encoded as JSON: ' . $e->getMessage(), 0, $e);
        }

        $signingInput = Base64Url::encode($header) . '.' . Base64Url::encode($payload);
        $privateKey = openssl_pkey_get_private($key->privateKeyPem);
        $signature = null;
        if ($privateKey === false || !openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256) || !is_string($signature)) {
            throw new RuntimeException('Signing failed.');
        }

        return $signingInput . '.' . Base64Url::encode($signature);
    }
}
