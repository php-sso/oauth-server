<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use JsonException;
use PhpSso\OAuthServer\Encoding\Base64Url;

/**
 * Checks the signature of a JWT and returns its header and claims. It does not judge the claims: expiry,
 * issuer and audience are checked by {@see ClaimsValidator}.
 *
 * Deliberately narrow: only RS256 is accepted, the token must name a key we know by `kid`, and headers
 * that would let a token point at other keys (`jku`, `jwk`, `x5u`, `x5c`) or need extensions (`crit`)
 * are rejected. The algorithm is never taken from the token to choose how to verify.
 */
final readonly class JwtDecoder
{
    private const FORBIDDEN_HEADERS = ['crit', 'jku', 'jwk', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

    public function __construct(private VerificationKeys $keys)
    {
    }

    /**
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     *
     * @throws InvalidJwt
     */
    public function decode(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || in_array('', $parts, true)) {
            throw new InvalidJwt('The token is not in the header.payload.signature form.');
        }
        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = $this->json($encodedHeader, 'header');
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new InvalidJwt('Only RS256 tokens are accepted.');
        }
        foreach (self::FORBIDDEN_HEADERS as $name) {
            if (array_key_exists($name, $header)) {
                throw new InvalidJwt("The {$name} header is not supported.");
            }
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new InvalidJwt('The token does not name its signing key.');
        }

        $signature = Base64Url::decode($encodedSignature);
        if ($signature === null) {
            throw new InvalidJwt('The signature is not valid base64url.');
        }

        foreach ($this->keys->verificationKeys() as $key) {
            if ($key->kid === $kid) {
                if (openssl_verify($encodedHeader . '.' . $encodedPayload, $signature, $key->openSslKey(), OPENSSL_ALGO_SHA256) !== 1) {
                    throw new InvalidJwt('The signature does not match.');
                }

                return ['header' => $header, 'claims' => $this->json($encodedPayload, 'payload')];
            }
        }

        throw new InvalidJwt('The token was signed with an unknown key.');
    }

    /** @return array<string, mixed> */
    private function json(string $encoded, string $what): array
    {
        $bytes = Base64Url::decode($encoded);
        if ($bytes === null) {
            throw new InvalidJwt("The {$what} is not valid base64url.");
        }

        try {
            $data = json_decode($bytes, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidJwt("The {$what} is not valid JSON.");
        }
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            throw new InvalidJwt("The {$what} is not a JSON object.");
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
