<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use Psr\Clock\ClockInterface;

/** Checks what a token claims, once its signature is known to be good: issuer, audience and the time window. */
final readonly class ClaimsValidator
{
    /** @param int $leeway Seconds of clock difference between servers that are tolerated. */
    public function __construct(
        private ClockInterface $clock,
        private string $issuer,
        private int $leeway = 30,
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     * @param string|null          $audience The audience this token must be for; null skips the check.
     *
     * @throws InvalidJwt
     */
    public function validate(array $claims, ?string $audience = null): void
    {
        $now = $this->clock->now()->getTimestamp();

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new InvalidJwt('The token was issued by someone else.');
        }

        $exp = $claims['exp'] ?? null;
        if (!is_int($exp)) {
            throw new InvalidJwt('The token has no expiry.');
        }
        if ($exp + $this->leeway <= $now) {
            throw new InvalidJwt('The token has expired.');
        }

        $nbf = $claims['nbf'] ?? null;
        if ($nbf !== null && (!is_int($nbf) || $nbf - $this->leeway > $now)) {
            throw new InvalidJwt('The token is not valid yet.');
        }

        $iat = $claims['iat'] ?? null;
        if ($iat !== null && (!is_int($iat) || $iat - $this->leeway > $now)) {
            throw new InvalidJwt('The token was issued in the future.');
        }

        if ($audience !== null) {
            $aud = $claims['aud'] ?? null;
            $audiences = is_string($aud) ? [$aud] : (is_array($aud) ? $aud : []);
            if (!in_array($audience, $audiences, true)) {
                throw new InvalidJwt('The token is meant for a different audience.');
            }
        }
    }
}
