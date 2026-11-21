<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

/**
 * Access tokens are signed JWTs, so one that was revoked on its own (RFC 7009) has to be remembered by its
 * `jti` until it would have expired anyway. Tokens whose whole family was revoked need no entry here.
 */
interface RevokedAccessTokens
{
    /** @param int $expiresAt Unix time the token expires; the entry can be dropped after that. */
    public function revoke(string $tokenId, int $expiresAt): void;

    public function isRevoked(string $tokenId): bool;
}
