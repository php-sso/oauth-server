<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\InMemory;

use PhpSso\OAuthServer\Grant\RevokedAccessTokens;

/** Keeps revoked access token ids in memory: for tests and examples, not for production. */
final class InMemoryRevokedAccessTokens implements RevokedAccessTokens
{
    /** @var array<string, int> */
    private array $revoked = [];

    public function revoke(string $tokenId, int $expiresAt): void
    {
        $this->revoked[$tokenId] = $expiresAt;
    }

    public function isRevoked(string $tokenId): bool
    {
        return isset($this->revoked[$tokenId]);
    }
}
