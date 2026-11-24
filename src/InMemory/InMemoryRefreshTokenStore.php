<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\InMemory;

use PhpSso\OAuthServer\Grant\RefreshTokenRecord;
use PhpSso\OAuthServer\Grant\RefreshTokenStore;

/** Keeps refresh tokens in memory: for tests and examples, not for production. */
final class InMemoryRefreshTokenStore implements RefreshTokenStore
{
    /** @var array<string, RefreshTokenRecord> */
    private array $tokens = [];

    /** @var array<string, int> family id => revoked at */
    private array $revokedFamilies = [];

    public function save(RefreshTokenRecord $token): void
    {
        $this->tokens[$token->tokenHash] = $token;
    }

    public function find(string $tokenHash): ?RefreshTokenRecord
    {
        return $this->tokens[$tokenHash] ?? null;
    }

    public function markUsed(string $tokenHash, int $at): bool
    {
        $token = $this->tokens[$tokenHash] ?? null;
        if ($token === null || $token->usedAt !== null) {
            return false;
        }

        $this->tokens[$tokenHash] = new RefreshTokenRecord(
            $token->tokenHash, $token->familyId, $token->clientId, $token->userId, $token->scopes,
            $token->sessionId, $token->expiresAt, $at, $token->authTime, $token->amr, $token->resources,
        );

        return true;
    }

    public function revokeFamily(string $familyId, int $at): void
    {
        $this->revokedFamilies[$familyId] ??= $at;
    }

    public function revokeSession(string $sessionId, int $at): void
    {
        foreach ($this->tokens as $token) {
            if ($token->sessionId === $sessionId) {
                $this->revokeFamily($token->familyId, $at);
            }
        }
    }

    public function isFamilyRevoked(string $familyId): bool
    {
        return isset($this->revokedFamilies[$familyId]);
    }
}
