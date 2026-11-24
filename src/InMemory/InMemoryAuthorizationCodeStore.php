<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\InMemory;

use PhpSso\OAuthServer\Grant\AuthorizationCodeRecord;
use PhpSso\OAuthServer\Grant\AuthorizationCodeStore;

/** Keeps codes in memory: for tests and examples, not for production (nothing survives the request). */
final class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore
{
    /** @var array<string, AuthorizationCodeRecord> */
    private array $codes = [];

    public function save(AuthorizationCodeRecord $code): void
    {
        $this->codes[$code->codeHash] = $code;
    }

    public function find(string $codeHash): ?AuthorizationCodeRecord
    {
        return $this->codes[$codeHash] ?? null;
    }

    public function markUsed(string $codeHash, int $at): bool
    {
        $code = $this->codes[$codeHash] ?? null;
        if ($code === null || $code->usedAt !== null) {
            return false;
        }

        $this->codes[$codeHash] = new AuthorizationCodeRecord(
            $code->codeHash, $code->clientId, $code->userId, $code->redirectUri, $code->scopes,
            $code->codeChallenge, $code->nonce, $code->sessionId, $code->familyId, $code->expiresAt, $at, $code->authTime, $code->amr, $code->resources,
        );

        return true;
    }
}
