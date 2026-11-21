<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

interface AuthorizationCodeStore
{
    public function save(AuthorizationCodeRecord $code): void;

    public function find(string $codeHash): ?AuthorizationCodeRecord;

    /**
     * Marks the code as used. Must be atomic: when two requests race to redeem the same code, exactly one
     * gets `true`. Returns false when the code is unknown or was already used.
     */
    public function markUsed(string $codeHash, int $at): bool;
}
