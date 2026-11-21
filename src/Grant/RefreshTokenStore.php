<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

interface RefreshTokenStore extends FamilyRevocations
{
    public function save(RefreshTokenRecord $token): void;

    public function find(string $tokenHash): ?RefreshTokenRecord;

    /** Marks the token as exchanged. Atomic like {@see AuthorizationCodeStore::markUsed()}. */
    public function markUsed(string $tokenHash, int $at): bool;

    /** Revokes every token of the family, used or not, because a used token was presented again. */
    public function revokeFamily(string $familyId, int $at): void;

    /** Revokes the tokens that belong to a login session, because it ended. */
    public function revokeSession(string $sessionId, int $at): void;
}
