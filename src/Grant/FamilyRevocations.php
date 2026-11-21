<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

/**
 * Answers whether a token family was revoked (a login session ended, or a used token was replayed).
 * Access tokens carry their family id, so an API can reject them as soon as the family is revoked.
 */
interface FamilyRevocations
{
    public function isFamilyRevoked(string $familyId): bool;
}
