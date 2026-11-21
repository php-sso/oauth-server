<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRefreshTokenStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\RefreshTokenRecord;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;

#[CoversMethod(InMemoryRefreshTokenStore::class, 'revokeSession')]
final class RevokeSessionTest extends TestCase
{
    public function testItRevokesTheFamiliesOfTheSessionOnly(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();
        $store->save($this->token('hash-1', 'family-a', 'session-1'));
        $store->save($this->token('hash-2', 'family-b', 'session-1'));
        $store->save($this->token('hash-3', 'family-c', 'session-2'));
        $store->save($this->token('hash-4', 'family-d', null));

        // Act
        $store->revokeSession('session-1', 1_700_000_200);

        // Assert
        self::assertTrue($store->isFamilyRevoked('family-a'));
        self::assertTrue($store->isFamilyRevoked('family-b'));
        self::assertFalse($store->isFamilyRevoked('family-c'));
        self::assertFalse($store->isFamilyRevoked('family-d'));
    }

    private function token(string $hash = 'hash-1', string $family = 'family-1', ?string $session = 'session-1'): RefreshTokenRecord
    {
        return new RefreshTokenRecord($hash, $family, 'client-1', 'user-1', ['openid'], $session, 1_700_000_600, null, null);
    }
}
